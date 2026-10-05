"""Session management testing — fixation, cookie security, expiration."""

from __future__ import annotations

import re
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class SessionManagementModule(BaseTestModule):
    name = "session_mgmt"
    category = "auth"
    owasp_categories = ["A07"]
    description = "Session management security testing"

    def get_techniques(self) -> list[str]:
        return ["session_fixation", "session_entropy", "session_expiration", "concurrent_sessions"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url

        # Get initial session
        try:
            resp1 = await http.get(base_url, module="session_mgmt")
        except Exception:
            return findings

        # Bail on SPA fallback — there's no server-side session machinery
        # to test if the apex just serves index.html for unknown paths.
        from pencheff.core.spa_detector import is_real_endpoint
        if not is_real_endpoint(resp1, session):
            return findings

        # Check session ID entropy
        from pencheff.core.cookie_parser import parse_set_cookie
        session_ids = []
        for _ in range(3):
            try:
                r = await http.get(base_url, module="session_mgmt", inject_creds=False)
                # Properly parse Set-Cookie so attributes like "Path=/"
                # don't get mistaken for cookies (which yields a length-1
                # "session ID" and the bogus low-entropy finding).
                for parsed in parse_set_cookie(r.headers.get("set-cookie", "")):
                    if parsed.value:
                        session_ids.append(parsed.value)
                        break  # one SID per response is enough for the entropy test
            except Exception:
                pass

        if len(session_ids) >= 2:
            # Check if session IDs are sequential or low-entropy
            if all(sid.isdigit() for sid in session_ids):
                findings.append(Finding(
                    title="Weak Session ID (Numeric/Sequential)",
                    severity=Severity.HIGH,
                    category="auth",
                    owasp_category="A07",
                    description="Session IDs appear to be numeric and potentially sequential/predictable.",
                    remediation="Use cryptographically random session IDs of at least 128 bits.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cvss_score=9.1,
                    cwe_id="CWE-330",
                ))
            elif all(len(sid) < 16 for sid in session_ids):
                findings.append(Finding(
                    title="Short Session ID (Low Entropy)",
                    severity=Severity.MEDIUM,
                    category="auth",
                    owasp_category="A07",
                    description=f"Session IDs are short (length: {len(session_ids[0])}). May be brute-forceable.",
                    remediation="Use session IDs of at least 128 bits (32 hex characters).",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cvss_score=5.9,
                    cwe_id="CWE-330",
                ))

        # Session fixation: check if pre-auth session ID survives authentication
        try:
            pre_auth = await http.get(base_url, module="session_mgmt", inject_creds=False)
            pre_parsed = parse_set_cookie(pre_auth.headers.get("set-cookie", ""))
            pre_sid = pre_parsed[0].value if pre_parsed else ""

            # Now make an authenticated request
            post_auth = await http.get(base_url, module="session_mgmt", inject_creds=True)
            post_parsed = parse_set_cookie(post_auth.headers.get("set-cookie", ""))
            post_sid = post_parsed[0].value if post_parsed else ""

            if pre_sid and post_sid and pre_sid == post_sid:
                findings.append(Finding(
                    title="Session Fixation Vulnerability",
                    severity=Severity.HIGH,
                    category="auth",
                    owasp_category="A07",
                    description="Session ID does not change after authentication. "
                                "An attacker can fix a session ID before login and hijack the authenticated session.",
                    remediation="Regenerate the session ID after successful authentication.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    cvss_score=8.1,
                    cwe_id="CWE-384",
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=base_url,
                        description=f"Pre-auth SID: {pre_sid[:8]}..., Post-auth SID: {post_sid[:8]}... (same)",
                    )],
                ))
        except Exception:
            pass

        # Check for session in URL
        try:
            resp = await http.get(base_url, module="session_mgmt", follow_redirects=False)
            location = resp.headers.get("location", "")
            if re.search(r"[?&](session|sid|token|jsessionid)=", location, re.IGNORECASE):
                findings.append(Finding(
                    title="Session ID Exposed in URL",
                    severity=Severity.MEDIUM,
                    category="auth",
                    owasp_category="A07",
                    description="Session identifier is passed in the URL, making it visible in browser history, "
                                "server logs, and Referer headers.",
                    remediation="Transmit session IDs only via cookies, never in URLs.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    cvss_score=6.5,
                    cwe_id="CWE-598",
                ))
        except Exception:
            pass

        return findings
