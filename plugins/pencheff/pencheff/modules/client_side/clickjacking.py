"""Clickjacking / UI redressing testing."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class ClickjackingModule(BaseTestModule):
    name = "clickjacking"
    category = "misconfiguration"
    owasp_categories = ["A05"]
    description = "Clickjacking / iframe embedding protection testing"

    def get_techniques(self) -> list[str]:
        return ["x_frame_options", "csp_frame_ancestors"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url

        try:
            resp = await http.get(base_url, module="clickjacking")
        except Exception:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}
        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")

        has_xfo = xfo.upper() in ("DENY", "SAMEORIGIN")
        has_csp_frame = "frame-ancestors" in csp

        if not has_xfo and not has_csp_frame:
            findings.append(Finding(
                title="Clickjacking: No Frame Protection",
                severity=Severity.MEDIUM,
                category="misconfiguration",
                owasp_category="A05",
                description="Neither X-Frame-Options nor CSP frame-ancestors is set. "
                            "The page can be embedded in iframes on attacker-controlled sites.",
                remediation="Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors none'.",
                endpoint=base_url,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cvss_score=4.3,
                cwe_id="CWE-1021",
                evidence=[Evidence(
                    request_method="GET",
                    request_url=base_url,
                    response_status=resp.status_code,
                    description="No X-Frame-Options or CSP frame-ancestors header found",
                )],
            ))
        elif xfo.upper() == "ALLOWALL":
            findings.append(Finding(
                title="Clickjacking: X-Frame-Options Set to ALLOWALL",
                severity=Severity.MEDIUM,
                category="misconfiguration",
                owasp_category="A05",
                description="X-Frame-Options is set to ALLOWALL, which permits framing by any site.",
                remediation="Change X-Frame-Options to DENY or SAMEORIGIN.",
                endpoint=base_url,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cvss_score=4.3,
                cwe_id="CWE-1021",
            ))

        return findings
