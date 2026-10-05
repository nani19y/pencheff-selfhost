"""Security headers analysis module."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": Severity.MEDIUM,
        "description": "HSTS not set. Browser can be MITM'd to HTTP.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        "cwe": "CWE-319",
    },
    "content-security-policy": {
        "severity": Severity.MEDIUM,
        "description": "CSP not set. No protection against XSS and data injection.",
        "remediation": "Implement a Content-Security-Policy header. Start with 'default-src self'.",
        "cwe": "CWE-1021",
    },
    "x-content-type-options": {
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options not set. Browser may MIME-sniff responses.",
        "remediation": "Add 'X-Content-Type-Options: nosniff'.",
        "cwe": "CWE-16",
    },
    "x-frame-options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options not set. Page may be embedded in iframes (clickjacking).",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
        "cwe": "CWE-1021",
    },
    "referrer-policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy not set. Full URL may leak to external sites via Referer header.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
        "cwe": "CWE-200",
    },
    "permissions-policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy not set. Browser features (camera, mic, geolocation) not restricted.",
        "remediation": "Add 'Permissions-Policy' header to restrict unused browser features.",
        "cwe": "CWE-16",
    },
    # x-xss-protection deliberately omitted — the header has been
    # deprecated since 2020. Modern browsers (Chrome 78+, Edge, Safari,
    # Firefox) ignore it entirely; OWASP and Mozilla now recommend
    # either omitting it or explicitly disabling with `X-XSS-Protection:
    # 0`. Flagging it as missing gives users actively wrong advice.
}

# Headers that other specialized modules already report on with richer
# context. We skip them in the generic missing-header loop so the report
# doesn't list the same problem twice with different titles. Source of
# truth (header → owning module):
#   * x-frame-options          → modules.client_side.clickjacking
#   * strict-transport-security → modules.web.ssl_tls
_HEADERS_OWNED_ELSEWHERE: frozenset[str] = frozenset({
    "x-frame-options",
    "strict-transport-security",
})

# Dangerous CSP directives
DANGEROUS_CSP = [
    ("unsafe-inline", "Allows inline scripts/styles, defeating XSS protection"),
    ("unsafe-eval", "Allows eval(), enabling code execution from strings"),
    ("*", "Wildcard source allows loading from any origin"),
    ("data:", "Allows data: URIs which can be used for XSS"),
    ("http:", "Allows loading over insecure HTTP"),
]


class SecurityHeadersModule(BaseTestModule):
    name = "security_headers"
    category = "misconfiguration"
    owasp_categories = ["A05"]
    description = "Security headers analysis"

    def get_techniques(self) -> list[str]:
        return ["missing_headers", "weak_csp", "cookie_flags"]

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
            resp = await http.get(base_url, module="security_headers")
        except Exception:
            return findings

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing security headers — skip those owned by other modules.
        for header, info in SECURITY_HEADERS.items():
            if header in _HEADERS_OWNED_ELSEWHERE:
                continue
            if header not in headers_lower:
                findings.append(Finding(
                    title=f"Missing Security Header: {header}",
                    severity=info["severity"],
                    category="misconfiguration",
                    owasp_category="A05",
                    description=info["description"],
                    remediation=info["remediation"],
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    cvss_score=4.3 if info["severity"] == Severity.MEDIUM else 3.1,
                    cwe_id=info["cwe"],
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=base_url,
                        response_status=resp.status_code,
                        description=f"Header '{header}' is absent from the response",
                    )],
                ))

        # Analyze CSP if present
        csp = headers_lower.get("content-security-policy", "")
        if csp:
            # Parse CSP into {directive: [sources]} so we can tell which
            # directive carries the dangerous source — `unsafe-inline` in
            # style-src/img-src is far less critical than in script-src.
            csp_directives: dict[str, list[str]] = {}
            for chunk in csp.split(";"):
                parts = chunk.strip().split()
                if not parts:
                    continue
                csp_directives[parts[0].lower()] = [p.lower() for p in parts[1:]]

            high_risk_directives = {"script-src", "default-src", "object-src"}

            for directive, risk in DANGEROUS_CSP:
                if directive not in csp:
                    continue
                # Find which CSP directives actually carry this token.
                carriers = [
                    name for name, sources in csp_directives.items()
                    if any(directive in s for s in sources)
                ]
                f = Finding(
                    title=f"Weak CSP Directive: '{directive}'",
                    severity=Severity.MEDIUM,
                    category="misconfiguration",
                    owasp_category="A05",
                    description=f"CSP contains '{directive}': {risk}",
                    remediation=f"Remove '{directive}' from CSP and use nonce-based or hash-based policies.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    cvss_score=5.4,
                    cwe_id="CWE-1021",
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=base_url,
                        response_status=resp.status_code,
                        description=f"CSP: {csp[:200]}",
                    )],
                )
                # Only flag actively when the dangerous source lives in
                # script-execution directives. unsafe-inline in
                # style-src / img-src / font-src is non-exploitable for
                # XSS — record but suppress so it doesn't dominate the
                # report.
                if carriers and not any(c in high_risk_directives for c in carriers):
                    from datetime import datetime, timezone
                    from pencheff.core.findings import SuppressReason
                    f.suppressed = True
                    f.suppress_reason = SuppressReason.ACCEPTED_RISK
                    f.suppress_notes = (
                        f"Auto-suppressed: '{directive}' appears only in "
                        f"non-script directives ({', '.join(sorted(set(carriers)))}). "
                        "Not exploitable for XSS — still flagged for "
                        "completeness, hidden from the active list."
                    )
                    f.suppressed_at = datetime.now(timezone.utc)
                findings.append(f)

        # Check cookie security flags via the proper parser so cookie
        # *attributes* (Path, Domain, …) don't get mistaken for cookie
        # names — which used to produce findings like "Cookie Missing
        # 'SameSite' Attribute: Path".
        from pencheff.core.cookie_parser import parse_set_cookie

        set_cookies_raw = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookies_raw:
            raw = headers_lower.get("set-cookie", "")
            if raw:
                set_cookies_raw = [raw]

        parsed_cookies = []
        for raw in set_cookies_raw:
            parsed_cookies.extend(parse_set_cookie(raw))

        for cookie in parsed_cookies:
            if not cookie.secure:
                findings.append(Finding(
                    title=f"Cookie Missing 'Secure' Flag: {cookie.name}",
                    severity=Severity.MEDIUM,
                    category="auth",
                    owasp_category="A07",
                    description=f"Cookie '{cookie.name}' is not marked Secure. It will be sent over HTTP.",
                    remediation="Add the 'Secure' flag to all cookies.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cvss_score=3.1,
                    cwe_id="CWE-614",
                ))
            if not cookie.httponly:
                findings.append(Finding(
                    title=f"Cookie Missing 'HttpOnly' Flag: {cookie.name}",
                    severity=Severity.MEDIUM,
                    category="auth",
                    owasp_category="A07",
                    description=f"Cookie '{cookie.name}' is not marked HttpOnly. JavaScript can access it (XSS risk).",
                    remediation="Add the 'HttpOnly' flag to session cookies.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cvss_score=4.3,
                    cwe_id="CWE-1004",
                ))
            if not cookie.has_samesite:
                findings.append(Finding(
                    title=f"Cookie Missing 'SameSite' Attribute: {cookie.name}",
                    severity=Severity.LOW,
                    category="auth",
                    owasp_category="A07",
                    description=f"Cookie '{cookie.name}' has no SameSite attribute. May be vulnerable to CSRF.",
                    remediation="Add 'SameSite=Lax' or 'SameSite=Strict' to cookies.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    cvss_score=4.3,
                    cwe_id="CWE-1275",
                ))

        return findings
