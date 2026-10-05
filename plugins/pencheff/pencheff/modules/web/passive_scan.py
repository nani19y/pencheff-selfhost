"""Passive scanning — detect issues in observed traffic without sending new requests.

Runs over either:
  - proxy flows captured by ``core.proxy``
  - response data passed directly from an active-scan module

Rules here intentionally do NOT fire new requests. They extract signals from
the already-available response only.
"""

from __future__ import annotations

import re
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding


# Common info-leak patterns in bodies / headers
PATTERNS = [
    (re.compile(r"(?i)eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
     "JWT token visible in response body", Severity.MEDIUM),
    (re.compile(r"(?i)AKIA[0-9A-Z]{16}"),
     "AWS access key disclosed in response", Severity.CRITICAL),
    (re.compile(r"(?i)ghp_[A-Za-z0-9]{36}"),
     "GitHub PAT disclosed in response", Severity.CRITICAL),
    (re.compile(r"(?i)-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
     "Private key disclosed in response", Severity.CRITICAL),
    (re.compile(r"(?i)stack\s*trace"),
     "Stack trace leaked in response", Severity.MEDIUM),
    (re.compile(r"(?i)(ORA-\d{4,5}|PG::|PostgreSQL error|SQLSTATE\[\d+\]|Warning: mysql)"),
     "Database error leaked in response", Severity.MEDIUM),
    (re.compile(r"(?i)Internal Server Error.{0,200}Traceback"),
     "Python traceback exposed", Severity.MEDIUM),
    (re.compile(r"(?i)(username|password|email)\s*[:=]\s*\"[^\"]{4,64}\""),
     "Credentials visible in response JSON/body", Severity.HIGH),
]


HEADER_RULES = [
    ("x-powered-by", Severity.INFO,
     "Server discloses technology via X-Powered-By header",
     "Remove the X-Powered-By header from your reverse proxy / app config."),
    ("server", Severity.INFO,
     "Server discloses version via Server header",
     "Set Server header to a generic value at your edge."),
    ("x-aspnet-version", Severity.LOW,
     "ASP.NET version disclosed",
     "Remove X-AspNet-Version header in web.config."),
    ("x-debug-token-link", Severity.HIGH,
     "Symfony debug toolbar leaked",
     "Disable the debug toolbar in production environments."),
    ("x-debug", Severity.HIGH,
     "Debug header exposed in production response",
     "Disable debug mode in production."),
]


def scan_flow(flow) -> list[Finding]:
    """Passive scan of a single captured flow (mitmproxy / fallback flow)."""
    findings: list[Finding] = []
    body = getattr(flow, "resp_body", "") or ""
    headers = {k.lower(): v for k, v in (getattr(flow, "resp_headers", {}) or {}).items()}
    url = getattr(flow, "url", "") or ""

    for pattern, title, sev in PATTERNS:
        if pattern.search(body):
            findings.append(_f(title, url, sev,
                "Remove the sensitive data from the response; rotate if the value is real.",
                body[:300]))

    for header, sev, title, remediation in HEADER_RULES:
        if header in headers:
            findings.append(_f(f"{title}: '{headers[header]}'", url, sev, remediation,
                              f"{header}: {headers[header]}"))

    # Missing HTTPS
    if url.startswith("http://") and not url.startswith("http://localhost"):
        findings.append(_f(
            "Insecure HTTP traffic observed", url, Severity.MEDIUM,
            "Redirect all HTTP to HTTPS; enable HSTS with includeSubDomains + preload.",
            "",
        ))

    # Set-Cookie flag analysis (passive — cookie on an observed response)
    set_cookie = headers.get("set-cookie", "") or ""
    if set_cookie:
        lower = set_cookie.lower()
        if "secure" not in lower and url.startswith("https://"):
            findings.append(_f("Cookie missing Secure flag on HTTPS response", url,
                              Severity.LOW, "Add Secure attribute to Set-Cookie.",
                              set_cookie[:200]))
        if "httponly" not in lower:
            findings.append(_f("Cookie missing HttpOnly flag", url, Severity.LOW,
                              "Add HttpOnly attribute to Set-Cookie.",
                              set_cookie[:200]))
        if "samesite" not in lower:
            findings.append(_f("Cookie missing SameSite attribute", url, Severity.LOW,
                              "Add SameSite=Lax or Strict to Set-Cookie.",
                              set_cookie[:200]))
    return findings


def scan_response(
    method: str, url: str, status: int,
    headers: dict[str, str], body: str,
) -> list[Finding]:
    """Passive scan on an active-scanner response — same rules, different source."""
    class _Pseudo:
        pass
    p = _Pseudo()
    p.method, p.url, p.status = method, url, status
    p.resp_headers, p.resp_body = headers, body
    return scan_flow(p)


def _f(title: str, url: str, sev: Severity, remediation: str, snippet: str) -> Finding:
    return Finding(
        title=f"Passive: {title}",
        severity=sev,
        category="misconfiguration",
        owasp_category="A05",
        description=f"Passive scanner observed: {title}",
        remediation=remediation,
        endpoint=url,
        evidence=[Evidence(
            request_method="PASSIVE", request_url=url,
            response_status=200, description=snippet[:300],
        )],
    )
