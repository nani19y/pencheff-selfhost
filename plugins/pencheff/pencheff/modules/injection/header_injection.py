"""HTTP header injection and response splitting module."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule
from pencheff.modules.injection import param_names

CRLF_PAYLOADS = [
    "%0d%0aInjected-Header:pencheff-canary",
    "%0aInjected-Header:pencheff-canary",
    "%0dInjected-Header:pencheff-canary",
    "%E5%98%8A%E5%98%8DInjected-Header:pencheff-canary",
    "\\r\\nInjected-Header:pencheff-canary",
    "%0d%0aSet-Cookie:pencheff=injected",
    "%0d%0a%0d%0a<html>pencheff-canary</html>",
    "\r\nInjected-Header:pencheff-canary",
    "%c0%8d%c0%8aInjected-Header:pencheff-canary",
]

HOST_HEADER_PAYLOADS = [
    "attacker.example.com",
    "localhost",
    "127.0.0.1",
    "attacker.example.com:80",
]


class HeaderInjectionModule(BaseTestModule):
    """Detect HTTP header injection, response splitting, and host header attacks."""

    name = "header_injection"
    category = "header_injection"
    owasp_categories = ["A03"]
    description = "CRLF injection, HTTP response splitting, host header poisoning"

    def get_techniques(self) -> list[str]:
        return ["crlf_injection", "response_splitting", "host_header_poisoning"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = self._get_target_endpoints(session, targets)
        base_url = session.target.base_url

        # Test CRLF injection
        crlf = await self._test_crlf(http, endpoints, session)
        findings.extend(crlf)

        # Test host header poisoning
        host = await self._test_host_header(http, base_url, session)
        findings.extend(host)

        return findings

    async def _test_crlf(
        self, http: PencheffHTTPClient,
        endpoints: list[dict[str, Any]],
        session: PentestSession,
    ) -> list[Finding]:
        """Test for CRLF injection in parameters reflected in headers."""
        findings: list[Finding] = []

        for ep in self._cap_endpoints(endpoints, 15):
            url = ep["url"]
            params = param_names(ep.get("params", []))
            test_params = list(params[:5]) or ["q", "url", "redirect", "path"]

            for param_name in test_params:
                for payload in CRLF_PAYLOADS[:5]:
                    try:
                        resp = await http.request(
                            "GET", url,
                            params={param_name: payload},
                            follow_redirects=False,
                            module="header_injection",
                        )

                        # Check if injected header appears
                        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                        if "injected-header" in resp_headers_lower:
                            findings.append(Finding(
                                title=f"CRLF Injection / Response Splitting: {url}",
                                severity=Severity.HIGH,
                                category="header_injection",
                                owasp_category="A03",
                                description=(
                                    f"CRLF injection in parameter '{param_name}' allows injection of "
                                    f"arbitrary HTTP headers. This enables: response splitting for cache "
                                    f"poisoning, XSS via injected Content-Type, session fixation via "
                                    f"Set-Cookie injection."
                                ),
                                remediation=(
                                    "Strip or encode CRLF characters (\\r\\n, %0d%0a) from all user "
                                    "input before using it in HTTP headers. Use framework-provided "
                                    "header-setting functions that auto-escape."
                                ),
                                endpoint=url,
                                parameter=param_name,
                                evidence=[Evidence(
                                    request_method="GET",
                                    request_url=f"{url}?{param_name}={payload}",
                                    response_status=resp.status_code,
                                    response_headers=dict(resp.headers),
                                    description=f"Injected header via CRLF payload: {payload[:40]}",
                                )],
                                cwe_id="CWE-113",
                                cvss_score=7.5,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                            ))
                            return findings  # One finding is enough

                        # Check for response body injection
                        if "pencheff-canary" in resp.text and "%0d%0a%0d%0a" in payload:
                            findings.append(Finding(
                                title=f"HTTP Response Splitting: {url}",
                                severity=Severity.CRITICAL,
                                category="header_injection",
                                owasp_category="A03",
                                description=(
                                    f"Full HTTP response splitting achieved via parameter '{param_name}'. "
                                    f"An attacker can inject a complete second HTTP response, enabling "
                                    f"cache poisoning, XSS, and content spoofing."
                                ),
                                remediation="Strip CRLF characters from all user-controlled header values.",
                                endpoint=url,
                                parameter=param_name,
                                evidence=[Evidence(
                                    request_method="GET",
                                    request_url=f"{url}?{param_name}={payload}",
                                    response_status=resp.status_code,
                                    response_body_snippet=resp.text[:300],
                                    description="Response body contains injected HTML",
                                )],
                                cwe_id="CWE-113",
                                cvss_score=9.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            ))
                            return findings
                    except Exception:
                        continue

        return findings

    async def _test_host_header(
        self, http: PencheffHTTPClient, base_url: str, session: PentestSession,
    ) -> list[Finding]:
        """Test for host header poisoning (password reset, cache poisoning)."""
        findings: list[Finding] = []

        for host_payload in HOST_HEADER_PAYLOADS:
            try:
                resp = await http.get(
                    base_url,
                    headers={"Host": host_payload},
                    module="header_injection",
                )

                # Check if the poisoned host is reflected in the response
                if host_payload in resp.text:
                    findings.append(Finding(
                        title="Host Header Poisoning",
                        severity=Severity.MEDIUM,
                        category="header_injection",
                        owasp_category="A05",
                        description=(
                            f"The Host header value '{host_payload}' is reflected in the response. "
                            f"This enables: password reset poisoning (link points to attacker), "
                            f"web cache poisoning, and server-side request forgery."
                        ),
                        remediation=(
                            "Validate the Host header against a whitelist. Use server-configured "
                            "canonical URLs for password reset links. Don't use the Host header "
                            "to construct URLs."
                        ),
                        endpoint=base_url,
                        parameter="Host",
                        evidence=[Evidence(
                            request_method="GET",
                            request_url=base_url,
                            request_headers={"Host": host_payload},
                            response_status=resp.status_code,
                            response_body_snippet=resp.text[:300],
                            description=f"Host header '{host_payload}' reflected in response body",
                        )],
                        cwe_id="CWE-644",
                        cvss_score=6.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    ))
                    break
            except Exception:
                continue

        return findings
