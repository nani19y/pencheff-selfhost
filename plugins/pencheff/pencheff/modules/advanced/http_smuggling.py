"""HTTP request smuggling detection module."""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.payload_loader import load_payloads
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Transfer-Encoding obfuscation variants for TE.TE attacks
TE_OBFUSCATIONS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding: xchunked",
    " Transfer-Encoding: chunked",
    "X: x\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding\r\n: chunked",
    "Transfer-Encoding: chunked\r\n",
    "Transfer-encoding: cow\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding: identity, chunked",
    "Transfer-Encoding: chunKed",
]


class HTTPSmugglingModule(BaseTestModule):
    """Detect HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE, H2.CL)."""

    name = "http_smuggling"
    category = "smuggling"
    owasp_categories = ["A05"]
    description = "HTTP request smuggling and desync attack detection"

    def get_techniques(self) -> list[str]:
        return [
            "cl_te_smuggling",
            "te_cl_smuggling",
            "te_te_obfuscation",
            "crlf_injection",
            "h2c_smuggling",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(session.target.base_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        path = parsed.path or "/"

        # CL.TE detection
        cl_te = await self._test_cl_te(http, host, port, path, use_tls, session)
        findings.extend(cl_te)

        # TE.CL detection
        te_cl = await self._test_te_cl(http, host, port, path, use_tls, session)
        findings.extend(te_cl)

        # TE.TE obfuscation detection
        te_te = await self._test_te_te(http, host, port, path, use_tls, session)
        findings.extend(te_te)

        # CRLF injection in headers
        crlf = await self._test_crlf(http, session)
        findings.extend(crlf)

        return findings

    async def _test_cl_te(
        self, http: PencheffHTTPClient, host: str, port: int,
        path: str, use_tls: bool, session: PentestSession,
    ) -> list[Finding]:
        """CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding."""
        findings: list[Finding] = []

        # Time-based detection: send a request where CL says the body is short,
        # but TE chunked says there's more. If back-end waits for more data, we get a timeout.
        probe = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"
        ).encode()

        try:
            resp = await asyncio.wait_for(
                http.raw_request(host, port, probe, module="http_smuggling", use_tls=use_tls, timeout=5),
                timeout=10,
            )
            # If we get a normal response, CL was used (front-end behavior)
        except asyncio.TimeoutError:
            # Timeout suggests the back-end is using TE and waiting for chunk termination
            findings.append(Finding(
                title="Potential CL.TE HTTP Request Smuggling",
                severity=Severity.CRITICAL,
                category="smuggling",
                owasp_category="A05",
                description=(
                    "The server appears to handle Content-Length and Transfer-Encoding headers "
                    "differently between the front-end and back-end, suggesting CL.TE desync "
                    "vulnerability. This can be exploited to smuggle requests, bypass security "
                    "controls, poison caches, and hijack other users' requests."
                ),
                remediation=(
                    "Configure front-end and back-end to use the same method for determining "
                    "request length. Reject ambiguous requests with both CL and TE headers. "
                    "Use HTTP/2 end-to-end where possible."
                ),
                endpoint=f"{session.target.base_url}{path}",
                evidence=[Evidence(
                    request_method="POST",
                    request_url=f"{session.target.base_url}{path}",
                    description="CL.TE probe caused timeout — back-end likely uses Transfer-Encoding",
                )],
                cwe_id="CWE-444",
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            ))
        except Exception:
            pass

        return findings

    async def _test_te_cl(
        self, http: PencheffHTTPClient, host: str, port: int,
        path: str, use_tls: bool, session: PentestSession,
    ) -> list[Finding]:
        """TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length."""
        findings: list[Finding] = []

        probe = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()

        try:
            resp = await asyncio.wait_for(
                http.raw_request(host, port, probe, module="http_smuggling", use_tls=use_tls, timeout=5),
                timeout=10,
            )
        except asyncio.TimeoutError:
            findings.append(Finding(
                title="Potential TE.CL HTTP Request Smuggling",
                severity=Severity.CRITICAL,
                category="smuggling",
                owasp_category="A05",
                description=(
                    "The server appears vulnerable to TE.CL request smuggling. The front-end "
                    "processes Transfer-Encoding while the back-end uses Content-Length. "
                    "An attacker can smuggle requests to bypass security controls, poison caches, "
                    "or hijack other users' sessions."
                ),
                remediation=(
                    "Normalize request parsing between front-end and back-end servers. "
                    "Reject requests containing both Content-Length and Transfer-Encoding. "
                    "Use HTTP/2 end-to-end."
                ),
                endpoint=f"{session.target.base_url}{path}",
                evidence=[Evidence(
                    request_method="POST",
                    request_url=f"{session.target.base_url}{path}",
                    description="TE.CL probe caused timeout — back-end likely uses Content-Length",
                )],
                cwe_id="CWE-444",
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            ))
        except Exception:
            pass

        return findings

    async def _test_te_te(
        self, http: PencheffHTTPClient, host: str, port: int,
        path: str, use_tls: bool, session: PentestSession,
    ) -> list[Finding]:
        """TE.TE: Both servers use TE but one can be confused with obfuscated headers."""
        findings: list[Finding] = []

        for obfuscation in TE_OBFUSCATIONS[:6]:
            probe = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{obfuscation}\r\n"
                f"\r\n"
                f"1\r\n"
                f"Z\r\n"
                f"Q"
            ).encode()

            try:
                resp = await asyncio.wait_for(
                    http.raw_request(host, port, probe, module="http_smuggling", use_tls=use_tls, timeout=5),
                    timeout=8,
                )
            except asyncio.TimeoutError:
                findings.append(Finding(
                    title="Potential TE.TE HTTP Smuggling via Header Obfuscation",
                    severity=Severity.HIGH,
                    category="smuggling",
                    owasp_category="A05",
                    description=(
                        f"Transfer-Encoding header obfuscation may cause desync between "
                        f"front-end and back-end. Obfuscation variant: '{obfuscation[:60]}'. "
                        f"This can lead to request smuggling attacks."
                    ),
                    remediation="Normalize Transfer-Encoding headers. Reject malformed TE headers.",
                    endpoint=f"{session.target.base_url}{path}",
                    evidence=[Evidence(
                        request_method="POST",
                        request_url=f"{session.target.base_url}{path}",
                        description=f"TE obfuscation '{obfuscation[:40]}' caused timeout",
                    )],
                    cwe_id="CWE-444",
                    cvss_score=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                ))
                break  # One finding is enough for TE.TE
            except Exception:
                continue

        return findings

    async def _test_crlf(
        self, http: PencheffHTTPClient, session: PentestSession,
    ) -> list[Finding]:
        """Test for CRLF injection in headers that could enable request splitting."""
        findings: list[Finding] = []
        base_url = session.target.base_url

        crlf_payloads = [
            "%0d%0aInjected-Header:true",
            "%0d%0a%0d%0a<html>injected</html>",
            "\\r\\nInjected-Header:true",
            "%E5%98%8A%E5%98%8DInjected-Header:true",  # Unicode CRLF
        ]

        for payload in crlf_payloads:
            test_url = f"{base_url}/?param={payload}"
            try:
                resp = await http.get(test_url, module="http_smuggling")
                # Check if our injected header appears in the response
                if "injected-header" in {k.lower() for k in resp.headers.keys()}:
                    findings.append(Finding(
                        title="CRLF Injection / HTTP Response Splitting",
                        severity=Severity.HIGH,
                        category="header_injection",
                        owasp_category="A03",
                        description=(
                            "The application reflects user input into HTTP response headers "
                            "without sanitizing CRLF characters. This enables HTTP response "
                            "splitting, cache poisoning, and XSS via injected headers."
                        ),
                        remediation="Strip or encode CRLF characters (\\r\\n) from all user input reflected in headers.",
                        endpoint=test_url,
                        parameter="param",
                        evidence=[Evidence(
                            request_method="GET",
                            request_url=test_url,
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            description=f"Injected header appeared in response via payload: {payload}",
                        )],
                        cwe_id="CWE-113",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    ))
                    break
            except Exception:
                continue

        return findings
