"""SSL/TLS configuration testing."""

from __future__ import annotations

import ssl
from typing import Any
from urllib.parse import urlparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.core.tool_runner import run_tool, tool_available
from pencheff.modules.base import BaseTestModule

# Each entry is (display name, openssl s_client force-version flag).
# We force the version explicitly because greping the negotiated-output for
# the literal protocol string is unsafe — "TLSv1" is a substring of "TLSv1.3".
WEAK_PROTOCOLS: list[tuple[str, str]] = [
    ("SSLv2", "-ssl2"),
    ("SSLv3", "-ssl3"),
    ("TLSv1", "-tls1"),
    ("TLSv1.1", "-tls1_1"),
]
WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"}


class SSLTLSModule(BaseTestModule):
    name = "ssl_tls"
    category = "crypto"
    owasp_categories = ["A02"]
    description = "SSL/TLS configuration analysis"

    def get_techniques(self) -> list[str]:
        return ["protocol_check", "cipher_check", "certificate_check", "hsts_check"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        # TLS-bearing schemes. wss:// and grpcs:// are encrypted just like https,
        # so they must NOT be flagged as plaintext (the old ``!= "https"`` check
        # false-positived on every WebSocket/gRPC-TLS target).
        encrypted_schemes = {"https", "wss", "grpcs"}
        parsed = urlparse(session.target.base_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme in encrypted_schemes else 80)
        findings = []

        # gRPC uses the grpc:// scheme for BOTH plaintext (h2c) and TLS, and the
        # scheme alone (or the operator's kind_config.plaintext, which is often
        # mis-declared) is NOT authoritative. Probe the actual transport with a
        # real TLS handshake so the finding reflects reality — an operator who
        # sets plaintext=false against a plaintext server must still be flagged.
        from pencheff.artifact_tools import _kind_config_for_session
        kcfg = _kind_config_for_session(session.id) or {}
        if parsed.scheme in ("grpc", "grpcs") or kcfg.get("kind") == "grpc":
            gport = parsed.port or 443
            if tool_available("openssl"):
                probe = await run_tool([
                    "openssl", "s_client", "-connect", f"{host}:{gport}",
                    "-servername", host, "-brief",
                ], timeout=8)
                # A successful handshake prints "Protocol version:"; a plaintext
                # port yields "wrong version number" and no such line.
                tls_live = "Protocol version:" in (probe.stdout + probe.stderr)
            else:
                # No prober available — fall back to the operator's declaration.
                tls_live = not bool(kcfg.get("plaintext", parsed.scheme == "grpc"))
            if not tls_live:
                findings.append(Finding(
                    title="Service Endpoint Not Using TLS",
                    severity=Severity.HIGH,
                    category="crypto",
                    owasp_category="A02",
                    description=("The gRPC endpoint accepts plaintext h2c connections "
                                 "(no TLS) — traffic and metadata are transmitted "
                                 "unencrypted. Verified by a failed TLS handshake."),
                    remediation="Serve gRPC over TLS and disable plaintext h2c.",
                    endpoint=session.target.base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cvss_score=7.5,
                    cwe_id="CWE-319",
                ))
                return findings
            # TLS gRPC: fall through to the openssl cert / weak-protocol checks
            # below (they operate on the TLS layer, identical to HTTPS).
            port = gport
        elif parsed.scheme not in encrypted_schemes:
            # Word the finding to the transport. urlparse reads a bare ``host:port``
            # (e.g. a gRPC target) with the host as the "scheme", so anything that
            # isn't a known plaintext web/ws scheme is treated as a non-HTTP service.
            if parsed.scheme == "ws":
                title = "WebSocket Endpoint Not Using TLS"
                description = ("The endpoint is served over ws://, not wss:// — "
                               "WebSocket frames are transmitted unencrypted.")
                remediation = "Serve the WebSocket over wss:// with a valid TLS certificate."
            elif parsed.scheme in ("http", ""):
                title = "Site Not Using HTTPS"
                description = "The target is served over HTTP, not HTTPS. All traffic is unencrypted."
                remediation = "Enable HTTPS with a valid TLS certificate. Redirect all HTTP to HTTPS."
            else:
                title = "Service Endpoint Not Using TLS"
                description = ("The endpoint is reachable over a plaintext transport "
                               "(no TLS) — traffic is unencrypted.")
                remediation = "Enable TLS on the service and require encrypted connections."
            findings.append(Finding(
                title=title,
                severity=Severity.HIGH,
                category="crypto",
                owasp_category="A02",
                description=description,
                remediation=remediation,
                endpoint=session.target.base_url,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_score=7.5,
                cwe_id="CWE-319",
            ))
            return findings

        # Check certificate details via openssl
        if tool_available("openssl"):
            # Force-probe each weak protocol independently. We only flag a
            # weak protocol as "supported" when openssl can actually
            # negotiate it under that explicit version flag — a plain
            # connection negotiates the highest mutually-supported version,
            # so its output will mention "TLSv1.3" even on servers that
            # refuse TLS 1.0/1.1, which used to fire a false positive.
            for proto, flag in WEAK_PROTOCOLS:
                forced = await run_tool([
                    "openssl", "s_client", "-connect", f"{host}:{port}",
                    "-servername", host, flag, "-brief",
                ], timeout=8)
                forced_output = forced.stdout + forced.stderr
                # `-brief` prints "Protocol version: <X>" on a successful
                # handshake. We require that exact line to mention the
                # forced protocol — substring matching is unsafe because
                # "TLSv1" is a substring of "TLSv1.3".
                negotiated = ""
                for line in forced_output.splitlines():
                    if line.startswith("Protocol version:"):
                        negotiated = line.split(":", 1)[1].strip()
                        break
                if not negotiated or negotiated != proto:
                    continue
                findings.append(Finding(
                    title=f"Weak TLS Protocol Supported: {proto}",
                    severity=Severity.HIGH if proto in ("SSLv2", "SSLv3") else Severity.MEDIUM,
                    category="crypto",
                    owasp_category="A02",
                    description=f"The server supports {proto}, which has known vulnerabilities.",
                    remediation=f"Disable {proto}. Use TLS 1.2 or TLS 1.3 only.",
                    endpoint=f"{host}:{port}",
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cvss_score=5.9,
                    cwe_id="CWE-326",
                    evidence=[Evidence(
                        request_method="TLS",
                        request_url=f"{host}:{port}",
                        response_body_snippet=forced_output[:300],
                        description=(
                            f"Forced {flag} handshake negotiated {negotiated}"
                        ),
                    )],
                ))

            # Check for weak ciphers
            for cipher_class in ["RC4", "DES", "NULL", "EXPORT"]:
                cipher_result = await run_tool([
                    "openssl", "s_client", "-connect", f"{host}:{port}",
                    "-cipher", cipher_class, "-brief",
                ], timeout=5)
                if cipher_result.success and "CONNECTED" in cipher_result.stdout:
                    findings.append(Finding(
                        title=f"Weak Cipher Suite Accepted: {cipher_class}",
                        severity=Severity.HIGH,
                        category="crypto",
                        owasp_category="A02",
                        description=f"The server accepts {cipher_class} cipher suites, which are cryptographically weak.",
                        remediation=f"Disable {cipher_class} cipher suites in your TLS configuration.",
                        endpoint=f"{host}:{port}",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cvss_score=5.9,
                        cwe_id="CWE-327",
                    ))

            # Check certificate expiration
            cert_result = await run_tool([
                "openssl", "s_client", "-connect", f"{host}:{port}",
                "-servername", host,
            ], timeout=10)
            if cert_result.success:
                dates_result = await run_tool(
                    ["openssl", "x509", "-noout", "-dates"],
                    stdin_data=cert_result.stdout,
                    timeout=5,
                )
                if dates_result.success and "notAfter" in dates_result.stdout:
                    # Parse expiry
                    for line in dates_result.stdout.split("\n"):
                        if "notAfter" in line:
                            expiry = line.split("=", 1)[1].strip()
                            import datetime
                            try:
                                exp_date = datetime.datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
                                if exp_date < datetime.datetime.now():
                                    findings.append(Finding(
                                        title="SSL Certificate Expired",
                                        severity=Severity.HIGH,
                                        category="crypto",
                                        owasp_category="A02",
                                        description=f"The SSL certificate expired on {expiry}.",
                                        remediation="Renew the SSL certificate immediately.",
                                        endpoint=f"{host}:{port}",
                                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                                        cvss_score=6.5,
                                        cwe_id="CWE-295",
                                    ))
                            except ValueError:
                                pass

        # Check HSTS via HTTP response
        try:
            resp = await http.get(session.target.base_url, module="ssl_tls")
            hsts = resp.headers.get("strict-transport-security")
            if not hsts:
                findings.append(Finding(
                    title="HSTS Not Configured",
                    severity=Severity.MEDIUM,
                    category="crypto",
                    owasp_category="A05",
                    description="HTTP Strict Transport Security header is not set. "
                                "Users can be downgraded to HTTP via MITM.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                    endpoint=session.target.base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    cvss_score=4.8,
                    cwe_id="CWE-319",
                ))
        except Exception:
            pass

        return findings
