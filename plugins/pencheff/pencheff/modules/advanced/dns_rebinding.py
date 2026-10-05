"""DNS rebinding susceptibility detection module."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class DNSRebindingModule(BaseTestModule):
    """Detect susceptibility to DNS rebinding attacks."""

    name = "dns_rebinding"
    category = "misconfiguration"
    owasp_categories = ["A05"]
    description = "DNS rebinding susceptibility assessment"

    def get_techniques(self) -> list[str]:
        return [
            "host_header_validation",
            "ip_binding_check",
            "dns_pinning_detection",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        base_url = session.target.base_url

        # Test 1: Host header validation
        host_findings = await self._test_host_header(http, base_url, session)
        findings.extend(host_findings)

        # Test 2: Alternative IP binding
        ip_findings = await self._test_ip_binding(http, base_url, session)
        findings.extend(ip_findings)

        return findings

    async def _test_host_header(
        self, http: PencheffHTTPClient, base_url: str, session: PentestSession,
    ) -> list[Finding]:
        """Test if the server validates the Host header — weak validation enables DNS rebinding."""
        findings: list[Finding] = []

        spoofed_hosts = [
            "127.0.0.1",
            "localhost",
            "attacker.example.com",
            "0.0.0.0",
            "[::1]",
        ]

        try:
            baseline = await http.get(base_url, module="dns_rebinding")
            baseline_status = baseline.status_code
            baseline_len = len(baseline.text)
        except Exception:
            return findings

        for host in spoofed_hosts:
            try:
                resp = await http.get(
                    base_url,
                    headers={"Host": host},
                    module="dns_rebinding",
                )

                # If the server responds normally to a spoofed Host, it doesn't validate
                if resp.status_code == baseline_status and abs(len(resp.text) - baseline_len) < baseline_len * 0.3:
                    findings.append(Finding(
                        title="Missing Host Header Validation (DNS Rebinding Risk)",
                        severity=Severity.MEDIUM,
                        category="misconfiguration",
                        owasp_category="A05",
                        description=(
                            f"The server accepts requests with arbitrary Host headers (tested: '{host}'). "
                            f"This makes the application susceptible to DNS rebinding attacks, where an "
                            f"attacker's domain resolves to the target's internal IP, bypassing "
                            f"same-origin policy and accessing internal services."
                        ),
                        remediation=(
                            "Validate the Host header against a whitelist of expected values. "
                            "Return 400/403 for unrecognized Host values. "
                            "Bind services to specific hostnames, not 0.0.0.0."
                        ),
                        endpoint=base_url,
                        evidence=[Evidence(
                            request_method="GET",
                            request_url=base_url,
                            request_headers={"Host": host},
                            response_status=resp.status_code,
                            description=f"Spoofed Host '{host}' accepted — same response as legitimate host",
                        )],
                        cwe_id="CWE-350",
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    ))
                    break
            except Exception:
                continue

        return findings

    async def _test_ip_binding(
        self, http: PencheffHTTPClient, base_url: str, session: PentestSession,
    ) -> list[Finding]:
        """Check if internal service ports accept connections from any interface."""
        findings: list[Finding] = []

        # Check common internal service indicators in responses
        try:
            resp = await http.get(base_url, module="dns_rebinding")
            body_lower = resp.text.lower()

            internal_indicators = [
                "127.0.0.1", "localhost", "0.0.0.0",
                "internal", "intranet", "admin-panel",
            ]

            for indicator in internal_indicators:
                if indicator in body_lower:
                    findings.append(Finding(
                        title="Internal Service Reference Detected",
                        severity=Severity.LOW,
                        category="misconfiguration",
                        owasp_category="A05",
                        description=(
                            f"The response references '{indicator}', suggesting internal "
                            f"services may be accessible. Combined with DNS rebinding, this "
                            f"could allow external attackers to access internal resources."
                        ),
                        remediation="Remove internal service references from public responses. Segment internal services.",
                        endpoint=base_url,
                        evidence=[Evidence(
                            request_method="GET",
                            request_url=base_url,
                            response_status=resp.status_code,
                            description=f"Internal indicator '{indicator}' found in response",
                        )],
                        cwe_id="CWE-200",
                        cvss_score=3.7,
                    ))
                    break
        except Exception:
            pass

        return findings
