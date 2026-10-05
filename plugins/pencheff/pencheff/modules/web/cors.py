"""CORS misconfiguration testing."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class CORSModule(BaseTestModule):
    name = "cors"
    category = "misconfiguration"
    owasp_categories = ["A05"]
    description = "CORS misconfiguration testing"

    def get_techniques(self) -> list[str]:
        return ["wildcard_origin", "reflected_origin", "null_origin", "subdomain_bypass", "credentials_leak"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url
        domain = urlparse(base_url).hostname

        test_origins = [
            ("https://evil.com", "arbitrary_origin"),
            ("null", "null_origin"),
            (f"https://evil.{domain}", "subdomain_bypass"),
            (f"https://{domain}.evil.com", "domain_suffix_bypass"),
            (base_url, "same_origin_baseline"),
        ]

        for origin, test_name in test_origins:
            try:
                resp = await http.get(
                    base_url,
                    headers={"Origin": origin},
                    module="cors",
                )
            except Exception:
                continue

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            if test_name == "same_origin_baseline":
                continue

            if acao == "*":
                findings.append(Finding(
                    title="CORS Wildcard Origin Allowed",
                    severity=Severity.MEDIUM,
                    category="misconfiguration",
                    owasp_category="A05",
                    description="The server responds with Access-Control-Allow-Origin: *. "
                                "Any website can read responses from this origin.",
                    remediation="Restrict CORS to specific trusted origins instead of wildcard.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cvss_score=4.3,
                    cwe_id="CWE-942",
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=base_url,
                        request_headers={"Origin": origin},
                        response_status=resp.status_code,
                        description=f"ACAO: {acao}",
                    )],
                ))
                if acac == "true":
                    findings.append(Finding(
                        title="CORS Wildcard with Credentials",
                        severity=Severity.HIGH,
                        category="misconfiguration",
                        owasp_category="A05",
                        description="Wildcard CORS with credentials allowed. Browsers block this, but indicates misconfiguration.",
                        remediation="Never combine wildcard origin with credentials. Use specific origins.",
                        endpoint=base_url,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                        cvss_score=6.5,
                        cwe_id="CWE-942",
                    ))

            elif acao == origin and test_name != "same_origin_baseline":
                sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
                findings.append(Finding(
                    title=f"CORS Reflects Untrusted Origin ({test_name})",
                    severity=sev,
                    category="misconfiguration",
                    owasp_category="A05",
                    description=f"The server reflects the attacker-controlled origin '{origin}' "
                                f"in Access-Control-Allow-Origin. "
                                f"{'Credentials are also allowed, enabling full data theft.' if acac == 'true' else ''}",
                    remediation="Validate the Origin header against a whitelist of trusted origins.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N" if acac == "true"
                               else "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cvss_score=7.1 if acac == "true" else 4.3,
                    cwe_id="CWE-942",
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=base_url,
                        request_headers={"Origin": origin},
                        response_status=resp.status_code,
                        description=f"ACAO: {acao}, ACAC: {acac}",
                    )],
                ))

        return findings
