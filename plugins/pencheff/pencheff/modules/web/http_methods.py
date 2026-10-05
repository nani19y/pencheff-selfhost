"""HTTP method testing and verb tampering."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]


class HTTPMethodsModule(BaseTestModule):
    name = "http_methods"
    category = "misconfiguration"
    owasp_categories = ["A05"]
    description = "HTTP method testing and verb tampering"

    def get_techniques(self) -> list[str]:
        return ["options_check", "verb_tampering", "trace_check"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)[:10]

        for ep in endpoints:
            url = ep["url"]

            # OPTIONS check
            try:
                resp = await http.options(url, module="http_methods")
                allow = resp.headers.get("allow", "")
                if allow:
                    allowed_methods = [m.strip().upper() for m in allow.split(",")]
                    dangerous = [m for m in allowed_methods if m in DANGEROUS_METHODS]
                    if dangerous:
                        findings.append(Finding(
                            title=f"Dangerous HTTP Methods Allowed: {', '.join(dangerous)}",
                            severity=Severity.MEDIUM,
                            category="misconfiguration",
                            owasp_category="A05",
                            description=f"Endpoint allows: {allow}. "
                                        f"Dangerous methods ({', '.join(dangerous)}) may enable modification or info disclosure.",
                            remediation="Disable unnecessary HTTP methods. Only allow GET, POST, HEAD as needed.",
                            endpoint=url,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                            cvss_score=5.3,
                            cwe_id="CWE-749",
                            evidence=[Evidence(
                                request_method="OPTIONS",
                                request_url=url,
                                response_status=resp.status_code,
                                description=f"Allow: {allow}",
                            )],
                        ))
            except Exception:
                pass

            # TRACE check (XST vulnerability)
            try:
                resp = await http.request("TRACE", url, module="http_methods")
                if resp.status_code == 200 and "TRACE" in resp.text.upper():
                    findings.append(Finding(
                        title="HTTP TRACE Method Enabled (XST Risk)",
                        severity=Severity.MEDIUM,
                        category="misconfiguration",
                        owasp_category="A05",
                        description="TRACE method is enabled, which can be used for Cross-Site Tracing (XST) "
                                    "to steal credentials from HttpOnly cookies.",
                        remediation="Disable the TRACE HTTP method on the web server.",
                        endpoint=url,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        cvss_score=3.1,
                        cwe_id="CWE-693",
                        evidence=[Evidence(
                            request_method="TRACE",
                            request_url=url,
                            response_status=resp.status_code,
                            response_body_snippet=resp.text[:300],
                            description="TRACE method reflected request back",
                        )],
                    ))
            except Exception:
                pass

        return findings
