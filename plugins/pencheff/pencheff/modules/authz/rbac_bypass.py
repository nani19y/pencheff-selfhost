"""Role-Based Access Control bypass testing."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class RBACBypassModule(BaseTestModule):
    name = "rbac_bypass"
    category = "authz"
    owasp_categories = ["A01"]
    description = "Role-Based Access Control bypass testing"

    def get_techniques(self) -> list[str]:
        return ["parameter_role_injection", "header_role_injection", "path_traversal_bypass"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url
        endpoints = self._get_target_endpoints(session, targets)

        # Test 1: Role injection via parameters
        for ep in self._cap_endpoints(endpoints, 15):
            url = ep["url"]
            role_params = [
                {"role": "admin"}, {"isAdmin": "true"}, {"admin": "1"},
                {"user_role": "administrator"}, {"access_level": "admin"},
                {"privilege": "admin"}, {"group": "admin"},
            ]

            for params in role_params:
                try:
                    resp = await http.get(url, params=params, module="rbac_bypass")
                    baseline = await http.get(url, module="rbac_bypass")

                    if (resp.status_code == 200 and
                        baseline.status_code == 200 and
                        len(resp.text) > len(baseline.text) + 100):
                        findings.append(Finding(
                            title="RBAC Bypass via Parameter Injection",
                            severity=Severity.HIGH,
                            category="authz",
                            owasp_category="A01",
                            description=f"Adding role parameter {params} to the request "
                                        "returned additional data, suggesting the application trusts "
                                        "client-supplied role information.",
                            remediation="Never trust client-supplied role/permission data. "
                                        "Derive roles from the authenticated session server-side.",
                            endpoint=url,
                            parameter=str(params),
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            cvss_score=8.8,
                            cwe_id="CWE-269",
                        ))
                        break
                except Exception:
                    continue

        # Test 2: Path-based authorization bypass
        bypass_patterns = [
            ("/admin", "/admin/..;/"),
            ("/admin", "/ADMIN"),
            ("/admin", "/admin%20"),
            ("/admin", "/admin/./"),
            ("/admin", "/%61dmin"),
            ("/api/admin", "/api/admin;"),
        ]

        for original, bypass in bypass_patterns:
            try:
                orig_resp = await http.get(f"{base_url}{original}", module="rbac_bypass")
                bypass_resp = await http.get(f"{base_url}{bypass}", module="rbac_bypass")

                if (orig_resp.status_code in (401, 403) and
                    bypass_resp.status_code == 200 and
                    len(bypass_resp.text) > 50):
                    findings.append(Finding(
                        title="Authorization Bypass via Path Manipulation",
                        severity=Severity.HIGH,
                        category="authz",
                        owasp_category="A01",
                        description=f"Path '{original}' returned {orig_resp.status_code} but "
                                    f"'{bypass}' returned 200. Path normalization inconsistency "
                                    "allows authorization bypass.",
                        remediation="Normalize paths before authorization checks. Use middleware "
                                    "that canonicalizes URLs before matching access rules.",
                        endpoint=f"{base_url}{bypass}",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        cvss_score=8.2,
                        cwe_id="CWE-863",
                        evidence=[Evidence(
                            request_method="GET",
                            request_url=f"{base_url}{bypass}",
                            response_status=bypass_resp.status_code,
                            description=f"Original: {orig_resp.status_code}, Bypass: {bypass_resp.status_code}",
                        )],
                    ))
            except Exception:
                continue

        return findings
