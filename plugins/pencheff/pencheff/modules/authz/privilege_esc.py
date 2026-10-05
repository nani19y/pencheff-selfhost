"""Privilege escalation testing — vertical and horizontal."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/dashboard",
    "/api/admin", "/api/v1/admin", "/management", "/panel",
    "/admin/users", "/admin/settings", "/admin/config",
    "/api/admin/users", "/api/users?role=admin",
    "/internal", "/debug", "/console",
]


class PrivilegeEscalationModule(BaseTestModule):
    name = "privilege_esc"
    category = "authz"
    owasp_categories = ["A01"]
    description = "Privilege escalation testing"

    def get_techniques(self) -> list[str]:
        return ["admin_path_access", "role_parameter_manipulation", "method_override"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url

        # Test 1: Access admin paths with regular user credentials
        from pencheff.core.spa_detector import is_real_endpoint
        for path in ADMIN_PATHS:
            try:
                resp = await http.get(f"{base_url}{path}", module="privilege_esc")
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Suppress SPA-fallback hits — a SPA serves index.html
                    # for any unknown path with HTTP 200 and would
                    # otherwise fire a HIGH "admin path accessible"
                    # finding for every entry in ADMIN_PATHS.
                    if not is_real_endpoint(resp, session):
                        continue
                    # Verify it's not just a redirect to login
                    if not any(kw in resp.text.lower() for kw in ["login", "sign in", "unauthorized"]):
                        findings.append(Finding(
                            title=f"Admin Path Accessible: {path}",
                            severity=Severity.HIGH,
                            category="authz",
                            owasp_category="A01",
                            description=f"Admin endpoint {path} is accessible with current credentials. "
                                        "This may indicate missing role-based access control.",
                            remediation="Implement role-based access control. Restrict admin endpoints "
                                        "to users with admin privileges only.",
                            endpoint=f"{base_url}{path}",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                            cvss_score=8.8,
                            cwe_id="CWE-269",
                            evidence=[Evidence(
                                request_method="GET",
                                request_url=f"{base_url}{path}",
                                response_status=resp.status_code,
                                response_body_snippet=resp.text[:200],
                                description="Admin path returned 200 with content",
                            )],
                        ))
            except Exception:
                continue

        # Test 2: HTTP method override for privilege escalation
        endpoints = self._get_target_endpoints(session, targets)
        for ep in self._cap_endpoints(endpoints, 10):
            url = ep["url"]
            override_headers = [
                {"X-HTTP-Method-Override": "PUT"},
                {"X-HTTP-Method-Override": "DELETE"},
                {"X-Method-Override": "PUT"},
                {"X-Original-Method": "PUT"},
            ]
            for headers in override_headers:
                try:
                    resp = await http.post(url, headers=headers, module="privilege_esc")
                    if resp.status_code in (200, 201, 204):
                        original_resp = await http.get(url, module="privilege_esc")
                        if resp.text != original_resp.text:
                            findings.append(Finding(
                                title="HTTP Method Override Accepted",
                                severity=Severity.MEDIUM,
                                category="authz",
                                owasp_category="A01",
                                description=f"Server honors {list(headers.keys())[0]} header. "
                                            "This may allow bypassing method-based access controls.",
                                remediation="Disable HTTP method override headers. Enforce method restrictions at the framework level.",
                                endpoint=url,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                                cvss_score=5.4,
                                cwe_id="CWE-650",
                            ))
                            break
                except Exception:
                    continue

        return findings
