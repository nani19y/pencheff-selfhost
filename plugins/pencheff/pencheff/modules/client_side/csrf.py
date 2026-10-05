"""CSRF (Cross-Site Request Forgery) testing."""

from __future__ import annotations

import re
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class CSRFModule(BaseTestModule):
    name = "csrf"
    category = "auth"
    owasp_categories = ["A01"]
    description = "CSRF protection testing"

    def get_techniques(self) -> list[str]:
        return ["missing_csrf_token", "token_validation", "samesite_cookie"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)

        # Find state-changing endpoints (POST/PUT/DELETE)
        state_changing = [
            ep for ep in endpoints
            if ep.get("method", "GET") in ("POST", "PUT", "DELETE", "PATCH")
        ]

        if not state_changing:
            # Check form endpoints discovered by crawler
            state_changing = [
                ep for ep in endpoints if ep.get("source") == "form"
            ]

        for ep in state_changing[:15]:
            url = ep["url"]
            params = ep.get("params", [])

            # Check if any param looks like a CSRF token
            csrf_param_names = {"csrf", "csrf_token", "csrfmiddlewaretoken", "_token",
                                "authenticity_token", "xsrf", "_csrf", "__RequestVerificationToken"}
            has_csrf = any(p.lower() in csrf_param_names for p in params)

            if not has_csrf:
                # Try submitting without CSRF token
                try:
                    body = {p: "test" for p in params if p.lower() not in csrf_param_names}
                    resp = await http.post(
                        url, body="&".join(f"{k}={v}" for k, v in body.items()),
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Origin": "https://evil-site.com",
                            "Referer": "https://evil-site.com/attack",
                        },
                        module="csrf",
                    )

                    if resp.status_code in (200, 201, 302):
                        findings.append(Finding(
                            title="Missing CSRF Protection",
                            severity=Severity.MEDIUM,
                            category="auth",
                            owasp_category="A01",
                            description=f"State-changing endpoint {url} ({ep.get('method', 'POST')}) "
                                        "has no CSRF token and accepts requests with cross-origin headers.",
                            remediation="Implement CSRF tokens for all state-changing requests. "
                                        "Use SameSite=Strict or SameSite=Lax cookies.",
                            endpoint=url,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                            cvss_score=4.3,
                            cwe_id="CWE-352",
                            evidence=[Evidence(
                                request_method="POST",
                                request_url=url,
                                request_headers={"Origin": "https://evil-site.com"},
                                response_status=resp.status_code,
                                description="Request accepted with cross-origin headers and no CSRF token",
                            )],
                        ))
                except Exception:
                    continue

        return findings
