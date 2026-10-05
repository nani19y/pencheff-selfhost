"""Password policy testing — weak passwords, password requirements."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

WEAK_PASSWORDS = ["password", "123456", "admin", "test", "1234", "pass", "a"]

REGISTER_PATHS = [
    "/register", "/signup", "/api/register", "/api/signup",
    "/api/v1/register", "/api/v1/users", "/user/register",
    "/account/register", "/auth/register",
]


class PasswordPolicyModule(BaseTestModule):
    name = "password_policy"
    category = "auth"
    owasp_categories = ["A07"]
    description = "Password policy strength testing"

    def get_techniques(self) -> list[str]:
        return ["weak_password_acceptance", "password_requirements"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url

        # Find registration endpoint
        register_url = None
        for path in REGISTER_PATHS:
            try:
                resp = await http.get(f"{base_url}{path}", module="password_policy", inject_creds=False)
                if resp.status_code in (200, 405, 422):
                    register_url = f"{base_url}{path}"
                    break
            except Exception:
                continue

        # Also check password change endpoints
        change_paths = ["/api/change-password", "/api/v1/password", "/user/password",
                        "/account/password", "/settings/password"]
        change_url = None
        for path in change_paths:
            try:
                resp = await http.get(f"{base_url}{path}", module="password_policy")
                if resp.status_code in (200, 401, 405):
                    change_url = f"{base_url}{path}"
                    break
            except Exception:
                continue

        test_url = register_url or change_url
        if not test_url:
            return findings

        # Test weak passwords
        import random
        import string
        random_user = "pencheff_test_" + "".join(random.choices(string.ascii_lowercase, k=6))

        for weak_pw in WEAK_PASSWORDS:
            try:
                if register_url:
                    resp = await http.post(
                        test_url,
                        json_data={
                            "username": random_user,
                            "email": f"{random_user}@pencheff-test.invalid",
                            "password": weak_pw,
                        },
                        module="password_policy",
                        inject_creds=False,
                    )
                else:
                    resp = await http.post(
                        test_url,
                        json_data={"old_password": "current", "new_password": weak_pw},
                        module="password_policy",
                    )

                # If weak password was accepted (not rejected with 400/422)
                if resp.status_code in (200, 201):
                    findings.append(Finding(
                        title=f"Weak Password Accepted: '{weak_pw}'",
                        severity=Severity.MEDIUM,
                        category="auth",
                        owasp_category="A07",
                        description=f"The application accepted the weak password '{weak_pw}'. "
                                    "This allows users to set easily guessable passwords.",
                        remediation="Enforce minimum password requirements: 8+ characters, "
                                    "mixed case, numbers, and special characters. Check against breach databases.",
                        endpoint=test_url,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cvss_score=7.5,
                        cwe_id="CWE-521",
                        evidence=[Evidence(
                            request_method="POST",
                            request_url=test_url,
                            description=f"Password '{weak_pw}' was accepted (HTTP {resp.status_code})",
                        )],
                    ))
                    break  # One finding is enough
            except Exception:
                continue

        return findings
