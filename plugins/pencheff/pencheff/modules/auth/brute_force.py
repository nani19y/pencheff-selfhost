"""Brute force resistance and account enumeration testing."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class BruteForceModule(BaseTestModule):
    name = "brute_force"
    category = "auth"
    owasp_categories = ["A07"]
    description = "Brute force resistance and account enumeration testing"

    def get_techniques(self) -> list[str]:
        return ["account_enumeration", "lockout_policy", "rate_limiting"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url

        # Find login endpoint
        login_paths = ["/login", "/signin", "/auth/login", "/api/login", "/api/auth/login",
                       "/api/v1/auth/login", "/user/login", "/account/login"]
        login_url = None

        from pencheff.core.spa_detector import is_real_endpoint
        for path in login_paths:
            try:
                resp = await http.get(f"{base_url}{path}", module="brute_force", inject_creds=False)
                # 200 alone is too loose on SPAs (every path 200s); require
                # an auth-shaped response (401/403/405) OR a 200 that
                # genuinely differs from the SPA fallback.
                if resp.status_code in (401, 403, 405):
                    login_url = f"{base_url}{path}"
                    break
                if resp.status_code == 200 and is_real_endpoint(resp, session):
                    login_url = f"{base_url}{path}"
                    break
            except Exception:
                continue

        # Also check discovered endpoints
        for ep in session.discovered.endpoints:
            if any(kw in ep["url"].lower() for kw in ["login", "signin", "auth"]):
                login_url = ep["url"]
                break

        if not login_url:
            return findings

        # Test 1: Account enumeration via different error messages
        valid_user = None
        creds = session.credentials.get("default")
        if creds and creds.username:
            valid_user = creds.username.get()

        if valid_user:
            try:
                # Request with valid username, wrong password
                valid_resp = await http.post(
                    login_url,
                    json_data={"username": valid_user, "password": "wrong_password_12345"},
                    module="brute_force",
                    inject_creds=False,
                )
                # Request with invalid username
                invalid_resp = await http.post(
                    login_url,
                    json_data={"username": "nonexistent_user_xyz_98765", "password": "wrong_password_12345"},
                    module="brute_force",
                    inject_creds=False,
                )

                # Compare responses
                if (valid_resp.status_code != invalid_resp.status_code or
                    abs(len(valid_resp.text) - len(invalid_resp.text)) > 20 or
                    valid_resp.text != invalid_resp.text):
                    findings.append(Finding(
                        title="Username Enumeration via Login Response",
                        severity=Severity.MEDIUM,
                        category="auth",
                        owasp_category="A07",
                        description="Login endpoint returns different responses for valid vs invalid usernames, "
                                    "allowing attackers to enumerate valid accounts.",
                        remediation="Return identical error messages for invalid username and invalid password. "
                                    "Use generic messages like 'Invalid credentials'.",
                        endpoint=login_url,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cvss_score=5.3,
                        cwe_id="CWE-204",
                        evidence=[Evidence(
                            request_method="POST",
                            request_url=login_url,
                            description=f"Valid user status: {valid_resp.status_code} ({len(valid_resp.text)} bytes), "
                                        f"Invalid user status: {invalid_resp.status_code} ({len(invalid_resp.text)} bytes)",
                        )],
                    ))
            except Exception:
                pass

        # Test 2: Account lockout / rate limiting
        try:
            statuses = []
            for i in range(10):
                resp = await http.post(
                    login_url,
                    json_data={"username": "test_user", "password": f"wrong_{i}"},
                    module="brute_force",
                    inject_creds=False,
                )
                statuses.append(resp.status_code)

            # If all responses are the same (no lockout/rate limit)
            if len(set(statuses)) == 1 and 429 not in statuses:
                findings.append(Finding(
                    title="No Account Lockout or Rate Limiting",
                    severity=Severity.MEDIUM,
                    category="auth",
                    owasp_category="A07",
                    description="10 failed login attempts produced no lockout or rate limiting. "
                                "The endpoint is vulnerable to brute force attacks.",
                    remediation="Implement account lockout after 5 failed attempts. "
                                "Add rate limiting (e.g., progressive delays). Use CAPTCHA after failures.",
                    endpoint=login_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cvss_score=7.5,
                    cwe_id="CWE-307",
                ))
        except Exception:
            pass

        return findings
