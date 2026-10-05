"""MFA/2FA bypass testing module."""

from __future__ import annotations

import asyncio
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class MFABypassModule(BaseTestModule):
    """Test MFA/2FA bypass techniques: direct access, OTP brute force, response manipulation."""

    name = "mfa_bypass"
    category = "mfa_bypass"
    owasp_categories = ["A07"]
    description = "2FA/MFA bypass: direct access, OTP brute force, backup code abuse, race conditions"

    def get_techniques(self) -> list[str]:
        return [
            "direct_endpoint_access",
            "otp_brute_force",
            "backup_code_abuse",
            "response_manipulation",
            "race_condition",
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

        # Discover MFA-related endpoints
        mfa_endpoints = await self._discover_mfa_endpoints(http, base_url, session)

        if not mfa_endpoints:
            return findings

        # Test direct endpoint access (skip 2FA)
        direct = await self._test_direct_access(http, mfa_endpoints, session)
        findings.extend(direct)

        # Test OTP rate limiting
        rate = await self._test_otp_rate_limiting(http, mfa_endpoints, session)
        findings.extend(rate)

        # Test backup code brute force
        backup = await self._test_backup_codes(http, mfa_endpoints, session)
        findings.extend(backup)

        # Test race condition on OTP validation
        race = await self._test_otp_race_condition(http, mfa_endpoints, session)
        findings.extend(race)

        return findings

    async def _discover_mfa_endpoints(
        self, http: PencheffHTTPClient, base_url: str, session: PentestSession,
    ) -> dict[str, str]:
        """Discover MFA-related endpoints."""
        endpoints: dict[str, str] = {}
        mfa_paths = [
            "/mfa", "/2fa", "/two-factor", "/verify", "/otp", "/totp",
            "/mfa/verify", "/2fa/verify", "/auth/mfa", "/auth/2fa",
            "/login/mfa", "/login/2fa", "/account/mfa", "/challenge",
            "/mfa/setup", "/2fa/setup", "/mfa/backup", "/2fa/backup",
        ]

        for path in mfa_paths:
            url = f"{base_url}{path}"
            try:
                resp = await http.get(url, module="mfa_bypass")
                if resp.status_code in (200, 302, 401, 403):
                    body_lower = resp.text.lower()
                    if any(kw in body_lower for kw in [
                        "verification", "otp", "code", "token", "authenticator",
                        "two-factor", "2fa", "mfa", "backup",
                    ]):
                        if "verify" in path or "otp" in path or "challenge" in path:
                            endpoints["verify"] = url
                        elif "backup" in path:
                            endpoints["backup"] = url
                        elif "setup" in path:
                            endpoints["setup"] = url
                        else:
                            endpoints.setdefault("mfa_page", url)
            except Exception:
                continue

        return endpoints

    async def _test_direct_access(
        self, http: PencheffHTTPClient,
        mfa_endpoints: dict[str, str],
        session: PentestSession,
    ) -> list[Finding]:
        """Try accessing protected resources directly, bypassing the 2FA step."""
        findings: list[Finding] = []

        # Common post-MFA endpoints
        protected_paths = [
            "/dashboard", "/account", "/profile", "/settings",
            "/admin", "/api/user", "/api/me", "/home",
        ]

        base_url = session.target.base_url
        for path in protected_paths:
            url = f"{base_url}{path}"
            try:
                resp = await http.get(url, module="mfa_bypass")
                if resp.status_code == 200 and len(resp.text) > 200:
                    body_lower = resp.text.lower()
                    # Check if we got an actual protected page
                    if any(kw in body_lower for kw in ["dashboard", "settings", "profile", "welcome", "account"]):
                        if "login" not in body_lower and "sign in" not in body_lower:
                            findings.append(Finding(
                                title=f"2FA Bypass via Direct Access: {path}",
                                severity=Severity.CRITICAL,
                                category="mfa_bypass",
                                owasp_category="A07",
                                description=(
                                    f"The protected endpoint '{path}' is accessible without completing "
                                    f"the 2FA step. After first-factor authentication, navigating directly "
                                    f"to post-2FA URLs bypasses the second factor entirely."
                                ),
                                remediation=(
                                    "Implement server-side session flags that track 2FA completion. "
                                    "Block access to all protected resources until 2FA is verified. "
                                    "Do not rely on client-side redirects for 2FA enforcement."
                                ),
                                endpoint=url,
                                evidence=[Evidence(
                                    request_method="GET",
                                    request_url=url,
                                    response_status=resp.status_code,
                                    response_body_snippet=resp.text[:300],
                                    description="Protected page accessible without 2FA completion",
                                )],
                                cwe_id="CWE-308",
                                cvss_score=9.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                            ))
                            return findings
            except Exception:
                continue

        return findings

    async def _test_otp_rate_limiting(
        self, http: PencheffHTTPClient,
        mfa_endpoints: dict[str, str],
        session: PentestSession,
    ) -> list[Finding]:
        """Test if OTP verification has proper rate limiting."""
        findings: list[Finding] = []
        verify_url = mfa_endpoints.get("verify")
        if not verify_url:
            return findings

        # Send multiple wrong OTP codes rapidly
        success_count = 0
        for i in range(20):
            otp = f"{i:06d}"
            try:
                resp = await http.post(
                    verify_url,
                    json_data={"code": otp, "otp": otp, "token": otp},
                    module="mfa_bypass",
                )
                if resp.status_code in (200, 401, 403, 422):
                    success_count += 1
                if resp.status_code == 429:
                    # Rate limited — good
                    return findings
            except Exception:
                continue

        if success_count >= 15:
            findings.append(Finding(
                title="OTP Endpoint Lacks Rate Limiting",
                severity=Severity.HIGH,
                category="mfa_bypass",
                owasp_category="A07",
                description=(
                    f"The OTP verification endpoint ({verify_url}) accepted {success_count} "
                    f"rapid attempts without rate limiting. A 6-digit OTP has only 1M possibilities "
                    f"and can be brute-forced in minutes without rate limiting."
                ),
                remediation=(
                    "Implement rate limiting on OTP verification (max 3-5 attempts per session). "
                    "Lock the account after repeated failures. Add exponential backoff."
                ),
                endpoint=verify_url,
                evidence=[Evidence(
                    request_method="POST",
                    request_url=verify_url,
                    description=f"{success_count}/20 rapid OTP attempts accepted without rate limiting",
                )],
                cwe_id="CWE-307",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            ))

        return findings

    async def _test_backup_codes(
        self, http: PencheffHTTPClient,
        mfa_endpoints: dict[str, str],
        session: PentestSession,
    ) -> list[Finding]:
        """Test backup code endpoint for rate limiting."""
        findings: list[Finding] = []
        backup_url = mfa_endpoints.get("backup")
        if not backup_url:
            return findings

        success_count = 0
        for i in range(15):
            code = f"backup{i:04d}"
            try:
                resp = await http.post(
                    backup_url,
                    json_data={"code": code, "backup_code": code},
                    module="mfa_bypass",
                )
                if resp.status_code != 429:
                    success_count += 1
                else:
                    return findings
            except Exception:
                continue

        if success_count >= 10:
            findings.append(Finding(
                title="Backup Code Endpoint Lacks Rate Limiting",
                severity=Severity.MEDIUM,
                category="mfa_bypass",
                owasp_category="A07",
                description=(
                    f"The backup code endpoint accepts rapid attempts without rate limiting. "
                    f"If backup codes are short or predictable, they can be brute-forced."
                ),
                remediation="Apply the same rate limiting to backup codes as primary OTP verification.",
                endpoint=backup_url,
                cwe_id="CWE-307",
                cvss_score=6.5,
            ))

        return findings

    async def _test_otp_race_condition(
        self, http: PencheffHTTPClient,
        mfa_endpoints: dict[str, str],
        session: PentestSession,
    ) -> list[Finding]:
        """Test if OTP codes can be reused via race condition."""
        findings: list[Finding] = []
        verify_url = mfa_endpoints.get("verify")
        if not verify_url:
            return findings

        # Send the same OTP code concurrently
        test_code = "123456"

        async def send_otp():
            try:
                return await http.post(
                    verify_url,
                    json_data={"code": test_code, "otp": test_code},
                    module="mfa_bypass",
                )
            except Exception:
                return None

        results = await asyncio.gather(*[send_otp() for _ in range(5)])
        success_responses = [r for r in results if r and r.status_code == 200]

        if len(success_responses) > 1:
            findings.append(Finding(
                title="OTP Race Condition — Code Reuse",
                severity=Severity.HIGH,
                category="mfa_bypass",
                owasp_category="A07",
                description=(
                    f"The same OTP code was accepted {len(success_responses)} times when "
                    f"submitted concurrently. An attacker who obtains a valid OTP can use "
                    f"it multiple times via parallel requests."
                ),
                remediation=(
                    "Use atomic operations for OTP validation. Mark codes as used in a "
                    "transaction before returning success. Implement distributed locking."
                ),
                endpoint=verify_url,
                cwe_id="CWE-367",
                cvss_score=7.5,
            ))

        return findings
