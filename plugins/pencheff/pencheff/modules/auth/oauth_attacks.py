"""OAuth/OIDC flow attack module."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urlencode, urlparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.payload_loader import load_payloads
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Common OAuth/OIDC discovery endpoints
OAUTH_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize",
    "/oauth2/authorize",
    "/auth/authorize",
    "/oauth/token",
    "/oauth2/token",
    "/auth/token",
    "/oauth/callback",
    "/auth/callback",
    "/login/oauth",
    "/api/oauth",
    "/connect/authorize",
    "/connect/token",
]

# redirect_uri bypass payloads
REDIRECT_URI_BYPASSES = [
    "https://attacker.com",
    "https://attacker.com@legitimate.com",
    "https://legitimate.com.attacker.com",
    "https://legitimate.com%40attacker.com",
    "https://legitimate.com%2F%2Fattacker.com",
    "//attacker.com",
    "https://legitimate.com/callback?rd=https://attacker.com",
    "https://legitimate.com/callback/..%2f..%2fattacker.com",
    "https://legitimate.com/callback#@attacker.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "https://legitimate.com/callback/../../../attacker.com",
    "https://legitimate.com\\@attacker.com",
]


class OAuthAttackModule(BaseTestModule):
    """Test OAuth/OIDC implementation for common vulnerabilities."""

    name = "oauth_attacks"
    category = "oauth"
    owasp_categories = ["A07"]
    description = "OAuth/OIDC flow attacks: redirect_uri manipulation, state bypass, token theft"

    def get_techniques(self) -> list[str]:
        return [
            "oauth_endpoint_discovery",
            "redirect_uri_manipulation",
            "state_parameter_check",
            "token_leakage",
            "scope_escalation",
            "pkce_bypass",
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

        # Phase 1: Discover OAuth endpoints
        oauth_config = await self._discover_oauth(http, base_url, session)

        # Phase 2: Test redirect_uri manipulation
        if oauth_config.get("authorization_endpoint"):
            redirect_findings = await self._test_redirect_uri(
                http, oauth_config, session
            )
            findings.extend(redirect_findings)

        # Phase 3: Test state parameter
        if oauth_config.get("authorization_endpoint"):
            state_findings = await self._test_state_param(
                http, oauth_config, session
            )
            findings.extend(state_findings)

        # Phase 4: Test token leakage via Referer
        token_findings = await self._test_token_leakage(http, session)
        findings.extend(token_findings)

        return findings

    async def _discover_oauth(
        self, http: PencheffHTTPClient, base_url: str, session: PentestSession,
    ) -> dict[str, Any]:
        """Discover OAuth/OIDC endpoints."""
        oauth_config: dict[str, Any] = {}

        for path in OAUTH_DISCOVERY_PATHS:
            url = f"{base_url}{path}"
            try:
                resp = await http.get(url, module="oauth_attacks")
                if resp.status_code == 200:
                    session.discovered.oauth_endpoints.append({
                        "url": url,
                        "path": path,
                        "status": resp.status_code,
                    })

                    # Parse OIDC discovery document
                    if "openid-configuration" in path or "oauth-authorization-server" in path:
                        try:
                            config_data = resp.json()
                            oauth_config.update(config_data)
                        except Exception:
                            pass

                    # Detect authorization endpoint
                    if "authorize" in path:
                        oauth_config.setdefault("authorization_endpoint", url)
                    if "token" in path:
                        oauth_config.setdefault("token_endpoint", url)
                    if "callback" in path:
                        oauth_config.setdefault("callback_endpoint", url)

            except Exception:
                continue

        return oauth_config

    async def _test_redirect_uri(
        self, http: PencheffHTTPClient,
        oauth_config: dict[str, Any],
        session: PentestSession,
    ) -> list[Finding]:
        """Test redirect_uri manipulation for open redirect / token theft."""
        findings: list[Finding] = []
        auth_endpoint = oauth_config["authorization_endpoint"]
        parsed = urlparse(session.target.base_url)
        legitimate_host = parsed.hostname or ""

        # Load additional payloads
        extra_payloads = load_payloads("oauth.txt")
        all_bypasses = REDIRECT_URI_BYPASSES + extra_payloads

        for bypass in all_bypasses[:20]:
            # Replace 'legitimate.com' with actual host
            test_redirect = bypass.replace("legitimate.com", legitimate_host)

            params = {
                "response_type": "code",
                "client_id": "test",
                "redirect_uri": test_redirect,
                "scope": "openid",
                "state": "test123",
            }

            test_url = f"{auth_endpoint}?{urlencode(params)}"
            try:
                resp = await http.get(
                    test_url,
                    follow_redirects=False,
                    module="oauth_attacks",
                )

                # If we get a redirect to the attacker URL, the bypass worked
                location = resp.headers.get("location", "")
                if "attacker" in location or resp.status_code in (200, 302):
                    if resp.status_code == 302 and "attacker" in location:
                        findings.append(Finding(
                            title="OAuth redirect_uri Bypass — Token Theft Possible",
                            severity=Severity.CRITICAL,
                            category="oauth",
                            owasp_category="A07",
                            description=(
                                f"The OAuth authorization endpoint accepts a manipulated redirect_uri "
                                f"('{test_redirect}'). An attacker can steal authorization codes or "
                                f"tokens by redirecting the OAuth flow to their server."
                            ),
                            remediation=(
                                "Implement strict redirect_uri validation — exact match only. "
                                "Do not allow wildcards, subdomains, or path variations. "
                                "Register all valid redirect URIs in the OAuth provider."
                            ),
                            endpoint=auth_endpoint,
                            parameter="redirect_uri",
                            evidence=[Evidence(
                                request_method="GET",
                                request_url=test_url,
                                response_status=resp.status_code,
                                response_headers={"Location": location},
                                description=f"Redirect to attacker URL accepted: {location[:100]}",
                            )],
                            cwe_id="CWE-601",
                            cvss_score=9.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
                        ))
                        return findings  # Critical finding — stop testing

                    # Server accepted the request (200) — may still be exploitable
                    if resp.status_code == 200 and "error" not in resp.text.lower():
                        # SPA fallback would 200 every probe to a non-
                        # existent /oauth/authorize. Confirm this is a
                        # real OAuth endpoint before flagging.
                        from pencheff.core.spa_detector import is_real_endpoint
                        if not is_real_endpoint(resp, session):
                            continue
                        findings.append(Finding(
                            title="OAuth redirect_uri Validation Weak",
                            severity=Severity.HIGH,
                            category="oauth",
                            owasp_category="A07",
                            description=(
                                f"The OAuth authorization endpoint does not reject the manipulated "
                                f"redirect_uri ('{test_redirect[:60]}'). This may allow token theft."
                            ),
                            remediation="Enforce strict redirect_uri whitelist validation.",
                            endpoint=auth_endpoint,
                            parameter="redirect_uri",
                            evidence=[Evidence(
                                request_method="GET",
                                request_url=test_url,
                                response_status=resp.status_code,
                                description=f"Manipulated redirect_uri not rejected",
                            )],
                            cwe_id="CWE-601",
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
                        ))
                        return findings

            except Exception:
                continue

        return findings

    async def _test_state_param(
        self, http: PencheffHTTPClient,
        oauth_config: dict[str, Any],
        session: PentestSession,
    ) -> list[Finding]:
        """Test if state parameter is required and validated."""
        findings: list[Finding] = []
        auth_endpoint = oauth_config["authorization_endpoint"]

        # Test without state parameter
        params = {
            "response_type": "code",
            "client_id": "test",
            "redirect_uri": session.target.base_url,
            "scope": "openid",
        }

        test_url = f"{auth_endpoint}?{urlencode(params)}"
        try:
            resp = await http.get(test_url, follow_redirects=False, module="oauth_attacks")

            if resp.status_code in (200, 302) and "state" not in resp.text.lower():
                # SPA fallback would match this; gate on real-endpoint detection.
                from pencheff.core.spa_detector import is_real_endpoint
                if not is_real_endpoint(resp, session):
                    return findings
                findings.append(Finding(
                    title="OAuth Missing State Parameter Validation",
                    severity=Severity.MEDIUM,
                    category="oauth",
                    owasp_category="A07",
                    description=(
                        "The OAuth authorization endpoint processes requests without a state "
                        "parameter. This makes the OAuth flow vulnerable to CSRF attacks, "
                        "allowing an attacker to link their account to a victim's session."
                    ),
                    remediation=(
                        "Require the state parameter on all authorization requests. "
                        "Validate that the state is bound to the user's session and is single-use."
                    ),
                    endpoint=auth_endpoint,
                    parameter="state",
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=test_url,
                        response_status=resp.status_code,
                        description="Request processed without state parameter",
                    )],
                    cwe_id="CWE-352",
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                ))
        except Exception:
            pass

        return findings

    async def _test_token_leakage(
        self, http: PencheffHTTPClient, session: PentestSession,
    ) -> list[Finding]:
        """Check if tokens are leaked via URL fragments or Referer headers."""
        findings: list[Finding] = []

        # Check endpoints for token parameters in URLs
        for ep in session.discovered.endpoints[:20]:
            url = ep.get("url", "")
            if any(param in url.lower() for param in ["access_token=", "token=", "code="]):
                findings.append(Finding(
                    title="Token/Code Exposed in URL",
                    severity=Severity.HIGH,
                    category="oauth",
                    owasp_category="A07",
                    description=(
                        f"An access token or authorization code was found in the URL: {url[:100]}. "
                        f"Tokens in URLs are leaked via Referer headers, browser history, "
                        f"server logs, and proxy logs."
                    ),
                    remediation=(
                        "Use response_type=code with PKCE instead of implicit flow. "
                        "Send tokens in response bodies or via POST, never in URLs."
                    ),
                    endpoint=url,
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=url,
                        description="Token/code found in URL parameter",
                    )],
                    cwe_id="CWE-598",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                ))

        return findings
