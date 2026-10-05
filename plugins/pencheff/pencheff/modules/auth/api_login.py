"""API-based authenticated session establishment.

Replaces the Playwright login macro for the credential-only path. Probes
common login endpoints (``/api/login``, ``/api/auth/login``, ``/oauth/token``,
``/login``, ``/users/sign_in``, …) with the configured username/password,
parses tokens and cookies out of the response, and injects them into the
session credentials so all subsequent HTTP-based modules run authenticated.

Trade-offs vs the Playwright path:
- ✅ No headless browser dependency (Chromium binary not required)
- ✅ No SPA hydration timing problems
- ✅ Headless-bot detection / Cloudflare Turnstile aren't triggered
- ✅ Lower latency (≤2s vs 15-30s)
- ❌ Won't handle SSO/SAML/MFA/CAPTCHA flows — for those, supply explicit
     ``login_steps`` to ``authenticated_crawl`` and the Playwright path
     still runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

from pencheff.config import Severity
from pencheff.core.findings import Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


# Endpoints to try, ordered most-likely-to-succeed first. Each is appended
# to the target's origin (scheme://host[:port]).
_LOGIN_PATHS: tuple[str, ...] = (
    "/api/login",
    "/api/auth/login",
    "/api/v1/auth/login",
    "/api/v2/auth/login",
    "/api/v1/login",
    "/api/users/login",
    "/api/sessions",
    "/api/v1/sessions",
    "/auth/login",
    "/oauth/token",
    "/login",
    "/users/sign_in",
    "/account/signin",
    "/accounts/login",
)

# JSON request body shapes. The API picks whichever your backend recognises
# — most accept ``username`` or ``email`` interchangeably.
def _candidate_bodies(username: str, password: str) -> list[dict[str, Any]]:
    return [
        {"username": username, "password": password},
        {"email": username, "password": password},
        {"login": username, "password": password},
        {"user": username, "pass": password},
        {"identifier": username, "password": password},
    ]


# Form-urlencoded shapes (some legacy / Rails / OAuth password-grant servers
# only accept these).
def _candidate_forms(username: str, password: str) -> list[dict[str, str]]:
    return [
        {"username": username, "password": password},
        {"email": username, "password": password},
        # OAuth 2.0 ROPC (Resource Owner Password Credentials)
        {"grant_type": "password", "username": username, "password": password,
         "scope": "*"},
    ]


# Keys we recognise as bearer-style auth material in a JSON response.
# Walked recursively so we'll match nested under "data": { ... }, etc.
_TOKEN_KEYS = re.compile(
    r"^(?:access[_-]?token|auth[_-]?token|bearer[_-]?token|"
    r"jwt|id[_-]?token|session[_-]?token|api[_-]?token|token)$",
    re.IGNORECASE,
)

# Status codes we treat as definitive auth failure (skip the rest of the
# bodies for this URL).
_DEAD_STATUSES = frozenset({400, 401, 403, 404, 405, 410, 414, 422})


@dataclass
class _LoginResult:
    success: bool
    final_url: str = ""
    status: int = 0
    cookies: dict[str, str] | None = None
    token: str | None = None
    trace: list[str] | None = None


class ApiLoginModule(BaseTestModule):
    name = "api_login"
    category = "auth"
    owasp_categories = ["A07"]
    description = "API-based authenticated session establishment (no Playwright)"

    def get_techniques(self) -> list[str]:
        return ["api_credential_login", "token_extraction", "cookie_extraction"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        config = config or {}
        login_url_override = config.get("login_url")
        explicit_paths = config.get("login_paths")

        creds = session.credentials.get("default")
        if not creds or not creds.username or not creds.password:
            return [Finding(
                title="No Credentials Configured",
                severity=Severity.INFO,
                category="auth",
                owasp_category="A07",
                description=(
                    "API login attempted but no username/password are configured "
                    "on the session. Supply credentials via pentest_init or "
                    "pentest_configure."
                ),
                remediation="Configure credentials via pentest_init.",
                endpoint=session.target.base_url,
            )]

        username = creds.username.get()
        password = creds.password.get()

        # Build the candidate URL list. Caller-supplied URL (or paths) wins.
        urls = self._build_url_candidates(
            session.target.base_url, login_url_override, explicit_paths,
        )

        trace: list[str] = []
        won: _LoginResult | None = None

        for url in urls:
            res = await self._try_login(http, url, username, password, trace)
            if res.success:
                won = res
                break
            if res.status in _DEAD_STATUSES:
                # 4xx that means "wrong endpoint shape". Move on.
                continue

        if won and won.success:
            self._inject_credentials(session, won)
            return [Finding(
                title="Authenticated Session Established via API Login",
                severity=Severity.INFO,
                category="auth",
                owasp_category="A07",
                description=(
                    f"API login succeeded against `{won.final_url}` (HTTP {won.status}). "
                    f"Captured {len(won.cookies or {})} cookie(s)"
                    + (" and 1 bearer token." if won.token else ".")
                    + " Subsequent HTTP modules will run authenticated."
                ),
                remediation="Verify the authenticated session is being used in subsequent scans.",
                endpoint=won.final_url,
            )]

        # All candidates exhausted without a working login. This is an
        # OPERATIONAL note (the scanner couldn't reach an authenticated
        # state) — not a vulnerability of the target — so emit at INFO
        # severity. Inflating it to HIGH used to skew the grade and
        # confuse the dashboard.
        trace_block = "\n".join(f"  • {line}" for line in trace[-30:])  # last 30
        return [Finding(
            title="Login Probe Could Not Authenticate — Scan Continued Unauthenticated",
            severity=Severity.INFO,
            category="auth",
            owasp_category="A07",
            description=(
                "None of the probed login endpoints accepted the configured "
                "credentials. All subsequent scans will run UNAUTHENTICATED, "
                "which means most of the attack surface is invisible.\n\n"
                "**Probe trace** (last 30 attempts shown):\n"
                f"{trace_block}\n\n"
                "Most common causes:\n"
                "1. The login URL isn't in the default probe list — supply "
                "   `login_url` (or `login_paths`) to authenticated_crawl.\n"
                "2. The API expects a CSRF token / pre-flight handshake — for "
                "   these flows, supply explicit Playwright `login_steps`.\n"
                "3. The site is behind SSO/SAML/MFA — record an interactive "
                "   macro with `record_login_macro`.\n"
                "4. The credentials are simply wrong — verify what's stored "
                "   on the Target row."
            ),
            remediation=(
                "Three options, easiest first:\n"
                "1. Save a session cookie directly: log in to the target in "
                "your browser, copy the cookie from devtools, save it on the "
                "Target as a `cookie` credential. The scan will use it without "
                "needing to run a login at all.\n"
                "2. Pass `login_url` to authenticated_crawl pointing at the "
                "actual login endpoint.\n"
                "3. For SSO/SAML/MFA flows, supply `login_steps` and the "
                "Playwright macro path will run instead."
            ),
            endpoint=session.target.base_url,
        )]

    # ── internals ──────────────────────────────────────────────────

    @staticmethod
    def _build_url_candidates(
        base_url: str,
        override: str | None,
        explicit_paths: list[str] | None,
    ) -> list[str]:
        if override:
            return [override]
        parsed = urlparse(base_url)
        origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        paths = list(explicit_paths) if explicit_paths else list(_LOGIN_PATHS)
        return [origin.rstrip("/") + p for p in paths]

    async def _try_login(
        self,
        http: PencheffHTTPClient,
        url: str,
        username: str,
        password: str,
        trace: list[str],
    ) -> _LoginResult:
        """Try every body shape against one URL. Stop at the first success."""
        # Try JSON first (most modern APIs).
        for body in _candidate_bodies(username, password):
            try:
                resp = await http.post(
                    url, json_data=body, module="api_login",
                    inject_creds=False, follow_redirects=False,
                )
            except Exception as exc:
                trace.append(f"POST {url} json={list(body.keys())} ✗ "
                             f"{type(exc).__name__}: {str(exc)[:80]}")
                continue
            ok = self._evaluate(resp)
            trace.append(
                f"POST {url} json={list(body.keys())} → {resp.status_code} "
                f"{'✓' if ok else '✗'}"
            )
            if ok:
                return self._build_result(url, resp)
            if resp.status_code in _DEAD_STATUSES and resp.status_code in (404, 405):
                # URL doesn't exist or method not allowed — don't try more bodies.
                return _LoginResult(success=False, final_url=url,
                                    status=resp.status_code, trace=trace)

        # Fall back to form-urlencoded (Rails apps, legacy auth).
        for form in _candidate_forms(username, password):
            try:
                resp = await http.post(
                    url, body=_url_encode(form),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    module="api_login",
                    inject_creds=False, follow_redirects=False,
                )
            except Exception as exc:
                trace.append(f"POST {url} form={list(form.keys())} ✗ "
                             f"{type(exc).__name__}: {str(exc)[:80]}")
                continue
            ok = self._evaluate(resp)
            trace.append(
                f"POST {url} form={list(form.keys())} → {resp.status_code} "
                f"{'✓' if ok else '✗'}"
            )
            if ok:
                return self._build_result(url, resp)

        return _LoginResult(success=False, final_url=url,
                            status=0, trace=trace)

    @staticmethod
    def _evaluate(resp: Any) -> bool:
        """Did this response actually authenticate us?"""
        if resp.status_code not in (200, 201, 202, 204, 301, 302, 303, 307, 308):
            return False
        # Set-Cookie indicates a session was minted.
        if resp.headers.get("set-cookie"):
            return True
        # Token-bearing JSON response.
        try:
            data = resp.json()
        except Exception:
            return False
        if _find_token(data):
            return True
        return False

    @staticmethod
    def _build_result(url: str, resp: Any) -> _LoginResult:
        cookies = _parse_set_cookies(resp.headers.get_list("set-cookie")
                                     if hasattr(resp.headers, "get_list")
                                     else [resp.headers.get("set-cookie", "")])
        token: str | None = None
        try:
            token = _find_token(resp.json())
        except Exception:
            pass
        return _LoginResult(
            success=True,
            final_url=str(resp.url) if hasattr(resp, "url") else url,
            status=resp.status_code,
            cookies=cookies,
            token=token,
        )

    @staticmethod
    def _inject_credentials(session: PentestSession, res: _LoginResult) -> None:
        from pencheff.core.credentials import MaskedSecret
        cred_set = session.credentials.get("default")
        if cred_set is None:
            session.credentials.add_from_dict("api_auth", {})
            cred_set = session.credentials.get("api_auth")
        if cred_set is None:
            return
        if res.cookies:
            cookie_header = "; ".join(f"{n}={v}" for n, v in res.cookies.items())
            cred_set.cookie = MaskedSecret(cookie_header)
        if res.token:
            cred_set.token = MaskedSecret(res.token)


# ── helpers ────────────────────────────────────────────────────────


def _find_token(value: Any) -> str | None:
    """Recursively walk a JSON-decoded response for a bearer token."""
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and _TOKEN_KEYS.match(k) and isinstance(v, str) and v.strip():
                return v.strip()
        # Recurse into values
        for v in value.values():
            found = _find_token(v)
            if found:
                return found
    elif isinstance(value, list):
        for v in value:
            found = _find_token(v)
            if found:
                return found
    return None


def _parse_set_cookies(set_cookie_headers: list[str]) -> dict[str, str]:
    """Pull name=value out of each Set-Cookie header (drop attributes)."""
    out: dict[str, str] = {}
    for header in set_cookie_headers:
        if not header:
            continue
        first = header.split(";", 1)[0].strip()
        if "=" not in first:
            continue
        name, value = first.split("=", 1)
        if name and value:
            out[name.strip()] = value.strip()
    return out


def _url_encode(form: dict[str, str]) -> str:
    from urllib.parse import urlencode
    return urlencode(form)
