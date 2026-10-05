"""Authenticated crawl — API login first, Playwright as escape hatch.

Authentication strategy:
1. **Credential-only path (default)** —
   :class:`pencheff.modules.auth.api_login.ApiLoginModule` probes common
   login API endpoints with the configured username/password, captures
   the resulting session cookie + bearer token, and injects them into
   the session. No headless browser required.
2. **Explicit-macro path** — when ``login_steps`` are supplied (or
   ``prefer_browser=True``), Playwright drives a real Chromium and
   replays the steps. Used for SSO/SAML/MFA/CAPTCHA flows that can't be
   expressed as a single API call.

After either path succeeds, cookies/tokens are extracted and injected
into the session for subsequent HTTP-based module testing.
"""

from __future__ import annotations

import json
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

from playwright.async_api import async_playwright, Page, Browser

_PLAYWRIGHT_AVAILABLE = True

# Macro step types:
# {"action": "navigate", "url": "https://..."}
# {"action": "fill",     "selector": "#username", "value": "admin"}
# {"action": "click",    "selector": "button[type=submit]"}
# {"action": "wait",     "ms": 1000}
# {"action": "wait_for", "selector": ".dashboard"}
# {"action": "screenshot"}


class LoginMacroModule(BaseTestModule):
    name = "login_macro"
    category = "auth"
    owasp_categories = ["A07"]
    description = "Automated authenticated crawl via Playwright login macro"

    def get_techniques(self) -> list[str]:
        return ["auto_login", "macro_replay", "sso_handling", "cookie_extraction"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        config = config or {}
        macro_steps = config.get("steps", [])
        headless = config.get("headless", True)
        login_url = config.get("login_url", session.target.base_url)
        prefer_browser = bool(config.get("prefer_browser", False))

        creds = session.credentials.get("default")

        # Credential-only path: hand off to the API-login module. No
        # Playwright is started — that path is reserved for explicit
        # ``login_steps`` (SSO/SAML/MFA/CAPTCHA flows that can't be
        # expressed as a single API call) or when ``prefer_browser=True``
        # is forced by the caller.
        if not macro_steps and not prefer_browser \
                and creds and creds.username and creds.password:
            from pencheff.modules.auth.api_login import ApiLoginModule
            return await ApiLoginModule().run(
                session, http,
                config={
                    "login_url": config.get("login_url"),
                    "login_paths": config.get("login_paths"),
                },
            )

        if not macro_steps:
            return [Finding(
                title="No Login Macro Configured",
                severity=Severity.INFO,
                category="auth",
                owasp_category="A07",
                description=(
                    "No login macro steps were provided and no "
                    "username/password credentials are configured. "
                    "Provide credentials via pentest_init or supply "
                    "macro steps via pentest_configure."
                ),
                remediation="Configure credentials or provide macro steps via pentest_configure.",
                endpoint=session.target.base_url,
            )]

        findings: list[Finding] = []

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(headless=headless)
            context = await browser.new_context(ignore_https_errors=True)
            page: Page = await context.new_page()

            try:
                success, cookies, local_storage, trace = await _execute_macro(
                    page, macro_steps
                )

                if success:
                    # Inject extracted cookies into the session
                    cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
                    if cookie_header:
                        from pencheff.core.credentials import MaskedSecret
                        cred_set = session.credentials.get("default")
                        if cred_set:
                            cred_set.cookie = MaskedSecret(cookie_header)
                        else:
                            session.credentials.add_from_dict("browser_auth", {
                                "cookie": cookie_header,
                            })

                    # Look for JWT/Bearer tokens in localStorage
                    token_found = None
                    for key, value in local_storage.items():
                        if any(tok in key.lower() for tok in ("token", "jwt", "auth", "access")):
                            token_found = value
                            break

                    if token_found:
                        from pencheff.core.credentials import MaskedSecret
                        cred_set = session.credentials.get("default")
                        if cred_set:
                            cred_set.token = MaskedSecret(token_found)

                    findings.append(Finding(
                        title="Authenticated Session Established via Login Macro",
                        severity=Severity.INFO,
                        category="auth",
                        owasp_category="A07",
                        description=(
                            f"Login macro executed successfully. "
                            f"Extracted {len(cookies)} cookies"
                            + (f" and 1 auth token from localStorage." if token_found else ".")
                            + " Session credentials updated for subsequent module testing."
                        ),
                        remediation="Verify the authenticated session is being used in subsequent scans.",
                        endpoint=login_url,
                    ))
                else:
                    final_url = page.url
                    pw_selector = await page.query_selector("input[type='password']")
                    page_title = ""
                    try:
                        page_title = await page.title()
                    except Exception:
                        pass

                    # Inventory every input on the page so the user can see
                    # WHY the auto-detect didn't match — almost always the
                    # site uses unusual name/id attributes the default
                    # selector list doesn't cover.
                    input_inventory: list[str] = []
                    try:
                        input_inventory = await page.evaluate(
                            """() => {
                                const out = [];
                                for (const el of document.querySelectorAll('input, button')) {
                                    const tag = el.tagName.toLowerCase();
                                    const type = el.getAttribute('type') || '';
                                    const name = el.getAttribute('name') || '';
                                    const id = el.getAttribute('id') || '';
                                    const ph = el.getAttribute('placeholder') || '';
                                    const ac = el.getAttribute('autocomplete') || '';
                                    const text = (el.innerText || '').trim().slice(0, 30);
                                    out.push(`${tag} type=${type} name=${name} id=${id} placeholder=${ph} autocomplete=${ac} text=${text}`);
                                }
                                return out.slice(0, 40);
                            }"""
                        )
                    except Exception:
                        pass

                    trace_block = "\n".join(f"  • {line}" for line in trace)
                    inv_block = "\n".join(f"  • {line}" for line in input_inventory)

                    findings.append(Finding(
                        title="Login Macro Could Not Authenticate — Scan Continued Unauthenticated",
                        severity=Severity.INFO,
                        category="auth",
                        owasp_category="A07",
                        description=(
                            "The login macro did not complete successfully. "
                            "All subsequent scans will run UNAUTHENTICATED, which "
                            "means most of the attack surface is invisible.\n\n"
                            f"**Final URL**: `{final_url}`\n"
                            f"**Page title**: `{page_title or '(no title)'}`\n"
                            f"**Password field after submit**: "
                            f"{'still present' if pw_selector else 'gone'}\n\n"
                            "**Macro step trace** (top-down — first ✗ is usually the cause):\n"
                            f"{trace_block}\n\n"
                            "**Visible inputs/buttons on the page** (use these to "
                            "build a custom login_steps macro):\n"
                            f"{inv_block if inv_block else '  (none captured)'}\n\n"
                            "Most common causes when no fill_first ✓ appears: "
                            "(1) the page is JS-heavy and the form hadn't rendered "
                            "yet — bump the wait or supply `login_url` explicitly; "
                            "(2) the form uses non-standard selectors not in the "
                            "auto-detect list — see the inventory above; "
                            "(3) the page is behind CAPTCHA / Cloudflare turnstile; "
                            "(4) the URL we navigated to was wrong — many sites "
                            "expose `/auth/login`, `/users/sign_in`, or "
                            "`/account/signin` rather than `/login`."
                        ),
                        remediation=(
                            "Three options, easiest first:\n"
                            "1. Save a session cookie directly: log in to the "
                            "target in your browser, copy the cookie from devtools, "
                            "save it on the Target as a `cookie` credential. The "
                            "scan will use it without needing to drive the form.\n"
                            "2. Supply explicit login_steps via the "
                            "`pencheff_configure(session_id, updates={'login_steps': [...]})` "
                            "tool, building selectors from the inventory above.\n"
                            "3. Capture the flow interactively with "
                            "`record_login_macro(session_id, login_url=...)` — pops "
                            "a real Chromium where you log in by hand."
                        ),
                        endpoint=login_url,
                    ))

            except Exception as e:
                findings.append(Finding(
                    title="Login Macro Error — Authenticated Scan Disabled",
                    severity=Severity.HIGH,
                    category="auth",
                    owasp_category="A07",
                    description=(
                        f"Login macro raised an exception while logging in: "
                        f"{type(e).__name__}: {e}. "
                        "Subsequent scans will run unauthenticated. "
                        "Most often this means Playwright's Chromium browser binary "
                        "is not installed in the worker environment "
                        "(run `playwright install chromium` once)."
                    ),
                    remediation=(
                        "Install Playwright browsers in the Celery worker: "
                        "`pip install playwright && playwright install chromium`. "
                        "If that's already done, capture the real login flow with "
                        "`record_login_macro` and re-scan."
                    ),
                    endpoint=login_url,
                ))
            finally:
                await browser.close()

        return findings


def _build_auto_login_steps(login_url: str, username: str, password: str) -> list[dict]:
    """Construct auto-login steps by trying common selectors.

    The macro is forgiving with modern SPA login pages:
      * try several candidate login URL paths and stop at the first one
        that actually renders a password field (sites expose ``/login``,
        ``/auth/login``, ``/users/sign_in``, ``/account/signin``, …)
      * wait for *any* password field to render before filling (SPAs hydrate
        their forms after first paint; an immediate fill misses every input)
      * try a generous list of name/id/autocomplete patterns
      * fall back to clicking a "Sign in / Log in / Continue" button by text
        when no `type=submit` exists (common in headless React forms)
    """
    base = login_url.rstrip("/")
    # If the caller passed an exact login URL (containing /login, /signin,
    # /sign_in, /auth, etc.) try it first. Otherwise probe the common paths.
    if any(x in base.lower() for x in ("/login", "/signin", "/sign_in", "/auth")):
        candidates = [login_url]
    else:
        candidates = [
            f"{base}/login",
            f"{base}/signin",
            f"{base}/auth/login",
            f"{base}/users/sign_in",
            f"{base}/account/signin",
            f"{base}/accounts/login",
            base,  # last resort — homepage may host the login modal
        ]
    return [
        {"action": "navigate_first",
         "urls": candidates,
         "stop_when": "input[type='password']"},
        # Wait for an actual password field rather than a fixed timeout.
        {"action": "wait_for", "selector": "input[type='password']"},
        {"action": "wait", "ms": 500},
        # Try common username selectors. ``fill_first`` short-circuits on the
        # first selector that resolves to a visible element.
        {"action": "fill_first", "selectors": [
            "input[name='username']", "input[name='email']",
            "input[name='login']", "input[name='user']",
            "input[id='username']", "input[id='email']",
            "input[id='login']", "input[id='user']",
            "input[type='email']",
            "input[autocomplete='username']",
            "input[autocomplete='email']",
            "input[placeholder*='mail' i]", "input[placeholder*='user' i]",
        ], "value": username},
        # Try common password selectors.
        {"action": "fill_first", "selectors": [
            "input[name='password']", "input[type='password']",
            "input[id='password']", "input[autocomplete='current-password']",
        ], "value": password},
        # Try common submit selectors.
        {"action": "click_first", "selectors": [
            "button[type='submit']", "input[type='submit']",
            "button:has-text('Log in')", "button:has-text('Login')",
            "button:has-text('Sign in')", "button:has-text('Sign In')",
            "button:has-text('Continue')",
            "[role='button']:has-text('Log in')",
            "[role='button']:has-text('Sign in')",
        ]},
        # Wait long enough for a redirect after submit on slow SPAs.
        {"action": "wait", "ms": 3500},
    ]


async def _execute_macro(
    page: "Page",
    steps: list[dict],
) -> tuple[bool, list[dict], dict, list[str]]:
    """Execute macro steps. Returns (success, cookies, local_storage, trace).

    ``trace`` is a list of one human-readable line per step describing what
    happened. The login_macro module attaches it to the failure finding so
    the user sees *exactly* which step broke instead of a generic
    "auto-login failed" message.
    """
    success = False
    trace: list[str] = []

    for step in steps:
        action = step.get("action", "")
        try:
            if action == "navigate":
                url = step["url"]
                await page.goto(url, wait_until="networkidle", timeout=15000)
                trace.append(f"navigate → {url} (final: {page.url})")

            elif action == "navigate_first":
                # Try each URL until one renders the ``stop_when`` selector
                # (default ``input[type='password']``). Surfaces which login
                # path actually exists on the target — by far the most
                # common cause of macro failures on real-world SPAs.
                stop_sel = step.get("stop_when", "input[type='password']")
                landed: str | None = None
                for url in step.get("urls", []):
                    try:
                        await page.goto(url, wait_until="networkidle", timeout=15000)
                    except Exception as exc:  # noqa: BLE001
                        trace.append(f"navigate_first try {url} ✗ {type(exc).__name__}")
                        continue
                    try:
                        await page.wait_for_selector(stop_sel, timeout=4000)
                        landed = url
                        break
                    except Exception:
                        trace.append(
                            f"navigate_first try {url} → {page.url} (no `{stop_sel}` within 4s)"
                        )
                        continue
                if landed:
                    trace.append(
                        f"navigate_first ✓ landed on {landed} (final: {page.url}) "
                        f"with `{stop_sel}` visible"
                    )
                else:
                    trace.append(
                        f"navigate_first ✗ none of the {len(step.get('urls', []))} "
                        f"candidate URLs rendered `{stop_sel}`. Final URL: {page.url}"
                    )

            elif action == "fill":
                await page.fill(step["selector"], step["value"])
                trace.append(f"fill `{step['selector']}` ✓")

            elif action == "fill_first":
                matched: str | None = None
                for sel in step.get("selectors", []):
                    try:
                        el = await page.query_selector(sel)
                        if el and await el.is_visible():
                            await el.fill(step["value"])
                            matched = sel
                            break
                    except Exception:
                        continue
                if matched:
                    trace.append(f"fill_first ✓ via `{matched}`")
                else:
                    trace.append(
                        "fill_first ✗ no visible match in "
                        f"{len(step.get('selectors', []))} selectors"
                    )

            elif action == "click":
                await page.click(step["selector"])
                trace.append(f"click `{step['selector']}` ✓")

            elif action == "click_first":
                matched_c: str | None = None
                for sel in step.get("selectors", []):
                    try:
                        el = await page.query_selector(sel)
                        if el and await el.is_visible():
                            await el.click()
                            matched_c = sel
                            break
                    except Exception:
                        continue
                if matched_c:
                    trace.append(f"click_first ✓ via `{matched_c}`")
                else:
                    trace.append(
                        "click_first ✗ no visible match in "
                        f"{len(step.get('selectors', []))} selectors"
                    )

            elif action == "wait":
                await page.wait_for_timeout(step.get("ms", 1000))
                trace.append(f"wait {step.get('ms', 1000)}ms")

            elif action == "wait_for":
                try:
                    await page.wait_for_selector(step["selector"], timeout=10000)
                    trace.append(f"wait_for `{step['selector']}` ✓")
                except Exception as exc:  # noqa: BLE001
                    trace.append(
                        f"wait_for `{step['selector']}` ✗ "
                        f"({type(exc).__name__})"
                    )

            elif action == "screenshot":
                # Capture for evidence (returns base64 but we just mark it)
                await page.screenshot()
                trace.append("screenshot ✓")

        except Exception as exc:  # noqa: BLE001
            trace.append(f"{action} ✗ {type(exc).__name__}: {str(exc)[:120]}")
            continue

    # Determine success: be conservative.
    #
    # The previous heuristic flipped to success the moment the URL no longer
    # contained "login" — but plenty of sites land you on `/login?error=…`
    # after a failed submit, and SPAs with a single root URL ("/") never
    # change at all. Combine both signals: URL no longer looks like a login
    # AND the password field is gone. Either alone is too eager.
    current_url = page.url
    url_left_login = (
        "login" not in current_url.lower() and "signin" not in current_url.lower()
    )
    pw_gone = False
    try:
        password_field = await page.query_selector("input[type='password']")
        pw_gone = password_field is None
    except Exception:
        pass
    success = url_left_login and pw_gone
    trace.append(
        f"success-check: url_left_login={url_left_login} pw_field_gone={pw_gone} "
        f"→ {'authenticated' if success else 'still unauthenticated'}"
    )

    # Extract cookies
    cookies = []
    try:
        cookies = await page.context.cookies()
    except Exception:
        pass

    # Extract localStorage
    local_storage: dict[str, str] = {}
    try:
        local_storage = await page.evaluate("""() => {
            const result = {};
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                result[key] = localStorage.getItem(key);
            }
            return result;
        }""")
    except Exception:
        pass

    return success, cookies, local_storage or {}, trace
