"""DOM-based XSS detection using Playwright.

Detects DOM XSS by injecting payloads and observing browser-side
execution — something HTTP-only scanners fundamentally cannot do.
Also performs static JS sink analysis on all discovered endpoints.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

from playwright.async_api import async_playwright

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

_PLAYWRIGHT_AVAILABLE = True

# Common DOM XSS sinks — static analysis targets
_DOM_SINKS = [
    "document.write", "document.writeln", "innerHTML", "outerHTML",
    "insertAdjacentHTML", "eval(", "setTimeout(", "setInterval(",
    "Function(", "location.href", "location.assign", "location.replace",
    "document.URL", "document.documentURI", "document.referrer",
    "window.location", "src=", "href=",
]

# Static sources that feed DOM sinks
_DOM_SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.referrer", "document.URL", "document.cookie",
    "window.name", "localStorage", "sessionStorage",
    "URLSearchParams", "history.state",
]

# Payloads for dynamic DOM XSS testing
_DOM_XSS_PAYLOADS = [
    '<img src=x onerror=window.__pencheff_xss=1>',
    'javascript:window.__pencheff_xss=1///',
    '"><script>window.__pencheff_xss=1</script>',
    "'><svg/onload=window.__pencheff_xss=1>",
    '"><iframe/onload=window.__pencheff_xss=1>',
    '<details/open/ontoggle=window.__pencheff_xss=1>',
    '<body/onload=window.__pencheff_xss=1>',
]


class DOMXSSModule(BaseTestModule):
    name = "dom_xss"
    category = "xss"
    owasp_categories = ["A03"]
    description = "DOM-based XSS detection via browser execution and static sink analysis"

    def get_techniques(self) -> list[str]:
        return ["dynamic_dom_xss", "static_sink_analysis", "hash_injection", "query_param_injection"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = self._get_target_endpoints(session, targets)

        # Static analysis (JS sink pattern matching)
        findings.extend(await self._static_sink_analysis(session, http, endpoints))

        # Dynamic analysis (Playwright browser execution)
        findings.extend(await self._dynamic_dom_xss(session, endpoints))

        return findings

    async def _static_sink_analysis(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        endpoints: list[dict],
    ) -> list[Finding]:
        """Fetch pages and scan inline JS for dangerous sink+source patterns."""
        findings: list[Finding] = []
        seen_urls: set[str] = set()

        for ep in endpoints[:20]:
            url = ep["url"]
            if url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                resp = await http.get(url, module="dom_xss")
            except Exception:
                continue

            body = resp.text
            # Extract inline scripts
            script_blocks = re.findall(
                r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE
            )
            all_js = "\n".join(script_blocks)
            # Also check linked JS if small enough
            if not all_js.strip():
                continue

            sinks_found = [s for s in _DOM_SINKS if s in all_js]
            sources_found = [s for s in _DOM_SOURCES if s in all_js]

            if sinks_found and sources_found:
                # Check if a source feeds into a sink in the same block
                for src in sources_found:
                    for sink in sinks_found:
                        # Simple proximity check — within 200 chars
                        pattern = re.compile(
                            re.escape(src) + r'.{0,200}' + re.escape(sink),
                            re.DOTALL,
                        )
                        if pattern.search(all_js):
                            snippet_match = pattern.search(all_js)
                            snippet = snippet_match.group(0)[:300] if snippet_match else ""
                            findings.append(Finding(
                                title=f"Potential DOM XSS: {src} → {sink}",
                                severity=Severity.HIGH,
                                category="xss",
                                owasp_category="A03",
                                description=(
                                    f"Static analysis detected a data flow from the DOM source "
                                    f"`{src}` into the dangerous sink `{sink}` in inline JavaScript. "
                                    f"If user-controlled input reaches this sink without sanitization, "
                                    f"DOM-based XSS is exploitable."
                                ),
                                remediation=(
                                    "Use textContent instead of innerHTML. Sanitize all URL-derived "
                                    "inputs before passing to DOM sinks. Use a CSP with strict-dynamic."
                                ),
                                endpoint=url,
                                evidence=[Evidence(
                                    request_method="GET",
                                    request_url=url,
                                    response_status=resp.status_code,
                                    response_body_snippet=snippet,
                                    description=f"Source: {src} → Sink: {sink}",
                                )],
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                cvss_score=6.1,
                                cwe_id="CWE-79",
                            ))
                            break  # one finding per sink per URL

        return findings

    async def _dynamic_dom_xss(
        self,
        session: PentestSession,
        endpoints: list[dict],
    ) -> list[Finding]:
        """Inject payloads via URL hash and query params; observe browser execution."""
        findings: list[Finding] = []
        base_domain = urlparse(session.target.base_url).netloc

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)

            # Cap at 8 endpoints (was 15). Each endpoint runs through every
            # payload and every parameter, so the multiplicative cost is
            # ``endpoints × payloads × params``. 15 × 7 + 15 × 3 × 3 = 240
            # page loads at 5s each = 20 min worst case, way too long.
            for ep in endpoints[:8]:
                url = ep["url"]
                parsed = urlparse(url)
                if parsed.netloc and parsed.netloc != base_domain:
                    continue

                for payload in _DOM_XSS_PAYLOADS:
                    # Test via URL fragment (hash) — common DOM XSS vector
                    test_url = url + f"#{payload}"
                    try:
                        page = await context.new_page()
                        # ``networkidle`` is unreliable on modern apps with
                        # long-poll / WebSocket / analytics traffic — it can
                        # eat the full ``timeout`` even when the page is
                        # interactive. ``domcontentloaded`` is enough for
                        # DOM-XSS detection: payloads run on parse.
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=5000)
                        await page.wait_for_timeout(250)
                        triggered = await page.evaluate("() => !!window.__pencheff_xss")
                        await page.close()

                        if triggered:
                            findings.append(Finding(
                                title="DOM XSS via URL Fragment",
                                severity=Severity.HIGH,
                                category="xss",
                                owasp_category="A03",
                                description=(
                                    f"DOM-based XSS confirmed: payload injected via URL fragment "
                                    f"executed JavaScript in the browser context.\n\n"
                                    f"Payload: {payload}"
                                ),
                                remediation=(
                                    "Never pass `location.hash` or `location.search` content to "
                                    "innerHTML/document.write/eval. Use textContent. Implement CSP."
                                ),
                                endpoint=url,
                                parameter="#fragment",
                                evidence=[Evidence(
                                    request_method="GET",
                                    request_url=test_url,
                                    response_status=200,
                                    description="Browser executed payload injected via URL fragment",
                                )],
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
                                cvss_score=7.6,
                                cwe_id="CWE-79",
                            ))
                            break  # one finding per endpoint
                    except Exception:
                        try:
                            await page.close()
                        except Exception:
                            pass
                        continue

                # Test via query parameters
                params = ep.get("params", [])
                for param in params[:3]:
                    for payload in _DOM_XSS_PAYLOADS[:3]:
                        qs = parse_qs(parsed.query)
                        qs[param] = [payload]
                        test_url = parsed._replace(
                            query=urlencode(qs, doseq=True)
                        ).geturl()
                        try:
                            page = await context.new_page()
                            await page.goto(test_url, wait_until="networkidle", timeout=10000)
                            await page.wait_for_timeout(500)
                            triggered = await page.evaluate("() => !!window.__pencheff_xss")
                            await page.close()

                            if triggered:
                                findings.append(Finding(
                                    title=f"DOM XSS via Query Parameter '{param}'",
                                    severity=Severity.HIGH,
                                    category="xss",
                                    owasp_category="A03",
                                    description=(
                                        f"DOM-based XSS confirmed via query parameter `{param}`. "
                                        f"Payload executed JavaScript in the browser.\n\nPayload: {payload}"
                                    ),
                                    remediation=(
                                        "Sanitize all URL parameter values before passing to DOM sinks. "
                                        "Use DOMPurify for HTML sanitization. Implement strict CSP."
                                    ),
                                    endpoint=url,
                                    parameter=param,
                                    evidence=[Evidence(
                                        request_method="GET",
                                        request_url=test_url,
                                        response_status=200,
                                        description=f"Browser executed payload via ?{param}=",
                                    )],
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
                                    cvss_score=7.6,
                                    cwe_id="CWE-79",
                                ))
                                break
                        except Exception:
                            try:
                                await page.close()
                            except Exception:
                                pass
                            continue

            await browser.close()

        return findings
