"""Headless browser crawler using Playwright.

Capabilities beyond the regex crawler:
- Full JavaScript execution (React, Angular, Vue, SPAs)
- DOM-based link/form extraction after JS rendering
- Single-page app route discovery via pushState interception
- Network request interception for API endpoint discovery
- Screenshot capture for evidence
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs

from playwright.async_api import async_playwright, Browser, Page

from pencheff.config import Severity
from pencheff.core.findings import Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

_PLAYWRIGHT_AVAILABLE = True


class BrowserCrawlerModule(BaseTestModule):
    """Playwright-powered headless browser crawler for SPA/JS-heavy targets."""

    name = "browser_crawler"
    category = "recon"
    owasp_categories = ["A05"]
    description = "Headless browser crawling with full JS rendering for SPA discovery"

    def get_techniques(self) -> list[str]:
        return ["js_rendering", "spa_routing", "network_interception", "form_discovery"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        config = config or {}
        max_pages = config.get("max_pages", 100)
        max_depth = config.get("max_depth", 3)
        headless = config.get("headless", True)
        base_url = session.target.base_url
        base_domain = urlparse(base_url).netloc

        visited: set[str] = set()
        discovered_endpoints: list[dict] = []
        api_calls: list[dict] = []
        findings: list[Finding] = []

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(headless=headless)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                ),
            )

            # Inject credentials if available
            creds = session.credentials.get("default")
            if creds and creds.cookie:
                await context.add_cookies([{
                    "name": "session",
                    "value": creds.cookie.get(),
                    "domain": base_domain,
                    "path": "/",
                }])

            # Intercept network requests to discover API endpoints
            async def on_request(request: Any) -> None:
                url = request.url
                if any(url.startswith(s) for s in ("data:", "blob:", "chrome-extension:")):
                    return
                parsed = urlparse(url)
                if parsed.netloc == base_domain:
                    path = parsed.path
                    if any(path.startswith(p) for p in ("/api/", "/v1/", "/v2/", "/graphql")):
                        params = list(parse_qs(parsed.query).keys())
                        api_calls.append({
                            "url": url,
                            "method": request.method,
                            "source": "network_intercept",
                            "params": params,
                        })

            page: Page = await context.new_page()
            page.on("request", on_request)

            # Track SPA routing via URL changes
            spa_routes: set[str] = set()

            async def on_framenavigated(frame: Any) -> None:
                if frame == page.main_frame:
                    spa_routes.add(frame.url)

            page.on("framenavigated", on_framenavigated)

            queue: list[tuple[str, int]] = [(base_url, 0)]

            while queue and len(visited) < max_pages:
                url, depth = queue.pop(0)
                if url in visited or depth > max_depth:
                    continue

                parsed = urlparse(url)
                if parsed.netloc and parsed.netloc != base_domain:
                    continue
                if parsed.scheme not in ("http", "https", ""):
                    continue
                if any(url.startswith(f"{base_url}{exc}") for exc in session.target.exclude_paths):
                    continue

                visited.add(url)

                try:
                    # Modern web apps with WebSocket / long-poll / analytics
                    # rarely hit ``networkidle`` — wait_until eats the full
                    # timeout on every navigation. ``domcontentloaded`` is
                    # enough to capture SPA routes via DOM scraping.
                    await page.goto(url, wait_until="domcontentloaded", timeout=8000)
                    # Brief settle for lazy-loaded content.
                    await page.wait_for_timeout(300)
                except Exception:
                    continue

                # Extract all links from the rendered DOM
                links = await page.evaluate("""() => {
                    const links = [];
                    document.querySelectorAll('a[href], [data-href], [data-url]').forEach(el => {
                        const href = el.getAttribute('href') || el.getAttribute('data-href') || el.getAttribute('data-url');
                        if (href) links.push(href);
                    });
                    return links;
                }""")
                for href in (links or []):
                    full_url = urljoin(url, href)
                    if full_url not in visited:
                        queue.append((full_url, depth + 1))

                # Extract forms
                forms = await page.evaluate("""() => {
                    return Array.from(document.forms).map(f => ({
                        action: f.action,
                        method: f.method || 'GET',
                        inputs: Array.from(f.elements).map(e => e.name).filter(Boolean),
                    }));
                }""")
                for form in (forms or []):
                    form_url = form.get("action") or url
                    session.discovered.endpoints.append({
                        "url": form_url,
                        "method": form.get("method", "GET").upper(),
                        "source": "browser_form",
                        "params": form.get("inputs", []),
                    })

                # Extract JavaScript API endpoint patterns
                scripts = await page.evaluate("""() => {
                    return Array.from(document.scripts)
                        .map(s => s.textContent || '')
                        .join('\\n');
                }""")
                js_patterns = [
                    r'["\'](/api/[^"\'?#\s]{1,100})["\']',
                    r'["\'](/v\d+/[^"\'?#\s]{1,100})["\']',
                    r'fetch\(\s*["\']([^"\']+)["\']',
                    r'axios\.[a-z]+\(\s*["\']([^"\']+)["\']',
                    r'\.ajax\(\s*\{[^}]*url:\s*["\']([^"\']+)["\']',
                ]
                for pattern in js_patterns:
                    for match in re.findall(pattern, scripts or ""):
                        endpoint_url = urljoin(url, match)
                        ep = urlparse(endpoint_url)
                        if not ep.netloc or ep.netloc == base_domain:
                            params = list(parse_qs(ep.query).keys())
                            session.discovered.endpoints.append({
                                "url": endpoint_url,
                                "method": "GET",
                                "source": "browser_js",
                                "params": params,
                            })

                # Record current page as endpoint
                ep_parsed = urlparse(url)
                session.discovered.endpoints.append({
                    "url": url,
                    "method": "GET",
                    "source": "browser_crawl",
                    "params": list(parse_qs(ep_parsed.query).keys()),
                })

            # Add API calls discovered via network interception
            session.discovered.endpoints.extend(api_calls)

            await browser.close()

        # Deduplicate
        seen: set[str] = set()
        unique: list[dict] = []
        for ep in session.discovered.endpoints:
            key = f"{ep['method']}:{ep['url']}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        session.discovered.endpoints = unique

        # Crawl completion is a scan event, not a vulnerability. We
        # previously emitted it as an INFO Finding which then cluttered
        # the report alongside real issues. Log it on the session
        # request trail instead so the data is still visible to
        # operators who want it.
        try:
            session.log_request(
                method="CRAWL",
                url=session.target.base_url,
                status=None,
                module="browser_crawler",
            )
        except Exception:
            pass
        import logging as _logging
        _logging.getLogger("pencheff.browser_crawler").info(
            "browser crawl complete: %d unique endpoints from %d pages, %d API calls intercepted",
            len(unique), len(visited), len(api_calls),
        )

        return findings
