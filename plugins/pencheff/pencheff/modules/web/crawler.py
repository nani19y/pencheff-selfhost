"""Async web crawler for endpoint and parameter discovery."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs

from pencheff.config import Severity
from pencheff.core.findings import Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class CrawlerModule(BaseTestModule):
    name = "crawler"
    category = "recon"
    owasp_categories = ["A05"]
    description = "Web crawling for endpoint and parameter discovery"

    def get_techniques(self) -> list[str]:
        return ["link_extraction", "form_discovery", "js_endpoint_extraction"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        config = config or {}
        max_depth = config.get("max_depth", 3)
        max_pages = config.get("max_pages", 200)
        base_url = session.target.base_url
        base_domain = urlparse(base_url).netloc

        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(base_url, 0)]
        findings = []

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue

            # Stay within scope
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != base_domain:
                continue
            # Skip non-HTTP
            if parsed.scheme and parsed.scheme not in ("http", "https"):
                continue
            # Skip excluded paths
            if any(url.startswith(f"{base_url}{exc}") for exc in session.target.exclude_paths):
                continue

            visited.add(url)

            try:
                resp = await http.get(url, module="crawler")
            except Exception:
                continue

            content_type = resp.headers.get("content-type", "")
            if "text/html" not in content_type and "application/json" not in content_type:
                continue

            body = resp.text

            # Extract links from HTML
            link_patterns = [
                r'href=["\']([^"\']+)["\']',
                r'src=["\']([^"\']+)["\']',
                r'action=["\']([^"\']+)["\']',
            ]
            for pattern in link_patterns:
                for match in re.findall(pattern, body, re.IGNORECASE):
                    full_url = urljoin(url, match)
                    full_parsed = urlparse(full_url)
                    # Normalize — strip fragment
                    clean = f"{full_parsed.scheme}://{full_parsed.netloc}{full_parsed.path}"
                    if full_parsed.query:
                        clean += f"?{full_parsed.query}"
                    if clean not in visited:
                        queue.append((clean, depth + 1))

            # Extract forms
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']'
            for action, method in re.findall(form_pattern, body, re.IGNORECASE):
                form_url = urljoin(url, action) if action else url
                # Extract input names
                input_names = re.findall(
                    r'<input[^>]*name=["\']([^"\']+)["\']', body, re.IGNORECASE
                )
                session.discovered.endpoints.append({
                    "url": form_url,
                    "method": method.upper() or "POST",
                    "source": "form",
                    "params": input_names,
                })

            # Extract JS API endpoints
            js_patterns = [
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](/v[0-9]+/[^"\']+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
            ]
            for pattern in js_patterns:
                for match in re.findall(pattern, body):
                    endpoint_url = urljoin(url, match)
                    ep_parsed = urlparse(endpoint_url)
                    if ep_parsed.netloc == base_domain or not ep_parsed.netloc:
                        params = list(parse_qs(ep_parsed.query).keys())
                        session.discovered.endpoints.append({
                            "url": endpoint_url,
                            "method": "GET",
                            "source": "javascript",
                            "params": params,
                        })

            # Record as endpoint
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            session.discovered.endpoints.append({
                "url": url,
                "method": "GET",
                "source": "crawl",
                "params": params,
            })

        # Deduplicate endpoints
        seen_urls = set()
        unique_endpoints = []
        for ep in session.discovered.endpoints:
            if ep["url"] not in seen_urls:
                seen_urls.add(ep["url"])
                unique_endpoints.append(ep)
        session.discovered.endpoints = unique_endpoints

        return findings
