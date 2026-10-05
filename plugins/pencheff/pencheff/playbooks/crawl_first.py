"""crawl_first — populate session.discovered.endpoints BEFORE any other phase.

Runs three HTTP-only discovery passes and merges + filters their output:

1. **Link/form/JS crawler** — :class:`pencheff.modules.web.crawler.CrawlerModule`
   walks same-origin links, extracts <form> targets, and regex-extracts
   ``fetch('/api/...')``-style endpoints from inline JS and bundle files.
2. **sitemap.xml + robots.txt** — fetched once each, parsed for ``<loc>``
   and ``Disallow:`` lines that the crawler may not have seen because the
   homepage doesn't link them.
3. **REST/OpenAPI spec discovery** —
   :class:`pencheff.modules.api.rest_discovery.RestDiscoveryModule` probes
   ~20 known spec paths; if a spec is found, every endpoint in it (with
   parameters) gets seeded into ``session.discovered.endpoints``.

The merged endpoint list is then filtered through
:func:`pencheff.core.route_filter.filter_endpoints` so static assets,
third-party CDN URLs, and fragment links don't pollute the surface that
the vuln playbooks will later test.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from pencheff.core.route_filter import filter_endpoints
from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_ROBOTS_PATH_RE = re.compile(r"^\s*(?:Allow|Disallow|Sitemap)\s*:\s*(\S+)",
                             re.IGNORECASE | re.MULTILINE)


class CrawlFirstPlaybook(Playbook):
    name = "crawl_first"
    tier = 2
    phase = "crawl"
    noise = "moderate"
    mitre = ["T1595", "T1596"]
    handoff_to = ["api_authenticator", "recon_advisor"]
    requires_scope = True
    description = (
        "HTTP-first crawl: link/form/JS extraction + sitemap + robots + "
        "OpenAPI spec discovery. Filters and seeds session.discovered.endpoints."
    )

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  max_depth: int = 3, max_pages: int = 200,
                  **kwargs: Any) -> RunResult:
        guard = current_scope()
        if guard:
            guard.validate(session.target.base_url)

        from pencheff.core.http_client import PencheffHTTPClient
        from pencheff.modules.web.crawler import CrawlerModule
        from pencheff.modules.api.rest_discovery import RestDiscoveryModule

        results: dict[str, Any] = {}
        before_count = len(session.discovered.endpoints)
        http = PencheffHTTPClient(session)
        try:
            # 1. HTTP link/form/JS crawler — populates endpoints in-place.
            try:
                await CrawlerModule().run(session, http, config={
                    "max_depth": max_depth, "max_pages": max_pages,
                })
                results["crawler"] = {
                    "endpoints_after_crawl": len(session.discovered.endpoints),
                }
            except Exception as exc:
                results["crawler"] = {"error": str(exc)[:200]}

            # 2. sitemap + robots — additive list of URL candidates.
            sitemap_added = await self._fetch_sitemap(session, http)
            robots_added = await self._fetch_robots(session, http)
            results["sitemap"] = {"added": sitemap_added}
            results["robots"] = {"added": robots_added}

            # 3. OpenAPI / Swagger discovery — fills params + methods properly.
            try:
                await RestDiscoveryModule().run(session, http, config={})
                results["spec_discovery"] = {
                    "specs": len(session.discovered.api_specs or []),
                }
            except Exception as exc:
                results["spec_discovery"] = {"error": str(exc)[:200]}
        finally:
            try:
                await http.close()
            except Exception:
                pass

        # Filter the merged set down to useful-for-pentest entries. Replace
        # the raw list with the filtered, score-sorted one so every later
        # phase sees the curated surface.
        base_host = urlparse(session.target.base_url).hostname or ""
        filtered = filter_endpoints(
            list(session.discovered.endpoints),
            base_host=base_host,
        )
        dropped = len(session.discovered.endpoints) - len(filtered)
        session.discovered.endpoints = filtered

        results["filter"] = {
            "kept": len(filtered),
            "dropped_as_noise": dropped,
        }
        results["total_useful_endpoints"] = len(filtered)

        # Mirror the base host to the engagement DB so downstream
        # playbooks have a host_id to attach services/vulns to.
        if eng_db and engagement_id:
            try:
                eng_db.add_host(engagement_id, hostname=base_host,
                                discovered_by=self.name)
            except Exception:
                pass

        self._log(eng_db, engagement_id, "crawl_first",
                  summary=f"{len(filtered)} useful endpoint(s) "
                          f"({dropped} dropped as noise)")
        return RunResult(
            playbook=self.name,
            summary=(
                f"Crawled {len(filtered)} useful endpoint(s) "
                f"(dropped {dropped} as noise; baseline before was {before_count})."
            ),
            findings_added=0,
            handoffs=list(self.handoff_to),
            artifacts=results,
        )

    # ── sitemap / robots helpers ─────────────────────────────────────

    @staticmethod
    async def _fetch_sitemap(session: Any, http: Any) -> int:
        """Pull URLs out of /sitemap.xml. Returns count added."""
        url = urljoin(session.target.base_url + "/", "/sitemap.xml")
        try:
            resp = await http.get(url, module="crawl_first")
        except Exception:
            return 0
        if resp.status_code != 200 or "xml" not in (resp.headers.get("content-type") or "").lower():
            # Some sites return 200 + HTML for unknown URLs. Trust ``<loc>`` either way.
            pass
        urls = _SITEMAP_LOC_RE.findall(resp.text or "")
        added = 0
        seen = {(e.get("url"), (e.get("method") or "GET").upper())
                for e in session.discovered.endpoints}
        for u in urls[:300]:  # cap so a giant sitemap doesn't explode the list
            key = (u, "GET")
            if key in seen:
                continue
            seen.add(key)
            session.discovered.endpoints.append({
                "url": u, "method": "GET", "source": "sitemap", "params": [],
            })
            added += 1
        return added

    @staticmethod
    async def _fetch_robots(session: Any, http: Any) -> int:
        """Pull Allow/Disallow paths out of /robots.txt. Returns count added.

        robots.txt is a goldmine for paths the org does not want indexed —
        often the same paths an attacker most wants to find (admin areas,
        backup locations, internal dashboards).
        """
        url = urljoin(session.target.base_url + "/", "/robots.txt")
        try:
            resp = await http.get(url, module="crawl_first")
        except Exception:
            return 0
        if resp.status_code != 200:
            return 0
        added = 0
        seen = {(e.get("url"), (e.get("method") or "GET").upper())
                for e in session.discovered.endpoints}
        for raw in _ROBOTS_PATH_RE.findall(resp.text or ""):
            path = raw.strip()
            if not path or path == "*":
                continue
            # Sitemap: lines hold full URLs; everything else is a path.
            if path.startswith("http"):
                full = path
            else:
                if not path.startswith("/"):
                    path = "/" + path
                full = urljoin(session.target.base_url + "/", path)
            key = (full, "GET")
            if key in seen:
                continue
            seen.add(key)
            session.discovered.endpoints.append({
                "url": full, "method": "GET", "source": "robots", "params": [],
            })
            added += 1
        return added
