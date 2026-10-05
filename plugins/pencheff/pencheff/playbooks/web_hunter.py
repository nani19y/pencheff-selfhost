"""web-hunter — Tier 2 execution.

Client-side scanning + content discovery (ffuf/gobuster) + DOM XSS
exploration via the browser crawler.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable

from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


_log = logging.getLogger("pencheff.web_hunter")


# Per-step hard ceilings. Playwright steps are wrapped so a stalled
# browser process (zombie ``headless_shell``, slow target with no
# ``networkidle``, etc.) can't hang the whole engagement at the
# ``engage:vuln`` phase. Tuned generously — a healthy run finishes in
# 30-60s; the timeouts only fire when the browser is genuinely stuck.
_CLIENT_SIDE_TIMEOUT_S = 90
_DOM_XSS_TIMEOUT_S = 180
_BROWSER_CRAWL_TIMEOUT_S = 120
_FFUF_TIMEOUT_S = 600


async def _bounded(
    coro: Awaitable[Any], *, label: str, timeout: float,
) -> Any:
    """Run ``coro`` with a hard timeout; return a structured ``error`` dict
    rather than raising so the playbook keeps marching past the failure.
    Logs prominently so operators see *why* a step was skipped."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        _log.warning("web_hunter step %s timed out after %ss", label, timeout)
        return {"error": f"{label} timed out after {int(timeout)}s — skipped"}
    except Exception as exc:  # noqa: BLE001
        _log.warning("web_hunter step %s failed: %s", label, exc)
        return {"error": f"{label} raised: {str(exc)[:200]}"}


class WebHunterPlaybook(Playbook):
    name = "web_hunter"
    tier = 2
    phase = "vuln"
    noise = "loud"
    mitre = ["T1190", "T1185", "T1059.007"]
    handoff_to = ["poc_validator", "exploit_chainer"]
    requires_scope = True
    description = "Client-side scan, content discovery, DOM XSS."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  wordlist: str | None = None, **kwargs: Any) -> RunResult:
        guard = current_scope()
        if guard:
            guard.validate(session.target.base_url)
        from pencheff import server as _srv
        from pencheff.core import route_enum
        from pencheff.core.http_client import PencheffHTTPClient

        before = session.findings.count
        results: dict[str, Any] = {}

        # Always run the built-in route enumerator. Discovers /admin, /.env,
        # /actuator, /swagger, etc. — the "all routes" coverage that scanners
        # used to require an external wordlist for.
        http = PencheffHTTPClient(session)
        try:
            discovered, route_findings = await route_enum.enumerate(
                session.target.base_url, session=session, http=http,
                wordlist=wordlist,
            )
            session.findings.add_many(route_findings)
            for url in discovered:
                if not any(e.get("url") == url for e in session.discovered.endpoints):
                    session.discovered.endpoints.append({"url": url, "method": "GET"})
            results["routes"] = {"discovered": discovered[:50], "found_findings": len(route_findings)}
        except Exception as exc:
            results["routes"] = {"error": str(exc)[:200]}
        finally:
            try:
                await http.close()
            except Exception:
                pass

        # Each Playwright-based step is bounded so a stalled browser
        # (the most common cause of "scan stuck at 42%" tickets) can't
        # block the rest of the engagement. The bounds are deliberately
        # generous — only fire on genuinely hung runs.
        results["client_side"] = await _bounded(
            _srv.scan_client_side(session_id=session.id),
            label="scan_client_side", timeout=_CLIENT_SIDE_TIMEOUT_S,
        )
        results["dom_xss"] = await _bounded(
            _srv.scan_dom_xss(session_id=session.id),
            label="scan_dom_xss", timeout=_DOM_XSS_TIMEOUT_S,
        )
        results["browser_crawl"] = await _bounded(
            _srv.browser_crawl(session_id=session.id),
            label="browser_crawl", timeout=_BROWSER_CRAWL_TIMEOUT_S,
        )
        if wordlist:
            results["ffuf"] = await _bounded(
                _srv.run_security_tool(
                    session_id=session.id, tool="ffuf",
                    args=["-u", session.target.base_url + "/FUZZ",
                          "-w", wordlist, "-mc", "200,301,302,403"],
                ),
                label="ffuf", timeout=_FFUF_TIMEOUT_S,
            )
        new_findings = session.findings.count - before
        self._log(eng_db, engagement_id, "scan_client_side",
                  summary=f"+{new_findings} findings")
        return RunResult(
            playbook=self.name,
            summary=f"Web hunt: +{new_findings} finding(s).",
            findings_added=new_findings,
            handoffs=list(self.handoff_to),
            artifacts=results,
        )
