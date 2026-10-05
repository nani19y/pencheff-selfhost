"""swarm-orchestrator — Tier 2 coordinator.

Runs the 9-phase engagement lifecycle:

    Scoping → Crawl → Auth → Recon → Vuln Assessment → Exploitation
    → Post-Exploitation → Detection Engineering → Reporting

The two phases between Scoping and Recon are inserted up-front so every
later phase sees a populated, filtered, authenticated endpoint surface:

* **Crawl** runs an HTTP-only crawl + sitemap/robots/JS extraction +
  OpenAPI spec discovery. Filters out static assets and third-party CDN
  URLs, replaces ``session.discovered.endpoints`` with the curated set.
* **Auth** scores the crawled URLs by login-shape, hands the highest
  scorer to :class:`pencheff.modules.auth.api_login.ApiLoginModule`. On
  success, cookies + bearer tokens land on the session for every
  subsequent module.

Behaves as either a one-shot driver invoked by ``pencheff engage`` /
``pencheff swarm``, or by the ``playbook_engage`` MCP tool.

The orchestrator imports the registry lazily to avoid a circular dep.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, Awaitable, Callable

from pencheff.core import opsec
from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


# Progress callback signature: ``await cb(event_type, payload)``.
# Event types fired by the orchestrator:
#   "phase_start"     payload: {"phase": str, "playbooks": list[str]}
#   "playbook_done"   payload: {"phase": str, "playbook": str, "summary": str,
#                               "findings_added": int, "skipped": str | None,
#                               "error": str | None}
#   "phase_done"      payload: {"phase": str, "ran": int, "skipped": int}
#   "subdomain_start" payload: {"subdomain": str}
#   "subdomain_done"  payload: {"subdomain": str, "findings": int}
ProgressCb = Callable[[str, dict[str, Any]], Awaitable[None] | None]


async def _fire(cb: ProgressCb | None, event: str, payload: dict[str, Any]) -> None:
    if cb is None:
        return
    try:
        ret = cb(event, payload)
        if inspect.isawaitable(ret):
            await ret
    except Exception:  # noqa: BLE001 — never let UX hooks break the scan
        pass


# (phase, [playbook names]) — names that match REGISTRY keys.
#
# ``crawl`` and ``auth`` are inserted between scope and recon so every
# downstream phase sees a populated, authenticated endpoint surface.
# Without crawl, vuln modules default to just the base URL via
# BaseTestModule._get_target_endpoints. Without auth, the swarm tests
# only the unauthenticated surface.
DEFAULT_PHASE_DAG: list[tuple[str, list[str]]] = [
    ("scope",   ["engagement_planner", "threat_modeler"]),
    ("crawl",   ["crawl_first"]),
    ("auth",    ["api_authenticator"]),
    ("recon",   ["osint_collector", "recon_advisor"]),         # parallelisable
    ("vuln",    ["vuln_scanner", "web_hunter", "api_security",
                 "cloud_security", "bizlogic_hunter", "stig_analyst"]),
    ("exploit", ["exploit_guide", "attack_planner", "exploit_chainer", "poc_validator"]),
    ("postex",  ["privesc_advisor"]),
    ("detect",  ["detection_engineer"]),
    ("report",  ["report_generator", "bug_bounty"]),
]


class SwarmOrchestratorPlaybook(Playbook):
    name = "swarm_orchestrator"
    tier = 2
    phase = "scope"
    noise = "moderate"
    mitre = []
    handoff_to = []
    requires_scope = True
    description = "Drives the 9-phase engagement lifecycle (scope→crawl→auth→recon→vuln→…)."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  scope: dict[str, Any] | None = None,
                  noise_ceiling: opsec.NoiseLevel | None = None,
                  tier: int = 2, phases: list[str] | None = None,
                  parallel_recon: bool = True,
                  include_subdomains: bool = True,
                  max_subdomains: int = 10,
                  progress_cb: ProgressCb | None = None,
                  **kwargs: Any) -> RunResult:
        from pencheff.playbooks import REGISTRY  # avoid circular import at module load

        guard = current_scope()
        if guard:
            guard.validate(session.target.base_url)

        ran: list[dict[str, Any]] = []
        all_artifacts: dict[str, Any] = {}
        subdomain_runs: list[dict[str, Any]] = []

        # progress_cb is forwarded to each playbook via kwargs only when the
        # playbook explicitly accepts it; otherwise it'd land in **kwargs and
        # confuse playbooks that don't expect it. We strip it before _run_one.
        kwargs.pop("progress_cb", None)

        async def _run_one(name: str, phase_key: str) -> dict[str, Any]:
            cls = REGISTRY.get(name)
            if not cls:
                out = {"playbook": name, "skipped": "not in registry"}
                await _fire(progress_cb, "playbook_done", {"phase": phase_key, **out})
                return out
            pb_inst = cls()
            # Tier filter
            if tier == 1 and pb_inst.tier == 2:
                out = {"playbook": name, "skipped": "tier filter"}
                await _fire(progress_cb, "playbook_done", {"phase": phase_key, **out})
                return out
            # Noise filter
            if noise_ceiling is not None and not opsec.at_or_below(pb_inst.noise, noise_ceiling):
                out = {"playbook": name, "skipped": f"noise > {noise_ceiling}"}
                await _fire(progress_cb, "playbook_done", {"phase": phase_key, **out})
                return out
            try:
                res = await pb_inst.run(session, eng_db, engagement_id,
                                        scope=scope, **kwargs)
                out = {"playbook": name, "summary": res.summary,
                       "findings_added": res.findings_added,
                       "artifacts": res.artifacts}
                await _fire(progress_cb, "playbook_done",
                            {"phase": phase_key, **{k: v for k, v in out.items()
                                                      if k != "artifacts"}})
                return out
            except Exception as exc:
                err = f"{type(exc).__name__}: {exc}"
                await _fire(progress_cb, "playbook_done",
                            {"phase": phase_key, "playbook": name, "error": err})
                return {"playbook": name, "error": err}

        for phase_key, names in DEFAULT_PHASE_DAG:
            if phases and phase_key not in phases:
                continue
            if eng_db and engagement_id:
                eng_db.log(engagement_id, agent=self.name, action=f"phase_start:{phase_key}",
                           summary=f"running {len(names)} playbook(s)")
            await _fire(progress_cb, "phase_start",
                        {"phase": phase_key, "playbooks": list(names)})
            if parallel_recon and phase_key == "recon":
                outs = await asyncio.gather(*(_run_one(n, phase_key) for n in names))
            else:
                outs = []
                for n in names:
                    outs.append(await _run_one(n, phase_key))
            ran.extend(outs)
            all_artifacts[phase_key] = outs
            await _fire(progress_cb, "phase_done", {
                "phase": phase_key,
                "ran": sum(1 for o in outs if "skipped" not in o and "error" not in o),
                "skipped": sum(1 for o in outs if "skipped" in o),
            })

        # ── Subdomain fan-out ────────────────────────────────────────
        # Each subdomain gets its own crawl+auth+vuln+exploit pass so
        # the auth credentials and the discovered surface are scoped to
        # *that* subdomain (admin., api., www. usually have different
        # routing and auth backends). Without crawl+auth on the sub-
        # session, vuln modules default to the base URL — losing the
        # whole point of the fan-out.
        SUB_PHASES = ("crawl", "auth", "vuln", "exploit")

        if include_subdomains:
            subdomains = list(getattr(session.discovered, "subdomains", None) or [])
            from urllib.parse import urlparse
            base_host = urlparse(session.target.base_url).hostname or ""
            subdomains = [s for s in subdomains if s and s != base_host]
            if guard:
                subdomains = [s for s in subdomains if _in_scope(guard, s)]
            subdomains = subdomains[:max_subdomains]
            for sd in subdomains:
                sub_session = _spawn_subdomain_session(session, sd)
                if eng_db and engagement_id:
                    eng_db.log(engagement_id, agent=self.name,
                               action=f"subdomain:{sd}",
                               summary=f"{'+'.join(SUB_PHASES)} fan-out")
                await _fire(progress_cb, "subdomain_start", {"subdomain": sd})
                sub_runs: list[dict[str, Any]] = []
                for phase_key in SUB_PHASES:
                    pb_names = dict(DEFAULT_PHASE_DAG)[phase_key]
                    for n in pb_names:
                        cls = REGISTRY.get(n)
                        if not cls or cls.tier > tier:
                            continue
                        if noise_ceiling is not None and not opsec.at_or_below(cls.noise, noise_ceiling):
                            continue
                        try:
                            res = await cls().run(sub_session, eng_db, engagement_id,
                                                  scope=scope)
                            sub_runs.append({"playbook": n, "summary": res.summary,
                                             "findings_added": res.findings_added})
                            await _fire(progress_cb, "playbook_done", {
                                "phase": f"sub:{sd}:{phase_key}",
                                "playbook": n, "summary": res.summary,
                                "findings_added": res.findings_added,
                            })
                        except Exception as exc:
                            err = f"{type(exc).__name__}: {exc}"
                            sub_runs.append({"playbook": n, "error": err})
                            await _fire(progress_cb, "playbook_done", {
                                "phase": f"sub:{sd}:{phase_key}",
                                "playbook": n, "error": err,
                            })
                # Merge subdomain findings back into the master session
                for f in sub_session.findings.get_all(include_suppressed=True):
                    session.findings.add(f)
                subdomain_runs.append({"subdomain": sd, "runs": sub_runs,
                                       "findings": sub_session.findings.count})
                await _fire(progress_cb, "subdomain_done",
                            {"subdomain": sd, "findings": sub_session.findings.count})

        self._log(eng_db, engagement_id, "engage_complete",
                  summary=f"phases={len(DEFAULT_PHASE_DAG)} playbooks={len(ran)} "
                          f"subdomains={len(subdomain_runs)}")
        if eng_db and engagement_id:
            eng_db.close_engagement(engagement_id, status="completed")

        return RunResult(
            playbook=self.name,
            summary=(
                f"Swarm complete: {len(ran)} playbook run(s) on base target, "
                f"{len(subdomain_runs)} subdomain(s) fanned out."
            ),
            artifacts={"runs": ran, "phases": all_artifacts,
                       "subdomain_runs": subdomain_runs},
        )


def _in_scope(guard: Any, host: str) -> bool:
    try:
        guard.validate(host)
        return True
    except Exception:
        return False


def _spawn_subdomain_session(parent: Any, sub_host: str) -> Any:
    """Build a fresh PentestSession bound to a subdomain.

    Reuses the parent's depth. Does NOT share the FindingsDB so we can
    attribute findings to the subdomain before merging back.
    Credentials default to none — subdomain auth is usually different.
    """
    from urllib.parse import urlparse, urlunparse
    from pencheff.core.session import create_session

    parsed = urlparse(parent.target.base_url)
    new_url = urlunparse(parsed._replace(netloc=sub_host))
    depth = parent.depth.value if hasattr(parent.depth, "value") else str(parent.depth)
    return create_session(target_url=new_url, depth=depth)
