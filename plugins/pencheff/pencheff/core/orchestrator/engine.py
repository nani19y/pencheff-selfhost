"""Top-level Orchestrator — the headline ``run`` method.

Wires together selector, param optimizer, throttle, fallback, cache, and the
state machine into a deterministic engagement runner. Subclasses or
workflows can override individual phase handlers via ``register_phase``.

Design principle: all decisions consult policy YAMLs. The engine should
never embed numeric thresholds or tool-specific branching in code.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pencheff.core.orchestrator.cache import OrchestratorCache
from pencheff.core.orchestrator.chain_planner import ChainPlan, ChainPlanner
from pencheff.core.orchestrator.fallback import FallbackResolver
from pencheff.core.orchestrator.param_optimizer import ParamOptimizer
from pencheff.core.orchestrator.policies import Policies, load_policies
from pencheff.core.orchestrator.result_normalizer import normalize
from pencheff.core.orchestrator.rng import deterministic_rng
from pencheff.core.orchestrator.selector import Selector, ToolCandidate
from pencheff.core.orchestrator.state_machine import (
    EngagementPhase,
    PHASE_ORDER,
    StateMachine,
    StateMachineContext,
)
from pencheff.core.orchestrator.throttle import Throttle
from pencheff.core.tool_runner import ToolResult, run_tool, tool_available


log = logging.getLogger("pencheff.orchestrator")


@dataclass
class EngagementResult:
    target: str
    target_profile: str
    profile: str
    intensity: str
    transitions: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)
    chains: list[ChainPlan] = field(default_factory=list)
    policy_versions: dict[str, int] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    cancelled: bool = False
    cancel_reason: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "profile": self.profile,
            "duration_s": round(self.finished_at - self.started_at, 2),
            "findings": len(self.findings),
            "chains": len(self.chains),
            "transitions": [
                {
                    "phase": t["phase"],
                    "skipped": t.get("skipped", False),
                    "actions": t.get("actions", []),
                    "findings_added": t.get("findings_added", 0),
                    "duration_ms": round(t.get("duration_ms", 0.0), 1),
                }
                for t in self.transitions
            ],
            "policy_versions": self.policy_versions,
        }


@dataclass
class _EngineContext(StateMachineContext):
    """Adds engine-internal helpers to the public context."""

    session_id: str = ""
    scope_hash: str = ""
    policies_versions: dict[str, int] = field(default_factory=dict)
    chains_planned: list[ChainPlan] = field(default_factory=list)


class Orchestrator:
    """Headline deterministic engagement runner."""

    def __init__(
        self,
        *,
        policies: Policies | None = None,
        cache: OrchestratorCache | None = None,
        throttle: Throttle | None = None,
        cache_dir: Path | str | None = None,
    ) -> None:
        self.policies = policies or load_policies()
        self.selector = Selector(self.policies)
        self.params = ParamOptimizer(self.policies)
        self.fallback = FallbackResolver(self.policies)
        self.chain_planner = ChainPlanner(self.policies)
        self.throttle = throttle or Throttle(self.policies)
        self.cache = cache or OrchestratorCache(cache_dir=cache_dir)

        self.machine = StateMachine()
        self._register_default_phases()

    # ─── public API ─────────────────────────────────────────────────────
    def run(
        self,
        target: str,
        *,
        target_profile: str = "web",
        intensity: str = "default",
        session_id: str = "ad-hoc",
        scope_hash: str = "",
    ) -> EngagementResult:
        """Synchronous wrapper around ``run_async``."""
        return asyncio.run(
            self.run_async(
                target,
                target_profile=target_profile,
                intensity=intensity,
                session_id=session_id,
                scope_hash=scope_hash,
            )
        )

    async def run_async(
        self,
        target: str,
        *,
        target_profile: str = "web",
        intensity: str = "default",
        session_id: str = "ad-hoc",
        scope_hash: str = "",
    ) -> EngagementResult:
        ctx = _EngineContext(
            target=target,
            target_profile=target_profile,
            intensity=intensity,
            session_id=session_id,
            scope_hash=scope_hash,
            policies_versions=self.policies.versions,
        )
        # State-machine ``run`` is sync today (one in-process loop per phase).
        # Async tool calls live inside the phase handlers.
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.machine.run, ctx)

        chains = self.chain_planner.plan(ctx.findings)
        result = EngagementResult(
            target=target,
            target_profile=target_profile,
            profile=target_profile,
            intensity=intensity,
            findings=list(ctx.findings),
            chains=list(chains),
            policy_versions=ctx.policies_versions,
            cancelled=ctx.cancelled,
            cancel_reason=ctx.cancel_reason,
            transitions=[
                {
                    "phase": t.phase.value,
                    "skipped": t.skipped,
                    "skip_reason": t.skip_reason,
                    "actions": list(t.actions),
                    "findings_added": t.findings_added,
                    "duration_ms": t.duration_ms,
                }
                for t in ctx.transitions
            ],
            finished_at=time.time(),
        )
        return result

    def register_phase(self, phase: EngagementPhase, handler) -> None:
        """Override a phase handler (workflows use this)."""
        self.machine.register(phase, handler)

    # ─── tool execution ─────────────────────────────────────────────────
    async def run_tool_with_fallback(
        self,
        *,
        primary_tool: str,
        target: str,
        objective: str = "vuln_scan",
        target_profile: str = "web",
        extra_args: list[str] | None = None,
        timeout: float = 60.0,
        scope_hash: str = "",
    ) -> tuple[str, ToolResult, list[Any]]:
        """Run a tool deterministically with cache + fallback + throttle.

        Returns (resolved_tool_name, ToolResult, normalized_findings).
        """
        chosen = self.fallback.resolve(primary_tool)
        if chosen is None:
            log.info("orchestrator: no available tool for %s", primary_tool)
            return (primary_tool, ToolResult("", "tool unavailable", -1), [])

        tier = self.intensity_to_tier(self._safe_intensity(target_profile))
        args = self.params.args_for(chosen, tier=tier)
        if extra_args:
            args = [*args, *extra_args]
        # Convention: tool argv is [tool, *args, target] — wrappers can
        # override by registering custom argv builders later.
        argv = [chosen, *args, target]

        cache_key = OrchestratorCache.make_key(
            tool=chosen, target=target, args=args, scope_hash=scope_hash,
        )
        cached = self.cache.get(cache_key)
        if cached is not None:
            log.debug("orchestrator: cache hit for %s/%s", chosen, target)
            return cached  # already normalized

        rng = deterministic_rng(target, chosen)
        await self.throttle.before_request_async(jitter_rng=rng)

        t0 = time.monotonic()
        result = await run_tool(argv, timeout=timeout)
        latency_ms = (time.monotonic() - t0) * 1000.0
        # Subprocess returncode is mapped to a synthetic HTTP status for the
        # throttle adapter — successes increase the rate, failures back off.
        synthetic_status = 200 if result.success else 500
        self.throttle.on_response(status=synthetic_status, latency_ms=latency_ms)

        findings = normalize(chosen, result.stdout, target, stderr=result.stderr)
        ttl = self._ttl_for(chosen, target_profile, objective)
        payload = (chosen, result, findings)
        self.cache.set(cache_key, payload, ttl=ttl)
        return payload

    # ─── helpers ────────────────────────────────────────────────────────
    @staticmethod
    def intensity_to_tier(intensity: str) -> str:
        if intensity == "quick":
            return "stealth"
        if intensity == "deep":
            return "aggressive"
        return "default"

    def _safe_intensity(self, _profile: str) -> str:
        return "default"

    def _ttl_for(self, tool: str, profile: str, objective: str) -> int:
        candidates = self.selector.candidates(profile, objective)
        for cand in candidates:
            if cand.tool == tool:
                return cand.ttl
        return 1800

    # ─── default phase handlers ─────────────────────────────────────────
    def _register_default_phases(self) -> None:
        self.machine.register(EngagementPhase.SCOPE, self._phase_scope)
        self.machine.register(EngagementPhase.RECON_PASSIVE, self._phase_recon_passive)
        self.machine.register(EngagementPhase.RECON_ACTIVE, self._phase_recon_active)
        self.machine.register(EngagementPhase.AUTH, self._phase_noop)
        self.machine.register(EngagementPhase.SURFACE_MAP, self._phase_noop)
        self.machine.register(EngagementPhase.VULN_PROBE, self._phase_noop)
        self.machine.register(EngagementPhase.EXPLOIT, self._phase_exploit)
        self.machine.register(EngagementPhase.POST_EX, self._phase_noop)
        self.machine.register(EngagementPhase.REPORT, self._phase_noop)

    def _phase_scope(self, _ctx: _EngineContext) -> dict[str, Any]:
        return {"actions": ["scope_validated"]}

    def _phase_recon_passive(self, ctx: _EngineContext) -> dict[str, Any]:
        actions: list[str] = []
        for cand in self.selector.candidates(ctx.target_profile, "discovery"):
            chosen = self.fallback.resolve(cand.tool)
            actions.append(f"select:{cand.tool}->{chosen or 'unavailable'}")
            if chosen is None:
                continue
            # Default phase handler is a no-op for actual tool execution; the
            # workflows in pencheff/workflows/ call ``run_tool_with_fallback``
            # explicitly. This keeps tests fast and offline.
        return {"actions": actions}

    def _phase_recon_active(self, ctx: _EngineContext) -> dict[str, Any]:
        return {"actions": ["recon_active_planned"]}

    def _phase_exploit(self, ctx: _EngineContext) -> dict[str, Any]:
        chains = self.chain_planner.plan(ctx.findings)
        ctx.chains_planned = chains
        return {"actions": [f"chain:{c.id}" for c in chains]}

    @staticmethod
    def _phase_noop(_ctx: _EngineContext) -> dict[str, Any]:
        return {"actions": []}
