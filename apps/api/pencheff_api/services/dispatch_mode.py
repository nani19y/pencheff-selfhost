"""Resolve which scan dispatch mode an org should get.

Three modes (in order of decreasing capability):

  ``deterministic_then_agent`` — populator runs first, then the autonomous
    engine operates on the populated PentestSession. Highest-fidelity but
    longest scans.

  ``agent_only`` — engine runs first, falls back to the deterministic
    populator if the engine errors / the upstream backend is unreachable.

  ``deterministic_only`` — engine disabled (no API key configured, kind
    not agent-capable, or org-level kill switch enabled); only the
    deterministic populator runs.

Selection rules (after feature 001-multi-target-scan-pipelines):

  0. If ``Org.force_deterministic_only`` is true → ``deterministic_only``.  [NEW]
  1. If ``target_kind`` is not in the known set → ``deterministic_only``.   [NEW]
  2. If NEITHER ``AGENT_FALLBACK_LLM_API_KEY`` (new primary) NOR
     ``AGENT_LLM_API_KEY`` (secondary fallback) is configured →
     ``deterministic_only``.                                                [CHANGED]
  3. If ``AGENT_DISPATCH_BETA_OVERRIDE`` is true (beta default), every
     scan gets ``deterministic_then_agent`` regardless of plan.
  4. Pro / Team / self_hosted orgs always get ``deterministic_then_agent``.
  5. Free-plan orgs get ``deterministic_then_agent`` for the first
     ``FREE_PLAN_OPTION_3_QUOTA`` scans (counter on ``Org.option_3_scans_used``)
     and ``agent_only`` thereafter.

The legacy 2-arg signature ``resolve_dispatch_mode(session, org_id)`` is
preserved for backwards compatibility — when called without a ``target_kind``
arg, the kind-capability check is skipped (used by call sites that haven't
been migrated yet).
"""
from __future__ import annotations

from typing import Literal

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import Org

DispatchMode = Literal[
    "deterministic_then_agent",
    "agent_only",
    "deterministic_only",
]

_PAID_PLANS = frozenset({"pro", "team", "self_hosted"})

# All known Target.kind values after feature 001. Anything outside this set
# routes to deterministic_only (defensive — protects against typo'd kinds).
_KIND_SUPPORTS_AGENT: frozenset[str] = frozenset({
    # Legacy kinds.
    "url", "repo", "llm",
    # DAST cluster.
    "web_app", "rest_api", "graphql", "websocket", "grpc",
    # Artifact cluster.
    "source_code", "container_image", "iac", "package_registry", "sbom",
    # Hybrid cluster.
    "cicd_pipeline", "k8s_cluster",
})


def _has_any_agent_key(settings) -> bool:
    """True when at least one LLM credential family is configured.

    Prefers ``agent_fallback_llm_api_key`` (new primary per feature 001's
    AGENT_FALLBACK_LLM_* swap) but accepts the legacy ``agent_llm_api_key``
    as fallback. The actual primary/fallback selection inside the agent loop
    is handled in ``services/agent_swarm/agent_loop.py``.
    """
    return bool(
        getattr(settings, "agent_fallback_llm_api_key", "")
        or getattr(settings, "agent_llm_api_key", "")
    )


async def resolve_dispatch_mode(
    session: AsyncSession,
    org_id: str,
    target_kind: str | None = None,
) -> DispatchMode:
    """Return the dispatch mode that should drive this org's next scan.

    Args:
        session: AsyncSession for the Org lookup.
        org_id: Org whose dispatch policy to resolve.
        target_kind: Optional Target.kind value. When provided, enables the
            kind-capability check. When omitted (legacy call sites), the
            kind check is skipped.
    """
    settings = get_settings()

    # NEW (feature 001): org-level kill switch precedes everything.
    if target_kind is not None:
        org = (
            await session.execute(
                select(Org.plan, Org.option_3_scans_used, Org.force_deterministic_only)
                .where(Org.id == org_id)
            )
        ).one_or_none()
        if org is not None and org.force_deterministic_only:
            return "deterministic_only"
        # NEW: defensive kind-capability check.
        if target_kind not in _KIND_SUPPORTS_AGENT:
            return "deterministic_only"
        plan = org.plan if org else None
        used = org.option_3_scans_used if org else None
    else:
        # Legacy path: fetch only the columns the existing logic needs.
        row = (
            await session.execute(
                select(Org.plan, Org.option_3_scans_used).where(Org.id == org_id)
            )
        ).one_or_none()
        if row is None:
            plan, used = None, None
        else:
            plan, used = row

    # CHANGED (feature 001): prefer AGENT_FALLBACK_LLM_* (new primary) but
    # accept legacy AGENT_LLM_* — neither configured → deterministic_only.
    if not _has_any_agent_key(settings):
        return "deterministic_only"

    if settings.agent_dispatch_beta_override:
        return "deterministic_then_agent"

    if plan is None and used is None:
        # No Org row found — defensive default.
        return "agent_only"

    if (plan or "free") in _PAID_PLANS:
        return "deterministic_then_agent"

    if (used or 0) < settings.free_plan_option_3_quota:
        return "deterministic_then_agent"

    return "agent_only"


async def increment_option_3_counter(session: AsyncSession, org_id: str) -> None:
    """Bump the per-org Option 3 consumption counter by 1."""
    await session.execute(
        update(Org)
        .where(Org.id == org_id)
        .values(option_3_scans_used=Org.option_3_scans_used + 1)
    )


__all__ = ["DispatchMode", "resolve_dispatch_mode", "increment_option_3_counter"]
