"""Single source of truth for whether an org can use AI features.

The deterministic Pencheff methodology — recon, scanning modules, evidence,
remediation, reports, compliance mapping, RBAC, recheck — is free for every
plan. Pro / Team / self_hosted unlock the LLM-backed features: per-finding
AI explanations, false-positive triage, audit-style grade attestation, and
the LLM agent-driven scan stage.

Operators can also unlock AI features for **all plans** (including Free) by
setting ``AI_FREE_TIER_ENABLED=true`` in the environment — useful for
self-hosted deployments and for evaluators who want to try the AI surfaces
without plumbing a paid tier.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import Org

AI_PLANS = frozenset({"pro", "team", "self_hosted"})


def plan_has_ai(plan: str | None) -> bool:
    return (plan or "free") in AI_PLANS


async def org_has_ai(session: AsyncSession, org_id: str) -> bool:
    """True when the org's plan allows AI features OR the operator has
    flipped the global free-tier override."""
    if get_settings().ai_free_tier_enabled:
        return True
    plan = (
        await session.execute(select(Org.plan).where(Org.id == org_id))
    ).scalar_one_or_none()
    return plan_has_ai(plan)
