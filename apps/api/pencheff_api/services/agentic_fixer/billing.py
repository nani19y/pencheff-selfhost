"""Plan-tier limits + concurrency accounting for agentic runs.

One pre-flight check gates every new agentic run:

* **Concurrency cap.** Each plan tier limits how many runs can be
  in-flight (queued or running) at once. A free-plan workspace
  attempting a second concurrent run gets 429.

Plan tier limits are defined as module constants. Operators with
contracted enterprise customers override via the Org's ``plan``
column being set to ``"enterprise"``.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db.models import AgenticFixRun

log = logging.getLogger("pencheff.agentic_fixer.billing")


@dataclass(frozen=True)
class PlanTierLimits:
    """Per-tier limits. ``concurrent_runs`` is the hard cap;
    ``max_iterations`` overrides the global default in config
    (lower of the two wins).
    """

    name: str
    concurrent_runs: int
    max_iterations: int


# Tier table. Constants — adjust here when pricing changes.
PLAN_TIERS: dict[str, PlanTierLimits] = {
    "free": PlanTierLimits(
        name="free",
        concurrent_runs=5,
        max_iterations=10,
    ),
    "pro": PlanTierLimits(
        name="pro",
        concurrent_runs=3,
        max_iterations=30,
    ),
    "team": PlanTierLimits(
        name="team",
        concurrent_runs=10,
        max_iterations=50,
    ),
    "enterprise": PlanTierLimits(
        name="enterprise",
        concurrent_runs=50,
        max_iterations=100,
    ),
}


def limits_for_plan(plan: str) -> PlanTierLimits:
    """Resolve plan name → limits. Unknown plan strings default to
    ``free`` (most restrictive) so an org with a typo'd plan can't
    accidentally get unlimited concurrency.
    """
    return PLAN_TIERS.get(plan, PLAN_TIERS["free"])


@dataclass
class BillingCheck:
    """Result of a pre-flight billing check."""

    allowed: bool
    code: str             # "ok" | "concurrency_exceeded" | "disabled"
    message: str
    plan: str
    in_flight_runs: int
    max_concurrent_runs: int


async def get_in_flight_run_count(
    session: AsyncSession, workspace_id: str,
) -> int:
    """Count runs in non-terminal states (``queued`` / ``cloning`` /
    ``running`` / ``committing`` / ``pushing``) for this workspace.
    """
    non_terminal = ("queued", "cloning", "running", "committing", "pushing")
    result = await session.execute(
        select(func.count(AgenticFixRun.id))
        .where(
            AgenticFixRun.workspace_id == workspace_id,
            AgenticFixRun.status.in_(non_terminal),
        )
    )
    return int(result.scalar() or 0)


async def check_can_start(
    *,
    session: AsyncSession,
    workspace_id: str,
    plan: str,
) -> BillingCheck:
    """Pre-flight: would starting a new run exceed the concurrency cap?

    Credit-metered plans (pro/team) have NO concurrency cap — the credit
    balance is the only limit (enforced separately by the caller's
    ``ai_credit_ok`` check). ``max_concurrent_runs=-1`` signals "unlimited"
    to the UI. Non-metered plans (free, …) keep their plan cap.
    """
    # ponytail: CE is credit-free (single-tenant) — no metered plans; every
    # plan keeps its concurrency cap.
    limits = limits_for_plan(plan)
    in_flight = await get_in_flight_run_count(session, workspace_id)

    if in_flight >= limits.concurrent_runs:
        return BillingCheck(
            allowed=False,
            code="concurrency_exceeded",
            message=(
                f"Concurrency limit reached: {in_flight} run"
                f"{'s' if in_flight != 1 else ''} already in-flight "
                f"(max {limits.concurrent_runs} on the {limits.name} plan). "
                "Wait for an existing run to finish or cancel it."
            ),
            plan=limits.name,
            in_flight_runs=in_flight,
            max_concurrent_runs=limits.concurrent_runs,
        )

    return BillingCheck(
        allowed=True, code="ok", message="",
        plan=limits.name,
        in_flight_runs=in_flight,
        max_concurrent_runs=limits.concurrent_runs,
    )
