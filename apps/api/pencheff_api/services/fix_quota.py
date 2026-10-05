"""Plan-tier + monthly-quota gating for LLM-backed fix proposals.

Every plan now gets a monthly allotment of LLM-backed fixes:

  * **free** — ``FIX_LIMITS["free"]`` fixes/month (served by the Instant model)
  * **pro**  — ``FIX_LIMITS["pro"]`` fixes/month (served by the Expert model)
  * **team / self_hosted / enterprise** — effectively unlimited

A "fix" is one LLM-backed proposal (SAST or DAST), counted **per org** over
the current calendar month (UTC). Hitting the cap raises ``QuotaExceeded``
with reason ``"monthly_cap"`` → HTTP 402 → upgrade prompt.

PAYG (pay-as-you-go overage) is retained but **dormant** (``PAYG_ENABLED``
is ``False``): the ``fix_llm_usage`` ledger, the cost helpers, and the
``payg_cost_usd`` column all stay in place so per-fix overage billing can be
switched back on later without a rebuild. While dormant, ``preflight`` never
returns ``free=False`` — it raises ``monthly_cap`` at the cap instead.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import FixLlmUsage, Org, Subscription

FixKind = Literal["sast", "dast"]

# Monthly LLM-fix allotment per plan. Free gets a taste; Pro is the headline
# tier; team/self_hosted/enterprise are effectively uncapped. Retune here.
FIX_LIMITS: dict[str, int] = {
    "free": 3,
    "pro": 40,
    "team": 500,
    "self_hosted": 100000,
    "enterprise": 100000,
}

# Pay-as-you-go overage beyond the monthly cap. Implemented but disabled —
# flip to True (and set real per-1k prices in config) to bill per fix past
# the included allotment instead of hard-stopping.
PAYG_ENABLED = False

# Shown to the user when the monthly AI allotment is spent and we fall back
# to the deterministic (non-LLM) approach instead of blocking.
DETERMINISTIC_FALLBACK_NOTICE = (
    "AI usage limit completed, proceeding with the deterministic approach."
)


def cap_for_plan(plan: str) -> int:
    return FIX_LIMITS.get(plan, FIX_LIMITS["free"])


class QuotaExceeded(Exception):
    """Raised when a caller asks for an LLM fix but the monthly cap is spent.

    ``reason`` is ``"monthly_cap"`` (cap reached) — surfaced on the API so
    the UI can render the right upgrade / "resets next month" message.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass
class QuotaSnapshot:
    """What the UI quota strip needs. All counts reflect the current month."""
    plan: str
    has_fix_access: bool
    monthly_cap: int
    monthly_used: int
    monthly_remaining: int
    period_resets_at: str  # ISO-8601 UTC timestamp of the next monthly reset
    beta: bool  # open-beta switch on → caps not enforced (strip shows unlimited)


async def _plan_for(db: AsyncSession, org_id: str) -> str:
    """Resolve the org's effective plan, preferring an active subscription
    over the column default on ``orgs``.
    """
    sub = (await db.execute(
        select(Subscription.plan, Subscription.status)
        .where(Subscription.org_id == org_id)
        .order_by(Subscription.created_at.desc())
        .limit(1)
    )).first()
    if sub and sub.status in ("active", "trialing", "past_due"):
        return sub.plan or "free"
    plan = (await db.execute(
        select(Org.plan).where(Org.id == org_id)
    )).scalar_one_or_none()
    return plan or "free"


async def plan_for(db: AsyncSession, org_id: str) -> str:
    """Public wrapper around :func:`_plan_for` for callers that need the
    org's effective plan (e.g. model routing in fix_proposer)."""
    return await _plan_for(db, org_id)


def _period_start(now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _next_period_start(now: datetime | None = None) -> datetime:
    start = _period_start(now)
    if start.month == 12:
        return start.replace(year=start.year + 1, month=1)
    return start.replace(month=start.month + 1)


async def _fixes_used_in_period(
    db: AsyncSession, org_id: str, period_start: datetime
) -> int:
    """Count every LLM-backed fix (SAST + DAST) the org has drawn this month."""
    return (await db.execute(
        select(func.count(FixLlmUsage.id)).where(
            FixLlmUsage.org_id == org_id,
            FixLlmUsage.created_at >= period_start,
        )
    )).scalar_one() or 0


async def _payg_balance(
    db: AsyncSession, org_id: str, period_start: datetime
) -> float:
    """Dormant: sum of PAYG charges this period. Kept for the day overage
    billing is re-enabled (``PAYG_ENABLED``)."""
    return float((await db.execute(
        select(func.coalesce(func.sum(FixLlmUsage.payg_cost_usd), 0.0))
        .where(
            FixLlmUsage.org_id == org_id,
            FixLlmUsage.created_at >= period_start,
        )
    )).scalar_one() or 0.0)


async def snapshot(
    db: AsyncSession, org_id: str, *, scan_id: str | None = None,
) -> QuotaSnapshot:
    """Build a read-only snapshot of the org's current fix-LLM allowance.

    ``scan_id`` is accepted for call-site compatibility but no longer
    affects the count — quota is per org per month, not per scan.
    """
    plan = await _plan_for(db, org_id)
    cap = cap_for_plan(plan)
    used = await _fixes_used_in_period(db, org_id, _period_start())
    return QuotaSnapshot(
        plan=plan,
        has_fix_access=cap > 0,
        monthly_cap=cap,
        monthly_used=used,
        monthly_remaining=max(0, cap - used),
        period_resets_at=_next_period_start().isoformat(),
        beta=get_settings().beta,
    )


@dataclass
class QuotaCharge:
    """Result of the pre-flight check.

    ``allow_llm`` is the gate the proposer reads: True → call the LLM; False →
    the org is over its monthly allotment, so degrade to the deterministic
    approach (preflight never raises for this). ``free`` is the PAYG-cost flag
    (always True while PAYG is dormant — no per-call billing)."""
    free: bool
    allow_llm: bool
    estimated_cost_usd: float
    reason: str  # "beta" | "free_quota" | "monthly_cap" | "payg"


async def preflight(
    db: AsyncSession,
    org_id: str,
    *,
    kind: FixKind,
    scan_id: str | None = None,
    estimated_input_tokens: int = 1500,
    estimated_output_tokens: int = 800,
) -> QuotaCharge:
    """Decide whether the next LLM fix is inside the monthly allotment.

    Never raises for the cap: when the org has spent its monthly allotment
    (and PAYG is disabled) it returns ``allow_llm=False`` so the caller falls
    back to the deterministic approach. ``kind`` / ``scan_id`` are kept for
    call-site compatibility and ledger attribution; the cap itself is a single
    per-org monthly counter across both fix kinds. Beta bypasses the cap.
    """
    from .credits import ai_credit_ok, is_credit_metered
    if not await ai_credit_ok(db, org_id):
        return QuotaCharge(free=True, allow_llm=False, estimated_cost_usd=0.0, reason="insufficient_credits")

    if get_settings().beta:
        return QuotaCharge(free=True, allow_llm=True, estimated_cost_usd=0.0, reason="beta")

    plan = await _plan_for(db, org_id)
    # Credit-metered plans (pro/team) are bounded by their credit balance
    # (checked above), not by a fix-count cap.
    if is_credit_metered(plan):
        return QuotaCharge(free=True, allow_llm=True, estimated_cost_usd=0.0, reason="credits")
    cap = cap_for_plan(plan)
    used = await _fixes_used_in_period(db, org_id, _period_start())

    if used < cap:
        return QuotaCharge(free=True, allow_llm=True, estimated_cost_usd=0.0, reason="free_quota")

    if PAYG_ENABLED:
        estimated = cost_for_call(estimated_input_tokens, estimated_output_tokens)
        return QuotaCharge(free=False, allow_llm=True, estimated_cost_usd=estimated, reason="payg")

    # Over the monthly allotment — degrade to deterministic, do not block.
    return QuotaCharge(free=True, allow_llm=False, estimated_cost_usd=0.0, reason="monthly_cap")


def cost_for_call(input_tokens: int, output_tokens: int) -> float:
    """Dormant PAYG helper — indicative cost of one call at configured prices."""
    s = get_settings()
    return (
        (input_tokens / 1000.0) * s.fix_llm_price_input_per_1k_usd
        + (output_tokens / 1000.0) * s.fix_llm_price_output_per_1k_usd
    )


async def record_usage(
    db: AsyncSession,
    *,
    org_id: str,
    scan_id: str | None,
    proposal_id: str | None,
    kind: FixKind,
    model: str,
    input_tokens: int,
    output_tokens: int,
    free: bool,
) -> FixLlmUsage:
    """Append one row to the ledger after a successful fix. Every row counts
    against the monthly cap (see :func:`_fixes_used_in_period`). Caller commits."""
    cost = 0.0 if free else cost_for_call(input_tokens, output_tokens)
    row = FixLlmUsage(
        org_id=org_id, scan_id=scan_id, proposal_id=proposal_id,
        kind=kind, model=model,
        input_tokens=input_tokens, output_tokens=output_tokens,
        free_quota_consumed=1 if free else 0,
        payg_cost_usd=cost,
    )
    db.add(row)
    from .credits import debit_credits
    try:
        await debit_credits(db, org_id, input_tokens=input_tokens,
                            output_tokens=output_tokens, source="fix_proposal", ref=proposal_id)
    except Exception:
        pass
    await db.flush()
    return row
