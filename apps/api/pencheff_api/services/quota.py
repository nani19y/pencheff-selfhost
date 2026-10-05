from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import Org, OrgInvite, OrgMember, Scan, Target, Workspace

# Org/workspace/seat/target capacity stays generous. ``scans_per_month_per_org``
# is now effectively unlimited for every tier: free/pro/team are credit-metered
# (AI is bounded by the credit balance, not a scan count), and scans are never
# hard-blocked regardless. The cap survives only as a dead ceiling for any
# hypothetical non-metered tier. Scans are counted per ORG per calendar month.
# ``targets_per_org`` caps registered targets across ALL workspaces in an org
# (Free 5, Pro 100, larger tiers effectively unlimited) — a real ceiling a Free
# user can't sidestep by spinning up extra workspaces. Enforced live at target
# creation (check_target_quota); existing targets over cap are never removed.
PLAN_LIMITS: dict[str, dict[str, int]] = {
    "free":        {"orgs": 9, "workspaces": 999, "seats": 999, "targets_per_org": 5,      "scans_per_month_per_org": 100000},
    "pro":         {"orgs": 9, "workspaces": 999, "seats": 999, "targets_per_org": 100,    "scans_per_month_per_org": 20},
    "team":        {"orgs": 9, "workspaces": 999, "seats": 999, "targets_per_org": 100000, "scans_per_month_per_org": 1000},
    "self_hosted": {"orgs": 9, "workspaces": 999, "seats": 999, "targets_per_org": 100000, "scans_per_month_per_org": 100000},
}


def _limits_for_plan(plan: str) -> dict[str, int]:
    return PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])


async def _plan(session: AsyncSession, org_id: str) -> str:
    plan = (await session.execute(select(Org.plan).where(Org.id == org_id))).scalar_one_or_none()
    return plan or "free"


async def check_org_quota(session: AsyncSession, user_id: str) -> None:
    """Block a user from owning more orgs than their highest-tier plan allows.

    The user's plan is the maximum plan across orgs they already own; a
    brand-new user with no orgs is treated as ``free``.
    """
    owned = (
        await session.execute(
            select(Org.plan).join(OrgMember, OrgMember.org_id == Org.id).where(
                OrgMember.user_id == user_id, OrgMember.role == "owner"
            )
        )
    ).scalars().all()
    # No plan beats "team"/"self_hosted"; ranked numerically.
    rank = {"free": 0, "pro": 1, "team": 2, "self_hosted": 3}
    best_plan = max(owned, key=lambda p: rank.get(p, 0)) if owned else "free"
    limit = _limits_for_plan(best_plan)["orgs"]
    if len(owned) >= limit:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"org limit {limit} reached for plan '{best_plan}' — upgrade for more",
        )


async def check_workspace_quota(session: AsyncSession, org_id: str) -> None:
    plan = await _plan(session, org_id)
    limit = _limits_for_plan(plan)["workspaces"]
    count = (
        await session.execute(
            select(func.count(Workspace.id)).where(Workspace.org_id == org_id)
        )
    ).scalar_one()
    if count >= limit:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"workspace limit {limit} reached for plan '{plan}' — upgrade for more",
        )


async def check_seat_quota(session: AsyncSession, org_id: str) -> None:
    """Members + pending invites count against the plan's seat cap."""
    plan = await _plan(session, org_id)
    limit = _limits_for_plan(plan)["seats"]
    members = (
        await session.execute(
            select(func.count(OrgMember.id)).where(OrgMember.org_id == org_id)
        )
    ).scalar_one()
    pending = (
        await session.execute(
            select(func.count(OrgInvite.id)).where(
                OrgInvite.org_id == org_id, OrgInvite.accepted_at.is_(None)
            )
        )
    ).scalar_one()
    if members + pending >= limit:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"seat limit {limit} reached for plan '{plan}' — upgrade for more",
        )


async def check_target_quota(session: AsyncSession, org_id: str) -> None:
    """Block registering more targets than the plan allows, counted across the
    whole org (all workspaces)."""
    plan = await _plan(session, org_id)
    limit = _limits_for_plan(plan)["targets_per_org"]
    count = (
        await session.execute(
            select(func.count(Target.id)).where(Target.org_id == org_id)
        )
    ).scalar_one()
    if count >= limit:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"target limit {limit} reached for plan '{plan}' — upgrade for more",
        )


def _month_start() -> datetime:
    """Start of the current calendar month (UTC). Quotas reset here."""
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _next_month_start() -> datetime:
    """Start of the next calendar month (UTC) — when the AI quota refreshes."""
    start = _month_start()
    if start.month == 12:
        return start.replace(year=start.year + 1, month=1)
    return start.replace(month=start.month + 1)


async def scan_ai_allowed(session: AsyncSession, org_id: str) -> bool:
    """Whether this org's scans may still use AI this month.

    Scans are never hard-blocked: once the org is over its monthly allotment
    the scan still runs, but in deterministic-only mode (no AI triage / agent).
    Counted per org (not per workspace) on the calendar-month boundary. Always
    True while the open-beta switch is on.

    Called from the scan runner, where the current scan is already persisted —
    so ``used`` includes it: the first ``cap`` scans of the month keep AI, the
    rest degrade to deterministic.
    """
    # Credit gate is authoritative even during beta: a credit-metered org that
    # is out of credit degrades to deterministic regardless of the beta switch.
    from .credits import ai_credit_ok, is_credit_metered
    if not await ai_credit_ok(session, org_id):
        return False
    if get_settings().beta:
        return True
    plan = await _plan(session, org_id)
    # Credit-metered plans (pro/team) are bounded by their credit balance —
    # already checked by ai_credit_ok above — not by a scan-count cap.
    if is_credit_metered(plan):
        return True
    limit = _limits_for_plan(plan)["scans_per_month_per_org"]
    used = (
        await session.execute(
            select(func.count(Scan.id)).where(
                Scan.org_id == org_id, Scan.created_at >= _month_start()
            )
        )
    ).scalar_one()
    return used <= limit


async def scan_ai_snapshot(session: AsyncSession, org_id: str) -> dict:
    """Pre-flight view of an org's scan-AI allowance, for the commission UI.

    Unlike :func:`scan_ai_allowed` — which runs inside the scan runner where
    the current scan is already counted — this is called *before* a scan is
    created. A new scan would become the ``used + 1``-th, so AI is available
    for it iff ``used < limit`` (kept consistent with the runner's
    ``used <= limit`` check that counts the in-flight scan). ``beta`` always
    grants AI; ``has_ai_access`` reflects the plan/operator gate from
    :func:`ai_gate.org_has_ai`.
    """
    from .ai_gate import org_has_ai
    from .credits import ai_credit_ok, is_credit_metered

    beta = get_settings().beta
    plan = await _plan(session, org_id)
    limit = _limits_for_plan(plan)["scans_per_month_per_org"]
    used = (
        await session.execute(
            select(func.count(Scan.id)).where(
                Scan.org_id == org_id, Scan.created_at >= _month_start()
            )
        )
    ).scalar_one()
    has_ai_access = await org_has_ai(session, org_id)

    # Credit-metered plans (pro/team) are gated by credit BALANCE, not the
    # scan-count cap — mirror scan_ai_allowed. The count cap only bounds the
    # non-metered tiers (free). Applying the count cap to a metered plan wrongly
    # showed "AI usage limit reached (used/cap)" in the commission modal even
    # with credits available.
    metered = is_credit_metered(plan)
    if metered:
        credit_ok = await ai_credit_ok(session, org_id)
        quota_exhausted = (not beta) and not credit_ok
        # Count cap does not apply — report it as unbounded for the UI.
        cap_out: int | None = None
        remaining_out: int | None = None
    else:
        quota_exhausted = (not beta) and used >= limit
        cap_out = limit
        remaining_out = max(0, limit - used)
    return {
        "plan": plan,
        "monthly_cap": cap_out,
        "monthly_used": used,
        "monthly_remaining": remaining_out,
        "credit_metered": metered,
        "has_ai_access": has_ai_access,
        "quota_exhausted": quota_exhausted,
        "ai_available": has_ai_access and not quota_exhausted,
        "period_resets_at": _next_month_start().isoformat(),
        "beta": beta,
    }
