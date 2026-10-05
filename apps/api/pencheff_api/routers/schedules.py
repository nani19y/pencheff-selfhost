"""Scheduled scans — cron-based recurring scans per target."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, get_current_user, require_scope
from ..db.base import get_session
from ..db.models import ScanSchedule, Target, User, Workspace
from ..services.scheduler import compute_next_run

router = APIRouter(prefix="/schedules", tags=["schedules"])


class ScheduleCreate(BaseModel):
    target_id: str
    name: str = Field(..., min_length=1, max_length=200)
    cron_expression: str = Field(..., description="Standard cron expression (5 fields)")
    # IANA timezone the cron is interpreted in. FE passes
    # ``Intl.DateTimeFormat().resolvedOptions().timeZone``. Defaults to UTC
    # for back-compat — but every fresh schedule from the FE should set this
    # explicitly to match the operator's local cron-display assumption.
    timezone: str = Field(default="UTC", min_length=1, max_length=64)
    profile: str = "standard"
    policy_yaml: str | None = None
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    name: str | None = None
    cron_expression: str | None = None
    timezone: str | None = None
    profile: str | None = None
    policy_yaml: str | None = None
    enabled: bool | None = None


class ScheduleOut(BaseModel):
    id: str
    target_id: str
    name: str
    cron_expression: str
    timezone: str = "UTC"
    profile: str
    policy_yaml: str | None
    enabled: bool
    last_run_at: datetime | None
    next_run_at: datetime | None
    created_at: datetime


def _to_out(s: ScanSchedule) -> ScheduleOut:
    return ScheduleOut(
        id=s.id, target_id=s.target_id, name=s.name,
        cron_expression=s.cron_expression,
        timezone=getattr(s, "timezone", None) or "UTC",
        profile=s.profile,
        policy_yaml=s.policy_yaml, enabled=s.enabled,
        last_run_at=s.last_run_at, next_run_at=s.next_run_at,
        created_at=s.created_at,
    )


@router.post(
    "",
    response_model=ScheduleOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("schedules:write"))],
)
async def create_schedule(
    body: ScheduleCreate,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ScheduleOut:
    t = (await session.execute(
        select(Target).where(Target.id == body.target_id, Target.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    # Repo-mirror targets schedule via /repos/{id}/scan, not here.
    # LLM targets are explicitly allowed — the kind-aware scan_runner
    # routes them to the LLM red-team pipeline at dispatch time.
    if t.kind == "repo" or t.repository_id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Repository targets are scheduled separately at /repos/{id}/scan.",
        )
    if t.kind == "llm" and not t.llm_config:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "LLM target is missing llm_config; complete the target before scheduling.",
        )
    s = ScanSchedule(
        org_id=workspace.org_id, workspace_id=workspace.id,
        target_id=body.target_id, owner_user_id=user.id,
        name=body.name, cron_expression=body.cron_expression,
        timezone=body.timezone,
        profile=body.profile, policy_yaml=body.policy_yaml, enabled=body.enabled,
        next_run_at=compute_next_run(body.cron_expression, tz=body.timezone),
    )
    session.add(s)
    await session.commit()
    await session.refresh(s)
    return _to_out(s)


@router.get(
    "",
    response_model=list[ScheduleOut],
    dependencies=[Depends(require_scope("schedules:read"))],
)
async def list_schedules(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[ScheduleOut]:
    rows = (await session.execute(
        select(ScanSchedule).where(ScanSchedule.workspace_id == workspace.id)
        .order_by(ScanSchedule.created_at.desc())
    )).scalars().all()
    return [_to_out(s) for s in rows]


@router.get(
    "/{schedule_id}",
    response_model=ScheduleOut,
    dependencies=[Depends(require_scope("schedules:read"))],
)
async def get_schedule(
    schedule_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ScheduleOut:
    s = (await session.execute(
        select(ScanSchedule).where(
            ScanSchedule.id == schedule_id, ScanSchedule.workspace_id == workspace.id
        )
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    return _to_out(s)


@router.patch(
    "/{schedule_id}",
    response_model=ScheduleOut,
    dependencies=[Depends(require_scope("schedules:write"))],
)
async def update_schedule(
    schedule_id: str,
    body: ScheduleUpdate,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ScheduleOut:
    s = (await session.execute(
        select(ScanSchedule).where(
            ScanSchedule.id == schedule_id, ScanSchedule.workspace_id == workspace.id
        )
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    data = body.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(s, k, v)
    # Recompute next_run_at when EITHER cron OR timezone changes — both
    # affect when the schedule fires.
    if body.cron_expression or body.timezone:
        s.next_run_at = compute_next_run(
            s.cron_expression,
            tz=getattr(s, "timezone", None) or "UTC",
        )
    await session.commit()
    await session.refresh(s)
    return _to_out(s)


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("schedules:write"))],
)
async def delete_schedule(
    schedule_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    s = (await session.execute(
        select(ScanSchedule).where(
            ScanSchedule.id == schedule_id, ScanSchedule.workspace_id == workspace.id
        )
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    await session.delete(s)
    await session.commit()
