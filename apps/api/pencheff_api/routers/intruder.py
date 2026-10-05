"""Intruder attacks — backend orchestration via Celery.

Each attack is a request template with `§marker§` payload positions, a
payload set, and an attack_type. Sniper substitutes one position at a
time; cluster-bomb does the cartesian product. Results are streamed to
``intruder_results`` and surfaced via SSE.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, get_current_user, require_scope
from ..db.base import get_session
from ..db.models import (
    Engagement,
    IntruderAttack,
    IntruderPayloadSet,
    IntruderResult,
    User,
    Workspace,
)
from ..services.worker_lifecycle import ensure_worker_started_or_503

router = APIRouter(prefix="/engagements/{engagement_id}/intruder", tags=["intruder"])


class PayloadSetCreate(BaseModel):
    name: str
    kind: str = "wordlist"
    entries: list[str]


class PayloadSetOut(BaseModel):
    id: str
    name: str
    kind: str
    entries_count: int


class AttackCreate(BaseModel):
    name: str = "Attack"
    request_template: dict[str, Any]
    payload_set_id: str
    attack_type: str = "sniper"
    concurrency: int = 5
    rate_limit: int = 20


class AttackOut(BaseModel):
    id: str
    name: str
    attack_type: str
    status: str
    progress_pct: int
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class ResultOut(BaseModel):
    id: str
    payload: str
    response_status: int | None
    response_length: int | None
    response_time_ms: int | None
    grep_match: list[str] | None
    diff_score: float | None


def _to_attack(a: IntruderAttack) -> AttackOut:
    return AttackOut(
        id=a.id, name=a.name, attack_type=a.attack_type, status=a.status,
        progress_pct=a.progress_pct, started_at=a.started_at,
        finished_at=a.finished_at, created_at=a.created_at,
    )


async def _engagement(eid: str, ws: Workspace, s: AsyncSession) -> Engagement:
    e = await s.get(Engagement, eid)
    if e is None or e.workspace_id != ws.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    return e


# ─── Payload sets ───
@router.post(
    "/payload-sets",
    response_model=PayloadSetOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("intruder:write"))],
)
async def create_payload_set(
    engagement_id: str,
    body: PayloadSetCreate,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> PayloadSetOut:
    await _engagement(engagement_id, workspace, session)
    ps = IntruderPayloadSet(
        workspace_id=workspace.id, name=body.name, kind=body.kind,
        entries=body.entries, entries_count=len(body.entries),
    )
    session.add(ps)
    await session.commit()
    await session.refresh(ps)
    return PayloadSetOut(id=ps.id, name=ps.name, kind=ps.kind, entries_count=ps.entries_count)


@router.get(
    "/payload-sets",
    response_model=list[PayloadSetOut],
    dependencies=[Depends(require_scope("intruder:read"))],
)
async def list_payload_sets(
    engagement_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[PayloadSetOut]:
    await _engagement(engagement_id, workspace, session)
    rows = (await session.execute(
        select(IntruderPayloadSet).where(IntruderPayloadSet.workspace_id == workspace.id)
    )).scalars().all()
    return [PayloadSetOut(id=p.id, name=p.name, kind=p.kind, entries_count=p.entries_count) for p in rows]


# ─── Attacks ───
@router.post(
    "/attacks",
    response_model=AttackOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("intruder:write"))],
)
async def create_attack(
    engagement_id: str,
    body: AttackCreate,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> AttackOut:
    e = await _engagement(engagement_id, workspace, session)
    await ensure_worker_started_or_503()

    a = IntruderAttack(
        engagement_id=e.id, workspace_id=workspace.id, name=body.name,
        request_template=body.request_template, payload_set_id=body.payload_set_id,
        attack_type=body.attack_type, concurrency=body.concurrency,
        rate_limit=body.rate_limit, created_by_user_id=user.id,
    )
    session.add(a)
    await session.commit()
    await session.refresh(a)
    # Lazy-import to avoid circular import at module load.
    from ..tasks.intruder_task import run_intruder_attack
    run_intruder_attack.delay(a.id)
    return _to_attack(a)


@router.get(
    "/attacks",
    response_model=list[AttackOut],
    dependencies=[Depends(require_scope("intruder:read"))],
)
async def list_attacks(
    engagement_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[AttackOut]:
    e = await _engagement(engagement_id, workspace, session)
    rows = (await session.execute(
        select(IntruderAttack)
        .where(IntruderAttack.engagement_id == e.id)
        .order_by(desc(IntruderAttack.created_at))
    )).scalars().all()
    return [_to_attack(a) for a in rows]


@router.get(
    "/attacks/{attack_id}",
    response_model=AttackOut,
    dependencies=[Depends(require_scope("intruder:read"))],
)
async def get_attack(
    engagement_id: str,
    attack_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> AttackOut:
    await _engagement(engagement_id, workspace, session)
    a = await session.get(IntruderAttack, attack_id)
    if a is None or a.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "attack not found")
    return _to_attack(a)


@router.get(
    "/attacks/{attack_id}/results",
    response_model=list[ResultOut],
    dependencies=[Depends(require_scope("intruder:read"))],
)
async def list_results(
    engagement_id: str,
    attack_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
    limit: int = 500,
) -> list[ResultOut]:
    await _engagement(engagement_id, workspace, session)
    rows = (await session.execute(
        select(IntruderResult)
        .where(IntruderResult.attack_id == attack_id)
        .order_by(desc(IntruderResult.created_at))
        .limit(limit)
    )).scalars().all()
    return [
        ResultOut(
            id=r.id, payload=r.payload, response_status=r.response_status,
            response_length=r.response_length, response_time_ms=r.response_time_ms,
            grep_match=r.grep_match, diff_score=r.diff_score,
        ) for r in rows
    ]
