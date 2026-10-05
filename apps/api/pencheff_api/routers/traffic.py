"""Traffic browse + FTS search for an engagement."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import desc, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import Engagement, ProxyTraffic, Workspace

router = APIRouter(prefix="/engagements/{engagement_id}/traffic", tags=["traffic"])


class TrafficRow(BaseModel):
    id: str
    captured_at: datetime
    method: str
    url: str
    host: str
    path: str
    response_status: int | None
    response_size: int | None
    duration_ms: int | None
    is_starred: bool
    tags: list[str] | None
    body_capture: str


class TrafficDetail(TrafficRow):
    request_headers: dict[str, str] | None
    request_body: str | None
    request_body_truncated: bool
    response_headers: dict[str, str] | None
    response_body: str | None
    response_body_truncated: bool
    notes: str | None
    ws_frames: list[dict[str, Any]] | None


class TrafficPatch(BaseModel):
    is_starred: bool | None = None
    tags: list[str] | None = None
    notes: str | None = None


def _row(t: ProxyTraffic) -> TrafficRow:
    return TrafficRow(
        id=t.id, captured_at=t.captured_at, method=t.method, url=t.url,
        host=t.host, path=t.path, response_status=t.response_status,
        response_size=t.response_size, duration_ms=t.duration_ms,
        is_starred=t.is_starred, tags=t.tags, body_capture=t.body_capture,
    )


def _detail(t: ProxyTraffic) -> TrafficDetail:
    return TrafficDetail(
        **_row(t).model_dump(),
        request_headers=t.request_headers, request_body=t.request_body,
        request_body_truncated=t.request_body_truncated,
        response_headers=t.response_headers, response_body=t.response_body,
        response_body_truncated=t.response_body_truncated,
        notes=t.notes, ws_frames=t.ws_frames,
    )


async def _resolve_engagement(
    engagement_id: str, workspace: Workspace, session: AsyncSession
) -> Engagement:
    e = await session.get(Engagement, engagement_id)
    if e is None or e.workspace_id != workspace.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    return e


@router.get(
    "",
    response_model=list[TrafficRow],
    dependencies=[Depends(require_scope("traffic:read"))],
)
async def list_traffic(
    engagement_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
    host: str | None = None,
    method: str | None = None,
    status_code: int | None = Query(default=None, alias="status"),
    starred: bool | None = None,
    limit: int = Query(default=200, le=1000),
    offset: int = 0,
) -> list[TrafficRow]:
    e = await _resolve_engagement(engagement_id, workspace, session)
    q = select(ProxyTraffic).where(ProxyTraffic.engagement_id == e.id)
    if host:
        q = q.where(ProxyTraffic.host == host)
    if method:
        q = q.where(ProxyTraffic.method == method.upper())
    if status_code is not None:
        q = q.where(ProxyTraffic.response_status == status_code)
    if starred:
        q = q.where(ProxyTraffic.is_starred.is_(True))
    q = q.order_by(desc(ProxyTraffic.captured_at)).limit(limit).offset(offset)
    rows = (await session.execute(q)).scalars().all()
    return [_row(t) for t in rows]


@router.get(
    "/search",
    response_model=list[TrafficRow],
    dependencies=[Depends(require_scope("traffic:read"))],
)
async def search_traffic(
    engagement_id: str,
    q: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=100, le=500),
) -> list[TrafficRow]:
    e = await _resolve_engagement(engagement_id, workspace, session)
    if not q.strip():
        return []
    stmt = (
        select(ProxyTraffic)
        .where(ProxyTraffic.engagement_id == e.id)
        .where(text("fts_doc @@ plainto_tsquery('simple', :qq)"))
        .order_by(desc(text("ts_rank(fts_doc, plainto_tsquery('simple', :qq))")))
        .limit(limit)
    )
    rows = (await session.execute(stmt, {"qq": q})).scalars().all()
    return [_row(t) for t in rows]


@router.get(
    "/{traffic_id}",
    response_model=TrafficDetail,
    dependencies=[Depends(require_scope("traffic:read"))],
)
async def get_traffic(
    engagement_id: str,
    traffic_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> TrafficDetail:
    await _resolve_engagement(engagement_id, workspace, session)
    t = await session.get(ProxyTraffic, traffic_id)
    if t is None or t.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "traffic not found")
    return _detail(t)


@router.patch(
    "/{traffic_id}",
    response_model=TrafficDetail,
    dependencies=[Depends(require_scope("traffic:write"))],
)
async def patch_traffic(
    engagement_id: str,
    traffic_id: str,
    body: TrafficPatch,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> TrafficDetail:
    await _resolve_engagement(engagement_id, workspace, session)
    t = await session.get(ProxyTraffic, traffic_id)
    if t is None or t.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "traffic not found")
    if body.is_starred is not None:
        t.is_starred = body.is_starred
    if body.tags is not None:
        t.tags = body.tags
    if body.notes is not None:
        t.notes = body.notes
    await session.commit()
    await session.refresh(t)
    return _detail(t)
