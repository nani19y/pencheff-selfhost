"""Repeater tabs + send-and-record."""
from __future__ import annotations

import time
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, get_current_user, require_scope
from ..db.base import get_session
from ..db.models import (
    Engagement,
    ProxyTraffic,
    RepeaterResponse,
    RepeaterTab,
    User,
    Workspace,
)

router = APIRouter(prefix="/engagements/{engagement_id}/repeater", tags=["repeater"])


class TabCreate(BaseModel):
    name: str = "Untitled"
    request_method: str = "GET"
    request_url: str
    request_headers: dict[str, str] | None = None
    request_body: str | None = None
    source_traffic_id: str | None = None


class TabPatch(BaseModel):
    name: str | None = None
    request_method: str | None = None
    request_url: str | None = None
    request_headers: dict[str, str] | None = None
    request_body: str | None = None
    pinned: bool | None = None
    notes: str | None = None


class TabOut(BaseModel):
    id: str
    name: str
    request_method: str
    request_url: str
    request_headers: dict[str, str] | None
    request_body: str | None
    pinned: bool
    notes: str | None
    source_traffic_id: str | None
    created_at: datetime
    updated_at: datetime


class ResponseOut(BaseModel):
    id: str
    sent_at: datetime
    response_status: int | None
    response_headers: dict[str, str] | None
    response_body: str | None
    duration_ms: int | None


class SendOverrides(BaseModel):
    request_method: str | None = None
    request_url: str | None = None
    request_headers: dict[str, str] | None = None
    request_body: str | None = None


def _to_tab_out(t: RepeaterTab) -> TabOut:
    return TabOut(
        id=t.id, name=t.name, request_method=t.request_method,
        request_url=t.request_url, request_headers=t.request_headers,
        request_body=t.request_body, pinned=t.pinned, notes=t.notes,
        source_traffic_id=t.source_traffic_id,
        created_at=t.created_at, updated_at=t.updated_at,
    )


def _to_resp_out(r: RepeaterResponse) -> ResponseOut:
    return ResponseOut(
        id=r.id, sent_at=r.sent_at, response_status=r.response_status,
        response_headers=r.response_headers, response_body=r.response_body,
        duration_ms=r.duration_ms,
    )


async def _engagement(eid: str, ws: Workspace, s: AsyncSession) -> Engagement:
    e = await s.get(Engagement, eid)
    if e is None or e.workspace_id != ws.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    return e


@router.post(
    "/tabs",
    response_model=TabOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("repeater:write"))],
)
async def create_tab(
    engagement_id: str,
    body: TabCreate,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> TabOut:
    e = await _engagement(engagement_id, workspace, session)
    method = body.request_method.upper()
    url = body.request_url
    headers = body.request_headers
    req_body = body.request_body
    # If a source traffic id is provided, hydrate from it.
    if body.source_traffic_id:
        t = await session.get(ProxyTraffic, body.source_traffic_id)
        if t is None or t.engagement_id != e.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid source_traffic_id")
        method = method or t.method
        url = url or t.url
        headers = headers or t.request_headers
        req_body = req_body if req_body is not None else t.request_body
    tab = RepeaterTab(
        engagement_id=e.id, workspace_id=workspace.id, name=body.name,
        request_method=method, request_url=url, request_headers=headers,
        request_body=req_body, source_traffic_id=body.source_traffic_id,
        created_by_user_id=user.id,
    )
    session.add(tab)
    await session.commit()
    await session.refresh(tab)
    return _to_tab_out(tab)


@router.get(
    "/tabs",
    response_model=list[TabOut],
    dependencies=[Depends(require_scope("repeater:read"))],
)
async def list_tabs(
    engagement_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[TabOut]:
    e = await _engagement(engagement_id, workspace, session)
    rows = (await session.execute(
        select(RepeaterTab)
        .where(RepeaterTab.engagement_id == e.id)
        .order_by(desc(RepeaterTab.pinned), desc(RepeaterTab.updated_at))
    )).scalars().all()
    return [_to_tab_out(t) for t in rows]


@router.patch(
    "/tabs/{tab_id}",
    response_model=TabOut,
    dependencies=[Depends(require_scope("repeater:write"))],
)
async def patch_tab(
    engagement_id: str,
    tab_id: str,
    body: TabPatch,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> TabOut:
    await _engagement(engagement_id, workspace, session)
    t = await session.get(RepeaterTab, tab_id)
    if t is None or t.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tab not found")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(t, field, value)
    t.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(t)
    return _to_tab_out(t)


@router.delete(
    "/tabs/{tab_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("repeater:write"))],
)
async def delete_tab(
    engagement_id: str,
    tab_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    await _engagement(engagement_id, workspace, session)
    t = await session.get(RepeaterTab, tab_id)
    if t is None or t.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tab not found")
    await session.delete(t)
    await session.commit()


@router.post(
    "/tabs/{tab_id}/send",
    response_model=ResponseOut,
    dependencies=[Depends(require_scope("repeater:write"))],
)
async def send_tab(
    engagement_id: str,
    tab_id: str,
    body: SendOverrides | None = None,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ResponseOut:
    await _engagement(engagement_id, workspace, session)
    t = await session.get(RepeaterTab, tab_id)
    if t is None or t.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tab not found")

    overrides = body.model_dump(exclude_unset=True) if body else {}
    method = (overrides.get("request_method") or t.request_method).upper()
    url = overrides.get("request_url") or t.request_url
    headers = overrides.get("request_headers") if overrides.get("request_headers") is not None else (t.request_headers or {})
    req_body = overrides.get("request_body") if "request_body" in overrides else t.request_body

    snap = {
        "method": method, "url": url, "headers": headers, "body": req_body,
    }
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False, verify=False) as client:
            res = await client.request(method, url, headers=headers or None, content=req_body)
        duration = int((time.monotonic() - started) * 1000)
        rr = RepeaterResponse(
            tab_id=t.id, request_snapshot=snap,
            response_status=res.status_code,
            response_headers={k: v for k, v in res.headers.items()},
            response_body=res.text[: 1024 * 1024],
            duration_ms=duration,
            sent_by_user_id=user.id,
        )
    except Exception as exc:
        duration = int((time.monotonic() - started) * 1000)
        rr = RepeaterResponse(
            tab_id=t.id, request_snapshot=snap,
            response_status=None,
            response_headers={"x-error": str(exc)[:200]},
            response_body=None,
            duration_ms=duration,
            sent_by_user_id=user.id,
        )

    session.add(rr)
    await session.commit()
    await session.refresh(rr)
    return _to_resp_out(rr)


@router.get(
    "/tabs/{tab_id}/responses",
    response_model=list[ResponseOut],
    dependencies=[Depends(require_scope("repeater:read"))],
)
async def list_responses(
    engagement_id: str,
    tab_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[ResponseOut]:
    await _engagement(engagement_id, workspace, session)
    rows = (await session.execute(
        select(RepeaterResponse)
        .where(RepeaterResponse.tab_id == tab_id)
        .order_by(desc(RepeaterResponse.sent_at))
        .limit(100)
    )).scalars().all()
    return [_to_resp_out(r) for r in rows]
