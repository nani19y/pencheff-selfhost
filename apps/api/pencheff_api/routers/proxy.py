"""Intercepting proxy control — start/stop/list captured sessions."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import ProxySession, Scan, Workspace

router = APIRouter(prefix="/proxy", tags=["proxy"])


class ProxyStart(BaseModel):
    scan_id: str
    port: int = 8888


class ProxyOut(BaseModel):
    id: str
    scan_id: str
    port: int
    mode: str
    request_count: int
    started_at: datetime
    stopped_at: datetime | None


def _out(p: ProxySession) -> ProxyOut:
    return ProxyOut(
        id=p.id, scan_id=p.scan_id, port=p.port, mode=p.mode,
        request_count=p.request_count, started_at=p.started_at,
        stopped_at=p.stopped_at,
    )


@router.post(
    "/start",
    response_model=ProxyOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("proxy:write"))],
)
async def start_proxy(
    body: ProxyStart,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ProxyOut:
    scan = (await session.execute(
        select(Scan).where(Scan.id == body.scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    ps = ProxySession(scan_id=body.scan_id, port=body.port)
    session.add(ps)
    await session.commit()
    await session.refresh(ps)
    return _out(ps)


@router.post(
    "/{proxy_id}/stop",
    response_model=ProxyOut,
    dependencies=[Depends(require_scope("proxy:write"))],
)
async def stop_proxy(
    proxy_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ProxyOut:
    from datetime import datetime, timezone
    ps = (await session.execute(
        select(ProxySession).where(ProxySession.id == proxy_id)
    )).scalar_one_or_none()
    if not ps:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "proxy session not found")
    ps.stopped_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(ps)
    return _out(ps)


@router.get(
    "/scan/{scan_id}",
    response_model=list[ProxyOut],
    dependencies=[Depends(require_scope("proxy:read"))],
)
async def list_scan_proxies(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[ProxyOut]:
    rows = (await session.execute(
        select(ProxySession)
        .join(Scan, ProxySession.scan_id == Scan.id)
        .where(ProxySession.scan_id == scan_id, Scan.workspace_id == workspace.id)
        .order_by(ProxySession.started_at.desc())
    )).scalars().all()
    return [_out(p) for p in rows]
