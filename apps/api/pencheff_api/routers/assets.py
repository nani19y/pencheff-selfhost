"""ASM — attack surface inventory."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import Asset, Workspace
from ..services.worker_lifecycle import ensure_worker_started_or_503

router = APIRouter(prefix="/assets", tags=["assets"])


class AssetOut(BaseModel):
    id: str
    type: str
    value: str
    meta: dict[str, Any] | None
    first_seen: datetime
    last_seen: datetime


class DiscoverBody(BaseModel):
    root_domain: str


def _out(a: Asset) -> AssetOut:
    return AssetOut(
        id=a.id, type=a.type, value=a.value, meta=a.meta,
        first_seen=a.first_seen, last_seen=a.last_seen,
    )


@router.get(
    "",
    response_model=list[AssetOut],
    dependencies=[Depends(require_scope("assets:read"))],
)
async def list_workspace_assets(
    asset_type: str | None = None,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[AssetOut]:
    q = select(Asset).where(Asset.workspace_id == workspace.id).order_by(Asset.last_seen.desc())
    if asset_type:
        q = q.where(Asset.type == asset_type)
    rows = (await session.execute(q)).scalars().all()
    return [_out(a) for a in rows]


@router.post(
    "/discover",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_scope("assets:write"))],
)
async def trigger_discovery(
    body: DiscoverBody,
    workspace: Workspace = Depends(get_active_workspace),
) -> dict[str, str]:
    await ensure_worker_started_or_503()

    from ..tasks.asset_discovery_task import run_discovery
    run_discovery.delay(workspace.org_id, workspace.id, body.root_domain)
    return {
        "status": "queued",
        "workspace_id": workspace.id,
        "root_domain": body.root_domain,
    }


@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("assets:write"))],
)
async def remove_asset(
    asset_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    a = (await session.execute(
        select(Asset).where(Asset.id == asset_id, Asset.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    await session.delete(a)
    await session.commit()
