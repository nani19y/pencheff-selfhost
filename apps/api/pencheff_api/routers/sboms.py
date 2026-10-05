"""SBOM generation + retrieval + external-SBOM ingest."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import Scan, Sbom, Workspace


router = APIRouter(
    prefix="/sboms",
    tags=["sboms"],
    dependencies=[Depends(require_scope("sboms:read"))],
)


class SbomOut(BaseModel):
    id: str
    scan_id: str
    format: str
    component_count: int | None
    created_at: datetime


class SbomDetail(SbomOut):
    content: dict[str, Any] | None


def _scope(workspace: Workspace, scan_id: str):
    return select(Sbom).join(Scan, Sbom.scan_id == Scan.id).where(
        Sbom.scan_id == scan_id, Scan.workspace_id == workspace.id,
    )


@router.get("/{scan_id}", response_model=list[SbomOut])
async def list_sboms(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[SbomOut]:
    rows = (await session.execute(_scope(workspace, scan_id))).scalars().all()
    return [SbomOut(id=s.id, scan_id=s.scan_id, format=s.format,
                    component_count=s.component_count, created_at=s.created_at)
            for s in rows]


@router.get("/{scan_id}/{sbom_id}", response_model=SbomDetail)
async def get_sbom_detail(
    scan_id: str, sbom_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> SbomDetail:
    q = _scope(workspace, scan_id).where(Sbom.id == sbom_id)
    s = (await session.execute(q)).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "sbom not found")
    return SbomDetail(
        id=s.id, scan_id=s.scan_id, format=s.format,
        component_count=s.component_count, created_at=s.created_at,
        content=s.content,
    )
