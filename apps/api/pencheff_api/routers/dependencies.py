"""Per-scan dependency inventory browsing (SCA)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import Dependency, Scan, Workspace

router = APIRouter(
    prefix="/dependencies",
    tags=["dependencies"],
    dependencies=[Depends(require_scope("dependencies:read"))],
)


class DependencyOut(BaseModel):
    id: str
    scan_id: str
    ecosystem: str
    name: str
    version: str
    license: str | None
    scope: str
    vulnerabilities: list[Any] | None
    created_at: datetime


@router.get("/{scan_id}", response_model=list[DependencyOut])
async def list_dependencies(
    scan_id: str,
    vulnerable_only: bool = False,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[DependencyOut]:
    q = (
        select(Dependency)
        .join(Scan, Dependency.scan_id == Scan.id)
        .where(Dependency.scan_id == scan_id, Scan.workspace_id == workspace.id)
        .order_by(Dependency.name)
    )
    rows = (await session.execute(q)).scalars().all()
    if vulnerable_only:
        rows = [d for d in rows if d.vulnerabilities]
    return [
        DependencyOut(
            id=d.id, scan_id=d.scan_id, ecosystem=d.ecosystem,
            name=d.name, version=d.version, license=d.license,
            scope=d.scope, vulnerabilities=d.vulnerabilities,
            created_at=d.created_at,
        )
        for d in rows
    ]
