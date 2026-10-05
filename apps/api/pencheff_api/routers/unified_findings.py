"""Unified finding stream — single sortable queue across DAST + SAST +
SCA + IaC + secrets, scoped to the active workspace.

This is the dashboard's main "show me everything that's wrong with my
target, ordered by what to fix first" feed. Sort order is the
prioritisation engine's ``risk_score`` (Phase 1.3) with severity-based
fallbacks for findings produced before the engine landed.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import Workspace
from ..schemas.unified_findings import UnifiedFindingItem, UnifiedFindingsPage
from ..services import unified_findings as uf_service


router = APIRouter(
    prefix="/unified-findings",
    tags=["unified-findings"],
    dependencies=[Depends(require_scope("unified_findings:read"))],
)


@router.get("", response_model=UnifiedFindingsPage)
async def list_unified_findings(
    target_id: str | None = Query(None,
        description="Restrict to findings that touch this target."),
    source: list[str] | None = Query(None,
        description="Filter by source kind: sast | dast | sca | iac | secret. "
                    "Repeat the param to combine."),
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None,
    reachability: Literal["exploited", "reachable", "present", "unknown"] | None = None,
    include_suppressed: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> UnifiedFindingsPage:
    rows, total = await uf_service.query_unified(
        session,
        workspace_id=workspace.id,
        target_id=target_id,
        source_filter=source,
        severity=severity,
        reachability=reachability,
        include_suppressed=include_suppressed,
        limit=limit, offset=offset,
    )
    items = [
        UnifiedFindingItem(
            id=r.id, source=r.source, table=r.table,
            title=r.title, severity=r.severity, risk_score=r.risk_score,
            reachability=r.reachability, ssvc_decision=r.ssvc_decision,
            epss=r.epss, kev=r.kev,
            cwe_id=r.cwe_id, owasp_category=r.owasp_category,
            location=r.location,
            package=r.package, fixed_version=r.fixed_version,
            suppressed=r.suppressed, created_at=r.created_at,
            workspace_id=r.workspace_id,
            target_id=r.target_id, repository_id=r.repository_id,
        )
        for r in rows
    ]
    return UnifiedFindingsPage(
        items=items, total=total, limit=limit, offset=offset,
    )
