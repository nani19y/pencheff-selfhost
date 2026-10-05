"""Executive dashboard aggregations.

Pure aggregation endpoints over data already in the DB — no new
schema, no LLM calls. The frontend at ``/dashboard/executive`` calls
these and renders charts via recharts.

Endpoints:
  * ``GET /dashboard/heatmap``     — finding count by (severity × category)
  * ``GET /dashboard/trend``       — finding count per day for the last N days
  * ``GET /dashboard/top-repos``   — top-N repos by open-finding count
  * ``GET /dashboard/kev-exposure`` — KEV-flagged findings + open count
  * ``GET /dashboard/fix-conversion`` — % of findings with applied fix
                                        proposals (lifetime + last-90d)

All endpoints are workspace-scoped via ``get_active_workspace``. No
plan-tier gate — every plan can read the aggregations.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import (
    Finding,
    FixProposal,
    RepoFinding,
    RepoScan,
    Repository,
    Scan,
    Target,
    Workspace,
)

log = logging.getLogger(__name__)

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_scope("dashboard:read"))],
)


# ── Response shapes ─────────────────────────────────────────────────


class HeatmapCell(BaseModel):
    severity: str
    category: str
    count: int


class HeatmapOut(BaseModel):
    cells: list[HeatmapCell]
    severities: list[str]   # row order — critical → info
    categories: list[str]   # column order — most-common first


class TrendPoint(BaseModel):
    date: str               # YYYY-MM-DD
    new: int
    closed: int


class TrendOut(BaseModel):
    points: list[TrendPoint]
    window_days: int


class TopRepoRow(BaseModel):
    repository_id: str
    full_name: str
    open_findings: int
    critical: int
    high: int


class TopReposOut(BaseModel):
    rows: list[TopRepoRow]


class KevExposureOut(BaseModel):
    total_kev_findings: int
    open_kev_findings: int
    suppressed_kev_findings: int
    fixed_kev_findings: int
    by_severity: dict[str, int]


class FixConversionOut(BaseModel):
    findings_total: int
    findings_with_proposal: int
    findings_with_applied_fix: int
    proposal_coverage_pct: float
    apply_coverage_pct: float


class TargetTrendScan(BaseModel):
    id: str
    created_at: str | None
    finished_at: str | None
    status: str
    grade: str | None
    score: float | None
    summary: dict[str, int]


class TargetTrendDelta(BaseModel):
    scan_id: str
    vs_prior_scan_id: str
    new: int
    fixed: int
    regressed: int


class TargetTrendOut(BaseModel):
    target: dict[str, str | None]
    scans: list[TargetTrendScan]
    deltas: list[TargetTrendDelta]
    mttr_days: float | None
    open_total: int
    fixed_total: int


# ── Endpoints ───────────────────────────────────────────────────────


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@router.get("/heatmap", response_model=HeatmapOut)
async def heatmap(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> HeatmapOut:
    """Severity × category counts over open (un-suppressed) findings.
    DAST + SAST combined — auditors care about composition, not source."""
    dast = (
        await session.execute(
            select(Finding.severity, Finding.category, func.count(Finding.id))
            .join(Scan, Scan.id == Finding.scan_id)
            .where(
                Scan.workspace_id == workspace.id,
                Finding.suppressed.is_(False),
            )
            .group_by(Finding.severity, Finding.category)
        )
    ).all()
    # SAST findings carry a ``scanner`` (semgrep / gitleaks / trivy_iac
    # / ghsa / yara / checkov) rather than a free-form ``category``;
    # use scanner as the heatmap column so the visual is still
    # readable for SAST-only workspaces.
    sast = (
        await session.execute(
            select(RepoFinding.severity, RepoFinding.scanner, func.count(RepoFinding.id))
            .join(RepoScan, RepoScan.id == RepoFinding.repo_scan_id)
            .where(
                RepoScan.workspace_id == workspace.id,
                RepoFinding.suppressed.is_(False),
            )
            .group_by(RepoFinding.severity, RepoFinding.scanner)
        )
    ).all()

    # Merge the two sources into a single severity×category counter.
    merged: dict[tuple[str, str], int] = defaultdict(int)
    for sev, cat, n in (*dast, *sast):
        merged[((sev or "info").lower(), (cat or "uncategorised").lower())] += n

    cells = [
        HeatmapCell(severity=sev, category=cat, count=n)
        for (sev, cat), n in merged.items()
    ]
    # Order severities by the canonical scale; categories by total
    # finding count so the highest-traffic columns sort left.
    cat_totals: dict[str, int] = defaultdict(int)
    for cell in cells:
        cat_totals[cell.category] += cell.count
    categories = [c for c, _ in sorted(cat_totals.items(),
                                        key=lambda kv: -kv[1])]
    return HeatmapOut(
        cells=cells,
        severities=list(_SEVERITY_ORDER),
        categories=categories,
    )


@router.get("/trend", response_model=TrendOut)
async def trend(
    days: int = Query(default=90, ge=7, le=365),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> TrendOut:
    """Findings created vs. closed per calendar day, last ``days`` days.

    "Closed" = finding moved to ``verification_status='fixed'`` or was
    suppressed. We use ``last_rechecked_at`` for the close timestamp;
    that's the column the recheck task updates on transition.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    new_dast = (
        await session.execute(
            select(func.date(Finding.created_at), func.count(Finding.id))
            .join(Scan, Scan.id == Finding.scan_id)
            .where(
                Scan.workspace_id == workspace.id,
                Finding.created_at >= cutoff,
            )
            .group_by(func.date(Finding.created_at))
        )
    ).all()
    new_sast = (
        await session.execute(
            select(func.date(RepoFinding.created_at), func.count(RepoFinding.id))
            .join(RepoScan, RepoScan.id == RepoFinding.repo_scan_id)
            .where(
                RepoScan.workspace_id == workspace.id,
                RepoFinding.created_at >= cutoff,
            )
            .group_by(func.date(RepoFinding.created_at))
        )
    ).all()
    closed_dast = (
        await session.execute(
            select(func.date(Finding.last_rechecked_at), func.count(Finding.id))
            .join(Scan, Scan.id == Finding.scan_id)
            .where(
                Scan.workspace_id == workspace.id,
                Finding.last_rechecked_at >= cutoff,
                Finding.verification_status == "fixed",
            )
            .group_by(func.date(Finding.last_rechecked_at))
        )
    ).all()

    # SAST closed proxies through fix proposal application timestamps
    # — the SAST repo flow doesn't have its own recheck status column
    # at this iteration. Aggregating fix_proposals.applied_at gives a
    # close-enough signal for the trend graph.
    closed_sast_proxy = (
        await session.execute(
            select(func.date(FixProposal.applied_at), func.count(FixProposal.id))
            .where(
                FixProposal.workspace_id == workspace.id,
                FixProposal.finding_kind == "sast",
                FixProposal.status == "applied",
                FixProposal.applied_at >= cutoff,
            )
            .group_by(func.date(FixProposal.applied_at))
        )
    ).all()

    new_per_day: dict[str, int] = defaultdict(int)
    closed_per_day: dict[str, int] = defaultdict(int)
    for d, n in (*new_dast, *new_sast):
        if d is None:
            continue
        new_per_day[d.isoformat() if hasattr(d, "isoformat") else str(d)] += n
    for d, n in (*closed_dast, *closed_sast_proxy):
        if d is None:
            continue
        closed_per_day[d.isoformat() if hasattr(d, "isoformat") else str(d)] += n

    # Render every day in the window so the chart has a contiguous
    # x-axis (recharts won't fill missing dates on its own).
    points: list[TrendPoint] = []
    for i in range(days, -1, -1):
        d = (datetime.now(timezone.utc).date() - timedelta(days=i)).isoformat()
        points.append(TrendPoint(
            date=d,
            new=new_per_day.get(d, 0),
            closed=closed_per_day.get(d, 0),
        ))
    return TrendOut(points=points, window_days=days)


@router.get("/top-repos", response_model=TopReposOut)
async def top_repos(
    limit: int = Query(default=10, ge=1, le=50),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> TopReposOut:
    """Repos with the most open SAST findings — joined through
    Repository → RepoScan → RepoFinding.

    Per-severity breakdowns use Postgres' ``COUNT(...) FILTER (WHERE
    ...)`` aggregate, which keeps the whole roll-up to one query
    rather than three.
    """
    rows = (
        await session.execute(
            select(
                Repository.id,
                Repository.full_name,
                func.count(RepoFinding.id).label("open_total"),
                func.count(RepoFinding.id).filter(
                    RepoFinding.severity == "critical"
                ).label("crit"),
                func.count(RepoFinding.id).filter(
                    RepoFinding.severity == "high"
                ).label("hi"),
            )
            .join(RepoScan, RepoScan.repository_id == Repository.id)
            .join(RepoFinding, RepoFinding.repo_scan_id == RepoScan.id)
            .where(
                Repository.workspace_id == workspace.id,
                RepoFinding.suppressed.is_(False),
            )
            .group_by(Repository.id, Repository.full_name)
            .order_by(func.count(RepoFinding.id).desc())
            .limit(limit)
        )
    ).all()

    return TopReposOut(
        rows=[
            TopRepoRow(
                repository_id=str(rid),
                full_name=str(name),
                open_findings=int(open_total or 0),
                critical=int(crit or 0),
                high=int(hi or 0),
            )
            for (rid, name, open_total, crit, hi) in rows
        ]
    )


@router.get("/kev-exposure", response_model=KevExposureOut)
async def kev_exposure(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> KevExposureOut:
    """KEV-flagged finding counts. The Kev (Known Exploited
    Vulnerabilities) column is set on the ``Finding`` row by the
    enrichment pipeline at scan time."""
    rows = (
        await session.execute(
            select(
                Finding.severity,
                Finding.suppressed,
                Finding.verification_status,
                func.count(Finding.id),
            )
            .join(Scan, Scan.id == Finding.scan_id)
            .where(
                Scan.workspace_id == workspace.id,
                Finding.kev.is_(True),
            )
            .group_by(Finding.severity, Finding.suppressed, Finding.verification_status)
        )
    ).all()

    total = open_count = sup = fixed = 0
    by_sev: dict[str, int] = defaultdict(int)
    for severity, suppressed, status_, n in rows:
        total += n
        if suppressed:
            sup += n
        elif (status_ or "") == "fixed":
            fixed += n
        else:
            open_count += n
        by_sev[(severity or "info").lower()] += n

    return KevExposureOut(
        total_kev_findings=total,
        open_kev_findings=open_count,
        suppressed_kev_findings=sup,
        fixed_kev_findings=fixed,
        by_severity=dict(by_sev),
    )


@router.get("/fix-conversion", response_model=FixConversionOut)
async def fix_conversion(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FixConversionOut:
    """% of findings with at least one fix proposal / applied PR.
    Useful as a leading indicator of MTTR — lots of proposals but
    few applied means PR review is the bottleneck."""
    findings_total_dast = (
        await session.execute(
            select(func.count(Finding.id))
            .join(Scan, Scan.id == Finding.scan_id)
            .where(Scan.workspace_id == workspace.id)
        )
    ).scalar_one()
    findings_total_sast = (
        await session.execute(
            select(func.count(RepoFinding.id))
            .join(RepoScan, RepoScan.id == RepoFinding.repo_scan_id)
            .where(RepoScan.workspace_id == workspace.id)
        )
    ).scalar_one()
    findings_total = (findings_total_dast or 0) + (findings_total_sast or 0)

    proposed_count = (
        await session.execute(
            select(func.count(func.distinct(FixProposal.finding_id)))
            .where(FixProposal.workspace_id == workspace.id)
        )
    ).scalar_one() or 0

    applied_count = (
        await session.execute(
            select(func.count(func.distinct(FixProposal.finding_id)))
            .where(
                FixProposal.workspace_id == workspace.id,
                FixProposal.status == "applied",
            )
        )
    ).scalar_one() or 0

    def _pct(n: int) -> float:
        return round(100.0 * n / findings_total, 1) if findings_total else 0.0

    return FixConversionOut(
        findings_total=findings_total,
        findings_with_proposal=proposed_count,
        findings_with_applied_fix=applied_count,
        proposal_coverage_pct=_pct(proposed_count),
        apply_coverage_pct=_pct(applied_count),
    )


def _normalise_summary(raw: dict | None) -> dict[str, int]:
    """Coerce a Scan.summary JSONB blob to {sev: int} for the five
    canonical severities. Older rows may carry numeric strings or
    extra keys (e.g. ``executive_summary``) — strip them."""
    out = {sev: 0 for sev in _SEVERITY_ORDER}
    if not isinstance(raw, dict):
        return out
    for sev in _SEVERITY_ORDER:
        v = raw.get(sev)
        try:
            out[sev] = int(v) if v is not None else 0
        except (TypeError, ValueError):
            out[sev] = 0
    return out


@router.get("/target/{target_id}/trend", response_model=TargetTrendOut)
async def target_trend(
    target_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> TargetTrendOut:
    """Per-target scan history for the trend dashboard.

    Returns every Scan for ``target_id`` (ordered oldest→newest) plus
    pairwise summary deltas and a workspace-scoped MTTR over fixed
    Findings of this target. The frontend uses ``scans[]`` for the
    severity stack chart and grade trajectory; ``deltas[]`` powers the
    "+N new · −N fixed · ±N regressed" strip between consecutive rows.

    Deltas are derived from severity-summary diffs, not finding-by-
    finding identity comparison — accurate enough for a trend view and
    avoids an O(scans²) cross-join over Finding rows.
    """
    target = await session.get(Target, target_id)
    if target is None or target.workspace_id != workspace.id:
        # Hide existence; same shape as a 404. Empty payload is the
        # cheapest signal for the frontend ("not yours").
        return TargetTrendOut(
            target={"id": target_id, "name": None, "base_url": None},
            scans=[], deltas=[], mttr_days=None,
            open_total=0, fixed_total=0,
        )

    rows = (
        await session.execute(
            select(Scan)
            .where(
                Scan.target_id == target_id,
                Scan.workspace_id == workspace.id,
            )
            .order_by(Scan.created_at.asc())
        )
    ).scalars().all()

    scans: list[TargetTrendScan] = []
    for s in rows:
        scans.append(TargetTrendScan(
            id=str(s.id),
            created_at=s.created_at.isoformat() if s.created_at else None,
            finished_at=s.finished_at.isoformat() if s.finished_at else None,
            status=s.status or "unknown",
            grade=s.grade,
            score=float(s.score) if s.score is not None else None,
            summary=_normalise_summary(s.summary),
        ))

    # Deltas via summary diff — for each consecutive pair (a, b):
    #   new      = sum over sev of max(0, b - a)
    #   fixed    = sum over sev of max(0, a - b)
    #   regressed = increases at higher severities than the previous
    #               scan's max — best-effort proxy without finding IDs
    deltas: list[TargetTrendDelta] = []
    for i in range(1, len(scans)):
        a, b = scans[i - 1].summary, scans[i].summary
        new_n = sum(max(0, b[sev] - a[sev]) for sev in _SEVERITY_ORDER)
        fixed_n = sum(max(0, a[sev] - b[sev]) for sev in _SEVERITY_ORDER)
        regressed_n = max(
            0,
            (b["critical"] + b["high"]) - (a["critical"] + a["high"]),
        )
        deltas.append(TargetTrendDelta(
            scan_id=scans[i].id,
            vs_prior_scan_id=scans[i - 1].id,
            new=new_n,
            fixed=fixed_n,
            regressed=regressed_n,
        ))

    # MTTR: average days between created_at and last_rechecked_at over
    # findings now in ``fixed`` state for this target's scans. Returns
    # None if there are no fixed findings to average.
    fixed_rows = (
        await session.execute(
            select(Finding.created_at, Finding.last_rechecked_at)
            .join(Scan, Scan.id == Finding.scan_id)
            .where(
                Scan.target_id == target_id,
                Scan.workspace_id == workspace.id,
                Finding.verification_status == "fixed",
                Finding.last_rechecked_at.is_not(None),
            )
        )
    ).all()
    mttr_days: float | None = None
    if fixed_rows:
        secs = [
            (closed - created).total_seconds()
            for (created, closed) in fixed_rows
            if created and closed and closed >= created
        ]
        if secs:
            mttr_days = round(sum(secs) / len(secs) / 86400.0, 2)

    # Open vs. fixed totals across this target.
    counts = (
        await session.execute(
            select(
                func.count(Finding.id).filter(
                    Finding.suppressed.is_(False),
                    Finding.verification_status != "fixed",
                ),
                func.count(Finding.id).filter(
                    Finding.verification_status == "fixed",
                ),
            )
            .join(Scan, Scan.id == Finding.scan_id)
            .where(
                Scan.target_id == target_id,
                Scan.workspace_id == workspace.id,
            )
        )
    ).one()
    open_total, fixed_total = counts

    return TargetTrendOut(
        target={
            "id": str(target.id),
            "name": target.name,
            "base_url": target.base_url,
        },
        scans=scans,
        deltas=deltas,
        mttr_days=mttr_days,
        open_total=int(open_total or 0),
        fixed_total=int(fixed_total or 0),
    )


