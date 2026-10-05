"""Unified finding stream — Snyk-style single-queue across DAST + SAST +
SCA + IaC + secrets, sorted by Pencheff's priority score.

Today findings live in two separate tables:

  * ``findings``        — DAST + SCA emitted by ``scan_runner`` (the
                          "live target" pipeline). These carry
                          ``risk_score``, ``reachability``, ``ssvc_decision``
                          from the prioritisation engine.
  * ``repo_findings``   — SAST + SCA + secrets + IaC emitted by repo
                          scans. These have ``scanner`` (semgrep/osv/ghsa/
                          gitleaks/trivy_iac/checkov), ``file_path``,
                          ``line_start``. No risk_score yet — we derive
                          one at query time so the unified stream sorts
                          consistently.

The service projects both into a common ``UnifiedFindingRow`` shape so
the dashboard can render a single sortable / filterable list. The
projection is read-only — no schema changes, no migrations. Sort order
is the Phase-1.3 priority score (NULL last), then severity, then date.

Filters supported:
  * source       — sast | dast | sca | iac | secret (multi-select)
  * severity     — critical | high | medium | low | info
  * reachability — exploited | reachable | present | unknown
  * include_suppressed — bool
  * limit / offset — pagination
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import (
    Finding as DbFinding,
    RepoFinding,
    RepoScan,
    Repository,
    Scan,
    Target,
    TargetRepository,
)


SourceKind = Literal["sast", "dast", "sca", "iac", "secret"]


# ── Output shape ────────────────────────────────────────────────────


@dataclass(frozen=True)
class UnifiedFindingRow:
    """Common projection across both tables. Field set is intentionally
    minimal — the consumer fetches the full record from the source
    table when the user clicks through."""
    id: str
    source: SourceKind
    table: Literal["findings", "repo_findings"]
    title: str
    severity: str
    risk_score: float
    reachability: str | None
    ssvc_decision: str | None
    epss: float | None
    kev: bool
    cwe_id: str | None
    owasp_category: str | None
    location: str                          # endpoint OR file_path:line_start
    package: str | None                    # SCA only
    fixed_version: str | None              # SCA only
    suppressed: bool
    created_at: datetime
    workspace_id: str
    target_id: str | None
    repository_id: str | None


# ── Source mapping ──────────────────────────────────────────────────


_SCANNER_TO_SOURCE: dict[str, SourceKind] = {
    # Phase 0.1 SAST replacement pack
    "semgrep":   "sast",
    "bandit":    "sast",
    "gosec":     "sast",
    "brakeman":  "sast",
    "eslint":    "sast",
    "ruff":      "sast",
    # Legacy — historical rows from before the CodeQL removal in v0.7
    # can still appear in the DB; keep classified as SAST.
    "codeql":    "sast",
    # SCA / IaC / secrets — unchanged
    "osv":       "sca",
    "ghsa":      "sca",
    "pip-audit": "sca",
    "npm-audit": "sca",
    "gitleaks":  "secret",
    "detect-secrets": "secret",
    "trivy_iac": "iac",
    "checkov":   "iac",
}


def _scanner_to_source(scanner: str | None) -> SourceKind:
    return _SCANNER_TO_SOURCE.get((scanner or "").lower(), "sast")


def _category_to_source(category: str | None) -> SourceKind:
    cat = (category or "").lower()
    if cat == "components":
        return "sca"
    return "dast"


# ── Severity → fallback risk score ─────────────────────────────────


_SEV_FALLBACK_SCORE: dict[str, float] = {
    "critical": 80.0,
    "high":     65.0,
    "medium":   45.0,
    "low":      25.0,
    "info":     10.0,
}


def _fallback_risk(severity: str | None) -> float:
    return _SEV_FALLBACK_SCORE.get((severity or "info").lower(), 10.0)


# ── Projections ─────────────────────────────────────────────────────


def _project_finding(
    f: DbFinding, *, workspace_id: str, target_id: str | None,
) -> UnifiedFindingRow:
    return UnifiedFindingRow(
        id=f.id,
        source=_category_to_source(f.category),
        table="findings",
        title=f.title,
        severity=(f.severity or "info").lower(),
        risk_score=f.risk_score if f.risk_score is not None else _fallback_risk(f.severity),
        reachability=f.reachability,
        ssvc_decision=f.ssvc_decision,
        epss=f.epss,
        kev=bool(f.kev),
        cwe_id=f.cwe_id,
        owasp_category=f.owasp_category,
        location=f.endpoint or "",
        package=None,
        fixed_version=None,
        suppressed=bool(f.suppressed),
        created_at=f.created_at,
        workspace_id=workspace_id,
        target_id=target_id,
        repository_id=None,
    )


def _project_repo_finding(
    r: RepoFinding, *, workspace_id: str,
) -> UnifiedFindingRow:
    location = r.file_path or ""
    if location and r.line_start:
        location = f"{location}:{r.line_start}"
    source = _scanner_to_source(r.scanner)
    return UnifiedFindingRow(
        id=r.id,
        source=source,
        table="repo_findings",
        title=r.title,
        severity=(r.severity or "info").lower(),
        risk_score=_fallback_risk(r.severity),
        reachability=None,                 # repo_findings has no priority engine yet
        ssvc_decision=None,
        epss=None,
        kev=False,
        cwe_id=None,
        owasp_category=None,
        location=location,
        package=r.package,
        fixed_version=r.fixed_version,
        suppressed=bool(r.suppressed),
        created_at=r.created_at,
        workspace_id=workspace_id,
        target_id=None,
        repository_id=r.repository_id,
    )


# ── Query ──────────────────────────────────────────────────────────


async def query_unified(
    session: AsyncSession,
    *,
    workspace_id: str,
    target_id: str | None = None,
    source_filter: Iterable[str] | None = None,
    severity: str | None = None,
    reachability: str | None = None,
    include_suppressed: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[UnifiedFindingRow], int]:
    """Return ``(rows, total_count)``.

    Pulls from both tables, projects, merges, sorts by ``risk_score``
    (DESC, NULLs last via the projection's fallback), then severity,
    then created_at. Pagination applies *after* the merge so the user
    sees a stable order across pages.

    The API caller pre-validates ``workspace_id`` ownership; this
    function trusts it.
    """
    sources: set[str] = set(source_filter or ()) or set()

    # ── findings (DAST + SCA) ────────────────────────────────────
    f_rows: list[UnifiedFindingRow] = []
    if not sources or sources & {"dast", "sca"}:
        # Join through Scan to enforce workspace ownership and (optionally)
        # filter to a specific target.
        q = (
            select(DbFinding, Scan.target_id)
            .join(Scan, Scan.id == DbFinding.scan_id)
            .where(Scan.workspace_id == workspace_id)
        )
        if target_id:
            q = q.where(Scan.target_id == target_id)
        if severity:
            q = q.where(DbFinding.severity == severity.lower())
        if reachability:
            q = q.where(DbFinding.reachability == reachability.lower())
        if not include_suppressed:
            q = q.where(DbFinding.suppressed.is_(False))
        result = (await session.execute(q)).all()
        for f, t_id in result:
            row = _project_finding(f, workspace_id=workspace_id, target_id=t_id)
            if sources and row.source not in sources:
                continue
            f_rows.append(row)

    # ── repo_findings (SAST + SCA + secrets + IaC) ──────────────
    r_rows: list[UnifiedFindingRow] = []
    if not sources or sources & {"sast", "sca", "iac", "secret"}:
        q2 = (
            select(RepoFinding)
            .join(RepoScan, RepoScan.id == RepoFinding.repo_scan_id)
            .join(Repository, Repository.id == RepoFinding.repository_id)
            .where(Repository.workspace_id == workspace_id)
        )
        if target_id:
            # Repo findings tie to a target only via the
            # target_repositories junction. Scope by it when present.
            q2 = q2.join(
                TargetRepository,
                TargetRepository.repository_id == RepoFinding.repository_id,
            ).where(TargetRepository.target_id == target_id)
        if severity:
            q2 = q2.where(RepoFinding.severity == severity.lower())
        if not include_suppressed:
            q2 = q2.where(RepoFinding.suppressed.is_(False))
        rs = (await session.execute(q2)).scalars().all()
        for r in rs:
            row = _project_repo_finding(r, workspace_id=workspace_id)
            if sources and row.source not in sources:
                continue
            # ``reachability`` filter only meaningful for findings table;
            # repo_findings carry no reachability today, so skip the row
            # when the user filters on it.
            if reachability and row.reachability != reachability.lower():
                continue
            r_rows.append(row)

    merged = f_rows + r_rows
    merged.sort(key=_sort_key, reverse=False)
    total = len(merged)
    paged = merged[offset: offset + limit] if limit > 0 else merged
    return paged, total


def _sort_key(row: UnifiedFindingRow) -> tuple:
    """Sort key — primary risk_score DESC, then severity rank, then
    created_at DESC. Negation flips numeric DESC under the natural sort.
    """
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        row.severity, 9,
    )
    return (-row.risk_score, sev_rank, -row.created_at.timestamp())
