"""Endpoints for the propose-fix → open-PR flow.

Routes:
  * ``POST   /findings/{kind}/{id}/propose_fix``  — generate a draft proposal
  * ``GET    /findings/{kind}/{id}/fix_proposal`` — fetch latest non-superseded
  * ``GET    /fix-proposals/{id}``                — fetch one
  * ``POST   /fix-proposals/{id}/apply``          — open PR / branch+commit
  * ``DELETE /fix-proposals/{id}``                — supersede (lets the user
    re-run the proposer)
  * ``GET    /usage/fix-llm``                     — quota snapshot for UI strip
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, get_current_user, require_scope
from ..db.base import get_session
from ..db.models import (
    BulkFixTask,
    Finding as DbFinding,
    FixProposal,
    RepoFinding,
    Repository,
    User,
    Workspace,
)
from ..schemas.fix_proposals import (
    ApplyResultOut,
    FixProposalOut,
    FixUsageOut,
    ProposeFixRequest,
)
from ..services import fix_applier, fix_proposer, fix_quota
from ..services.worker_lifecycle import ensure_worker_started_for_enqueue_sync

log = logging.getLogger(__name__)

router = APIRouter(tags=["fix-proposals"])


# ── Helpers ─────────────────────────────────────────────────────────


def _to_out(p: FixProposal, *, notice: str | None = None) -> FixProposalOut:
    return FixProposalOut(
        notice=notice,
        id=p.id,
        finding_kind=p.finding_kind,  # type: ignore[arg-type]
        finding_id=p.finding_id,
        repository_id=p.repository_id,
        status=p.status,  # type: ignore[arg-type]
        source=p.source,  # type: ignore[arg-type]
        diff=p.diff,
        target_files=list(p.target_files or []),
        provenance_confidence=p.provenance_confidence,
        provenance_reasoning=p.provenance_reasoning,
        llm_input_tokens=p.llm_input_tokens,
        llm_output_tokens=p.llm_output_tokens,
        cost_usd=p.cost_usd,
        branch_name=p.branch_name,
        pr_url=p.pr_url,
        commit_sha=p.commit_sha,
        error=p.error,
        created_at=p.created_at,
        applied_at=p.applied_at,
    )


async def _verify_finding_in_workspace(
    session: AsyncSession,
    *,
    finding_kind: str,
    finding_id: str,
    workspace_id: str,
) -> tuple[str | None, str | None]:
    """Confirm the finding belongs to the active workspace, returning
    ``(scan_id, repo_scan_id)`` for proposal bookkeeping."""
    if finding_kind == "dast":
        from ..db.models import Scan
        f = (await session.execute(
            select(DbFinding).where(DbFinding.id == finding_id)
        )).scalar_one_or_none()
        if f is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
        scan = (await session.execute(
            select(Scan).where(Scan.id == f.scan_id)
        )).scalar_one_or_none()
        if scan is None or scan.workspace_id != workspace_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not in workspace")
        return scan.id, None
    if finding_kind == "sast":
        # SAST findings produced via attach-to-URL flow live in DbFinding;
        # standalone repo-scans live in RepoFinding. Support both.
        f = (await session.execute(
            select(DbFinding).where(DbFinding.id == finding_id)
        )).scalar_one_or_none()
        if f is not None:
            from ..db.models import Scan
            scan = (await session.execute(
                select(Scan).where(Scan.id == f.scan_id)
            )).scalar_one_or_none()
            if scan is None or scan.workspace_id != workspace_id:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not in workspace")
            return scan.id, None
        rf = (await session.execute(
            select(RepoFinding).where(RepoFinding.id == finding_id)
        )).scalar_one_or_none()
        if rf is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
        if rf.workspace_id != workspace_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not in workspace")
        return None, rf.repo_scan_id
    raise HTTPException(status.HTTP_400_BAD_REQUEST, "kind must be sast or dast")


# ── Propose ─────────────────────────────────────────────────────────


@router.post(
    "/findings/{kind}/{finding_id}/propose_fix",
    response_model=FixProposalOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def propose_fix(
    kind: str = Path(..., pattern=r"^(sast|dast)$"),
    finding_id: str = Path(...),
    body: ProposeFixRequest = ProposeFixRequest(),
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FixProposalOut:
    scan_id, repo_scan_id = await _verify_finding_in_workspace(
        session, finding_kind=kind, finding_id=finding_id,
        workspace_id=workspace.id,
    )

    # Mark any existing draft as superseded so we never have two open drafts
    # for the same finding.
    existing = (await session.execute(
        select(FixProposal).where(
            FixProposal.finding_kind == kind,
            FixProposal.finding_id == finding_id,
            FixProposal.org_id == workspace.org_id,
            FixProposal.status == "draft",
        )
    )).scalars().all()
    for old in existing:
        old.status = "superseded"
    if existing:
        await session.flush()

    req = fix_proposer.ProposalRequest(
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        user_id=user.id,
        finding_kind=kind,
        finding_id=finding_id,
        scan_id=scan_id,
        repo_scan_id=repo_scan_id,
        allow_payg=body.allow_payg,
    )
    try:
        proposal, notice = await fix_proposer.propose_fix(session, req)
    except fix_quota.QuotaExceeded as qe:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            {"reason": qe.reason, "message": qe.message},
        )
    except fix_proposer.ProposerError as pe:
        if pe.code == "payg_confirmation_required":
            raise HTTPException(
                status.HTTP_402_PAYMENT_REQUIRED,
                {"reason": pe.code, "message": pe.message},
            )
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            {"reason": pe.code, "message": pe.message})

    if proposal.id is None:
        # propose_fix added the row but only flushed for LLM path; ensure
        # scanner-source proposals are committed-ready too.
        session.add(proposal)
        await session.flush()
    await session.commit()
    await session.refresh(proposal)
    return _to_out(proposal, notice=notice)


@router.get(
    "/findings/{kind}/{finding_id}/fix_proposal",
    response_model=FixProposalOut | None,
    dependencies=[Depends(require_scope("fix_proposals:read"))],
)
async def get_latest_proposal(
    kind: str = Path(..., pattern=r"^(sast|dast)$"),
    finding_id: str = Path(...),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FixProposalOut | None:
    p = (await session.execute(
        select(FixProposal)
        .where(
            FixProposal.finding_kind == kind,
            FixProposal.finding_id == finding_id,
            FixProposal.org_id == workspace.org_id,
            FixProposal.status != "superseded",
        )
        .order_by(FixProposal.created_at.desc())
        .limit(1)
    )).scalar_one_or_none()
    return _to_out(p) if p else None


# ── Get / delete one ────────────────────────────────────────────────


@router.get(
    "/fix-proposals/{proposal_id}",
    response_model=FixProposalOut,
    dependencies=[Depends(require_scope("fix_proposals:read"))],
)
async def get_proposal(
    proposal_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FixProposalOut:
    p = (await session.execute(
        select(FixProposal).where(
            FixProposal.id == proposal_id,
            FixProposal.org_id == workspace.org_id,
        )
    )).scalar_one_or_none()
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "proposal not found")
    return _to_out(p)


@router.delete(
    "/fix-proposals/{proposal_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def supersede_proposal(
    proposal_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    p = (await session.execute(
        select(FixProposal).where(
            FixProposal.id == proposal_id,
            FixProposal.org_id == workspace.org_id,
        )
    )).scalar_one_or_none()
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "proposal not found")
    if p.status == "applied":
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Cannot supersede an applied proposal.")
    p.status = "superseded"
    await session.commit()


# ── Apply ───────────────────────────────────────────────────────────


@router.post(
    "/fix-proposals/{proposal_id}/apply",
    response_model=ApplyResultOut,
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def apply_proposal(
    proposal_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ApplyResultOut:
    p = (await session.execute(
        select(FixProposal).where(
            FixProposal.id == proposal_id,
            FixProposal.org_id == workspace.org_id,
        )
    )).scalar_one_or_none()
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "proposal not found")
    if p.status not in ("draft", "failed"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"Cannot apply a proposal in status={p.status}.")
    if not p.repository_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Proposal has no associated repository.")
    repo = (await session.execute(
        select(Repository).where(Repository.id == p.repository_id)
    )).scalar_one_or_none()
    if repo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "Repository for this proposal has been deleted.")
    try:
        result = await fix_applier.apply_proposal(session, p, repo)
    except fix_applier.ApplyError as e:
        await session.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            {"reason": e.code, "message": str(e.args[0]) if e.args else e.code})
    await session.commit()
    await session.refresh(p)
    return ApplyResultOut(
        proposal_id=p.id, status=p.status,  # type: ignore[arg-type]
        branch_name=p.branch_name, commit_sha=p.commit_sha,
        pr_url=p.pr_url, error=p.error,
    )


# ── Revert (close PR, delete branch, supersede) ────────────────────


@router.post(
    "/fix-proposals/{proposal_id}/revert",
    response_model=FixProposalOut,
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def revert_proposal_route(
    proposal_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FixProposalOut:
    p = (await session.execute(
        select(FixProposal).where(
            FixProposal.id == proposal_id,
            FixProposal.org_id == workspace.org_id,
        )
    )).scalar_one_or_none()
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "proposal not found")
    if p.repository_id is None:
        # No repo → nothing to revert remotely; just supersede.
        p.status = "superseded"
        await session.commit()
        await session.refresh(p)
        return _to_out(p)
    repo = (await session.execute(
        select(Repository).where(Repository.id == p.repository_id)
    )).scalar_one_or_none()
    if repo is None:
        # Repo gone — best-effort supersede only.
        p.status = "superseded"
        await session.commit()
        await session.refresh(p)
        return _to_out(p)
    await fix_applier.revert_proposal(session, p, repo)
    await session.commit()
    await session.refresh(p)
    return _to_out(p)


# ── Bulk fix (async — Celery worker + status polling) ──────────────


from datetime import datetime, timedelta, timezone

from pydantic import BaseModel
from sqlalchemy import or_

# Re-export so code that previously imported these names from the
# router keeps working (the OpenAPI generator references them via
# ``BulkFixTaskStatusOut.results``).
from ..services.bulk_fix import BulkFixResultOut, BulkFixSummary  # noqa: F401


class BulkFixTaskAcceptedOut(BaseModel):
    """``202 Accepted`` body — frontend polls the GET endpoint with this id."""
    id: str
    status: str  # always ``queued`` here; transitions in the worker
    total_findings: int


class BulkFixTaskStatusOut(BaseModel):
    """Polling response. ``results`` is populated once status is
    terminal (``completed`` or ``failed``)."""
    id: str
    status: str  # queued | running | completed | failed
    total_findings: int
    completed_findings: int
    results: BulkFixSummary | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None


def _enqueue_bulk_fix(task_id: str) -> None:
    """Enqueue the worker task. Imported lazily so the router stays
    importable in environments where Celery isn't fully wired (tests,
    mock setups). Errors here surface immediately so the API caller
    knows the request didn't actually start."""
    ensure_worker_started_for_enqueue_sync()

    from ..tasks.bulk_fix_task import run_bulk_fix
    run_bulk_fix.delay(task_id)


def _task_to_status_out(t: BulkFixTask) -> BulkFixTaskStatusOut:
    results: BulkFixSummary | None = None
    if isinstance(t.results, dict):
        try:
            results = BulkFixSummary.model_validate(t.results)
        except Exception:  # noqa: BLE001 — corrupt JSON shouldn't 500 the poll
            log.warning("bulk_fix_task %s: results JSON is malformed", t.id)
            results = None
    return BulkFixTaskStatusOut(
        id=t.id, status=t.status,
        total_findings=t.total_findings,
        completed_findings=t.completed_findings,
        results=results, error=t.error,
        created_at=t.created_at, updated_at=t.updated_at,
        completed_at=t.completed_at,
    )


@router.post(
    "/scans/{scan_id}/fix-all",
    response_model=BulkFixTaskAcceptedOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def fix_all_for_scan(
    scan_id: str,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> BulkFixTaskAcceptedOut:
    """Enqueue a bulk fix across every open finding in this scan.

    Returns immediately with ``202 Accepted`` and a task id. Poll
    ``GET /fix-tasks/{id}`` for progress + the final summary. Long
    batches no longer time out at the reverse proxy because the
    actual proposing/applying happens in the Celery worker.
    """
    from ..db.models import Scan
    scan = (await session.execute(
        select(Scan).where(Scan.id == scan_id)
    )).scalar_one_or_none()
    if scan is None or scan.workspace_id != workspace.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    total = (await session.execute(
        select(DbFinding.id).where(
            DbFinding.scan_id == scan_id,
            DbFinding.suppressed.is_(False),
        )
    )).scalars().all()
    task = BulkFixTask(
        org_id=workspace.org_id, workspace_id=workspace.id,
        user_id=user.id, scan_id=scan_id, repo_scan_id=None,
        status="queued", total_findings=len(total),
    )
    session.add(task)
    await session.commit()
    await session.refresh(task)
    _enqueue_bulk_fix(task.id)
    return BulkFixTaskAcceptedOut(
        id=task.id, status=task.status, total_findings=task.total_findings,
    )


@router.post(
    "/repo-scans/{repo_scan_id}/fix-all",
    response_model=BulkFixTaskAcceptedOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def fix_all_for_repo_scan(
    repo_scan_id: str,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> BulkFixTaskAcceptedOut:
    """Repo-scan (SAST) variant of ``fix-all``. Same async pattern."""
    from ..db.models import RepoScan
    rs = (await session.execute(
        select(RepoScan).where(RepoScan.id == repo_scan_id)
    )).scalar_one_or_none()
    if rs is None or rs.workspace_id != workspace.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "repo scan not found")
    total = (await session.execute(
        select(RepoFinding.id).where(RepoFinding.repo_scan_id == repo_scan_id)
    )).scalars().all()
    task = BulkFixTask(
        org_id=workspace.org_id, workspace_id=workspace.id,
        user_id=user.id, scan_id=None, repo_scan_id=repo_scan_id,
        status="queued", total_findings=len(total),
    )
    session.add(task)
    await session.commit()
    await session.refresh(task)
    _enqueue_bulk_fix(task.id)
    return BulkFixTaskAcceptedOut(
        id=task.id, status=task.status, total_findings=task.total_findings,
    )


@router.get(
    "/fix-tasks/latest",
    response_model=BulkFixTaskStatusOut | None,
    dependencies=[Depends(require_scope("fix_proposals:read"))],
)
async def get_latest_bulk_fix_task(
    scan_id: str | None = None,
    repo_scan_id: str | None = None,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> BulkFixTaskStatusOut | None:
    """Look up the most-recent bulk-fix task for a given scan or
    repo-scan. Used by the frontend on mount so a refresh mid-run
    re-attaches to the live progress instead of showing a fresh
    "Fix all findings" button while the worker is still processing.

    Returns ``null`` when there's no active or recently-completed task
    for this scope. "Recently-completed" means within 30 minutes —
    older terminal tasks aren't surfaced because the user has already
    seen them and the UI shouldn't keep nagging about a job from
    yesterday.
    """
    # Exactly one of the two query params must be set; FastAPI doesn't
    # express XOR cleanly on Query params so we validate inline.
    if (scan_id is None) == (repo_scan_id is None):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "exactly one of scan_id or repo_scan_id must be provided",
        )

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)
    q = select(BulkFixTask).where(BulkFixTask.workspace_id == workspace.id)
    if scan_id is not None:
        q = q.where(BulkFixTask.scan_id == scan_id)
    else:
        q = q.where(BulkFixTask.repo_scan_id == repo_scan_id)
    q = q.where(
        or_(
            BulkFixTask.status.in_(("queued", "running")),
            BulkFixTask.completed_at >= cutoff,
        )
    ).order_by(BulkFixTask.created_at.desc()).limit(1)

    t = (await session.execute(q)).scalar_one_or_none()
    if t is None:
        return None
    return _task_to_status_out(t)


@router.get(
    "/fix-tasks/{task_id}",
    response_model=BulkFixTaskStatusOut,
    dependencies=[Depends(require_scope("fix_proposals:read"))],
)
async def get_bulk_fix_task(
    task_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> BulkFixTaskStatusOut:
    """Poll for status of an enqueued bulk fix.

    The frontend hits this every ~3s after kicking off ``fix-all`` and
    renders the same summary card as the old synchronous flow once
    ``status`` is ``completed``.
    """
    t = await session.get(BulkFixTask, task_id)
    if t is None or t.workspace_id != workspace.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")
    return _task_to_status_out(t)


@router.post(
    "/fix-tasks/{task_id}/cancel",
    response_model=BulkFixTaskStatusOut,
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def cancel_bulk_fix_task(
    task_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> BulkFixTaskStatusOut:
    t = await session.get(BulkFixTask, task_id)
    if t is None or t.workspace_id != workspace.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")
    if t.status in ("completed", "failed", "canceled"):
        return _task_to_status_out(t)
    t.status = "canceled"
    t.error = "canceled by user"
    t.completed_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(t)
    return _task_to_status_out(t)


# ── Quota strip ─────────────────────────────────────────────────────


@router.get(
    "/usage/fix-llm",
    response_model=FixUsageOut,
    dependencies=[Depends(require_scope("fix_proposals:read"))],
)
async def fix_llm_usage(
    scan_id: str | None = None,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FixUsageOut:
    snap = await fix_quota.snapshot(session, workspace.org_id, scan_id=scan_id)
    return FixUsageOut(
        plan=snap.plan,
        has_fix_access=snap.has_fix_access,
        monthly_cap=snap.monthly_cap,
        monthly_used=snap.monthly_used,
        monthly_remaining=snap.monthly_remaining,
        period_resets_at=snap.period_resets_at,
        beta=snap.beta,
    )
