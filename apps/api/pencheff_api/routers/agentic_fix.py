"""Endpoints for the agentic Fix-all flow.

See ``docs/superpowers/specs/2026-05-23-agentic-fixer-design.md``.

Routes:
* ``POST /fix-tasks/agentic``                — open a new AgenticFixRun
* ``GET  /fix-tasks/agentic/{run_id}``        — current status + last steps
* ``GET  /fix-tasks/agentic/{run_id}/stream`` — SSE: live step events
* ``POST /fix-tasks/agentic/{run_id}/cancel`` — flip the cancel flag
* ``GET  /fix-tasks/agentic/latest``           — re-attach to in-flight run

The Celery task that actually drives the loop lives in
``tasks/agentic_fix_task.py``. This router only owns the
"create row, return id; readers poll/stream" surface — no
synchronous LLM work happens here.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, get_current_user, require_scope
from ..config import get_settings
from ..db.base import get_session
from ..db.models import (
    AgenticFixRun,
    AgenticFixStep,
    AgenticFixUsage,
    Finding as DbFinding,
    Org,
    RepoFinding,
    RepoScan,
    Repository,
    Scan,
    Target,
    TargetRepository,
    User,
    Workspace,
)
from ..services import repo_link, upload_storage
from ..services.agentic_fixer import billing
from ..services.worker_lifecycle import ensure_worker_started_or_503

log = logging.getLogger(__name__)

router = APIRouter(tags=["agentic-fix"])


# ── Schemas ─────────────────────────────────────────────────────────


class StartAgenticRunRequest(BaseModel):
    """One of ``scan_id`` or ``repo_scan_id`` must be set. ``runtime``
    defaults to ``server`` for cloud-provider repos and is required to
    be ``desktop`` for local-provider repos (the API container can't
    see local paths)."""
    scan_id: str | None = None
    repo_scan_id: str | None = None
    repository_id: str | None = None
    finding_ids: list[str] | None = None
    runtime: str = "server"  # "server" | "desktop"


class AgenticRunOut(BaseModel):
    id: str
    runtime: str
    status: str
    findings_count: int
    iterations: int
    current_step: str | None
    branch_name: str | None
    pr_url: str | None
    error: str | None
    repository_id: str | None
    model: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    cancel_requested: bool


class AgenticRunDetailOut(AgenticRunOut):
    """Detail view: includes the last N tool-call steps + usage rollup."""
    recent_steps: list["AgenticStepOut"] = []
    usage_total_input_tokens: int = 0
    usage_total_output_tokens: int = 0
    usage_total_cost_cents: int = 0


class AgenticStepOut(BaseModel):
    iteration: int
    step_index: int
    tool_name: str
    tool_input: dict | None
    tool_error: str | None
    duration_ms: int
    created_at: datetime


class AgenticUsageOut(BaseModel):
    """Per-workspace concurrency snapshot. Drives the FixAllSheet's
    in-flight indicator and Run button gating."""
    plan: str
    in_flight_runs: int
    max_concurrent_runs: int
    can_start: bool
    block_reason: str | None


class AgenticStepIngestRequest(BaseModel):
    """Tool-call audit row posted by the desktop runtime. The server
    inserts the row exactly as supplied; ``tool_output_truncated``
    and ``tool_error`` are 8 KiB-capped + redacted on the desktop
    before send (matching the server-side workers's behaviour).
    """
    iteration: int
    step_index: int
    tool_name: str
    tool_input: dict | None = None
    tool_output_truncated: str | None = None
    tool_error: str | None = None
    duration_ms: int = 0


class AgenticFinishRequest(BaseModel):
    """Terminal status update from the desktop runtime. Exactly one
    of ``done`` / ``failed`` / ``canceled`` is expected; the server
    rejects re-finishing an already-terminal row.
    """
    status: str  # "done" | "failed" | "canceled"
    branch_name: str | None = None
    pr_url: str | None = None
    error: str | None = None
    current_step: str | None = None


# ── Helpers ─────────────────────────────────────────────────────────


def _run_to_out(r: AgenticFixRun) -> AgenticRunOut:
    return AgenticRunOut(
        id=r.id,
        runtime=r.runtime,
        status=r.status,
        findings_count=r.findings_count,
        iterations=r.iterations,
        current_step=r.current_step,
        branch_name=r.branch_name,
        pr_url=r.pr_url,
        error=r.error,
        repository_id=getattr(r, "repository_id", None),
        model=r.model,
        created_at=r.created_at,
        started_at=r.started_at,
        completed_at=r.completed_at,
        cancel_requested=r.cancel_requested,
    )


def _step_to_out(s: AgenticFixStep) -> AgenticStepOut:
    return AgenticStepOut(
        iteration=s.iteration,
        step_index=s.step_index,
        tool_name=s.tool_name,
        tool_input=s.tool_input,
        tool_error=s.tool_error,
        duration_ms=s.duration_ms,
        created_at=s.created_at,
    )


async def _load_run(session: AsyncSession, run_id: str, workspace_id: str) -> AgenticFixRun:
    row = (await session.execute(
        select(AgenticFixRun).where(
            AgenticFixRun.id == run_id,
            AgenticFixRun.workspace_id == workspace_id,
        )
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agentic fix run not found")
    return row


async def _backfill_attached_repos(*, session, target, workspace, requery):
    """Lazy bridge: a source_code target with a GitHub URL + PAT gets a connected
    Repository auto-linked on first fix, so pre-existing targets work without
    re-registering. ``requery`` re-runs the attached-repos query. Best-effort."""
    linked = await repo_link.ensure_repo_link_for_target(session, target, workspace)
    if linked is None:
        return []
    return list(await requery())


async def _scan_findings_count(session: AsyncSession, scan_id: str) -> int:
    return (await session.execute(
        select(DbFinding).where(
            DbFinding.scan_id == scan_id,
            DbFinding.suppressed.is_(False),
        )
    )).scalars().fetchall().__len__()


async def _repo_scan_findings_count(session: AsyncSession, scan_id: str) -> int:
    return (await session.execute(
        select(RepoFinding).where(
            RepoFinding.repo_scan_id == scan_id,
            RepoFinding.suppressed.is_(False),
        )
    )).scalars().fetchall().__len__()


async def _selected_finding_ids(
    session: AsyncSession, model, parent_column, parent_id: str,
    requested_ids: list[str] | None,
) -> tuple[int, list[str] | None]:
    """Validate a requested subset against the scan and return its count.

    ``None`` preserves the legacy select-all behavior for older clients.
    """
    if requested_ids is None:
        return 0, None
    normalized = list(dict.fromkeys(requested_ids))
    if not normalized:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Select at least one finding to remediate.")
    rows = (await session.execute(
        select(model.id).where(
            parent_column == parent_id,
            model.suppressed.is_(False),
            model.id.in_(normalized),
        )
    )).scalars().all()
    valid = {str(row_id) for row_id in rows}
    if len(valid) != len(normalized):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "One or more selected findings are not open findings in this scan.",
        )
    return len(valid), normalized


# ── POST /fix-tasks/agentic ─────────────────────────────────────────


@router.post(
    "/fix-tasks/agentic",
    response_model=AgenticRunOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def start_agentic_run(
    body: StartAgenticRunRequest,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> AgenticRunOut:
    """Open a new agentic fix run. Returns immediately with the row;
    the Celery task picks it up asynchronously (for runtime=server),
    or the desktop client begins driving the loop (for runtime=desktop).
    """
    s = get_settings()
    if not s.agentic_fix_enabled:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Agentic Fix-all is disabled on this deployment. "
            "Set AGENTIC_FIX_ENABLED=true and AGENTIC_FIX_API_KEY in "
            "the API + worker environment, then restart both containers.",
        )
    if not s.agentic_fix_effective_api_key:
        # Make the failure mode obvious BEFORE we open the row.
        # Effective key check picks up AGENTIC_FIX_API_KEY first,
        # then falls back to AGENT_FALLBACK_LLM_API_KEY — most
        # deployments already have the latter set.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Agentic Fix-all is not configured on this deployment. "
            "Set AGENTIC_FIX_API_KEY (or reuse the existing "
            "AGENT_FALLBACK_LLM_API_KEY) in the API + worker "
            "environment, then restart both containers.",
        )

    if (body.scan_id is None) == (body.repo_scan_id is None):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Exactly one of scan_id or repo_scan_id must be set.",
        )

    runtime = body.runtime if body.runtime in ("server", "desktop") else "server"
    findings_count = 0
    selected_finding_ids = body.finding_ids
    repo_provider: str | None = None
    repository_id: str | None = None

    if body.scan_id is not None:
        scan = (await session.execute(
            select(Scan).where(
                Scan.id == body.scan_id,
                Scan.workspace_id == workspace.id,
            )
        )).scalar_one_or_none()
        if scan is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
        if selected_finding_ids is None:
            findings_count = await _scan_findings_count(session, body.scan_id)
        else:
            findings_count, selected_finding_ids = await _selected_finding_ids(
                session, DbFinding, DbFinding.scan_id, body.scan_id,
                selected_finding_ids,
            )
        _tgt = (await session.execute(
            select(Target).where(Target.id == scan.target_id)
        )).scalar_one_or_none()
        _tcfg = dict((_tgt.kind_config if _tgt else None) or {})
        if (
            _tgt is not None
            and _tgt.kind == "source_code"
            and _tcfg.get("source") == "upload"
        ):
            # Uploaded source: no git repo — the fixer edits the extracted tree
            # and returns a downloadable .zip (agentic_fix_task upload path).
            if not upload_storage.storage_configured():
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "Upload storage (R2) is not configured on this deployment.",
                )
            repository_id = None
            repo_provider = None
        else:
            repo_stmt = (
                select(Repository)
                .join(TargetRepository, TargetRepository.repository_id == Repository.id)
                .where(
                    TargetRepository.target_id == scan.target_id,
                    Repository.workspace_id == workspace.id,
                )
                .order_by(Repository.full_name)
            )
            if body.repository_id:
                repo_stmt = repo_stmt.where(Repository.id == body.repository_id)
            attached_repos = (await session.execute(repo_stmt)).scalars().all()
            if body.repository_id and not attached_repos:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "Selected repository is not attached to this scan's target.",
                )
            if not attached_repos:
                async def _requery():
                    return (await session.execute(repo_stmt)).scalars().all()

                if _tgt is not None:
                    attached_repos = await _backfill_attached_repos(
                        session=session, target=_tgt, workspace=workspace,
                        requery=_requery,
                    )
            if not attached_repos:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "Attach a source repository to this target before running Agent fix.",
                )
            if len(attached_repos) > 1:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "Select one attached repository for this Agent fix run.",
                )
            repo = attached_repos[0]
            repository_id = repo.id
            repo_provider = repo.provider
    else:
        if body.repository_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "repository_id is only valid when scan_id is set.",
            )
        rs = (await session.execute(
            select(RepoScan).where(
                RepoScan.id == body.repo_scan_id,
                RepoScan.workspace_id == workspace.id,
            )
        )).scalar_one_or_none()
        if rs is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "repo scan not found")
        if selected_finding_ids is None:
            findings_count = await _repo_scan_findings_count(session, body.repo_scan_id)
        else:
            findings_count, selected_finding_ids = await _selected_finding_ids(
                session, RepoFinding, RepoFinding.repo_scan_id, body.repo_scan_id,
                selected_finding_ids,
            )
        # Look up the underlying repo's provider so we can refuse the
        # impossible combination of (local-provider repo) + (server
        # runtime) — the API container can't see the user's local path.
        repo = (await session.execute(
            select(Repository).where(Repository.id == rs.repository_id)
        )).scalar_one_or_none()
        if repo is not None:
            repo_provider = repo.provider

    if repo_provider == "local" and runtime == "server":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "This repo is local-provider; runtime must be 'desktop' so the "
            "Pencheff Studio agent can run against the local files.",
        )

    if findings_count == 0:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Nothing to fix: the target scan has no open findings.",
        )

    # Resolve the org's plan tier for billing limits.
    org = (await session.execute(
        select(Org).where(Org.id == workspace.org_id)
    )).scalar_one_or_none()
    plan = (org.plan if org else "free") or "free"

    # Pre-flight concurrency check. Surfaces as 429 with the specific
    # code so the UI can render the right CTA (wait-for-running-run).
    check = await billing.check_can_start(
        session=session, workspace_id=workspace.id, plan=plan,
    )
    if not check.allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": check.code,
                "message": check.message,
                "plan": check.plan,
                "in_flight_runs": check.in_flight_runs,
                "max_concurrent_runs": check.max_concurrent_runs,
            },
        )

    # ponytail: CE is credit-free (single-tenant) — no AI credit gate.
    # Use the plan's iteration cap if it's tighter than the global
    # default — so a free-plan workspace can't sneak in a 30-iter run.
    iter_cap = min(
        s.agentic_fix_max_iterations,
        billing.limits_for_plan(plan).max_iterations,
    )

    if runtime == "server":
        await ensure_worker_started_or_503()

    run = AgenticFixRun(
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        user_id=user.id,
        scan_id=body.scan_id,
        repo_scan_id=body.repo_scan_id,
        repository_id=repository_id,
        runtime=runtime,
        status="queued",
        findings_count=findings_count,
        selected_finding_ids=selected_finding_ids,
        model=s.agentic_fix_effective_model,
        max_iterations=iter_cap,
    )
    session.add(run)
    await session.commit()
    await session.refresh(run)

    if runtime == "server":
        # Lazy import so the API doesn't pull in Celery during boot.
        from ..tasks.agentic_fix_task import run_agentic_fix_task
        run_agentic_fix_task.delay(run.id)
    # Desktop runtime: the client polls /fix-tasks/agentic/{id} and
    # drives its own loop, posting per-step audit rows via internal
    # endpoints (added in a follow-up task).

    return _run_to_out(run)


# ── Literal-path GETs ───────────────────────────────────────────────
#
# These two MUST be declared before the ``/{run_id}`` parametric
# route — FastAPI matches in registration order, and ``{run_id}``
# would otherwise swallow ``/latest`` and ``/usage`` (treating each
# literal as a UUID value, which then 500s on the DB lookup).


@router.get(
    "/fix-tasks/agentic/latest",
    response_model=AgenticRunOut | None,
    dependencies=[Depends(require_scope("fix_proposals:read"))],
)
async def latest_agentic_run(
    scan_id: str | None = None,
    repo_scan_id: str | None = None,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> AgenticRunOut | None:
    """Return the most-recent run for the given scan / repo-scan, or
    null. Used by the FixAllSheet on mount to re-attach to in-flight
    runs (so a refresh mid-execution shows live status, not a fresh
    "Start" button)."""
    if (scan_id is None) == (repo_scan_id is None):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Pass exactly one of scan_id / repo_scan_id.",
        )
    q = select(AgenticFixRun).where(
        AgenticFixRun.workspace_id == workspace.id,
    )
    if scan_id is not None:
        q = q.where(AgenticFixRun.scan_id == scan_id)
    else:
        q = q.where(AgenticFixRun.repo_scan_id == repo_scan_id)
    q = q.order_by(desc(AgenticFixRun.created_at)).limit(1)
    row = (await session.execute(q)).scalar_one_or_none()
    return _run_to_out(row) if row is not None else None


@router.get(
    "/fix-tasks/agentic/usage",
    response_model=AgenticUsageOut,
    dependencies=[Depends(require_scope("fix_proposals:read"))],
)
async def get_agentic_usage(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> AgenticUsageOut:
    """Snapshot of the workspace's current concurrency state + whether
    a new run can start right now. Used by the FixAllSheet on mount to
    render the "N/M in-flight" indicator and decide whether to dim the
    Run button.
    """
    org = (await session.execute(
        select(Org).where(Org.id == workspace.org_id)
    )).scalar_one_or_none()
    plan = (org.plan if org else "free") or "free"
    check = await billing.check_can_start(
        session=session, workspace_id=workspace.id, plan=plan,
    )
    return AgenticUsageOut(
        plan=check.plan,
        in_flight_runs=check.in_flight_runs,
        max_concurrent_runs=check.max_concurrent_runs,
        can_start=check.allowed,
        block_reason=None if check.allowed else check.code,
    )


# ── GET /fix-tasks/agentic/{run_id}/download (source="upload" fixed .zip) ────


@router.get(
    "/fix-tasks/agentic/{run_id}/download",
    dependencies=[Depends(require_scope("fix_proposals:read"))],
)
async def download_fixed_zip(
    run_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Presigned URL for the agent-fixed .zip produced by an upload-source run.
    Key is deterministic (fixes/<run_id>/fixed.zip); 404 until it exists."""
    from starlette.concurrency import run_in_threadpool

    run = await session.get(AgenticFixRun, run_id)
    if run is None or run.workspace_id != workspace.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    key = f"fixes/{run_id}/fixed.zip"
    if not upload_storage.storage_configured() or not await run_in_threadpool(
        upload_storage.object_exists, key
    ):
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "no fixed archive for this run yet"
        )
    url = await run_in_threadpool(
        lambda: upload_storage.presigned_get(
            key, download_name="pencheff-fixed.zip"
        )
    )
    return {"url": url}


# ── GET /fix-tasks/agentic/{run_id} ─────────────────────────────────


@router.get(
    "/fix-tasks/agentic/{run_id}",
    response_model=AgenticRunDetailOut,
    dependencies=[Depends(require_scope("fix_proposals:read"))],
)
async def get_agentic_run(
    run_id: str,
    step_limit: int = Query(50, ge=1, le=500),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> AgenticRunDetailOut:
    run = await _load_run(session, run_id, workspace.id)
    steps = (await session.execute(
        select(AgenticFixStep)
        .where(AgenticFixStep.run_id == run_id)
        .order_by(desc(AgenticFixStep.created_at))
        .limit(step_limit)
    )).scalars().all()

    usage_rows = (await session.execute(
        select(AgenticFixUsage).where(AgenticFixUsage.run_id == run_id)
    )).scalars().all()
    total_in = sum(u.input_tokens for u in usage_rows)
    total_out = sum(u.output_tokens for u in usage_rows)
    total_cents = sum(u.cost_usd_cents for u in usage_rows)

    base = _run_to_out(run)
    return AgenticRunDetailOut(
        **base.model_dump(),
        recent_steps=[_step_to_out(s) for s in reversed(steps)],
        usage_total_input_tokens=total_in,
        usage_total_output_tokens=total_out,
        usage_total_cost_cents=total_cents,
    )


# ── POST /fix-tasks/agentic/{run_id}/cancel ─────────────────────────


@router.post(
    "/fix-tasks/agentic/{run_id}/cancel",
    response_model=AgenticRunOut,
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def cancel_agentic_run(
    run_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> AgenticRunOut:
    run = await _load_run(session, run_id, workspace.id)
    if run.status in ("done", "failed", "canceled"):
        # Terminal — no-op cancel returns the row unchanged.
        return _run_to_out(run)
    run.cancel_requested = True
    await session.commit()
    await session.refresh(run)
    return _run_to_out(run)


# ── POST /fix-tasks/agentic/{run_id}/step ──────────────────────────


@router.post(
    "/fix-tasks/agentic/{run_id}/step",
    response_model=AgenticStepOut,
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def ingest_agentic_step(
    run_id: str,
    body: AgenticStepIngestRequest,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> AgenticStepOut:
    """Insert a tool-call audit row from the desktop runtime.

    The desktop drives its own tool dispatcher (see
    ``pencheff-studio/.../LocalScan/Agent/DesktopAgentTools.swift``)
    and the proxy doesn't see individual tool calls — only the LLM
    requests. This endpoint lets the desktop ship each tool dispatch
    audit row so the UI's progress stream + the AuditLog still see
    them in real time.
    """
    run = await _load_run(session, run_id, workspace.id)
    if run.runtime != "desktop":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "step ingest is only valid for desktop-runtime runs",
        )
    if run.status in ("done", "failed", "canceled"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"run is already {run.status}",
        )
    step = AgenticFixStep(
        run_id=run.id,
        iteration=body.iteration,
        step_index=body.step_index,
        tool_name=body.tool_name,
        tool_input=body.tool_input,
        tool_output_truncated=body.tool_output_truncated,
        tool_error=body.tool_error,
        duration_ms=body.duration_ms,
    )
    session.add(step)
    # Bump current_step on the run so the UI's poll sees movement
    # between iterations.
    run.current_step = f"iter {body.iteration} · {body.tool_name}"
    if run.status == "queued":
        run.status = "running"
    await session.commit()
    await session.refresh(step)
    return _step_to_out(step)


# ── POST /fix-tasks/agentic/{run_id}/finish ────────────────────────


@router.post(
    "/fix-tasks/agentic/{run_id}/finish",
    response_model=AgenticRunOut,
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def finish_agentic_run(
    run_id: str,
    body: AgenticFinishRequest,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> AgenticRunOut:
    """Terminal status update from the desktop runtime.

    Idempotent on already-terminal rows: re-finishing returns the
    existing row unchanged so a flaky network retry doesn't 409.
    """
    if body.status not in ("done", "failed", "canceled"):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "status must be one of: done, failed, canceled",
        )
    run = await _load_run(session, run_id, workspace.id)
    if run.runtime != "desktop":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "finish is only valid for desktop-runtime runs",
        )
    if run.status in ("done", "failed", "canceled"):
        # Idempotent — return the row unchanged.
        return _run_to_out(run)
    run.status = body.status
    if body.branch_name is not None:
        run.branch_name = body.branch_name
    if body.pr_url is not None:
        run.pr_url = body.pr_url
    if body.error is not None:
        run.error = body.error
    if body.current_step is not None:
        run.current_step = body.current_step
    run.completed_at = datetime.utcnow()
    await session.commit()
    await session.refresh(run)
    return _run_to_out(run)


# ── GET /fix-tasks/agentic/{run_id}/stream ──────────────────────────


@router.get(
    "/fix-tasks/agentic/{run_id}/stream",
    dependencies=[Depends(require_scope("fix_proposals:read"))],
)
async def stream_agentic_run(
    run_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> StreamingResponse:
    """SSE stream of the run's tool-call steps + status changes.

    Implementation here is a polling loop over ``agentic_fix_steps``
    plus the run row's status. Cheap (1 query per 1.5s), and avoids
    coupling to a pub/sub layer for v1. Switch to NOTIFY/LISTEN in a
    later pass if the polling load shows up in profiles.
    """
    await _load_run(session, run_id, workspace.id)

    async def event_stream():
        last_seen_step_id: str | None = None
        last_status: str | None = None
        terminal = {"done", "failed", "canceled"}
        # Cap total stream lifetime so abandoned connections don't
        # hold a DB session forever.
        max_seconds = 30 * 60  # 30 min
        started = asyncio.get_event_loop().time()

        while True:
            if asyncio.get_event_loop().time() - started > max_seconds:
                yield "event: timeout\ndata: stream lifetime exceeded\n\n"
                return

            # New steps since the last id we saw.
            step_q = (
                select(AgenticFixStep)
                .where(AgenticFixStep.run_id == run_id)
                .order_by(AgenticFixStep.created_at)
            )
            steps = (await session.execute(step_q)).scalars().all()
            for s in steps:
                if last_seen_step_id is not None:
                    if s.id <= last_seen_step_id:
                        continue
                payload = json.dumps({
                    "iteration": s.iteration,
                    "step_index": s.step_index,
                    "tool_name": s.tool_name,
                    "tool_input": s.tool_input,
                    "duration_ms": s.duration_ms,
                    "is_error": s.tool_error is not None,
                })
                yield f"event: step\ndata: {payload}\n\n"
                last_seen_step_id = s.id

            # Status check (might be a terminal flip).
            current = (await session.execute(
                select(AgenticFixRun).where(AgenticFixRun.id == run_id)
            )).scalar_one_or_none()
            if current is None:
                yield "event: error\ndata: run deleted\n\n"
                return
            if current.status != last_status:
                last_status = current.status
                yield (
                    "event: status\n"
                    f"data: {json.dumps({'status': current.status, 'pr_url': current.pr_url})}\n\n"
                )
            if current.status in terminal:
                yield (
                    "event: terminal\n"
                    f"data: {json.dumps({'status': current.status, 'pr_url': current.pr_url, 'error': current.error})}\n\n"
                )
                return

            await asyncio.sleep(1.5)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
