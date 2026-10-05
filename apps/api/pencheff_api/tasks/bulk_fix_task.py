"""Celery task that runs the bulk fix-all engine asynchronously.

The router enqueues this with a ``BulkFixTask.id``; the worker picks
the row up, gathers the finding list (DAST scan or repo scan), runs
:func:`pencheff_api.services.bulk_fix.run_bulk_fix_engine` with a
progress callback that writes ``completed_findings`` back to the row,
then stores the final ``BulkFixSummary`` JSON in ``results``.

Why the worker re-resolves findings (instead of the router pre-fetching
and pickling them):

  * Pickle-safe Celery tasks must use JSON-serialisable args, and
    SQLAlchemy rows aren't.
  * Re-resolving from ``scan_id`` / ``repo_scan_id`` keeps the worker
    insulated from schema drift between API and worker images during
    rolling deploys.

Auth: the API has already verified ownership before inserting the
``BulkFixTask`` row; the worker trusts the row's ``org_id`` /
``workspace_id`` / ``user_id`` and acts on behalf of that user.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..config import get_settings
from ..db.models import (
    BulkFixTask,
    Finding as DbFinding,
    RepoFinding,
    RepoScan,
    Scan,
    User,
    Workspace,
)
from ..services.bulk_fix import BulkFixCancelled, run_bulk_fix_engine
from .celery_app import celery_app

log = logging.getLogger(__name__)


# Worker-local engine. Reused across tasks in the same process so we
# don't churn connections; the API process has its own engine in
# ``db/base.py``.
_settings = get_settings()
_engine = create_async_engine(_settings.database_url, pool_pre_ping=True, future=True)
_Session = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)


@celery_app.task(name="pencheff.fix.bulk")
def run_bulk_fix(task_id: str) -> None:
    """Sync Celery entrypoint — bridges to the async pipeline."""
    asyncio.run(_run_bulk_fix_async(task_id))


async def _run_bulk_fix_async(task_id: str) -> None:
    # Step 1 — load the BulkFixTask row, mark it ``running``, snapshot
    # the workspace/user ids and the finding list. Short-lived session
    # so no lock is held during the long engine call.
    async with _Session() as db:
        task = await db.get(BulkFixTask, task_id)
        if task is None:
            log.warning("bulk_fix_task %s not found — dropping", task_id)
            return
        if task.status not in ("queued", "running"):
            log.info(
                "bulk_fix_task %s already in terminal state %s — skipping",
                task_id, task.status,
            )
            return
        task.status = "running"
        await db.commit()

        workspace_id = task.workspace_id
        user_id = task.user_id
        # Capture ids now; ORM objects become detached when the session
        # closes so we re-load them in the engine session below.
        workspace_check = await db.get(Workspace, workspace_id)
        user_check = await db.get(User, user_id)
        if workspace_check is None or user_check is None:
            task.status = "failed"
            task.error = "workspace or user no longer exists"
            task.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return
        # Resolve the finding list inside this same session (cheap).
        findings = await _collect_findings(db, task)
        task.total_findings = len(findings)
        await db.commit()

    # Step 2 — run the engine on its own dedicated session so the
    # progress callback can operate on a separate session without
    # interleaving with the engine's mid-transaction state.
    progress_cb = _build_progress_callback(task_id)
    cancel_cb = _build_cancel_callback(task_id)

    try:
        async with _Session() as engine_db:
            # Re-load workspace + user inside this session so the
            # engine's ORM operations see them attached.
            workspace = await engine_db.get(Workspace, workspace_id)
            user = await engine_db.get(User, user_id)
            summary = await run_bulk_fix_engine(
                session=engine_db,
                workspace=workspace,
                user=user,
                findings=findings,
                progress_cb=progress_cb,
                cancel_cb=cancel_cb,
            )
    except BulkFixCancelled:
        async with _Session() as db:
            t = await db.get(BulkFixTask, task_id)
            if t is not None and t.status in ("queued", "running", "canceled"):
                t.status = "canceled"
                t.error = "canceled by user"
                t.completed_at = datetime.now(timezone.utc)
                await db.commit()
        return
    except Exception as exc:  # noqa: BLE001
        log.exception("bulk_fix_task %s crashed: %s", task_id, exc)
        async with _Session() as db:
            t = await db.get(BulkFixTask, task_id)
            if t is not None:
                t.status = "failed"
                t.error = f"{type(exc).__name__}: {exc!s}"
                t.completed_at = datetime.now(timezone.utc)
                await db.commit()
        return

    # Step 3 — persist the final summary.
    async with _Session() as db:
        t = await db.get(BulkFixTask, task_id)
        if t is None:
            return
        t.status = "completed"
        t.results = summary.model_dump()
        t.completed_findings = t.total_findings  # engine processed all
        t.completed_at = datetime.now(timezone.utc)
        await db.commit()


async def _collect_findings(
    db: AsyncSession, task: BulkFixTask,
) -> list[tuple[str, str, str | None, str | None]]:
    """Resolve which findings this task should process. Mirrors the
    router-side queries; kept here so the worker is self-contained."""
    if task.scan_id is not None:
        scan = await db.get(Scan, task.scan_id)
        if scan is None:
            return []
        rows = (await db.execute(
            select(DbFinding.id, DbFinding.category)
            .where(
                DbFinding.scan_id == task.scan_id,
                DbFinding.suppressed.is_(False),
            )
        )).all()
        result: list[tuple[str, str, str | None, str | None]] = []
        for fid, category in rows:
            kind = "sast" if category == "sast" else "dast"
            result.append((kind, fid, task.scan_id, None))
        return result

    if task.repo_scan_id is not None:
        rs = await db.get(RepoScan, task.repo_scan_id)
        if rs is None:
            return []
        rows = (await db.execute(
            select(RepoFinding.id).where(RepoFinding.repo_scan_id == task.repo_scan_id)
        )).scalars().all()
        return [("sast", fid, None, task.repo_scan_id) for fid in rows]

    return []


def _build_progress_callback(task_id: str):
    """Return a callback that writes (completed, total) to the task
    row. Uses a fresh short-lived session per call so the engine's
    long-running session isn't disturbed.

    Errors here are best-effort — losing a progress update doesn't
    invalidate the run, so we swallow exceptions and move on.
    """
    async def _cb(completed: int, total: int) -> None:
        try:
            async with _Session() as db:
                t = await db.get(BulkFixTask, task_id)
                if t is None:
                    return
                t.completed_findings = completed
                t.total_findings = total
                await db.commit()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "bulk_fix_task %s: progress update failed (%d/%d): %s",
                task_id, completed, total, exc,
            )

    return _cb


def _build_cancel_callback(task_id: str):
    async def _cb() -> bool:
        try:
            async with _Session() as db:
                t = await db.get(BulkFixTask, task_id)
                return bool(t and t.status == "canceled")
        except Exception:  # noqa: BLE001
            return False

    return _cb
