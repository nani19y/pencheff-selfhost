"""Email-dispatch Celery tasks.

Two flavours:

* ``send_scan_complete_email_task(scan_id)`` — one-shot, fired from the
  scan_runner finish path when ``Scan.notify_emails`` is populated.
* ``run_weekly_digest()`` — Celery beat target. Walks every Target with
  a non-empty ``weekly_digest_emails`` and every Workspace with one,
  composing per-target and per-workspace digest emails respectively.

All real work goes through ``services.email`` so the Resend client and
HTML/text rendering live in one place.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.models import Scan, Target, Workspace
from ..services import email as email_service
from .celery_app import celery_app


log = logging.getLogger(__name__)


def _sync_engine():
    """Drop the ``+asyncpg`` suffix so SQLAlchemy uses the default sync
    driver (psycopg2) — the only one installed in the worker container.
    Same pattern as ``integration_notify_task._engine()``; using
    ``+psycopg`` (psycopg3) here breaks the worker since that package is
    not in the dependency set."""
    return create_engine(
        get_settings().database_url.replace("+asyncpg", ""),
        future=True,
        pool_pre_ping=True,
    )


def _app_url() -> str:
    s = get_settings()
    return (s.email_app_url or s.web_base_url or "").rstrip("/")


@celery_app.task(name="pencheff_api.tasks.email_task.send_scan_complete_email_task")
def send_scan_complete_email_task(scan_id: str) -> bool:
    """One-shot scan-completion email. Reads recipients off the Scan
    row (set at commission time) and dispatches via Resend.

    Best-effort: returns False on any failure rather than retrying —
    we never want a hung email to block other scan post-processing.
    """
    if not email_service.is_configured():
        log.info("resend not configured — skipping scan-complete email for %s", scan_id)
        return False

    eng = _sync_engine()
    with Session(eng) as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            log.warning("scan %s not found for completion email", scan_id)
            return False
        recipients = scan.notify_emails or []
        if not recipients:
            return False
        if scan.status not in ("done", "failed"):
            log.info("scan %s not in terminal state (%s); skipping email", scan_id, scan.status)
            return False
        target = db.get(Target, scan.target_id) if scan.target_id else None
        target_name = (target.name if target else None) or "Unknown target"
        dashboard_url = f"{_app_url()}/scans/{scan_id}/dashboard"
        # Strip nested non-severity keys from summary before passing to
        # the email renderer — it only wants severity counts.
        summary = scan.summary or {}
        sev_only = {
            k: summary.get(k) or 0
            for k in ("critical", "high", "medium", "low", "info")
        }
        sent = email_service.send_scan_complete_email(
            to=list(recipients),
            target_name=target_name,
            grade=scan.grade,
            status=scan.status,
            summary=sev_only,
            dashboard_url=dashboard_url,
            error=(scan.error or None) if scan.status == "failed" else None,
        )
        return bool(sent)


def _recent_target_scan_summaries(
    db: Session, target_id: str, since: datetime
) -> list[dict]:
    """Most-recent completed scans for a target since `since`."""
    rows = db.execute(
        select(Scan)
        .where(
            Scan.target_id == target_id,
            Scan.finished_at.is_not(None),
            Scan.finished_at >= since,
        )
        .order_by(Scan.finished_at.desc())
        .limit(10)
    ).scalars().all()
    out: list[dict] = []
    for s in rows:
        summary = s.summary or {}
        out.append({
            "id": str(s.id),
            "grade": s.grade,
            "status": s.status,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "summary": {
                k: int(summary.get(k) or 0)
                for k in ("critical", "high", "medium", "low", "info")
            },
        })
    return out


def _latest_target_summary_in_workspace(
    db: Session, workspace_id: str, since: datetime
) -> list[dict]:
    """One row per target — the most recent finished scan in the past
    `since` window. Returns an empty list when nothing is fresh."""
    targets = db.execute(
        select(Target).where(Target.workspace_id == workspace_id)
    ).scalars().all()
    out: list[dict] = []
    for t in targets:
        latest = db.execute(
            select(Scan)
            .where(
                Scan.target_id == t.id,
                Scan.finished_at.is_not(None),
                Scan.finished_at >= since,
            )
            .order_by(Scan.finished_at.desc())
            .limit(1)
        ).scalars().first()
        if latest is None:
            continue
        summary = latest.summary or {}
        out.append({
            "name": t.name,
            "grade": latest.grade,
            "summary": {
                k: int(summary.get(k) or 0)
                for k in ("critical", "high", "medium", "low", "info")
            },
        })
    return out


@celery_app.task(name="pencheff_api.tasks.email_task.run_weekly_digest")
def run_weekly_digest() -> dict:
    """Beat-driven weekly digest. Sends:

    * one ``Weekly digest · {target_name}`` email per Target whose
      ``weekly_digest_emails`` list is non-empty;
    * one ``Weekly digest · {workspace_name}`` rollup email per
      Workspace whose ``weekly_digest_emails`` list is non-empty.

    Both windows look back 7 days from now. Returns a small dict of
    counts for observability.
    """
    if not email_service.is_configured():
        log.info("resend not configured — skipping weekly digest run")
        return {"sent": 0, "skipped_unconfigured": True}

    since = datetime.now(timezone.utc) - timedelta(days=7)
    app_url = _app_url()
    sent_targets = 0
    sent_workspaces = 0

    eng = _sync_engine()
    with Session(eng) as db:
        # Per-target subscriptions.
        targets = db.execute(
            select(Target).where(Target.weekly_digest_emails.is_not(None))
        ).scalars().all()
        for t in targets:
            recipients = t.weekly_digest_emails or []
            if not recipients:
                continue
            scans = _recent_target_scan_summaries(db, t.id, since)
            target_url = f"{app_url}/targets/{t.id}"
            ok = email_service.send_target_weekly_digest(
                to=list(recipients),
                target_name=t.name or "Target",
                scans=scans,
                target_url=target_url,
            )
            if ok:
                sent_targets += 1

        # Per-workspace rollup subscriptions.
        workspaces = db.execute(
            select(Workspace).where(Workspace.weekly_digest_emails.is_not(None))
        ).scalars().all()
        for w in workspaces:
            recipients = w.weekly_digest_emails or []
            if not recipients:
                continue
            target_rows = _latest_target_summary_in_workspace(db, w.id, since)
            workspace_url = f"{app_url}/dashboard"
            ok = email_service.send_workspace_weekly_digest(
                to=list(recipients),
                workspace_name=w.name or "Workspace",
                targets=target_rows,
                app_url=workspace_url,
            )
            if ok:
                sent_workspaces += 1

    log.info(
        "weekly digest dispatched · %d targets · %d workspaces",
        sent_targets, sent_workspaces,
    )
    return {"sent_targets": sent_targets, "sent_workspaces": sent_workspaces}
