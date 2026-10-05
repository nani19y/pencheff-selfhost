"""Scan-running Celery tasks + zombie-scan recovery."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, text

from ..config import get_settings
from ..services.scan_runner import run_scan_sync
from .celery_app import celery_app


log = logging.getLogger("pencheff.scan_task")


@celery_app.task(name="pencheff.scan.run_full_scan")
def run_full_scan(scan_id: str) -> None:
    """Root span entry for a full scan.

    Every downstream span (HTTP fan-out, tool subprocess, LLM turn,
    audit row) inherits the trace context started here, so a query
    like ``WHERE scan_id = $1`` against ``otel_spans`` returns the
    entire scan timeline. When observability is disabled the span is a
    NoOp and adds no measurable cost.
    """
    try:
        from opentelemetry import trace
        tracer = trace.get_tracer("pencheff.scan")
        with tracer.start_as_current_span(
            "scan.execute",
            attributes={
                "pencheff.scan_id": scan_id,
                "pencheff.scan_kind": "full",
            },
        ):
            run_scan_sync(scan_id)
    except ImportError:
        # OTel SDK absent (observability deps not installed). Run the
        # scan unchanged — the pipeline must never depend on telemetry.
        run_scan_sync(scan_id)


# ── Zombie recovery ──────────────────────────────────────────────────
#
# When a worker dies mid-scan (container rebuild, OOM kill, SIGKILL),
# the ``scans`` row stays in ``status='running'`` forever because nothing
# wrote ``finished_at``. The dashboard shows "In progress · 42%" with
# no way out.
#
# This task is invoked at worker startup (``celery_app._recover_zombies_on_boot``)
# and on a 5-minute cron. It looks for rows that:
#   * are still ``running`` / ``queued``,
#   * started more than ``ZOMBIE_THRESHOLD_MINUTES`` ago (longer than
#     any reasonable scan + a generous buffer for slow targets),
# and marks them ``failed`` with a clear note so the user can move on.

ZOMBIE_THRESHOLD_MINUTES = 120  # 2 hours — past the celery hard time
                                # limit (90m) and any realistic scan.


@celery_app.task(name="pencheff_api.tasks.scan_task.recover_zombie_scans")
def recover_zombie_scans() -> dict[str, int]:
    """Mark long-stuck running scans as failed. Returns ``{scans, repo_scans}``
    counts of rows updated."""
    settings = get_settings()
    # Use the sync DSN form for a one-shot UPDATE — async overhead would
    # dwarf the actual work.
    sync_url = settings.database_url.replace("+asyncpg", "")
    engine = create_engine(sync_url, future=True)
    cutoff = datetime.now(timezone.utc) - timedelta(
        minutes=ZOMBIE_THRESHOLD_MINUTES,
    )
    note = (
        f"Scan abandoned — no worker progress for "
        f"{ZOMBIE_THRESHOLD_MINUTES} minutes. The original task most "
        f"likely died (worker restart, OOM, SIGKILL). Re-run the scan."
    )

    out = {"scans": 0, "repo_scans": 0}
    with engine.begin() as conn:
        # ``scans`` table — main DAST/general scan rows. The failure note
        # lives in ``error``. ``started_at`` is nullable for queued rows;
        # use ``COALESCE(started_at, created_at)`` so the cutoff still
        # catches rows that never advanced past ``queued``.
        scan_count = conn.execute(text("""
            UPDATE scans
            SET status = 'failed',
                finished_at = NOW(),
                error = :note
            WHERE status IN ('running', 'queued')
              AND COALESCE(started_at, created_at) < :cutoff
              AND COALESCE(kind_payload->>'source', '') != 'mcp'
            RETURNING id
        """), {"note": note, "cutoff": cutoff}).rowcount
        out["scans"] = scan_count or 0

        # ``repo_scans`` table — uses ``completed_at`` instead of
        # ``finished_at`` (separate column convention).
        try:
            repo_count = conn.execute(text("""
                UPDATE repo_scans
                SET status = 'failed',
                    completed_at = NOW(),
                    error = :note
                WHERE status IN ('running', 'queued')
                  AND COALESCE(started_at, created_at) < :cutoff
                RETURNING id
            """), {"note": note, "cutoff": cutoff}).rowcount
            out["repo_scans"] = repo_count or 0
        except Exception as exc:  # noqa: BLE001
            log.warning("repo_scans recovery skipped: %s", exc)
            out["repo_scans"] = 0

    if out["scans"] or out["repo_scans"]:
        log.warning(
            "recovered %d zombie scan(s) and %d zombie repo-scan(s)",
            out["scans"], out["repo_scans"],
        )
    return out
