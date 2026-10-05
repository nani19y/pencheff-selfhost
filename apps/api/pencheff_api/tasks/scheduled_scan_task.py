"""Celery Beat-driven dispatcher that enqueues scans whose ``next_run_at`` is due."""

from __future__ import annotations

from ..services.on_demand_scheduler import dispatch_due_scans_sync
from .celery_app import celery_app


@celery_app.task(name="pencheff_api.tasks.scheduled_scan_task.dispatch_due_scans")
def dispatch_due_scans() -> dict[str, int]:
    return dispatch_due_scans_sync()
