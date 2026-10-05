from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.models import Scan, ScanSchedule, Target
from ..scan_categories import category_service
from .scan_dispatch import enqueue_full_scan
from .scheduler import compute_next_run
from .worker_lifecycle import ensure_worker_started_for_enqueue_sync


log = logging.getLogger("pencheff.on_demand_scheduler")


def dispatch_due_scans_sync(
    *,
    database_url: str | None = None,
    start_worker: Callable[[str], None] | None = None,
) -> dict[str, int]:
    settings = get_settings()
    db_url = database_url or settings.sync_database_url
    # ``start_worker`` takes the compose service to start — the fleet is split
    # per category, so a scheduled scan starts its category's worker, not one
    # generic worker.
    starter = start_worker or (
        lambda service: ensure_worker_started_for_enqueue_sync(settings, service)
    )
    engine = create_engine(db_url, future=True)
    dispatched = 0

    try:
        with Session(engine) as db:
            now = datetime.now(timezone.utc)
            due = db.execute(
                select(ScanSchedule).where(
                    ScanSchedule.enabled.is_(True),
                    ScanSchedule.next_run_at.isnot(None),
                    ScanSchedule.next_run_at <= now,
                )
            ).scalars().all()
            if not due:
                return {"dispatched": 0}

            # Resolve each schedule's target kind so we can route to the right
            # category queue/worker. One lookup for the whole batch.
            target_ids = {s.target_id for s in due}
            kind_by_target: dict[str, str] = dict(
                db.execute(
                    select(Target.id, Target.kind).where(Target.id.in_(target_ids))
                ).all()
            )

            # Start every category worker this batch needs BEFORE creating any
            # scan, so a start failure aborts the batch (no schedule advances,
            # no orphaned queued scan). Dedupe so we start each worker once.
            for service in {
                category_service(kind_by_target.get(s.target_id)) for s in due
            }:
                starter(service)

            for schedule in due:
                kind = kind_by_target.get(schedule.target_id)
                scan = Scan(
                    org_id=schedule.org_id,
                    workspace_id=schedule.workspace_id,
                    target_id=schedule.target_id,
                    user_id=schedule.owner_user_id,
                    status="queued",
                    profile=schedule.profile,
                )
                db.add(scan)
                db.flush()
                enqueue_full_scan(scan.id, kind)
                schedule.last_run_at = now
                schedule.next_run_at = compute_next_run(
                    schedule.cron_expression,
                    base=now,
                    tz=getattr(schedule, "timezone", None) or "UTC",
                )
                dispatched += 1
            db.commit()

        return {"dispatched": dispatched}
    finally:
        engine.dispose()


async def run_on_demand_schedule_loop(interval_seconds: float = 60.0) -> None:
    while True:
        try:
            result = await asyncio.to_thread(dispatch_due_scans_sync)
            if result.get("dispatched"):
                log.info("dispatched due on-demand schedules: %s", result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("on-demand schedule dispatch failed: %s", exc)
        await asyncio.sleep(interval_seconds)
