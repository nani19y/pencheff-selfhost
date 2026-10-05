"""Hourly SLA monitor — set ``sla_breached=True`` on overdue findings and emit notifications."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.models import Finding
from .celery_app import celery_app

# Severity → days to remediate. Override via env or admin config later.
DEFAULT_SLA_DAYS = {
    "critical": 1,
    "high": 7,
    "medium": 30,
    "low": 90,
    "info": 365,
}


@celery_app.task(name="pencheff_api.tasks.sla_monitor_task.check_sla_breaches")
def check_sla_breaches() -> dict[str, int]:
    settings = get_settings()
    engine = create_engine(settings.database_url.replace("+asyncpg", ""), future=True)
    now = datetime.now(timezone.utc)
    breached = 0
    with Session(engine) as db:
        # Backfill due_date on findings that don't have one yet.
        rows = db.execute(select(Finding).where(
            Finding.resolved_at.is_(None), Finding.due_date.is_(None),
        )).scalars().all()
        for f in rows:
            days = DEFAULT_SLA_DAYS.get(f.severity, 30)
            f.sla_days = days
            from datetime import timedelta
            f.due_date = (f.created_at or now) + timedelta(days=days)
        db.flush()

        # Flag breaches.
        res = db.execute(
            update(Finding)
            .where(
                Finding.resolved_at.is_(None),
                Finding.sla_breached.is_(False),
                Finding.due_date.isnot(None),
                Finding.due_date < now,
            )
            .values(sla_breached=True)
            .execution_options(synchronize_session=False)
        )
        breached = res.rowcount or 0
        db.commit()
    return {"breaches_flagged": breached}
