"""Hourly OTel partition pre-create + drop pass.

Mirrors ``retention_task.py`` shape for the proxy_traffic prune so future
operators recognise the pattern. Two responsibilities per run:

1. **Pre-create** day partitions for today + N days ahead (N = retention
   horizon, default 7) on every OTel table. Idempotent via ``IF NOT
   EXISTS``. Without this, the leading-edge partition wouldn't exist
   when 00:00 UTC ticks over and the next day's first INSERT would
   land in the DEFAULT partition (functional, but confusing on
   ``pg_partition_tree`` reads).
2. **Drop** day partitions older than the horizon. ``DROP TABLE`` is a
   metadata-only operation in Postgres — orders of magnitude faster
   than ``DELETE WHERE`` against tens of millions of rows.

The audit_logs table is NOT partitioned (existing schema) — historical
data lives in a single table. We prune it with a plain ``DELETE WHERE``
governed by a separate ``audit_retention_days`` knob, since compliance
frameworks often require longer audit retention than telemetry.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ..config import get_settings
from .celery_app import celery_app

log = logging.getLogger("pencheff.observability.retention")

_OTEL_TABLES = ("otel_spans", "otel_logs", "otel_metrics")
_PRECREATE_AHEAD_DAYS = 7


async def _prune_async() -> dict[str, int]:
    settings = get_settings()
    if not settings.observability_enabled:
        return {"skipped": 1}

    engine = create_async_engine(settings.database_url)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    created = 0
    dropped = 0
    audit_pruned = 0

    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    retention_cutoff = today - timedelta(days=settings.observability_retention_days)
    audit_cutoff = today - timedelta(days=settings.audit_retention_days)

    try:
        async with Session() as session:
            # ── Pre-create partitions for today + N future days ────
            for offset in range(_PRECREATE_AHEAD_DAYS + 1):
                day = today + timedelta(days=offset)
                nxt = day + timedelta(days=1)
                suffix = day.strftime("%Y%m%d")
                for table in _OTEL_TABLES:
                    res = await session.execute(
                        text(
                            f"CREATE TABLE IF NOT EXISTS {table}_{suffix} "
                            f"PARTITION OF {table} "
                            f"FOR VALUES FROM ('{day.isoformat()}') "
                            f"TO ('{nxt.isoformat()}')"
                        )
                    )
                    # `CREATE TABLE IF NOT EXISTS` returns no row count;
                    # we approximate "created" by counting the rounds,
                    # which is fine for the periodic-task summary.
                    if offset == _PRECREATE_AHEAD_DAYS:
                        created += 1

            # ── Drop partitions older than the retention horizon ───
            for table in _OTEL_TABLES:
                rows = (
                    await session.execute(
                        text(
                            "SELECT inhrelid::regclass::text AS partition "
                            "FROM pg_inherits "
                            "WHERE inhparent = (:t)::regclass"
                        ),
                        {"t": table},
                    )
                ).fetchall()
                for (partition,) in rows:
                    if partition.endswith("_default"):
                        continue
                    suffix = partition.rsplit("_", 1)[-1]
                    if not (len(suffix) == 8 and suffix.isdigit()):
                        continue
                    try:
                        partition_day = datetime.strptime(suffix, "%Y%m%d").replace(
                            tzinfo=timezone.utc
                        )
                    except ValueError:
                        continue
                    if partition_day < retention_cutoff:
                        await session.execute(text(f"DROP TABLE IF EXISTS {partition}"))
                        dropped += 1

            # ── Prune audit_logs (non-partitioned, separate horizon) ─
            res = await session.execute(
                text("DELETE FROM audit_logs WHERE created_at < :c"),
                {"c": audit_cutoff},
            )
            audit_pruned += res.rowcount or 0

            await session.commit()
    finally:
        await engine.dispose()

    log.info(
        "observability retention pass: created=%d dropped=%d audit_pruned=%d",
        created, dropped, audit_pruned,
    )
    return {"created": created, "dropped": dropped, "audit_pruned": audit_pruned}


@celery_app.task(name="pencheff.observability.prune_partitions")
def prune_partitions() -> dict[str, int]:
    return asyncio.run(_prune_async())
