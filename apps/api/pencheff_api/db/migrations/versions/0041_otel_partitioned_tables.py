"""OTel signal tables (spans / logs / metrics) — day-partitioned.

Revision ID: 0041
Revises: 0040
Create Date: 2026-05-08

The three tables here back the OpenTelemetry pipeline introduced by
this revision. Each is ``PARTITION BY RANGE (ts)`` at one-day
granularity so the hourly retention task
(``pencheff.observability.prune_partitions``) can ``DROP TABLE`` whole
day-partitions instead of running ``DELETE WHERE`` against tens of
millions of rows.

Pre-created partitions: today + 7 future days (the retention horizon)
plus a DEFAULT partition. The DEFAULT catches stragglers from clock
skew or migrations that run before the day's leading-edge partition is
created — without it, an INSERT against an unpartitioned timestamp
fails outright and would drop the whole batch.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0041"
down_revision: Union[str, None] = "0040"
branch_labels = None
depends_on = None


# Pre-create partitions starting from this date for ``_PRECREATE_DAYS``
# days. The retention task takes over for further pre-creation on every
# hourly run.
_BASE_DATE = datetime(2026, 5, 8, tzinfo=timezone.utc)
_PRECREATE_DAYS = 8  # today + 7 future days


def _day_partitions(table: str) -> str:
    parts: list[str] = []
    for offset in range(_PRECREATE_DAYS):
        day = _BASE_DATE + timedelta(days=offset)
        nxt = day + timedelta(days=1)
        suffix = day.strftime("%Y%m%d")
        parts.append(
            f"CREATE TABLE IF NOT EXISTS {table}_{suffix} "
            f"PARTITION OF {table} "
            f"FOR VALUES FROM ('{day.isoformat()}') TO ('{nxt.isoformat()}');"
        )
    parts.append(
        f"CREATE TABLE IF NOT EXISTS {table}_default "
        f"PARTITION OF {table} DEFAULT;"
    )
    return "\n".join(parts)


def upgrade() -> None:
    # ── otel_spans ──────────────────────────────────────────────────
    op.execute(
        """
        CREATE TABLE otel_spans (
            started_at      TIMESTAMPTZ      NOT NULL,
            trace_id        BYTEA            NOT NULL,
            span_id         BYTEA            NOT NULL,
            parent_span_id  BYTEA,
            name            TEXT             NOT NULL,
            kind            SMALLINT         NOT NULL,
            ended_at        TIMESTAMPTZ,
            duration_ns     BIGINT,
            status_code     SMALLINT,
            status_message  TEXT,
            service_name    TEXT             NOT NULL,
            scope_name      TEXT,
            attributes      JSONB,
            resource        JSONB,
            events          JSONB,
            links           JSONB,
            scan_id         UUID,
            engagement_id   UUID,
            org_id          UUID,
            user_id         TEXT,
            PRIMARY KEY (started_at, trace_id, span_id)
        ) PARTITION BY RANGE (started_at);
        """
    )
    # Indexes on the partitioned parent propagate to every child
    # partition (Postgres ≥ 11). New partitions inherit them too.
    op.execute("CREATE INDEX otel_spans_scan_idx ON otel_spans (scan_id);")
    op.execute("CREATE INDEX otel_spans_trace_idx ON otel_spans (trace_id);")
    op.execute(
        "CREATE INDEX otel_spans_engagement_idx "
        "ON otel_spans (engagement_id, started_at DESC);"
    )
    op.execute(
        "CREATE INDEX otel_spans_service_started_idx "
        "ON otel_spans (service_name, started_at DESC);"
    )
    op.execute(_day_partitions("otel_spans"))

    # ── otel_logs ───────────────────────────────────────────────────
    op.execute(
        """
        CREATE TABLE otel_logs (
            ts               TIMESTAMPTZ NOT NULL,
            severity_number  SMALLINT    NOT NULL DEFAULT 0,
            severity_text    TEXT,
            body             TEXT,
            trace_id         BYTEA,
            span_id          BYTEA,
            service_name     TEXT        NOT NULL,
            attributes       JSONB,
            resource         JSONB,
            scan_id          UUID,
            engagement_id    UUID,
            org_id           UUID,
            user_id          TEXT
        ) PARTITION BY RANGE (ts);
        """
    )
    op.execute("CREATE INDEX otel_logs_trace_idx ON otel_logs (trace_id);")
    op.execute(
        "CREATE INDEX otel_logs_severity_ts_idx "
        "ON otel_logs (severity_number, ts DESC);"
    )
    op.execute(
        "CREATE INDEX otel_logs_scan_idx "
        "ON otel_logs (scan_id) WHERE scan_id IS NOT NULL;"
    )
    op.execute(_day_partitions("otel_logs"))

    # ── otel_metrics ────────────────────────────────────────────────
    op.execute(
        """
        CREATE TABLE otel_metrics (
            ts            TIMESTAMPTZ NOT NULL,
            metric_name   TEXT        NOT NULL,
            kind          TEXT        NOT NULL,
            unit          TEXT,
            description   TEXT,
            value         DOUBLE PRECISION,
            sum_value     DOUBLE PRECISION,
            count_value   BIGINT,
            buckets       JSONB,
            service_name  TEXT        NOT NULL,
            attributes    JSONB,
            resource      JSONB
        ) PARTITION BY RANGE (ts);
        """
    )
    op.execute(
        "CREATE INDEX otel_metrics_name_ts_idx "
        "ON otel_metrics (metric_name, ts DESC);"
    )
    op.execute(_day_partitions("otel_metrics"))


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS otel_metrics CASCADE;")
    op.execute("DROP TABLE IF EXISTS otel_logs CASCADE;")
    op.execute("DROP TABLE IF EXISTS otel_spans CASCADE;")
