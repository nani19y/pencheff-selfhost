"""Read-only ORM models for the partitioned OTel tables.

The exporter writes via raw psycopg2 (see observability/exporter.py)
to bypass SQLAlchemy auto-instrumentation. These models exist only so
the ``observability`` read-router (``GET /scans/{id}/trace`` etc.)
can use the async SQLAlchemy session like every other read endpoint.

Models are deliberately thin — partition columns and PKs only — since
detailed shape access goes through the routers' raw SQL queries.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, LargeBinary, SmallInteger, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class OtelSpan(Base):
    __tablename__ = "otel_spans"

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    trace_id: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    span_id: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)

    parent_span_id: Mapped[bytes | None] = mapped_column(LargeBinary)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ns: Mapped[int | None] = mapped_column(BigInteger)
    status_code: Mapped[int | None] = mapped_column(SmallInteger)
    status_message: Mapped[str | None] = mapped_column(Text)
    service_name: Mapped[str] = mapped_column(Text, nullable=False)
    scope_name: Mapped[str | None] = mapped_column(Text)
    attributes: Mapped[dict | None] = mapped_column(JSONB)
    resource: Mapped[dict | None] = mapped_column(JSONB)
    events: Mapped[list | None] = mapped_column(JSONB)
    links: Mapped[list | None] = mapped_column(JSONB)

    scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    engagement_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    org_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    user_id: Mapped[str | None] = mapped_column(Text)


class OtelLog(Base):
    __tablename__ = "otel_logs"
    __table_args__ = (
        Index("ix_otel_logs_pk_synth", "ts", "trace_id", "span_id"),
    )

    # No natural PK on the logs table; we use a synthetic composite via
    # the index above and a default-rowid behaviour.
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    severity_number: Mapped[int] = mapped_column(SmallInteger, primary_key=True, default=0)
    trace_id: Mapped[bytes | None] = mapped_column(LargeBinary, primary_key=True)
    span_id: Mapped[bytes | None] = mapped_column(LargeBinary, primary_key=True)
    severity_text: Mapped[str | None] = mapped_column(Text)
    body: Mapped[str | None] = mapped_column(Text)
    service_name: Mapped[str] = mapped_column(Text, nullable=False)
    attributes: Mapped[dict | None] = mapped_column(JSONB)
    resource: Mapped[dict | None] = mapped_column(JSONB)

    scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    engagement_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    org_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    user_id: Mapped[str | None] = mapped_column(Text)


class OtelMetric(Base):
    __tablename__ = "otel_metrics"
    __table_args__ = (
        Index("ix_otel_metrics_pk_synth", "ts", "metric_name"),
    )

    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    metric_name: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    unit: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    value: Mapped[float | None]
    sum_value: Mapped[float | None]
    count_value: Mapped[int | None] = mapped_column(BigInteger)
    buckets: Mapped[dict | None] = mapped_column(JSONB)
    service_name: Mapped[str] = mapped_column(Text, nullable=False)
    attributes: Mapped[dict | None] = mapped_column(JSONB)
    resource: Mapped[dict | None] = mapped_column(JSONB)
