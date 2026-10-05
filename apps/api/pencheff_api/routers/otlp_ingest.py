"""OTLP/HTTP ingest endpoints for the MCP plugin.

When the operator authenticates the plugin (``PENCHEFF_OBSERVABILITY_OTLP_TOKEN``
+ ``PENCHEFF_OBSERVABILITY_OTLP_URL`` set), the plugin's
``OTLPSpanExporter`` ships traces here. The router decodes the
protobuf into row dicts shaped like the ``otel_spans`` columns and
writes them via psycopg2 — same recursion-safe pattern as the
in-process exporter (``observability/exporter.py``).

Auth: ``Authorization: Bearer <token>`` validated against
``engagement_ingest_tokens.token_hash`` (sha256 of plaintext). Revoked
tokens (``revoked_at IS NOT NULL``) are rejected with 401.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ..config import get_settings
from ..db.models import EngagementIngestToken
from ..observability.exporter import _get_conn, _suppress_instrumentation, _detach

log = logging.getLogger("pencheff.otlp.ingest")

router = APIRouter(tags=["observability-ingest"])


# --------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------- #


_engine = None
_session_factory = None


async def _session():
    global _engine, _session_factory
    if _session_factory is None:
        settings = get_settings()
        _engine = create_async_engine(settings.database_url)
        _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
    return _session_factory()


async def _authorize(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token"
        )
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Empty bearer token"
        )
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    async with await _session() as session:
        res = await session.execute(
            select(EngagementIngestToken).where(
                EngagementIngestToken.token_hash == token_hash
            )
        )
        row = res.scalar_one_or_none()
        if row is None or row.revoked_at is not None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked ingest token",
            )
        # Best-effort last-used touch — failure here doesn't block ingest.
        try:
            row.last_used_at = datetime.now(timezone.utc)
            await session.commit()
        except Exception:
            await session.rollback()

        return {
            "engagement_id": row.engagement_id,
            "workspace_id": row.workspace_id,
        }


# --------------------------------------------------------------------- #
# Trace ingest
# --------------------------------------------------------------------- #


@router.post("/v1/traces", status_code=status.HTTP_204_NO_CONTENT)
async def ingest_traces(
    request: Request,
    authorization: str | None = Header(None),
):
    settings = get_settings()
    if not settings.observability_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Observability is disabled on this deployment",
        )

    auth = await _authorize(authorization)
    body = await request.body()
    if not body:
        return

    try:
        rows = list(_decode_traces(body, auth))
    except Exception as exc:  # noqa: BLE001
        log.warning("trace decode failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OTLP trace decode failed: {exc}",
        ) from exc

    _bulk_insert(settings.sync_database_url, _SPAN_INSERT, rows)


@router.post("/v1/logs", status_code=status.HTTP_204_NO_CONTENT)
async def ingest_logs(
    request: Request,
    authorization: str | None = Header(None),
):
    settings = get_settings()
    if not settings.observability_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Observability is disabled on this deployment",
        )

    auth = await _authorize(authorization)
    body = await request.body()
    if not body:
        return

    try:
        rows = list(_decode_logs(body, auth))
    except Exception as exc:  # noqa: BLE001
        log.warning("log decode failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OTLP log decode failed: {exc}",
        ) from exc

    _bulk_insert(settings.sync_database_url, _LOG_INSERT, rows)


@router.post("/v1/metrics", status_code=status.HTTP_204_NO_CONTENT)
async def ingest_metrics(
    request: Request,
    authorization: str | None = Header(None),
):
    settings = get_settings()
    if not settings.observability_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Observability is disabled on this deployment",
        )

    auth = await _authorize(authorization)
    body = await request.body()
    if not body:
        return

    try:
        rows = list(_decode_metrics(body, auth))
    except Exception as exc:  # noqa: BLE001
        log.warning("metric decode failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OTLP metric decode failed: {exc}",
        ) from exc

    _bulk_insert(settings.sync_database_url, _METRIC_INSERT, rows)


# --------------------------------------------------------------------- #
# Protobuf decoding helpers
# --------------------------------------------------------------------- #


def _kv_to_dict(kvs) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for kv in kvs or []:
        v = kv.value
        if v.HasField("string_value"):
            out[kv.key] = v.string_value
        elif v.HasField("int_value"):
            out[kv.key] = v.int_value
        elif v.HasField("double_value"):
            out[kv.key] = v.double_value
        elif v.HasField("bool_value"):
            out[kv.key] = v.bool_value
        elif v.HasField("bytes_value"):
            out[kv.key] = v.bytes_value.hex()
        # Skip array/kvlist for v1 — operators rarely send these from the plugin.
    return out


def _from_ns(ns: int | None):
    if not ns:
        return None
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)


def _decode_traces(body: bytes, auth: dict[str, Any]):
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceRequest,
    )

    req = ExportTraceServiceRequest()
    req.ParseFromString(body)

    for resource_span in req.resource_spans:
        resource_attrs = _kv_to_dict(resource_span.resource.attributes)
        service_name = resource_attrs.get("service.name", "unknown-plugin")
        for scope_span in resource_span.scope_spans:
            scope_name = (
                scope_span.scope.name if scope_span.HasField("scope") else None
            )
            for span in scope_span.spans:
                attrs = _kv_to_dict(span.attributes)
                yield {
                    "started_at": _from_ns(span.start_time_unix_nano),
                    "trace_id": span.trace_id,
                    "span_id": span.span_id,
                    "parent_span_id": span.parent_span_id or None,
                    "name": (span.name or "")[:512] or "unknown",
                    "kind": int(span.kind),
                    "ended_at": _from_ns(span.end_time_unix_nano),
                    "duration_ns": (
                        span.end_time_unix_nano - span.start_time_unix_nano
                        if span.end_time_unix_nano and span.start_time_unix_nano
                        else None
                    ),
                    "status_code": int(span.status.code) if span.HasField("status") else 0,
                    "status_message": (
                        span.status.message if span.HasField("status") else None
                    ),
                    "service_name": service_name,
                    "scope_name": scope_name,
                    "attributes": json.dumps(attrs, default=str),
                    "resource": json.dumps(resource_attrs, default=str),
                    "events": json.dumps(
                        [
                            {
                                "name": e.name,
                                "ts": _from_ns(e.time_unix_nano).isoformat()
                                if e.time_unix_nano
                                else None,
                                "attrs": _kv_to_dict(e.attributes),
                            }
                            for e in span.events
                        ]
                    ),
                    "links": json.dumps([]),
                    "scan_id": attrs.get("pencheff.scan_id"),
                    "engagement_id": attrs.get("pencheff.engagement_id")
                    or auth.get("engagement_id"),
                    "org_id": attrs.get("pencheff.org_id"),
                    "user_id": attrs.get("pencheff.user_id"),
                }


def _decode_logs(body: bytes, auth: dict[str, Any]):
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
        ExportLogsServiceRequest,
    )

    req = ExportLogsServiceRequest()
    req.ParseFromString(body)

    for resource_log in req.resource_logs:
        resource_attrs = _kv_to_dict(resource_log.resource.attributes)
        service_name = resource_attrs.get("service.name", "unknown-plugin")
        for scope_log in resource_log.scope_logs:
            for record in scope_log.log_records:
                attrs = _kv_to_dict(record.attributes)
                body_str = (
                    record.body.string_value
                    if record.body.HasField("string_value")
                    else None
                )
                yield {
                    "ts": _from_ns(
                        record.time_unix_nano or record.observed_time_unix_nano
                    ),
                    "severity_number": int(record.severity_number),
                    "severity_text": record.severity_text or None,
                    "body": body_str,
                    "trace_id": record.trace_id or None,
                    "span_id": record.span_id or None,
                    "service_name": service_name,
                    "attributes": json.dumps(attrs, default=str),
                    "resource": json.dumps(resource_attrs, default=str),
                    "scan_id": attrs.get("pencheff.scan_id"),
                    "engagement_id": attrs.get("pencheff.engagement_id")
                    or auth.get("engagement_id"),
                    "org_id": attrs.get("pencheff.org_id"),
                    "user_id": attrs.get("pencheff.user_id"),
                }


def _decode_metrics(body: bytes, auth: dict[str, Any]):
    from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
        ExportMetricsServiceRequest,
    )

    req = ExportMetricsServiceRequest()
    req.ParseFromString(body)

    for resource_metric in req.resource_metrics:
        resource_attrs = _kv_to_dict(resource_metric.resource.attributes)
        service_name = resource_attrs.get("service.name", "unknown-plugin")
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                kind, points = _flatten_metric(metric)
                for point in points:
                    yield {
                        "ts": _from_ns(point.get("time_unix_nano")),
                        "metric_name": (metric.name or "")[:256],
                        "kind": kind,
                        "unit": metric.unit or None,
                        "description": metric.description or None,
                        "value": point.get("value"),
                        "sum_value": point.get("sum"),
                        "count_value": point.get("count"),
                        "buckets": point.get("buckets"),
                        "service_name": service_name,
                        "attributes": json.dumps(point.get("attrs", {}), default=str),
                        "resource": json.dumps(resource_attrs, default=str),
                    }


def _flatten_metric(metric):
    if metric.HasField("sum"):
        return "sum", [
            {
                "time_unix_nano": dp.time_unix_nano,
                "value": dp.as_double if dp.HasField("as_double") else dp.as_int,
                "attrs": _kv_to_dict(dp.attributes),
            }
            for dp in metric.sum.data_points
        ]
    if metric.HasField("gauge"):
        return "gauge", [
            {
                "time_unix_nano": dp.time_unix_nano,
                "value": dp.as_double if dp.HasField("as_double") else dp.as_int,
                "attrs": _kv_to_dict(dp.attributes),
            }
            for dp in metric.gauge.data_points
        ]
    if metric.HasField("histogram"):
        return "histogram", [
            {
                "time_unix_nano": dp.time_unix_nano,
                "sum": dp.sum,
                "count": dp.count,
                "buckets": json.dumps(
                    {
                        "boundaries": list(dp.explicit_bounds),
                        "counts": list(dp.bucket_counts),
                    }
                ),
                "attrs": _kv_to_dict(dp.attributes),
            }
            for dp in metric.histogram.data_points
        ]
    return "unknown", []


# --------------------------------------------------------------------- #
# Sync bulk insert (psycopg2 — bypasses SQLAlchemy auto-instrumentation)
# --------------------------------------------------------------------- #


_SPAN_INSERT = """
    INSERT INTO otel_spans (
        started_at, trace_id, span_id, parent_span_id,
        name, kind, ended_at, duration_ns,
        status_code, status_message,
        service_name, scope_name,
        attributes, resource, events, links,
        scan_id, engagement_id, org_id, user_id
    ) VALUES (
        %(started_at)s, %(trace_id)s, %(span_id)s, %(parent_span_id)s,
        %(name)s, %(kind)s, %(ended_at)s, %(duration_ns)s,
        %(status_code)s, %(status_message)s,
        %(service_name)s, %(scope_name)s,
        %(attributes)s::jsonb, %(resource)s::jsonb,
        %(events)s::jsonb, %(links)s::jsonb,
        %(scan_id)s, %(engagement_id)s, %(org_id)s, %(user_id)s
    )
    ON CONFLICT (started_at, trace_id, span_id) DO NOTHING
"""

_LOG_INSERT = """
    INSERT INTO otel_logs (
        ts, severity_number, severity_text, body,
        trace_id, span_id, service_name,
        attributes, resource,
        scan_id, engagement_id, org_id, user_id
    ) VALUES (
        %(ts)s, %(severity_number)s, %(severity_text)s, %(body)s,
        %(trace_id)s, %(span_id)s, %(service_name)s,
        %(attributes)s::jsonb, %(resource)s::jsonb,
        %(scan_id)s, %(engagement_id)s, %(org_id)s, %(user_id)s
    )
"""

_METRIC_INSERT = """
    INSERT INTO otel_metrics (
        ts, metric_name, kind, unit, description,
        value, sum_value, count_value, buckets,
        service_name, attributes, resource
    ) VALUES (
        %(ts)s, %(metric_name)s, %(kind)s, %(unit)s, %(description)s,
        %(value)s, %(sum_value)s, %(count_value)s, %(buckets)s::jsonb,
        %(service_name)s, %(attributes)s::jsonb, %(resource)s::jsonb
    )
"""


def _bulk_insert(dsn: str, sql: str, rows: list[dict]) -> None:
    if not rows:
        return
    suppression = _suppress_instrumentation()
    try:
        conn = _get_conn(dsn)
        with conn.cursor() as cur:
            cur.executemany(sql, rows)
    except Exception as exc:  # noqa: BLE001
        log.warning("OTLP bulk insert failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Persistence failure",
        ) from exc
    finally:
        _detach(suppression)
