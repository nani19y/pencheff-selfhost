"""Custom OTel exporters that write directly to Pencheff's Postgres.

Why not the OTLP exporter + a collector? Two reasons. (a) The plan
forbids new infra containers — Postgres is already in the stack.
(b) A SQLAlchemy/asyncpg auto-instrumented exporter would loop forever:
writing a span generates spans, which the exporter then tries to write,
generating more spans, ad infinitum.

Two safeguards break the cycle:

1. **psycopg2, not the async engine.** This module imports psycopg2
   directly (already a transitive dep via Alembic). Neither
   ``SQLAlchemyInstrumentor`` nor ``AsyncPGInstrumentor`` patches
   psycopg2 at our installation, so the writes are invisible to the
   tracer.
2. **``_SUPPRESS_INSTRUMENTATION_KEY``.** Belt-and-suspenders: every
   write is wrapped in an OTel context that explicitly suppresses
   instrumentation in case some future auto-instrumentation does start
   patching psycopg2.

The exporters are sync because OTel's ``BatchSpanProcessor`` calls
``export()`` from a single worker thread. Each thread gets its own
psycopg2 connection (psycopg2 connections are not thread-safe, but a
``threading.local`` keeps per-thread connections isolated).
"""
from __future__ import annotations

import json
import logging
import threading
from typing import Any, Sequence

log = logging.getLogger("pencheff.observability.exporter")


# --------------------------------------------------------------------- #
# Connection helpers
# --------------------------------------------------------------------- #

_local = threading.local()


def _get_conn(dsn: str):
    """Return a per-thread psycopg2 connection, opening on first use."""
    import psycopg2

    conn = getattr(_local, "conn", None)
    if conn is None or conn.closed:
        conn = psycopg2.connect(dsn, application_name="pencheff-otel-exporter")
        conn.autocommit = True
        _local.conn = conn
    return conn


def _suppress_instrumentation():
    """Context-manager helper that flips the OTel suppression flag.

    Returns the token to detach. Even though psycopg2 isn't currently
    auto-instrumented, future operators may pull in
    ``opentelemetry-instrumentation-psycopg2`` — at which point this
    guard is the difference between a healthy pipeline and a runaway
    recursion that consumes the worker thread.
    """
    from opentelemetry import context as otel_context

    try:
        from opentelemetry.context import _SUPPRESS_INSTRUMENTATION_KEY as KEY
    except ImportError:
        from opentelemetry.context import (
            suppress_instrumentation as _suppress,
        )
        return _suppress()
    return otel_context, otel_context.attach(otel_context.set_value(KEY, True))


def _detach(token_or_pair) -> None:
    if token_or_pair is None:
        return
    ctx, token = token_or_pair
    ctx.detach(token)


# --------------------------------------------------------------------- #
# Pencheff-attribute extraction
# --------------------------------------------------------------------- #

_PENCHEFF_ATTRS = {
    "scan_id": "pencheff.scan_id",
    "engagement_id": "pencheff.engagement_id",
    "org_id": "pencheff.org_id",
    "user_id": "pencheff.user_id",
}


def _extract_correlation(attrs: Any) -> dict[str, Any]:
    """Pull ``pencheff.*`` correlation attributes out for indexed columns.

    Spans set by ``scan_task`` root or downstream code carry these as
    span attributes; the denormalized columns let queries like
    ``WHERE scan_id = $1`` use an index instead of a JSONB filter.
    """
    out: dict[str, Any] = {k: None for k in _PENCHEFF_ATTRS}
    if not attrs:
        return out
    for col, key in _PENCHEFF_ATTRS.items():
        v = attrs.get(key) if hasattr(attrs, "get") else None
        if v is None and hasattr(attrs, "__contains__") and key in attrs:
            v = attrs[key]
        out[col] = str(v) if v is not None else None
    return out


def _attrs_to_jsonb(attrs: Any) -> str:
    """Convert OTel attributes (could be a dict-like or BoundedAttributes)
    into a JSON string suitable for psycopg2's JSONB cast.
    """
    if not attrs:
        return "{}"
    try:
        return json.dumps(dict(attrs), default=str)
    except Exception:
        return "{}"


def _from_ns(ns: int | None):
    """Postgres TIMESTAMPTZ from OTel nanosecond epoch."""
    if ns is None:
        return None
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)


# --------------------------------------------------------------------- #
# Span exporter
# --------------------------------------------------------------------- #


class PostgresSpanExporter:
    """Writes batches of OTel ``ReadableSpan`` rows into ``otel_spans``.

    Implements the ``SpanExporter`` interface duck-typed (no inheritance
    so this module doesn't blow up on import when the SDK isn't
    installed — bootstrap stays a no-op).
    """

    def __init__(self, dsn: str):
        self._dsn = dsn

    def export(self, spans: Sequence[Any]) -> Any:
        from opentelemetry.sdk.trace.export import SpanExportResult

        if not spans:
            return SpanExportResult.SUCCESS

        suppression = _suppress_instrumentation()
        try:
            conn = _get_conn(self._dsn)
            with conn.cursor() as cur:
                rows = [self._row(s) for s in spans]
                cur.executemany(
                    """
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
                    """,
                    rows,
                )
            return SpanExportResult.SUCCESS
        except Exception as exc:  # noqa: BLE001
            log.warning("span export failed: %s", exc)
            return SpanExportResult.FAILURE
        finally:
            _detach(suppression)

    def shutdown(self) -> None:
        conn = getattr(_local, "conn", None)
        if conn is not None and not conn.closed:
            try:
                conn.close()
            except Exception:
                pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    @staticmethod
    def _row(span: Any) -> dict[str, Any]:
        ctx = span.get_span_context()
        parent = span.parent
        attrs = span.attributes or {}
        corr = _extract_correlation(attrs)

        try:
            kind_value = span.kind.value if span.kind is not None else 0
        except AttributeError:
            kind_value = int(span.kind) if span.kind is not None else 0

        try:
            status_code = span.status.status_code.value
        except AttributeError:
            status_code = 0
        status_message = getattr(span.status, "description", None) if span.status else None

        scope = getattr(span, "instrumentation_scope", None) or getattr(
            span, "instrumentation_info", None
        )
        scope_name = getattr(scope, "name", None) if scope else None

        resource_attrs = (
            dict(span.resource.attributes) if getattr(span, "resource", None) else {}
        )
        service_name = (
            resource_attrs.get("service.name")
            if isinstance(resource_attrs, dict)
            else None
        ) or "unknown"

        events = [
            {
                "name": e.name,
                "ts": _from_ns(e.timestamp).isoformat() if e.timestamp else None,
                "attrs": dict(e.attributes or {}),
            }
            for e in (span.events or [])
        ]
        links = [
            {
                "trace_id": link.context.trace_id.to_bytes(16, "big").hex(),
                "span_id": link.context.span_id.to_bytes(8, "big").hex(),
                "attrs": dict(link.attributes or {}),
            }
            for link in (span.links or [])
        ]

        return {
            "started_at": _from_ns(span.start_time),
            "ended_at": _from_ns(span.end_time),
            "duration_ns": (
                (span.end_time - span.start_time)
                if (span.end_time and span.start_time)
                else None
            ),
            "trace_id": ctx.trace_id.to_bytes(16, "big"),
            "span_id": ctx.span_id.to_bytes(8, "big"),
            "parent_span_id": (
                parent.span_id.to_bytes(8, "big") if parent and parent.span_id else None
            ),
            "name": span.name[:512] if span.name else "unknown",
            "kind": kind_value,
            "status_code": status_code,
            "status_message": (status_message or "")[:512] if status_message else None,
            "service_name": service_name,
            "scope_name": scope_name,
            "attributes": _attrs_to_jsonb(attrs),
            "resource": json.dumps(resource_attrs, default=str),
            "events": json.dumps(events, default=str),
            "links": json.dumps(links, default=str),
            **corr,
        }


# --------------------------------------------------------------------- #
# Log exporter
# --------------------------------------------------------------------- #


class PostgresLogExporter:
    def __init__(self, dsn: str):
        self._dsn = dsn

    def export(self, batch: Sequence[Any]) -> Any:
        from opentelemetry.sdk._logs.export import LogExportResult

        if not batch:
            return LogExportResult.SUCCESS

        suppression = _suppress_instrumentation()
        try:
            conn = _get_conn(self._dsn)
            with conn.cursor() as cur:
                rows = [self._row(item) for item in batch]
                cur.executemany(
                    """
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
                    """,
                    rows,
                )
            return LogExportResult.SUCCESS
        except Exception as exc:  # noqa: BLE001
            log.warning("log export failed: %s", exc)
            return LogExportResult.FAILURE
        finally:
            _detach(suppression)

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    @staticmethod
    def _row(item: Any) -> dict[str, Any]:
        record = getattr(item, "log_record", item)
        attrs = record.attributes or {}
        corr = _extract_correlation(attrs)
        resource_attrs = (
            dict(record.resource.attributes) if getattr(record, "resource", None) else {}
        )
        service_name = (
            resource_attrs.get("service.name")
            if isinstance(resource_attrs, dict)
            else None
        ) or "unknown"

        body = record.body
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str)
        elif body is not None:
            body = str(body)[:32768]

        try:
            severity_number = int(record.severity_number) if record.severity_number else 0
        except Exception:
            severity_number = 0

        return {
            "ts": _from_ns(record.timestamp or record.observed_timestamp),
            "severity_number": severity_number,
            "severity_text": (record.severity_text or "")[:32] or None,
            "body": body,
            "trace_id": (
                record.trace_id.to_bytes(16, "big") if record.trace_id else None
            ),
            "span_id": (
                record.span_id.to_bytes(8, "big") if record.span_id else None
            ),
            "service_name": service_name,
            "attributes": _attrs_to_jsonb(attrs),
            "resource": json.dumps(resource_attrs, default=str),
            **corr,
        }


# --------------------------------------------------------------------- #
# Metric exporter
# --------------------------------------------------------------------- #


class PostgresMetricExporter:
    """One row per metric data point. Histograms are stored exploded —
    bucket counts in a JSONB column — so the schema stays flat."""

    def __init__(self, dsn: str):
        self._dsn = dsn
        self._preferred_temporality: dict | None = None

    def export(self, metrics_data: Any, timeout_millis: int = 10000) -> Any:
        from opentelemetry.sdk.metrics.export import MetricExportResult

        suppression = _suppress_instrumentation()
        try:
            rows = list(self._flatten(metrics_data))
            if not rows:
                return MetricExportResult.SUCCESS

            conn = _get_conn(self._dsn)
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO otel_metrics (
                        ts, metric_name, kind, unit, description,
                        value, sum_value, count_value, buckets,
                        service_name, attributes, resource
                    ) VALUES (
                        %(ts)s, %(metric_name)s, %(kind)s, %(unit)s, %(description)s,
                        %(value)s, %(sum_value)s, %(count_value)s, %(buckets)s::jsonb,
                        %(service_name)s, %(attributes)s::jsonb, %(resource)s::jsonb
                    )
                    """,
                    rows,
                )
            return MetricExportResult.SUCCESS
        except Exception as exc:  # noqa: BLE001
            log.warning("metric export failed: %s", exc)
            return MetricExportResult.FAILURE
        finally:
            _detach(suppression)

    def shutdown(self, timeout_millis: int = 30000, **_kwargs) -> None:
        pass

    def force_flush(self, timeout_millis: int = 10000) -> bool:
        return True

    def _flatten(self, metrics_data: Any):
        for resource_metric in getattr(metrics_data, "resource_metrics", []) or []:
            resource_attrs = (
                dict(resource_metric.resource.attributes)
                if getattr(resource_metric, "resource", None)
                else {}
            )
            service_name = (
                resource_attrs.get("service.name")
                if isinstance(resource_attrs, dict)
                else None
            ) or "unknown"

            for scope_metric in resource_metric.scope_metrics or []:
                for metric in scope_metric.metrics or []:
                    name = metric.name
                    unit = getattr(metric, "unit", "") or ""
                    desc = getattr(metric, "description", "") or ""
                    data = metric.data

                    for dp in getattr(data, "data_points", []) or []:
                        attrs = _attrs_to_jsonb(dp.attributes)
                        ts = _from_ns(getattr(dp, "time_unix_nano", None))
                        kind, value, sum_v, count_v, buckets = self._classify(data, dp)
                        yield {
                            "ts": ts,
                            "metric_name": name[:256],
                            "kind": kind,
                            "unit": unit[:64] if unit else None,
                            "description": desc[:512] if desc else None,
                            "value": value,
                            "sum_value": sum_v,
                            "count_value": count_v,
                            "buckets": buckets,
                            "service_name": service_name,
                            "attributes": attrs,
                            "resource": json.dumps(resource_attrs, default=str),
                        }

    @staticmethod
    def _classify(data: Any, dp: Any):
        cls = data.__class__.__name__
        if cls == "Sum":
            return "sum", float(dp.value), None, None, None
        if cls == "Gauge":
            return "gauge", float(dp.value), None, None, None
        if cls == "Histogram":
            buckets = json.dumps(
                {
                    "boundaries": list(getattr(dp, "explicit_bounds", []) or []),
                    "counts": list(getattr(dp, "bucket_counts", []) or []),
                }
            )
            return (
                "histogram",
                None,
                float(getattr(dp, "sum", 0.0) or 0.0),
                int(getattr(dp, "count", 0) or 0),
                buckets,
            )
        return cls.lower(), None, None, None, None
