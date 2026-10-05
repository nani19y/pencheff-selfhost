"""Idempotent OTel bootstrap.

The single-call entry point is ``init_observability(service_name)``.
When ``settings.observability_enabled`` is False, this is a no-op; no
OTel SDK code runs, no instrumentation is wired, no exporter is opened.

When enabled, the function:

1. Builds a ``Resource`` carrying the service name + environment.
2. Configures a ``TracerProvider`` with the head sampler + a
   ``BatchSpanProcessor`` wrapping the Postgres exporter.
3. Configures a ``LoggerProvider`` (logs pipeline) and bridges
   ``logging`` → OTel via ``LoggingInstrumentor``.
4. Configures a ``MeterProvider`` with the Postgres metric exporter.
5. Activates auto-instrumentation: FastAPI, SQLAlchemy (the exporter
   bypasses with raw psycopg2 — see exporter.py), AsyncPG, Celery,
   Redis. Httpx is NOT auto-instrumented; the plugin's
   ``PencheffHTTPClient`` does it manually with pencheff-specific
   attributes auto would duplicate.

Re-entry is idempotent: a global flag prevents double-instrumentation.
"""
from __future__ import annotations

import logging
import os
import threading

log = logging.getLogger("pencheff.observability")

_lock = threading.Lock()
_initialised = False
_providers: dict = {}


def init_observability(service_name: str | None = None) -> None:
    """Initialise OTel pipeline. Safe to call multiple times."""
    global _initialised

    from ..config import get_settings

    settings = get_settings()
    if not settings.observability_enabled:
        return

    with _lock:
        if _initialised:
            return
        _initialised = True

        try:
            _bootstrap(settings, service_name)
        except Exception as exc:  # noqa: BLE001
            log.exception("observability bootstrap failed: %s", exc)
            # Bootstrap failure must NEVER take the API down. The
            # observability pipeline is supplementary, not load-bearing
            # — flip the flag back so a future call can retry on the
            # next worker boot.
            _initialised = False


def _bootstrap(settings, service_name: str | None) -> None:
    from opentelemetry import trace, metrics
    from opentelemetry._logs import set_logger_provider
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

    from .exporter import (
        PostgresLogExporter,
        PostgresMetricExporter,
        PostgresSpanExporter,
    )
    from .sampler import build_sampler

    name = service_name or settings.observability_service_name
    dsn = settings.sync_database_url

    resource = Resource.create({
        "service.name": name,
        "service.version": "0.1.0",
        "deployment.environment": settings.environment,
    })

    # ---- Tracer ---------------------------------------------------- #
    span_exporter = PostgresSpanExporter(dsn)
    span_processor = BatchSpanProcessor(
        span_exporter,
        max_queue_size=4096,
        max_export_batch_size=512,
        schedule_delay_millis=2000,
    )
    tracer_provider = TracerProvider(
        resource=resource,
        sampler=build_sampler(settings.observability_sample_ratio),
    )
    tracer_provider.add_span_processor(span_processor)
    trace.set_tracer_provider(tracer_provider)
    _providers["tracer"] = tracer_provider

    # ---- Logger ---------------------------------------------------- #
    log_exporter = PostgresLogExporter(dsn)
    logger_provider = LoggerProvider(resource=resource)
    logger_provider.add_log_record_processor(
        BatchLogRecordProcessor(log_exporter)
    )
    set_logger_provider(logger_provider)
    _providers["logger"] = logger_provider

    # ---- Meter ----------------------------------------------------- #
    metric_exporter = PostgresMetricExporter(dsn)
    meter_provider = MeterProvider(
        resource=resource,
        metric_readers=[
            PeriodicExportingMetricReader(
                metric_exporter, export_interval_millis=15000
            )
        ],
    )
    metrics.set_meter_provider(meter_provider)
    _providers["meter"] = meter_provider

    # ---- Auto-instrumentation ------------------------------------- #
    _activate_auto_instrumentation()
    log.info("observability bootstrap: service=%s sample_ratio=%s retention_days=%s",
             name, settings.observability_sample_ratio,
             settings.observability_retention_days)


def _activate_auto_instrumentation() -> None:
    """Wire the auto-instrumentation packages we want.

    We deliberately do NOT instrument httpx — ``PencheffHTTPClient``
    has a manual span with pencheff-specific attributes auto-instrumentation
    can't know about, and double-instrumenting would create
    duplicate parent/child pairs. Same reasoning for psycopg2 (not
    listed): the exporter bypasses SQLAlchemy via raw psycopg2 to
    break the recursion loop.
    """
    # Each instrumentor is wrapped in its own try/except — if one fails
    # to import (say, the operator hasn't pulled in the optional dep
    # for that integration) the rest still wire up.
    #
    # ``excluded_urls`` keeps /health out of every spans/metrics row
    # (would otherwise dominate volume) and the OTLP receiver paths
    # out (instrumenting them would create a server span per ingest).
    _try_instrument(
        "fastapi", "FastAPIInstrumentor", excluded_urls=fastapi_excluded_urls()
    )
    _try_instrument("sqlalchemy", "SQLAlchemyInstrumentor")
    _try_instrument("asyncpg", "AsyncPGInstrumentor")
    _try_instrument("celery", "CeleryInstrumentor")
    _try_instrument("redis", "RedisInstrumentor")
    _try_instrument("logging", "LoggingInstrumentor", set_logging_format=True)


def _try_instrument(pkg: str, class_name: str, **kwargs) -> None:
    try:
        module = __import__(
            f"opentelemetry.instrumentation.{pkg}", fromlist=[class_name]
        )
        cls = getattr(module, class_name)
        cls().instrument(**kwargs)
    except Exception as exc:  # noqa: BLE001
        log.warning("could not instrument %s: %s", pkg, exc)


def fastapi_excluded_urls() -> str:
    """Comma-separated URL prefixes the FastAPI instrumentation should
    skip. /health spam shouldn't fill the spans table; /v1/* are the
    OTLP receivers and instrumenting them creates recursive spans."""
    return os.environ.get(
        "OTEL_PYTHON_FASTAPI_EXCLUDED_URLS",
        "/health,/v1/traces,/v1/logs,/v1/metrics",
    )


def shutdown_observability() -> None:
    """Flush + close providers. Called during graceful shutdown."""
    global _initialised
    if not _initialised:
        return
    with _lock:
        for kind, provider in _providers.items():
            try:
                fn = getattr(provider, "shutdown", None)
                if fn:
                    fn()
            except Exception as exc:  # noqa: BLE001
                log.warning("shutdown of %s provider failed: %s", kind, exc)
        _providers.clear()
        _initialised = False
