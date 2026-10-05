"""Plugin OTel bootstrap.

Idempotent. No-op when ``PENCHEFF_OBSERVABILITY_ENABLED`` is unset or
"false". When enabled:

* Resource attributes name the service ``pencheff-plugin``.
* A multi-exporter trace pipeline:
  - Always-on file exporter writing JSONL to
    ``~/.pencheff/logs/otel-YYYYMMDD.jsonl`` (one file per UTC day so
    daily prune is a single ``unlink`` per file).
  - OTLP/HTTP exporter targeting ``PENCHEFF_OBSERVABILITY_OTLP_URL``
    when set, with a bearer token from
    ``PENCHEFF_OBSERVABILITY_OTLP_TOKEN`` (an
    ``EngagementIngestToken`` issued by the API).

Local prune (delete log files older than 7 days) is invoked lazily
from ``server.py`` startup — the plugin has no scheduler.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

log = logging.getLogger("pencheff.observability")

_lock = threading.Lock()
_initialised = False
_providers: dict = {}


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


def _local_dir() -> Path:
    p = os.environ.get("PENCHEFF_OBSERVABILITY_LOCAL_DIR", "").strip()
    return Path(p) if p else Path.home() / ".pencheff" / "logs"


def init_plugin_observability(service_name: str = "pencheff-plugin") -> None:
    """Wire up OTel inside the plugin process. Safe to call repeatedly."""
    global _initialised
    if not _truthy(os.environ.get("PENCHEFF_OBSERVABILITY_ENABLED")):
        return

    with _lock:
        if _initialised:
            return
        _initialised = True
        try:
            _bootstrap(service_name)
        except Exception as exc:  # noqa: BLE001
            log.warning("plugin observability bootstrap failed: %s", exc)
            _initialised = False


def _bootstrap(service_name: str) -> None:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create({
        "service.name": service_name,
        "service.version": "0.6.0",
    })
    provider = TracerProvider(resource=resource)

    # Always-on file exporter — local debugging keeps working even when
    # the operator hasn't wired OTLP shipping.
    log_dir = _local_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    file_exporter = _FileSpanExporter(log_dir)
    provider.add_span_processor(BatchSpanProcessor(file_exporter))

    otlp_url = os.environ.get("PENCHEFF_OBSERVABILITY_OTLP_URL", "").strip()
    otlp_token = os.environ.get("PENCHEFF_OBSERVABILITY_OTLP_TOKEN", "").strip()
    if otlp_url and otlp_token:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            ship_url = otlp_url.rstrip("/") + "/v1/traces"
            otlp_exporter = OTLPSpanExporter(
                endpoint=ship_url,
                headers={"Authorization": f"Bearer {otlp_token}"},
            )
            provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
            log.info("plugin observability shipping to %s", ship_url)
        except Exception as exc:  # noqa: BLE001
            log.warning("OTLP exporter setup failed: %s", exc)

    trace.set_tracer_provider(provider)
    _providers["tracer"] = provider


def shutdown_plugin_observability() -> None:
    global _initialised
    if not _initialised:
        return
    with _lock:
        for provider in _providers.values():
            try:
                fn = getattr(provider, "shutdown", None)
                if fn:
                    fn()
            except Exception:
                pass
        _providers.clear()
        _initialised = False


# --------------------------------------------------------------------- #
# Local file exporter — JSONL, one file per UTC day for cheap pruning.
# --------------------------------------------------------------------- #


class _FileSpanExporter:
    """Append-only JSONL writer. One file per UTC date so the local
    prune (``observability/local_prune.py``) only has to ``unlink``
    whole files older than the retention horizon.
    """

    def __init__(self, dir_path: Path):
        self._dir = dir_path
        self._lock = threading.Lock()

    def export(self, spans: Sequence[Any]) -> Any:
        from opentelemetry.sdk.trace.export import SpanExportResult

        if not spans:
            return SpanExportResult.SUCCESS
        try:
            today = datetime.now(timezone.utc).strftime("%Y%m%d")
            path = self._dir / f"otel-{today}.jsonl"
            with self._lock, path.open("a", encoding="utf-8") as fh:
                for span in spans:
                    fh.write(json.dumps(self._row(span), default=str))
                    fh.write("\n")
            return SpanExportResult.SUCCESS
        except Exception as exc:  # noqa: BLE001
            log.warning("file span export failed: %s", exc)
            return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    @staticmethod
    def _row(span: Any) -> dict[str, Any]:
        ctx = span.get_span_context()
        parent = span.parent
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "name": span.name,
            "trace_id": ctx.trace_id.to_bytes(16, "big").hex(),
            "span_id": ctx.span_id.to_bytes(8, "big").hex(),
            "parent_span_id": (
                parent.span_id.to_bytes(8, "big").hex() if parent else None
            ),
            "kind": getattr(span.kind, "name", str(span.kind)),
            "start_time": span.start_time,
            "end_time": span.end_time,
            "duration_ns": (
                (span.end_time - span.start_time)
                if (span.end_time and span.start_time)
                else None
            ),
            "attributes": dict(span.attributes or {}),
            "status_code": (
                span.status.status_code.name if span.status else None
            ),
            "status_message": getattr(span.status, "description", None),
        }
