"""Plugin-side observability — OTel tracer for the MCP plugin.

When ``PENCHEFF_OBSERVABILITY_ENABLED=true`` the plugin's bootstrap
(see ``bootstrap.py``) sets up:
  * Always-on file exporter to ``~/.pencheff/logs/otel-YYYYMMDD.jsonl``
    (so a local pentest run still gets traces even when offline).
  * OTLP/HTTP exporter targeting the API's ``/v1/traces`` endpoint
    when ``PENCHEFF_OBSERVABILITY_OTLP_URL`` + a valid
    ``PENCHEFF_OBSERVABILITY_OTLP_TOKEN`` are present.

When disabled, every helper is a no-op and the OTel SDK is never
imported — keeps the plugin's cold-start time identical for users who
don't opt in.
"""
from .bootstrap import init_plugin_observability, shutdown_plugin_observability
from .redact import (
    REDACTED,
    SENSITIVE_HEADERS,
    SENSITIVE_QUERY_PARAMS,
    hash_argv,
    redact_headers,
    redact_url,
)

__all__ = [
    "init_plugin_observability",
    "shutdown_plugin_observability",
    "REDACTED",
    "SENSITIVE_HEADERS",
    "SENSITIVE_QUERY_PARAMS",
    "hash_argv",
    "redact_headers",
    "redact_url",
]
