"""Pencheff observability package — OTel SDK wiring + Postgres exporters.

Public surface intentionally minimal. Callers in ``main.py`` and the
Celery worker init signal call ``init_observability(service_name)``;
everything else is internal.

When ``settings.observability_enabled`` is ``False`` (the default) every
function in this package is a no-op — instrumentation packages are
imported lazily inside ``init_observability`` so a vanilla deployment
without OTel deps installed does not crash on import either.
"""
from .bootstrap import init_observability, shutdown_observability

__all__ = ["init_observability", "shutdown_observability"]
