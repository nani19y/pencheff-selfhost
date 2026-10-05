"""Base class for all testing modules + plugin-SDK discovery.

Built-in modules live under ``pencheff.modules.*`` and are imported explicitly.
Custom modules may also be loaded from ``~/.pencheff/custom_modules/*.py`` when
the user opts in via the ``PENCHEFF_ENABLE_CUSTOM_MODULES=1`` environment variable.

See ``docs/plugin-sdk.md`` for a full walkthrough.
"""

from __future__ import annotations

import importlib.util
import inspect
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pencheff.core.findings import Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession

# Endpoint "source" values that mean an operator explicitly imported this
# surface (an OpenAPI/Swagger/Postman spec, or a graphql/grpc/websocket target
# config) rather than the crawler stumbling onto it. These are curated and
# bounded, so per-module endpoint caps must never truncate them — the whole
# point of importing a spec is that every documented endpoint gets tested.
SPEC_SOURCES = frozenset(
    {"openapi3", "swagger2", "postman", "spec", "graphql", "grpc", "websocket"}
)


class BaseTestModule(ABC):
    """Abstract base for pentest testing modules."""

    name: str = ""
    category: str = ""
    owasp_categories: list[str] = []
    description: str = ""

    @abstractmethod
    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Execute this module's tests. Returns a list of findings."""
        ...

    @abstractmethod
    def get_techniques(self) -> list[str]:
        """Return list of technique names this module can run."""
        ...

    def _get_target_endpoints(
        self, session: PentestSession, targets: list[str] | None
    ) -> list[dict[str, Any]]:
        """Get endpoints to test — either explicit targets or all discovered."""
        if targets:
            return [{"url": t, "method": "GET", "params": []} for t in targets]
        eps = session.discovered.endpoints or [
            {"url": session.target.base_url, "method": "GET", "params": []}
        ]
        # Order operator-imported spec endpoints first so any module still using
        # a raw ``[:N]`` cap spends its budget on curated endpoints before crawl
        # noise. Modules that call ``_cap_endpoints`` get all spec endpoints
        # regardless; this is the safety net for the ones that don't.
        return sorted(eps, key=lambda e: 0 if e.get("source") in SPEC_SOURCES else 1)

    def _cap_endpoints(
        self, endpoints: list[dict[str, Any]], cap: int
    ) -> list[dict[str, Any]]:
        """Bound a per-module endpoint budget without dropping imported spec
        endpoints. Every spec-sourced endpoint is always tested; only crawl-
        discovered endpoints are capped at ``cap``. Pass the module's already-
        filtered endpoint list (e.g. write-only, /api/-only)."""
        spec = [e for e in endpoints if e.get("source") in SPEC_SOURCES]
        other = [e for e in endpoints if e.get("source") not in SPEC_SOURCES]
        return spec + other[:cap]


# ─── Custom module discovery (opt-in) ─────────────────────────────────

CUSTOM_DIR = Path.home() / ".pencheff" / "custom_modules"


def load_custom_modules() -> list[type[BaseTestModule]]:
    """Import every ``.py`` under ``~/.pencheff/custom_modules`` and return the
    discovered ``BaseTestModule`` subclasses.

    This is **opt-in**: requires ``PENCHEFF_ENABLE_CUSTOM_MODULES=1``. Custom
    modules run with full host process privileges; do not enable this on shared
    infrastructure without code review.
    """
    if os.environ.get("PENCHEFF_ENABLE_CUSTOM_MODULES") != "1":
        return []
    if not CUSTOM_DIR.exists():
        return []
    found: list[type[BaseTestModule]] = []
    for py in CUSTOM_DIR.glob("*.py"):
        if py.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"pencheff_custom_{py.stem}", py
            )
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for _name, obj in inspect.getmembers(mod, inspect.isclass):
                if (
                    issubclass(obj, BaseTestModule)
                    and obj is not BaseTestModule
                ):
                    found.append(obj)
        except Exception:  # noqa: BLE001
            continue
    return found
