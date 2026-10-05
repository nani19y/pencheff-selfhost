"""Fallback resolver — walks ``fallbacks.yaml`` when a tool is unavailable."""

from __future__ import annotations

from collections.abc import Callable

from pencheff.core.orchestrator.policies import Policies, load_policies


class FallbackResolver:
    def __init__(
        self,
        policies: Policies | None = None,
        *,
        is_available: Callable[[str], bool] | None = None,
    ) -> None:
        self._policies = policies or load_policies()
        # ``is_available`` is injected so tests don't need real binaries.
        # Default uses shutil.which via core.tool_runner.
        if is_available is None:
            from pencheff.core.tool_runner import tool_available
            is_available = tool_available
        self._is_available = is_available

    def resolve(self, primary: str) -> str | None:
        """Return ``primary`` if installed, else the first available fallback.

        Returns ``None`` if neither the primary nor any documented fallback
        is on PATH. Native (in-process) tools are always considered
        available — they are checked separately by the engine.
        """
        if self._is_available(primary):
            return primary
        for candidate in self._policies.fallbacks.get("fallbacks", {}).get(primary, []):
            if self._is_available(candidate):
                return candidate
        return None

    def chain(self, primary: str) -> list[str]:
        """Full ordered list (primary + fallbacks) for diagnostics."""
        return [primary, *self._policies.fallbacks.get("fallbacks", {}).get(primary, [])]
