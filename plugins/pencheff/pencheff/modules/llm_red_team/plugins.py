"""Plugin SDK for custom LLM red-team strategies, judges, and providers.

Three independent registries — strategies (prompt transforms), judges
(verdict overrides), and providers (chat dispatchers). Each registry
combines a built-in dict with an optional dynamic-discovery pass that
imports `*.py` files under ``~/.pencheff/custom_llm_*/`` when the
opt-in env var ``PENCHEFF_ENABLE_CUSTOM_MODULES=1`` is set.

Plugins are tiny, single-method protocol classes with a ``name``
class attribute used as the registry key. See
``docs/llm-redteam-plugin-sdk.md`` for examples.

Discovery is intentionally not "scan PyPI for an entry point" — that
would let a transitive dep silently inject judges/providers into a
red-team scan. Plugins must be physically placed under the user's
home directory and the env var must be set; both are explicit acts.
"""
from __future__ import annotations

import importlib.util
import inspect
import logging
import os
from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable

log = logging.getLogger(__name__)


CUSTOM_STRATEGIES_DIR = Path.home() / ".pencheff" / "custom_llm_strategies"
CUSTOM_JUDGES_DIR = Path.home() / ".pencheff" / "custom_llm_judges"
CUSTOM_PROVIDERS_DIR = Path.home() / ".pencheff" / "custom_llm_providers"


# ── Strategy plugin ─────────────────────────────────────────────────


@runtime_checkable
class StrategyPlugin(Protocol):
    """A strategy plugin transforms a single prompt.

    Implementations expose a class attribute ``name: str`` (the
    registry key) and a callable that takes a ``str`` prompt and
    returns a transformed ``str``. They can be plain classes with a
    ``transform`` static/classmethod, or plain functions wrapped via
    ``register_strategy``.
    """

    name: str

    def transform(self, prompt: str) -> str: ...  # pragma: no cover - protocol stub


_strategy_registry: dict[str, Callable[[str], str]] = {}


def register_strategy(name: str, fn: Callable[[str], str]) -> None:
    """Register a function-based strategy. Last writer wins so
    plugins can override built-ins; that's deliberate (a custom
    'jailbreak' that fits a specific deployment can replace ours)."""
    _strategy_registry[name.strip().lower()] = fn


def get_strategy(name: str) -> Callable[[str], str] | None:
    return _strategy_registry.get(name.strip().lower())


def all_strategy_names() -> list[str]:
    return sorted(_strategy_registry.keys())


# ── Judge plugin ────────────────────────────────────────────────────


@runtime_checkable
class JudgePlugin(Protocol):
    """A judge plugin classifies one (TestCase, response_text) pair.

    Implementations expose a class attribute ``name: str`` and an
    async classmethod ``judge`` returning ``JudgeResult | None`` (the
    same shape as the built-in ``LlmJudge``)."""

    name: str

    async def judge(self, tc: Any, response_text: str) -> Any: ...  # pragma: no cover - stub


_judge_registry: dict[str, type] = {}


def register_judge(name: str, cls: type) -> None:
    _judge_registry[name.strip().lower()] = cls


def get_judge(name: str) -> type | None:
    return _judge_registry.get(name.strip().lower())


def all_judge_names() -> list[str]:
    return sorted(_judge_registry.keys())


# ── Provider plugin ─────────────────────────────────────────────────


@runtime_checkable
class ProviderPlugin(Protocol):
    """A provider plugin dispatches a chat request and returns a
    ``ProbeResponse``-shaped object. Used to add transports beyond
    HTTP / executable / WebSocket without touching engine.py."""

    name: str

    async def chat(self, prompt: str, system: str | None, history: Any) -> Any: ...  # pragma: no cover - stub


_provider_registry: dict[str, type] = {}


def register_provider(name: str, cls: type) -> None:
    _provider_registry[name.strip().lower()] = cls


def get_provider(name: str) -> type | None:
    return _provider_registry.get(name.strip().lower())


def all_provider_names() -> list[str]:
    return sorted(_provider_registry.keys())


# ── Discovery ───────────────────────────────────────────────────────


_discovered = False


def discover_plugins(force: bool = False) -> None:
    """Import every ``.py`` under the three discovery directories,
    register their plugin classes, and call any ``register()`` hook
    they expose at module level.

    Idempotent — safe to call from multiple entry points (CLI, MCP
    tool, scan_runner). Passes silently when the opt-in env var is
    unset, when the directories don't exist, or when a single plugin
    raises during import."""
    global _discovered
    if _discovered and not force:
        return
    _discovered = True

    if os.environ.get("PENCHEFF_ENABLE_CUSTOM_MODULES") != "1":
        return

    for directory, registrar in (
        (CUSTOM_STRATEGIES_DIR, _try_register_strategy),
        (CUSTOM_JUDGES_DIR, _try_register_judge),
        (CUSTOM_PROVIDERS_DIR, _try_register_provider),
    ):
        if not directory.exists():
            continue
        for py in sorted(directory.glob("*.py")):
            if py.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"pencheff_custom_llm_{py.parent.name}_{py.stem}", py
                )
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
            except Exception as exc:  # noqa: BLE001 — bad plugin shouldn't poison the rest
                log.warning("failed to import plugin %s: %s", py, exc)
                continue
            # Allow modules to expose register(register_*) functions.
            register_fn = getattr(mod, "register", None)
            if callable(register_fn):
                try:
                    register_fn(register_strategy, register_judge, register_provider)
                except Exception as exc:  # noqa: BLE001
                    log.warning("plugin %s register() failed: %s", py, exc)
            for _name, obj in inspect.getmembers(mod, inspect.isclass):
                registrar(obj)


def _try_register_strategy(cls: type) -> None:
    name = getattr(cls, "name", None)
    transform = getattr(cls, "transform", None)
    if not isinstance(name, str) or not callable(transform):
        return
    if name.strip().lower() in _strategy_registry:
        return
    instance = _instantiate_safely(cls)
    if instance is None:
        return
    bound = getattr(instance, "transform", None)
    if not callable(bound):
        return
    _strategy_registry[name.strip().lower()] = bound  # type: ignore[assignment]


def _try_register_judge(cls: type) -> None:
    name = getattr(cls, "name", None)
    if not isinstance(name, str):
        return
    judge_method = getattr(cls, "judge", None)
    if not callable(judge_method):
        return
    _judge_registry.setdefault(name.strip().lower(), cls)


def _try_register_provider(cls: type) -> None:
    name = getattr(cls, "name", None)
    if not isinstance(name, str):
        return
    chat_method = getattr(cls, "chat", None)
    if not callable(chat_method):
        return
    _provider_registry.setdefault(name.strip().lower(), cls)


def _instantiate_safely(cls: type) -> Any | None:
    try:
        return cls()
    except TypeError:
        # Class needs args — caller is responsible for instantiation.
        return None


# Convenience: clear all dynamic registrations (used by tests).
def reset_registries() -> None:
    global _discovered
    _discovered = False
    _strategy_registry.clear()
    _judge_registry.clear()
    _provider_registry.clear()
