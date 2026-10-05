"""Tier 1 / Tier 2 enforcement.

Tier 1 = advisory only. Reads user-provided output, runs deterministic
lookups, never makes outbound network calls beyond DNS resolution.

Tier 2 = execution. Runs scanners, fuzzers, exploiters. Requires a loaded
:class:`pencheff.core.scope_guard.ScopeGuard` and validates every target.

Both decorators are inspectable (``fn.tier``) so the playbook orchestrator
can pre-flight a phase plan without invoking it.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Literal

from pencheff.core.scope_guard import ScopeNotDeclared, current_scope


class TierViolation(Exception):
    """A Tier 1 function attempted a Tier 2 action."""


_TIER_ATTR = "__pencheff_tier__"


def tier_1(fn: Callable[..., Any]) -> Callable[..., Any]:
    setattr(fn, _TIER_ATTR, 1)
    return fn


def tier_2(fn: Callable[..., Any]) -> Callable[..., Any]:
    setattr(fn, _TIER_ATTR, 2)

    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def aw(*args: Any, **kwargs: Any) -> Any:
            if current_scope() is None:
                raise ScopeNotDeclared(
                    f"{fn.__name__} is Tier 2 — requires an active scope guard "
                    "(load with --scope FILE on the CLI)."
                )
            return await fn(*args, **kwargs)
        setattr(aw, _TIER_ATTR, 2)
        return aw

    @functools.wraps(fn)
    def w(*args: Any, **kwargs: Any) -> Any:
        if current_scope() is None:
            raise ScopeNotDeclared(
                f"{fn.__name__} is Tier 2 — requires an active scope guard "
                "(load with --scope FILE on the CLI)."
            )
        return fn(*args, **kwargs)
    setattr(w, _TIER_ATTR, 2)
    return w


def get_tier(obj: Any) -> Literal[1, 2] | None:
    return getattr(obj, _TIER_ATTR, None)
