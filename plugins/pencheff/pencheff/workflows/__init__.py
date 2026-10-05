"""Deterministic workflow templates (Phase 4).

Each workflow is a top-level coroutine that drives the
:class:`pencheff.core.orchestrator.engine.Orchestrator` to completion against
a target — no LLM in the loop. Workflows share the same module + policy
layer as MCP-driven sessions.

Public registry: :func:`get_workflow` returns the coroutine by name.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

from pencheff.workflows import auto_pentest, bug_bounty, ctf_solve, cve_intel, red_team


_REGISTRY: dict[str, Callable[..., Coroutine[Any, Any, dict[str, Any]]]] = {
    "auto_pentest": auto_pentest.run,
    "bug_bounty":   bug_bounty.run,
    "ctf_solve":    ctf_solve.run,
    "cve_intel":    cve_intel.run,
    "red_team":     red_team.run,
}


def get_workflow(name: str):
    if name not in _REGISTRY:
        raise KeyError(
            f"unknown workflow {name!r}; choose from {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name]


def list_workflows() -> list[str]:
    return sorted(_REGISTRY.keys())
