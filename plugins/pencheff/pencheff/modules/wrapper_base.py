"""Shared helper for thin Phase-2 tool wrappers.

A wrapper turns ``(tool_name, target, opts)`` into ``[Finding]``. Wrappers
share a tiny adapter so each concrete wrapper is ~10 lines: the policy YAMLs
already encode the CLI args, and ``result_normalizer`` converts stdout to
findings.

Design: wrappers must NOT contain decision logic. If you find yourself
adding "if WAF detected, change params", that belongs in the orchestrator
or the policy YAML.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
from collections.abc import Iterable
from typing import Any

from pencheff.core.orchestrator.fallback import FallbackResolver
from pencheff.core.orchestrator.param_optimizer import ParamOptimizer
from pencheff.core.orchestrator.policies import load_policies
from pencheff.core.orchestrator.result_normalizer import normalize
from pencheff.core.tool_runner import ToolResult, run_tool, tool_available


log = logging.getLogger("pencheff.wrappers")


def build_argv(
    tool: str,
    target: str,
    *,
    tier: str = "default",
    extra_args: Iterable[str] = (),
    target_position: str = "tail",
    variant: str | None = None,
) -> list[str]:
    """Compose the subprocess argv for ``tool`` deterministically."""
    optimizer = ParamOptimizer(load_policies())
    args = optimizer.args_for(tool, tier=tier, variant=variant)
    extra = list(extra_args)
    if target_position == "head":
        return [tool, target, *args, *extra]
    return [tool, *args, *extra, target]


async def run_wrapper(
    tool: str,
    target: str,
    *,
    tier: str = "default",
    extra_args: Iterable[str] = (),
    target_position: str = "tail",
    timeout: float = 60.0,
    variant: str | None = None,
    use_fallback: bool = True,
) -> tuple[str, ToolResult, list[Any]]:
    """Resolve fallbacks, run the tool, return ``(resolved_name, result, findings)``.

    ``run_tool`` already shells via ``asyncio.create_subprocess_exec`` — no
    shell=True. If the tool isn't installed and fallbacks are exhausted,
    returns an empty findings list with a synthetic ToolResult.
    """
    if use_fallback:
        chosen = FallbackResolver().resolve(tool)
    else:
        chosen = tool if tool_available(tool) else None
    if chosen is None:
        return tool, ToolResult("", f"{tool}: not installed", -1), []

    argv = build_argv(
        chosen,
        target,
        tier=tier,
        extra_args=extra_args,
        target_position=target_position,
        variant=variant,
    )
    log.debug("wrapper run: %s", shlex.join(argv))
    result = await run_tool(argv, timeout=timeout)
    findings = normalize(chosen, result.stdout, target, stderr=result.stderr)
    return chosen, result, findings


def run_wrapper_sync(*args, **kwargs):
    """Sync convenience for the CLI/REPL."""
    return asyncio.run(run_wrapper(*args, **kwargs))
