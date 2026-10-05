"""Iterate-until-done outer driver for the agentic fixer.

The Celery task that owns this loop is responsible for:
* Cloning the repo (or pointing at the local_path)
* Loading findings
* Building the workspace path
* Persisting per-iteration state via the callbacks injected here

We deliberately don't take a DB session in this module — the loop is
pure async with hooks for I/O so it can be exercised in unit tests
with stubbed callbacks.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from ...config import get_settings
from .cost import Usage, compute_cost_cents
from .extra_tools import (
    current_streak,
    repeat_hard_stop_threshold,
)
from .file_tools import ToolResult
from .llm_client import LLMClient, AgentMessage, get_client
from .system_prompt import (
    FindingForAgent,
    build_initial_user_message,
    build_system_prompt,
)
from .tools import ToolCatalog, dispatch_tool

log = logging.getLogger("pencheff.agentic_fixer.loop")

# A model that keeps reading source without ever editing is stuck. We
# guard against that, but the read budget SCALES with the task — a
# 1-finding repo and a 49-finding repo spanning many manifests should
# not share the same cap (the old flat 8 fired on legitimate recon).
#
# Only read_file / grep count as "inspection reads". TodoWrite is
# planning, glob is file discovery, and web_search / mcp_call are
# external lookups — none of those are "re-reading source", so they
# don't count toward the stuck-reading budget. The guard only matters
# BEFORE the first edit; once any mutation happens it is disabled for
# the rest of the run. The cross-iteration repeat detector
# (current_streak) and the iteration / token budgets are the other
# backstops, so this guard can afford to be generous.
# Raised from 12: reasoning models (deepseek-v4-pro) explore more source before
# their first edit, and a flat-12 floor tripped "model_stuck_reading" on real
# multi-finding runs, producing zero changes. The iteration + token budgets and
# the repeat detector remain the hard runaway backstops, so this stays generous.
_MIN_READS_WITHOUT_EDIT = 30
_READS_PER_FINDING_FILE = 5
_INSPECTION_TOOLS = frozenset({"read_file", "grep"})
_MUTATING_TOOLS = frozenset({"edit_file", "write_file", "bash"})


class AgentCanceled(Exception):
    """Raised when the run's cancel flag flips between iterations."""


class AgentStuck(Exception):
    """Raised when the model stalls — repeats the same tool call, or reads
    source without ever editing — so the run is aborted with partial work
    preserved. (There is no per-run token budget; runs go to completion or the
    iteration cap.)"""


@dataclass
class IterationOutcome:
    """One iteration's bookkeeping. Reported to the caller's callbacks
    after the iteration completes so the DB row + SSE stream stay in
    sync with the worker's state.
    """

    iteration: int
    stop_reason: str
    usage: Usage
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    text: str = ""


# Callback signatures — the Celery task wires these up to write DB rows.
StepCb = Callable[
    [int, int, str, dict[str, Any], ToolResult, int],
    Awaitable[None],
]
"""(iteration, step_index, tool_name, tool_input, tool_result, duration_ms) -> None"""

IterationCb = Callable[[IterationOutcome], Awaitable[None]]
"""Called after each iteration (LLM response + all tool dispatches)."""

CancelCb = Callable[[], Awaitable[bool]]
"""Returns True if the run should abort."""


@dataclass
class AgenticFixer:
    """Stateful holder for one run's loop config + counters."""

    workspace_root: Path
    branch_name: str
    repo_full_name: str | None
    runtime: str  # "server" | "desktop"
    findings: list[FindingForAgent]
    # Server-side ``AgenticFixRun.id`` — used by the TodoWrite tool
    # to key its per-run scratch state. Optional only for legacy
    # callers that ran the loop without persistence.
    run_id: str | None = None
    # Counters for the "stuck reading" hard-stop. The repeat detector
    # already catches a model that calls the same tool with the same
    # args N times in a row, but it doesn't catch a model that reads
    # many different source files without ever editing. After more than
    # ``_read_budget()`` inspection reads (read_file / grep) with zero
    # edits, the loop aborts. Planning (TodoWrite) and discovery (glob)
    # do not count — see ``_classify``.
    _mutating_calls: int = 0
    _inspection_reads: int = 0

    # Wired by the Celery task to persistence.
    on_step: StepCb | None = None
    on_iteration: IterationCb | None = None
    cancel_cb: CancelCb | None = None

    # Optional overrides. Default values come from settings.
    model: str | None = None
    max_iterations: int | None = None

    # Internal counters.
    _total_input_tokens: int = 0
    _total_output_tokens: int = 0

    @staticmethod
    def _classify(tool_name: str) -> str:
        """Bucket a tool call for the stuck-reading guard.

        ``mutating``   — edit_file / write_file / bash (real progress).
        ``inspection`` — read_file / grep (re-reading source; counts).
        ``neutral``    — TodoWrite / glob / web_search / mcp_call
                          (planning, discovery, external lookups; do
                          NOT count toward the read budget).
        """
        if tool_name in _MUTATING_TOOLS:
            return "mutating"
        if tool_name in _INSPECTION_TOOLS:
            return "inspection"
        return "neutral"

    def _read_budget(self) -> int:
        """Inspection-read allowance before the first edit, scaled to
        the task. A run touching many distinct files legitimately needs
        more reads than a single-file one; the floor keeps small runs
        from tripping on normal recon.
        """
        distinct_files = len({f.file_path for f in self.findings if f.file_path})
        return max(_MIN_READS_WITHOUT_EDIT, _READS_PER_FINDING_FILE * distinct_files)

    async def run(self) -> str:
        """Drive the loop. Returns the agent's final assistant text.

        Raises ``AgentCanceled`` if cancellation is requested between
        iterations, ``AgentStuck`` if the model stalls (repeats a tool call
        or reads without editing). Any tool-level error is delivered to the
        agent as a tool result and does NOT raise here.
        """
        settings = get_settings()
        client: LLMClient = get_client()
        if not client.enabled:
            raise RuntimeError(
                "Agentic fixer LLM client disabled — AGENTIC_FIX_API_KEY missing."
            )

        system = build_system_prompt(
            branch_name=self.branch_name,
            repo_full_name=self.repo_full_name,
            runtime=self.runtime,
        )
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": build_initial_user_message(self.findings)},
        ]
        tools = ToolCatalog.for_server()  # same shape works for desktop in v1
        cap = self.max_iterations or settings.agentic_fix_max_iterations
        model = self.model or settings.agentic_fix_effective_model

        final_text = ""

        for iteration in range(1, cap + 1):
            await self._check_cancel()
            log.info(
                "agentic-fix loop iter=%d / model=%s / messages=%d",
                iteration, model, len(messages),
            )

            response: AgentMessage = await client.create_message(
                system=system,
                messages=messages,
                tools=tools,
                model=model,
            )

            self._total_input_tokens += response.usage.input_tokens
            self._total_output_tokens += response.usage.output_tokens

            outcome = IterationOutcome(
                iteration=iteration,
                stop_reason=response.stop_reason,
                usage=response.usage,
                text=response.text,
            )

            if not response.tool_uses:
                # Pure text turn → run is done.
                final_text = response.text or ""
                if self.on_iteration:
                    await self.on_iteration(outcome)
                break

            # Append the assistant turn (with tool_calls preserved
            # so the model can correlate its requests with the
            # tool-role responses we're about to add).
            assistant_msg: dict[str, Any] = {
                "role": "assistant",
                "content": response.text or "",
                "tool_calls": [
                    {
                        "id": tu.call_id,
                        "type": "function",
                        "function": {
                            "name": tu.name,
                            "arguments": json.dumps(tu.input),
                        },
                    }
                    for tu in response.tool_uses
                ],
            }
            # Echo back reasoning_content for providers that
            # require it (DeepSeek thinking mode). Absent for
            # providers that don't (Sarvam, OpenAI proper).
            if response.reasoning_content:
                assistant_msg["reasoning_content"] = response.reasoning_content
            messages.append(assistant_msg)

            # Dispatch each tool sequentially. Parallel dispatch is a
            # follow-up — sequential keeps state changes ordered and
            # easier to reason about while we settle the prompt.
            for step_index, tu in enumerate(response.tool_uses):
                await self._check_cancel()
                dispatch = await dispatch_tool(
                    self.workspace_root, tu.name, tu.input,
                    run_id=self.run_id,
                    iteration=iteration,
                )

                # Tool accounting feeds the "model_stuck_reading" guard
                # below. Only inspection reads count; planning (TodoWrite)
                # and discovery (glob) are neutral. See ``_classify``.
                bucket = self._classify(tu.name)
                if bucket == "mutating":
                    self._mutating_calls += 1
                elif bucket == "inspection":
                    self._inspection_reads += 1
                outcome.tool_calls.append({
                    "name": tu.name,
                    "input": tu.input,
                    "is_error": dispatch.result.is_error,
                    "duration_ms": dispatch.duration_ms,
                })
                if self.on_step:
                    await self.on_step(
                        iteration,
                        step_index,
                        tu.name,
                        tu.input,
                        dispatch.result,
                        dispatch.duration_ms,
                    )
                # OpenAI-compat backends (including Sarvam) reject
                # tool messages whose content is the empty string —
                # `body.messages.N.tool.content : String should have
                # at least 1 character`. Substitute a non-empty
                # marker so the request makes it through.
                tool_content = dispatch.result.content or "(tool produced no output)"
                messages.append({
                    "role": "tool",
                    "tool_call_id": tu.call_id,
                    "content": tool_content,
                })

            if self.on_iteration:
                await self.on_iteration(outcome)

            # Cross-iteration repeat hard-stop. Fires when the SAME
            # signature has appeared in N consecutive iterations.
            # Within-iteration repeats (a single response batching
            # several reads of the same file) don't count — that's
            # legitimate pagination, not a loop.
            streak = current_streak(self.run_id or "", iteration)
            if streak >= repeat_hard_stop_threshold():
                log.warning(
                    "agentic-fix: aborting run %s — repeated tool "
                    "signature across %d consecutive iterations",
                    self.run_id, streak,
                )
                raise AgentStuck(
                    f"model_stuck: same tool+target combination "
                    f"repeated across {streak} consecutive iterations. "
                    f"The selected LLM isn't making progress on this task."
                )

            # Stuck-reading hard-stop. Catches a model that reads source
            # without ever editing — but the budget scales with the task
            # (``_read_budget``) and only inspection reads count, so it
            # no longer fires on legitimate recon across many manifests.
            read_budget = self._read_budget()
            if (
                self._mutating_calls == 0
                and self._inspection_reads >= read_budget
            ):
                log.warning(
                    "agentic-fix: aborting run %s — %d inspection reads "
                    "(read_file / grep) across %d iterations with no edit "
                    "(budget %d)",
                    self.run_id, self._inspection_reads, iteration, read_budget,
                )
                raise AgentStuck(
                    f"model_stuck_reading: {self._inspection_reads} source "
                    f"reads (read_file / grep) across {iteration} iterations "
                    f"without a single edit_file / write_file / bash, "
                    f"exceeding this run's read budget of {read_budget}. "
                    f"No code changes were produced."
                )
        else:
            # ``for`` completed without break — hit the iteration cap.
            log.warning(
                "agentic-fix hit iteration cap %d without a final text turn", cap,
            )
            final_text = (
                "[Iteration cap reached without completion. "
                "Partial fixes may have been applied; review the workspace.]"
            )

        return final_text

    async def _check_cancel(self) -> None:
        if self.cancel_cb is None:
            return
        if await self.cancel_cb():
            raise AgentCanceled("run canceled by user")

    @property
    def total_cost_cents(self) -> int:
        """Cumulative USD cents across every iteration."""
        return compute_cost_cents(
            Usage(
                input_tokens=self._total_input_tokens,
                output_tokens=self._total_output_tokens,
            ),
            self.model or get_settings().agentic_fix_effective_model,
        )


async def run_agentic_fix(
    *,
    workspace_root: Path,
    branch_name: str,
    repo_full_name: str | None,
    runtime: str,
    findings: list[FindingForAgent],
    on_step: StepCb | None = None,
    on_iteration: IterationCb | None = None,
    cancel_cb: CancelCb | None = None,
    model: str | None = None,
    max_iterations: int | None = None,
) -> tuple[str, int, int]:
    """Convenience entry-point. Returns ``(final_text, total_in, total_out)``."""
    fixer = AgenticFixer(
        workspace_root=workspace_root,
        branch_name=branch_name,
        repo_full_name=repo_full_name,
        runtime=runtime,
        findings=findings,
        on_step=on_step,
        on_iteration=on_iteration,
        cancel_cb=cancel_cb,
        model=model,
        max_iterations=max_iterations,
    )
    text = await fixer.run()
    return text, fixer._total_input_tokens, fixer._total_output_tokens
