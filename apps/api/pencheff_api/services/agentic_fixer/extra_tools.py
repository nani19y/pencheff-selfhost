"""Claude Code-parity tools beyond the core file + shell set.

Three tools live here:
* ``TodoWrite`` — per-run scratch pad. The agent maintains a checklist
  of what it's going to do (matches Claude Code's TodoWrite); future
  iterations see the current state echoed back via the tool's own
  output, and the UI can show the checklist alongside the live
  transcript. Persists per-run via a small in-memory store keyed by
  ``run_id``.
* ``web_search`` — minimal HTTP search via Brave Search's free
  endpoint (no API key required for basic queries). Used by the
  agent to look up CVE details, advisory mitigations, or framework-
  specific fix guidance. Capped at 5 results to keep token budget
  bounded.
* ``mcp_call`` — stub for now. Returns a clear "not configured"
  error so the agent reverts to other tools. Full MCP host wiring
  ships in a follow-up — the protocol implementation is its own
  project.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from .file_tools import ToolResult

log = logging.getLogger("pencheff.agentic_fixer.extra_tools")


# ── TodoWrite ───────────────────────────────────────────────────────


@dataclass
class TodoState:
    """One run's TodoWrite state. Items are dict-shaped so the agent
    can carry whatever fields it wants (we don't validate beyond
    ``content`` being a string)."""
    items: list[dict[str, Any]] = field(default_factory=list)


# Per-run store. The Celery task creates an entry when it starts the
# loop and deletes it when the run terminates. The agent loop owns
# the lifecycle — we don't auto-clean here because runs may legitimately
# pause between iterations.
_todo_store: dict[str, TodoState] = {}


# Per-run repeat-call tracking. Keyed by run_id → signature → (last_iter, streak).
# We count repeats ACROSS iterations, not within a single iteration's
# batch — a model legitimately paginating a big file in one response
# will emit several read_file calls with the same primary id, and that
# isn't a loop. A real loop is when the SAME signature reappears in
# successive iterations.
_repeat_state: dict[str, dict[str, tuple[int, int]]] = {}


def todo_state_for(run_id: str) -> TodoState:
    state = _todo_store.get(run_id)
    if state is None:
        state = TodoState()
        _todo_store[run_id] = state
    return state


def clear_todo_state(run_id: str) -> None:
    _todo_store.pop(run_id, None)


# ── Repeat-call detection ───────────────────────────────────────────
#
# sarvam-105b (and other smaller open-weight models) can get stuck
# in a "call read_file 30 times in a row" loop. The dispatcher
# tracks a short history of recent (tool_name, input-hash) tuples
# per run; when the same call is repeated, it returns a strong
# nudge instead of running the tool a 4th time, and after 5
# consecutive repeats the runner force-ends the loop.

# Window of consecutive iterations containing the same signature
# before we kick in. Same thresholds as before, but now they're per
# iteration rather than per individual tool call.
_REPEAT_NUDGE_THRESHOLD = 3
_REPEAT_HARD_STOP_THRESHOLD = 5


def _signature(tool_name: str, tool_input: dict) -> str:
    """Stable string signature for a tool call. Uses the primary
    *identifier* (path / pattern / command / etc.) rather than the
    full input so that pagination-style variants
    (``read_file path=X offset=0`` vs ``read_file path=X offset=200``)
    both hash to the same signature. The agent shouldn't be
    re-reading the same file just at different offsets — once it
    has the file in context, it should commit to action.
    """
    primary = _primary_identifier(tool_name, tool_input)
    if primary is not None:
        return f"{tool_name}|{primary}"
    # Fallback: hash the full input for tools without an obvious
    # primary id (TodoWrite). This still catches "no-arg read"
    # loops where the agent calls TodoWrite() repeatedly.
    try:
        canon = json.dumps(tool_input, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        canon = repr(sorted(tool_input.items()))
    return f"{tool_name}|{canon}"


def _primary_identifier(tool_name: str, tool_input: dict) -> str | None:
    """Per-tool primary identifier — the thing that, if repeated,
    means the agent isn't making progress regardless of other args.

    Read-only operations (read_file, grep, glob, web_search, mcp_call) use
    coarser signatures because repeating them (even with paging/query shifts)
    typically signals loop behavior.

    Mutating operations (edit_file, write_file, bash) return None here
    to fall back to a full input hash (in _signature). This guarantees
    different edits to the same file or different shell commands (e.g.
    consecutive git status, git add, git commit) are never treated as repeats.
    """
    if tool_name == "read_file":
        return str(tool_input.get("path", ""))
    if tool_name in ("grep", "glob"):
        return str(tool_input.get("pattern", ""))
    if tool_name == "web_search":
        return str(tool_input.get("query", ""))
    if tool_name == "mcp_call":
        return f"{tool_input.get('server_url', '')}|{tool_input.get('method', '')}"
    return None


def record_tool_call(
    run_id: str, iteration: int, tool_name: str, tool_input: dict,
) -> int:
    """Record one tool dispatch and return the number of *consecutive
    iterations* in which this signature has appeared, ending at the
    current iteration.

    Within a single iteration: streak doesn't grow on repeated calls
    of the same signature. A model paginating ``read_file`` 5 times
    in one response is fine — that's one iteration's worth of work.

    Across iterations: streak grows when the same signature reappears
    in the very next iteration. Streak resets to 1 if the signature
    was last seen more than one iteration ago.
    """
    if not run_id:
        return 1
    sig = _signature(tool_name, tool_input)
    run_state = _repeat_state.setdefault(run_id, {})
    last_iter, streak = run_state.get(sig, (None, 0))
    if last_iter == iteration:
        # Same iteration, no change.
        return streak
    if last_iter is not None and last_iter == iteration - 1:
        streak += 1
    else:
        streak = 1
    run_state[sig] = (iteration, streak)
    # Cap retained signatures per run to avoid unbounded growth on
    # very long runs.
    if len(run_state) > 200:
        oldest_sig = min(run_state, key=lambda k: run_state[k][0])
        run_state.pop(oldest_sig, None)
    return streak


def current_streak(run_id: str, iteration: int) -> int:
    """Return the largest streak for any signature recorded in the
    given iteration. Used by the agent loop to decide whether to
    hard-stop AFTER processing all of an iteration's tool calls.
    """
    run_state = _repeat_state.get(run_id) or {}
    return max(
        (s for (it, s) in run_state.values() if it == iteration),
        default=0,
    )


def clear_call_history(run_id: str) -> None:
    _repeat_state.pop(run_id, None)


# Backward-compat alias — older callers (and tests) used the
# pre-refactor name.
consecutive_streak = current_streak


def repeat_nudge_threshold() -> int:
    return _REPEAT_NUDGE_THRESHOLD


def repeat_hard_stop_threshold() -> int:
    return _REPEAT_HARD_STOP_THRESHOLD


def repeat_nudge_message(tool_name: str, streak: int) -> str:
    """Strong message the agent sees when it's clearly stuck.
    Phrased to force a decision: edit, switch files, or skip."""
    return (
        f"⚠️ REPEATED CALL DETECTED ({streak}x): you have already called "
        f"`{tool_name}` with these exact arguments {streak} times in a "
        f"row. The result will NOT change. Stop repeating yourself and "
        f"take ONE of these actions right now:\n"
        f"  1. Call `edit_file` with a real fix for one of the findings.\n"
        f"  2. Call `read_file` on a DIFFERENT file (you have many "
        f"findings across the workspace).\n"
        f"  3. Call `TodoWrite` to mark a finding as a false positive "
        f"or low-priority and move on.\n"
        f"If you make another identical call, the run will be terminated."
    )


async def tool_todo_write(run_id: str, args: dict) -> ToolResult:
    """Replace the run's todo list. The agent passes the full list
    every time — partial updates aren't supported (matches Claude
    Code's actual behaviour).

    Args:
        todos: list of {content: str, status: "pending"|"in_progress"|"completed"}
    """
    todos = args.get("todos")
    if todos is None:
        # No-arg call → return current state (lets the agent re-read).
        state = todo_state_for(run_id)
        return ToolResult.ok(_format_todos(state.items))
    if not isinstance(todos, list):
        return ToolResult.err("TodoWrite: 'todos' must be a list")
    valid_status = {"pending", "in_progress", "completed"}
    cleaned: list[dict[str, Any]] = []
    for raw in todos:
        if not isinstance(raw, dict):
            return ToolResult.err("TodoWrite: each item must be an object")
        content = raw.get("content")
        if not isinstance(content, str) or not content.strip():
            return ToolResult.err("TodoWrite: each item needs a non-empty 'content' string")
        status = raw.get("status", "pending")
        if status not in valid_status:
            status = "pending"
        cleaned.append({"content": content.strip(), "status": status})
    state = todo_state_for(run_id)
    state.items = cleaned
    return ToolResult.ok(_format_todos(cleaned))


def _format_todos(items: list[dict[str, Any]]) -> str:
    if not items:
        return "(todo list is empty)"
    lines: list[str] = []
    for i, item in enumerate(items, start=1):
        marker = {
            "completed": "[x]",
            "in_progress": "[~]",
            "pending": "[ ]",
        }.get(item.get("status", "pending"), "[ ]")
        lines.append(f"{i}. {marker} {item['content']}")
    return "\n".join(lines)


# ── web_search ──────────────────────────────────────────────────────


_BRAVE_API = "https://search.brave.com/api/search"


async def tool_web_search(args: dict) -> ToolResult:
    """Web search via Brave's public search endpoint. The agent uses
    this for CVE advisory lookups + framework-specific fix guidance.

    Args:
        query: search query string. Required.
        count: number of results (default 5, max 10).
    """
    query = args.get("query")
    if not isinstance(query, str) or not query.strip():
        return ToolResult.err("web_search: 'query' is required")
    count = args.get("count", 5)
    try:
        count = max(1, min(int(count), 10))
    except (TypeError, ValueError):
        count = 5

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                _BRAVE_API,
                params={"q": query, "source": "web"},
                headers={
                    "Accept": "application/json",
                    "User-Agent": "PencheffAgent/1.0 (security fix research)",
                },
            )
    except httpx.HTTPError as e:
        return ToolResult.err(f"web_search: transport error: {e}")

    if resp.status_code != 200:
        return ToolResult.err(
            f"web_search: search backend returned {resp.status_code}"
        )

    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        return ToolResult.err("web_search: search backend returned non-JSON")

    results = ((body.get("web") or {}).get("results")) or []
    if not results:
        return ToolResult.ok(f"(no results for '{query}')")

    lines = [f"### Search results for '{query}'", ""]
    for r in results[:count]:
        title = (r.get("title") or "").strip()
        url = (r.get("url") or "").strip()
        snippet = (r.get("description") or "").strip()
        if not title or not url:
            continue
        lines.append(f"- **{title}**")
        lines.append(f"  {url}")
        if snippet:
            lines.append(f"  {snippet[:300]}")
        lines.append("")
    return ToolResult.ok("\n".join(lines))


# ── mcp_call (stub) ────────────────────────────────────────────────


async def tool_mcp_call(args: dict) -> ToolResult:
    """Stub for the MCP host. Returns a clear "not configured"
    response so the agent doesn't retry with the same tool, and
    falls back to file/grep/bash.

    A future implementation will accept a workspace-allowlisted MCP
    server URL + a JSON-RPC method + params, forward via the MCP
    client protocol, and return the response. The full protocol is a
    separate project; until then this stub is enough to keep the
    catalog complete.
    """
    return ToolResult.err(
        "mcp_call: MCP host is not configured on this deployment. "
        "Use the file/grep/bash tools instead. (Configure allowed MCP "
        "servers per-workspace in Settings → Agentic Fix to enable.)"
    )
