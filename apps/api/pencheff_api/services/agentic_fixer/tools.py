"""Tool catalog + dispatcher for the agentic fixer.

Two responsibilities:
1. ``openai_tool_catalog()`` — JSON-Schema tool definitions in OpenAI
   function-calling shape. This is what we send in the
   ``tools`` field of a chat-completions request.
2. ``dispatch_tool()`` — given a tool name + input dict, find the
   matching handler in ``file_tools`` / ``shell_tool`` / etc., run
   it, return a ``ToolResult``.

The dispatcher is intentionally a flat lookup table — adding a new
tool means adding one row here, one entry in the catalog, and one
handler in the appropriate ``*_tool.py`` file. No registry/decorator
magic, easy to audit.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from .extra_tools import (
    record_tool_call,
    repeat_nudge_message,
    repeat_nudge_threshold,
    tool_mcp_call,
    tool_todo_write,
    tool_web_search,
)
from .file_tools import (
    ToolResult,
    tool_edit_file,
    tool_glob,
    tool_grep,
    tool_read_file,
    tool_write_file,
)
from .shell_tool import tool_bash

log = logging.getLogger("pencheff.agentic_fixer.tools")


ToolHandler = Callable[[Path, dict], Awaitable[ToolResult]]


# Flat handler table. Add a new tool: append here + add to
# `openai_tool_catalog()` below.
#
# The handler signature is uniform (workspace_root + input dict)
# but ``TodoWrite`` needs the run id instead of the workspace path,
# so the dispatcher special-cases it via the ``run_id`` parameter
# threaded through ``dispatch_tool``.
_HANDLERS: dict[str, ToolHandler] = {
    "read_file": tool_read_file,
    "write_file": tool_write_file,
    "edit_file": tool_edit_file,
    "grep": tool_grep,
    "glob": tool_glob,
    "bash": tool_bash,
}


@dataclass
class DispatchOutcome:
    """Result of a single tool dispatch, with timing for observability."""

    result: ToolResult
    duration_ms: int


async def dispatch_tool(
    workspace_root: Path,
    tool_name: str,
    tool_input: dict[str, Any],
    run_id: str | None = None,
    iteration: int = 0,
) -> DispatchOutcome:
    """Run one tool. Unknown tools return an error result rather
    than raising, so the agent can recover by trying a different tool.

    ``run_id`` is required for the TodoWrite tool (per-run state
    lives keyed by run id); other tools ignore it.

    Repeat-call detection: tracks signatures *per iteration* — a
    model legitimately paginating a big file with several read_file
    calls in one response = streak of 1. A real loop = same
    signature reappearing in successive iterations. The nudge
    fires when this iteration's streak (carried over from prior
    iterations) crosses the threshold; the agent loop owns the
    hard-stop after the whole iteration batch processes.
    """
    started = time.monotonic()
    result: ToolResult

    # Loop-detection nudge — only for tools that have a clear notion
    # of "same call same result" (read-only ops). edit_file /
    # write_file / bash mutate state, so a "repeated" call there is
    # legitimately different on retry.
    streak = record_tool_call(run_id or "", iteration, tool_name, tool_input)
    if streak >= repeat_nudge_threshold() and tool_name not in (
        "edit_file", "write_file", "bash"
    ):
        return DispatchOutcome(
            result=ToolResult.err(repeat_nudge_message(tool_name, streak)),
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    try:
        # Three tools have non-standard signatures and live outside
        # ``_HANDLERS``: TodoWrite takes the run_id; web_search +
        # mcp_call take just the input dict (no workspace path).
        if tool_name == "TodoWrite":
            if run_id is None:
                result = ToolResult.err(
                    "TodoWrite: no run id wired into the dispatcher"
                )
            else:
                result = await tool_todo_write(run_id, tool_input)
        elif tool_name == "web_search":
            result = await tool_web_search(tool_input)
        elif tool_name == "mcp_call":
            result = await tool_mcp_call(tool_input)
        else:
            handler = _HANDLERS.get(tool_name)
            if handler is None:
                result = ToolResult.err(
                    f"unknown tool '{tool_name}'. Available: "
                    f"{', '.join(sorted(_HANDLERS.keys()) + ['TodoWrite', 'web_search', 'mcp_call'])}"
                )
            else:
                result = await handler(workspace_root, tool_input)
    except Exception as e:  # noqa: BLE001
        log.exception("tool %s crashed", tool_name)
        result = ToolResult.err(f"{tool_name} crashed: {e}")
    duration_ms = int((time.monotonic() - started) * 1000)
    return DispatchOutcome(result=result, duration_ms=duration_ms)


# ─────────────────────── OpenAI tool catalog ───────────────────────

def openai_tool_catalog() -> list[dict[str, Any]]:
    """Return the JSON-Schema tool list for an OpenAI-compatible
    chat-completions request. Each entry is a ``function``-typed
    tool — the only shape sarvam-105b + every other
    OpenAI-compatible provider implements consistently.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": (
                    "Read a file from the workspace. Returns the file contents as "
                    "a string. Use offset+limit (line-paged) for files larger than "
                    "a few hundred lines. Files over 1 MB must be paged."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path relative to the workspace root.",
                        },
                        "offset": {
                            "type": "integer",
                            "description": "0-based line offset to start reading from.",
                            "minimum": 0,
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of lines to return.",
                            "minimum": 1,
                        },
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "write_file",
                "description": (
                    "Create a new file. Refuses to overwrite an existing file — "
                    "use edit_file for existing files."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path relative to the workspace root.",
                        },
                        "content": {
                            "type": "string",
                            "description": "Full file contents.",
                        },
                    },
                    "required": ["path", "content"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "edit_file",
                "description": (
                    "Replace a string in an existing file. By default the old "
                    "string must appear exactly once; set replace_all=true to "
                    "change every occurrence. Include enough surrounding context "
                    "in old_string to make the match unique on the first try."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path relative to the workspace root.",
                        },
                        "old_string": {
                            "type": "string",
                            "description": "Exact text to replace.",
                        },
                        "new_string": {
                            "type": "string",
                            "description": "Replacement text.",
                        },
                        "replace_all": {
                            "type": "boolean",
                            "description": "If true, replace every occurrence.",
                            "default": False,
                        },
                    },
                    "required": ["path", "old_string", "new_string"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "grep",
                "description": (
                    "Search file contents using a regex pattern. Backed by "
                    "ripgrep when available; falls back to a Python "
                    "implementation otherwise. Limit your patterns to "
                    "reasonable scope — output is capped at 200 matches."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Regex pattern to search for.",
                        },
                        "path": {
                            "type": "string",
                            "description": "Subdirectory to search in (default: workspace root).",
                        },
                        "glob": {
                            "type": "string",
                            "description": "Glob to filter filenames (e.g. '*.py').",
                        },
                        "case_insensitive": {
                            "type": "boolean",
                            "description": "Match case-insensitively.",
                            "default": False,
                        },
                    },
                    "required": ["pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "glob",
                "description": (
                    "List files matching a glob pattern (e.g. '**/*.py'). "
                    "Output is capped at 200 paths."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Glob pattern (supports ** for recursive).",
                        },
                        "path": {
                            "type": "string",
                            "description": "Subdirectory to start from (default: workspace root).",
                        },
                    },
                    "required": ["pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "bash",
                "description": (
                    "Run a single binary from the allowlist (git, gh, npm, "
                    "pytest, semgrep, gitleaks, trivy, osv-scanner, linters, "
                    "etc.). Shell metacharacters (semicolon, ampersand, pipe, "
                    "dollar, backtick) are forbidden — call bash once per "
                    "binary; no chaining. Each call has its own timeout "
                    "(default 120s, max 600s). Use this for git operations, "
                    "running tests, and verifying fixes."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": (
                                "The command to run. Single binary + args, no "
                                "shell metacharacters."
                            ),
                        },
                        "cwd": {
                            "type": "string",
                            "description": (
                                "Working directory (relative to workspace root). "
                                "Default is workspace root."
                            ),
                        },
                        "timeout_sec": {
                            "type": "number",
                            "description": "Timeout in seconds (default 120, max 600).",
                            "minimum": 1,
                            "maximum": 600,
                        },
                    },
                    "required": ["command"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "TodoWrite",
                "description": (
                    "Maintain a per-run checklist of what you intend to do "
                    "and what's been completed. Call with a full list of "
                    "todos every time (no partial updates). Useful when the "
                    "task involves multiple findings and you want to track "
                    "progress across iterations. Call with no args to read "
                    "back the current state."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "todos": {
                            "type": "array",
                            "description": "Full list of todos (replaces existing).",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "content": {
                                        "type": "string",
                                        "description": "What needs to be done.",
                                    },
                                    "status": {
                                        "type": "string",
                                        "enum": ["pending", "in_progress", "completed"],
                                        "description": "Current state.",
                                    },
                                },
                                "required": ["content"],
                            },
                        },
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "web_search",
                "description": (
                    "Search the web for CVE advisories, fix guidance, or "
                    "framework-specific remediation notes. Returns up to 10 "
                    "results with title + URL + snippet. Useful when a "
                    "finding references a CVE you need more context on, or "
                    "you're unsure of the canonical fix pattern for a "
                    "library."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query.",
                        },
                        "count": {
                            "type": "integer",
                            "description": "Result count (1-10, default 5).",
                            "minimum": 1,
                            "maximum": 10,
                        },
                    },
                    "required": ["query"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "mcp_call",
                "description": (
                    "Call a method on an allowlisted MCP server. Stubbed in "
                    "this build — returns a 'not configured' error until "
                    "MCP host wiring lands. Don't rely on this tool yet."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "server_url": {
                            "type": "string",
                            "description": "Allowlisted MCP server URL.",
                        },
                        "method": {
                            "type": "string",
                            "description": "JSON-RPC method name.",
                        },
                        "params": {
                            "type": "object",
                            "description": "Method parameters.",
                        },
                    },
                    "required": ["server_url", "method"],
                },
            },
        },
    ]


class ToolCatalog:
    """Thin wrapper exposing the OpenAI tool catalog. Reserved for
    future per-runtime customisation (desktop will eventually drop
    bash from this catalog and route through a richer
    DesktopShellTool, etc.).
    """

    @staticmethod
    def for_server() -> list[dict[str, Any]]:
        return openai_tool_catalog()
