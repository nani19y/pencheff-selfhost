"""Agentic Fix-all — multi-turn LLM agent that fixes security findings.

Modelled on Claude Code / Cursor Agent mode: receives a batch of
findings + a tool surface (read/edit files, run shell commands), and
iterates until the fixes are in a state it can commit + open a PR.

Spec: ``docs/superpowers/specs/2026-05-23-agentic-fixer-design.md``.

Public surface:
* ``AgenticFixer`` — high-level orchestrator that the Celery worker
  drives. Mirrored in Swift on the desktop side.
* ``ToolCatalog`` — JSON-Schema tool definitions sent to Anthropic.
* ``run_agentic_fix(...)`` — the entry point used by tasks/.

Implementation lives in:
* ``llm_client.py`` — OpenAI-compatible chat-completions wrapper.
  Defaults to Sarvam AI's sarvam-105b; works against any
  function-calling-capable OpenAI-compatible endpoint.
* ``agent_loop.py`` — iterate-until-done outer loop + cancellation.
* ``tools.py`` — tool registry + dispatcher.
* ``file_tools.py`` — read_file / edit_file / write_file / grep / glob.
* ``shell_tool.py`` — bash with allowlist + secret redaction.
* ``system_prompt.py`` — context assembly for the agent.
* ``workspace.py`` — path-safety guards (chroot-style realpath check).
* ``cost.py`` — token → cost-in-cents.

The agent loop + tools are intentionally provider-agnostic — the only
shape that differs between Anthropic Messages and OpenAI Chat
Completions is what ``llm_client.create_message`` and the tool-catalog
formatter emit. Swap the client to repoint at a different backend.
"""

from .agent_loop import (  # noqa: F401
    AgenticFixer,
    AgentStuck,
    AgentCanceled,
    IterationOutcome,
    run_agentic_fix,
)
from .system_prompt import FindingForAgent  # noqa: F401
from .tools import ToolCatalog  # noqa: F401
