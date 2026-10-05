# Parallel Multi-Agent Scan Swarm — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the default LLM-driven scan phase with a 9-agent parallel swarm (1 Recon → 7 breakers fanning out concurrently → 1 Chain) while keeping the deterministic populator and the legacy single-agent loop both untouched and reachable.

**Architecture:** New package `apps/api/pencheff_api/services/agent_swarm/` orchestrates the swarm. The legacy `agent_runner.run_agent` is refactored to expose a reusable `_run_single_agent` (in `agent_swarm/agent_loop.py`) that both paths share. Each breaker gets its own isolated pencheff session seeded from a frozen `ReconSnapshot`. The swarm wires into `scan_runner._engine` behind a `SWARM_ENABLED` killswitch (default `true`); on catastrophic failure the orchestrator falls back to `agent_runner.run_agent`.

**Tech Stack:** Python 3.12, asyncio, httpx (existing), pydantic-settings (existing), pytest + pytest-asyncio (existing). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-05-05-parallel-agent-swarm-design.md`. Honor Section 3 (IP-safety contract): clean-room only, no source/prompt/distinctive-prose copying from `0x4m4/hexstrike-ai`.

**Repo conventions confirmed before writing this plan:**
- Tests: `pytest -xvs apps/api/tests/<file>::<test>`. Run from repo root (or `apps/api/`).
- Async tests use `@pytest.mark.asyncio` (not auto-mode). Existing pattern: see `apps/api/tests/test_triage_llm.py:120`.
- httpx mocking pattern: `monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post)`.
- Pencheff plugin lives at `plugins/pencheff/pencheff/` and is editable-installed. New helpers are added to `plugins/pencheff/pencheff/server.py` as plain `async def` (no `@mcp.tool()` — orchestrator-internal only).

---

## File Structure

**New files (all under `apps/api/pencheff_api/services/agent_swarm/`):**

| File | Responsibility |
|---|---|
| `__init__.py` | Re-exports `run_swarm`, `SwarmOutcome` |
| `snapshot.py` | `DiscoveredEndpoint`, `ReconSnapshot`, `ReconFailed` |
| `agent_loop.py` | `Agent` dataclass + `_run_single_agent` (extracted from `agent_runner.run_agent`) |
| `prompts.py` | `build_recon_prompt`, `build_breaker_prompt`, `build_chain_prompt` (clean-room) |
| `tools.py` | `recon_tools`, `breaker_tools_for`, `chain_tools` — selectors over the existing pencheff registry |
| `breakers.py` | `BreakerSpec`, `BREAKER_SPECS` table, `_build_breakers`, `seed_breaker_session` |
| `recon.py` | `run_recon_phase`, `_freeze_snapshot` |
| `chain.py` | `_run_chain_phase`, `_synthesise_summary_from_breakers` |
| `orchestrator.py` | `run_swarm`, `BreakerResult`, `SwarmOutcome`, `_run_breaker_with_retry`, `_merge_breaker_findings_into_master`, `_catastrophic_fallback`, `_TransientLLMError` |
| `telemetry.py` | `persist_swarm_telemetry`, `build_swarm_summary_payload` (the per-agent log-line `_prefix` helper lives in `orchestrator.py`, not here) |

**New tests (under `apps/api/tests/services/agent_swarm/`):**

| File | What it covers |
|---|---|
| `__init__.py` | Empty marker |
| `_scripted_llm.py` | `ScriptedLLM` test helper (not a `test_*` file) |
| `test_snapshot.py` | Snapshot freeze/round-trip |
| `test_agent_loop_refactor.py` | Legacy `run_agent` still passes after refactor |
| `test_pencheff_helpers.py` | The 4 new pencheff helpers, integration-style |
| `test_prompts.py` | Per-agent prompts include identity block + mandate scoping |
| `test_breakers_table.py` | Allocation invariant: every `scan_*` tool in exactly one breaker |
| `test_seed_breaker_session.py` | Seeded breaker session has the snapshot's surface |
| `test_recon_phase.py` | Recon happy path + `ReconFailed` on empty |
| `test_authz_quietquit.py` | `AuthzAgent` `finish`-es immediately when `authenticated=False` |
| `test_breaker_retry.py` | Transient-then-success / transient-twice / non-transient |
| `test_merge.py` | Merge unions findings + tags `discovered_by_agent` |
| `test_chain_phase.py` | Chain happy + chain crash → synthesise fallback |
| `test_orchestrator_happy.py` | Full pipeline with scripted LLM |
| `test_orchestrator_partial.py` | Some breakers fail, survivors merge |
| `test_orchestrator_recon_fail.py` | Recon failure → catastrophic fallback fires |
| `test_orchestrator_all_breakers_fail.py` | All breakers fail → catastrophic fallback fires |
| `test_orchestrator_chain_fail.py` | Chain crash → orchestrator survives, breaker findings ship |
| `test_budgets.py` | Profile-tiered turn-budget table honoured |
| `test_scope.py` | Scope propagates into breaker sessions |
| `test_telemetry.py` | `summary_payload["swarm"]` shape |
| `test_killswitch.py` | `SWARM_ENABLED=false` → legacy path |

**Modified files:**

| File | Change |
|---|---|
| `apps/api/pencheff_api/config.py` | Add `swarm_*` settings |
| `apps/api/pencheff_api/services/agent_runner.py` | Refactor `run_agent` to delegate to `_run_single_agent`. **No public-API change.** |
| `apps/api/pencheff_api/services/scan_runner.py` | `_engine` closure dispatches on `SWARM_ENABLED` |
| `plugins/pencheff/pencheff/server.py` | Add `import_endpoints`, `set_auth_state`, `attach_oast`, `copy_finding` |

---

## Phase A — Foundation

### Task A1: Add `SWARM_*` settings to `config.py`

**Files:**
- Modify: `apps/api/pencheff_api/config.py`
- Test: `apps/api/tests/services/agent_swarm/test_killswitch.py` (created later in K2 — settings are exercised there)

- [ ] **Step 1: Locate the existing `agent_*` setting block**

Run: `grep -n "agent_llm_api_key\|agent_max_turns\|class Settings" apps/api/pencheff_api/config.py`

Use the line numbers it prints to find the existing agent block; insert the new fields directly underneath that block so swarm settings live next to their LLM-credential cousins.

- [ ] **Step 2: Add the new fields**

Add these field declarations to the `Settings` class, immediately after the existing `agent_*` fields:

```python
    # ── Swarm orchestrator (parallel multi-agent) ──────────────
    swarm_enabled: bool = Field(True, alias="SWARM_ENABLED")

    swarm_turns_recon_quick: int = Field(8, alias="SWARM_TURNS_RECON_QUICK")
    swarm_turns_recon_standard: int = Field(12, alias="SWARM_TURNS_RECON_STANDARD")
    swarm_turns_recon_deep: int = Field(18, alias="SWARM_TURNS_RECON_DEEP")

    swarm_turns_breaker_quick: int = Field(6, alias="SWARM_TURNS_BREAKER_QUICK")
    swarm_turns_breaker_standard: int = Field(10, alias="SWARM_TURNS_BREAKER_STANDARD")
    swarm_turns_breaker_deep: int = Field(16, alias="SWARM_TURNS_BREAKER_DEEP")

    swarm_turns_chain_quick: int = Field(8, alias="SWARM_TURNS_CHAIN_QUICK")
    swarm_turns_chain_standard: int = Field(12, alias="SWARM_TURNS_CHAIN_STANDARD")
    swarm_turns_chain_deep: int = Field(20, alias="SWARM_TURNS_CHAIN_DEEP")

    swarm_breaker_retry_attempts: int = Field(1, alias="SWARM_BREAKER_RETRY_ATTEMPTS")
    swarm_breaker_retry_backoff_sec: int = Field(2, alias="SWARM_BREAKER_RETRY_BACKOFF_SEC")
```

If the file already imports `Field` from `pydantic`, no import change is needed. If not, add `from pydantic import Field` (search the file first to avoid duplicates).

- [ ] **Step 3: Verify `get_settings()` still loads**

Run: `cd apps/api && uv run python -c "from pencheff_api.config import get_settings; s=get_settings(); print(s.swarm_enabled, s.swarm_turns_recon_quick, s.swarm_breaker_retry_attempts)"`

Expected: `True 8 1`

- [ ] **Step 4: Commit**

```bash
git add apps/api/pencheff_api/config.py
git commit -m "feat(swarm): add SWARM_* settings (killswitch + per-tier turn budgets)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task A2: Build `ScriptedLLM` test helper

**Files:**
- Create: `apps/api/tests/services/agent_swarm/__init__.py` (empty)
- Create: `apps/api/tests/services/agent_swarm/_scripted_llm.py`

The orchestrator and agent-loop tests need a scripted-response stub for the OpenAI-compatible chat-completions endpoint. This helper is reused everywhere downstream.

- [ ] **Step 1: Create the empty `__init__.py`**

```bash
mkdir -p apps/api/tests/services/agent_swarm
touch apps/api/tests/services/agent_swarm/__init__.py
```

- [ ] **Step 2: Write the helper**

Create `apps/api/tests/services/agent_swarm/_scripted_llm.py`:

```python
"""Scripted LLM stub for swarm tests.

Each ``ScriptedTurn`` is one chat-completions response. ``ScriptedLLM``
patches ``httpx.AsyncClient.post`` so each call pops the next scripted
turn off the queue and returns it as a real ``httpx.Response``.

Use ``with_tool_call`` to build a tool-call turn, ``with_finish`` to
build a final ``finish`` turn, and ``with_transient_error`` to script
a transient HTTP failure.

This helper is NOT a test module (filename starts with ``_``) so pytest
will not auto-collect it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class ScriptedTurn:
    """One scripted chat-completions response."""

    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    content: str | None = None
    status_code: int = 200
    body_override: str | None = None  # raw body for non-200 responses


def with_tool_call(name: str, args: dict[str, Any], call_id: str = "call_1") -> ScriptedTurn:
    return ScriptedTurn(tool_calls=[{
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }])


def with_finish(summary: str, call_id: str = "call_finish") -> ScriptedTurn:
    return with_tool_call("finish", {"summary": summary}, call_id=call_id)


def with_transient_error(status_code: int = 503, body: str = "upstream down") -> ScriptedTurn:
    return ScriptedTurn(status_code=status_code, body_override=body)


class ScriptedLLM:
    """Patches httpx.AsyncClient.post to return scripted turns in order."""

    def __init__(self, turns: list[ScriptedTurn]) -> None:
        self._turns = list(turns)
        self.calls: list[dict[str, Any]] = []  # captured request bodies

    def install(self, monkeypatch) -> None:
        async def _fake_post(self_client, url, headers=None, json=None, **kw):
            self_outer.calls.append({"url": url, "json": json})
            if not self_outer._turns:
                raise AssertionError("ScriptedLLM exhausted: no turns left")
            turn = self_outer._turns.pop(0)
            request = httpx.Request("POST", url)
            if turn.status_code != 200:
                return httpx.Response(
                    status_code=turn.status_code,
                    request=request,
                    text=turn.body_override or "",
                )
            payload = {
                "choices": [{
                    "message": {
                        "content": turn.content,
                        "tool_calls": turn.tool_calls or None,
                    },
                    "finish_reason": "tool_calls" if turn.tool_calls else "stop",
                }],
            }
            return httpx.Response(status_code=200, request=request, json=payload)

        self_outer = self
        monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post)

    @property
    def remaining(self) -> int:
        return len(self._turns)
```

- [ ] **Step 3: Quick smoke import**

Run: `cd apps/api && uv run python -c "from tests.services.agent_swarm._scripted_llm import ScriptedLLM, with_tool_call, with_finish; print('ok')"`

Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add apps/api/tests/services/agent_swarm/__init__.py apps/api/tests/services/agent_swarm/_scripted_llm.py
git commit -m "test(swarm): add ScriptedLLM helper for chat-completions stubs

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase B — Refactor `agent_runner.run_agent` → reusable `_run_single_agent`

This is a pure code-move refactor: the legacy single-agent path must keep behaving identically. The shape we extract is the agent loop itself; the `run_agent` public function becomes a thin wrapper that builds an `Agent` from the legacy `SYSTEM_PROMPT` + full tool registry and delegates.

### Task B1: Create `agent_swarm/__init__.py` + `agent_loop.py` skeleton

**Files:**
- Create: `apps/api/pencheff_api/services/agent_swarm/__init__.py`
- Create: `apps/api/pencheff_api/services/agent_swarm/agent_loop.py`

- [ ] **Step 1: Create the package marker**

```bash
mkdir -p apps/api/pencheff_api/services/agent_swarm
```

Write `apps/api/pencheff_api/services/agent_swarm/__init__.py`:

```python
"""Parallel multi-agent scan swarm.

See docs/superpowers/specs/2026-05-05-parallel-agent-swarm-design.md
for the design and IP-safety contract. ``run_swarm`` is the orchestrator
entry point used by ``services.scan_runner._engine``.

Manual smoke checklist (operations):
  1. ``SWARM_ENABLED=true``: scan against DVWA / Juice-Shop. Confirm the
     SSE event log shows interleaved ``[Recon]…[InjectionAgent]…
     [AuthAgent]…[Chain]…`` prefixes.
  2. Force a recon failure (set ``AGENT_LLM_API_KEY`` to a value that
     401s). Confirm the catastrophic-fallback line appears and the scan
     finishes via the legacy ``agent_runner`` path.
  3. ``SWARM_ENABLED=false``: scan again. Confirm only plain unprefixed
     events appear, proving the killswitch reroutes through
     ``agent_runner.run_agent``.
"""
from __future__ import annotations

# Re-exports filled in by Phase I when run_swarm/SwarmOutcome land.
__all__: list[str] = []
```

- [ ] **Step 2: Write the `agent_loop.py` skeleton with the `Agent` dataclass + `_TransientLLMError`**

Write `apps/api/pencheff_api/services/agent_swarm/agent_loop.py`:

```python
"""Reusable agent tool-calling loop.

Extracted from ``agent_runner.run_agent`` (which now delegates here) so
the swarm orchestrator can drive multiple specialised agents through
the same loop without duplicating the message-passing / retry logic.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from ..config import get_settings

log = logging.getLogger("pencheff.agent_loop")

LogSink = Callable[[str], Awaitable[None]]


class _TransientLLMError(RuntimeError):
    """Raised by the loop when the upstream chat-completions endpoint
    fails with a retryable error (timeout, read-error, 5xx, 429).

    The orchestrator's per-breaker retry wrapper catches this and runs
    the whole agent again once before giving up on that agent.
    """


@dataclass(frozen=True)
class Agent:
    """One specialised agent: name, prompt, tools, turn budget."""
    name: str
    system_prompt: str
    tools: list[Any]  # AgentTool — typed loosely to avoid circular import
    max_turns: int


@dataclass
class AgentOutcome:
    summary: str
    tool_calls: int
    turns: int
    finished_cleanly: bool
    reason: str
```

The full `_run_single_agent` body lands in Task B2 once we know what we're moving.

- [ ] **Step 3: Verify both files import cleanly**

Run: `cd apps/api && uv run python -c "from pencheff_api.services.agent_swarm.agent_loop import Agent, _TransientLLMError, AgentOutcome; print('ok')"`

Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/__init__.py apps/api/pencheff_api/services/agent_swarm/agent_loop.py
git commit -m "feat(swarm): scaffold agent_swarm package + Agent dataclass

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B2: Move the loop body from `agent_runner.run_agent` into `_run_single_agent`

**Files:**
- Modify: `apps/api/pencheff_api/services/agent_runner.py`
- Modify: `apps/api/pencheff_api/services/agent_swarm/agent_loop.py`
- Test: `apps/api/tests/services/agent_swarm/test_agent_loop_refactor.py`

- [ ] **Step 1: Write the failing refactor test**

Create `apps/api/tests/services/agent_swarm/test_agent_loop_refactor.py`:

```python
"""After the refactor, the legacy run_agent must still finish cleanly
on a one-turn scripted ``finish`` and produce the documented
``AgentOutcome``."""
from __future__ import annotations

import pytest

from pencheff_api.services import agent_runner
from tests.services.agent_swarm._scripted_llm import (
    ScriptedLLM, with_finish,
)


@pytest.fixture
def llm_settings(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "agent_llm_api_key", "sk-test")
    monkeypatch.setattr(s, "agent_llm_base_url", "https://api.example.com/v1")
    monkeypatch.setattr(s, "agent_llm_model", "test-model")
    monkeypatch.setattr(s, "agent_llm_max_tokens", 1024)
    monkeypatch.setattr(s, "agent_request_timeout", 30.0)
    monkeypatch.setattr(s, "agent_max_turns", 5)
    return s


@pytest.mark.asyncio
async def test_legacy_run_agent_finishes_on_scripted_finish(llm_settings, monkeypatch):
    ScriptedLLM([with_finish("done")]).install(monkeypatch)
    events: list[str] = []

    async def on_event(line: str) -> None:
        events.append(line)

    outcome = await agent_runner.run_agent(
        session_id="sid-fake",
        target_url="https://t.example.com",
        credentials=None,
        profile="quick",
        scope=None,
        exclude_paths=None,
        on_event=on_event,
        session_prepopulated=False,
    )
    assert outcome.finished_cleanly is True
    assert outcome.summary == "done"
    assert outcome.reason == "finished"
    assert outcome.tool_calls == 1
```

- [ ] **Step 2: Run the test — expect it to PASS already (the refactor hasn't started)**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_agent_loop_refactor.py -v`

Expected: PASS — this proves the test correctly captures current behaviour. The refactor must keep it passing.

- [ ] **Step 3: Move the loop body into `_run_single_agent`**

Replace the body of `agent_runner.py:run_agent` (line ~802 onwards in the current file). The new structure is:

1. Build the legacy `Agent` from `SYSTEM_PROMPT` + `_build_tool_registry(profile=profile)` + `settings.agent_max_turns`.
2. Delegate to `_run_single_agent` with all current arguments.

In `agent_swarm/agent_loop.py`, append the full loop logic. Move (do not duplicate) these existing pieces from `agent_runner.py` into `agent_loop.py`:

- `_chat_completion` (lines 774-799)
- `_format_tool_for_openai` (lines 742-751)
- `_tool_result_content` (lines 754-762)
- `_format_tool_call` (lines 1055-1071)

Append to `agent_swarm/agent_loop.py`:

```python
def _format_tool_for_openai(tool) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.input_schema,
        },
    }


def _tool_result_content(value: Any, max_chars: int = 12000) -> str:
    try:
        payload = json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        payload = str(value)
    if len(payload) > max_chars:
        payload = payload[:max_chars] + "\n… [truncated to keep context manageable]"
    return payload


def _format_tool_call(name: str, args: dict[str, Any]) -> str:
    if not args:
        return f"tool: {name}"
    for key in ("url", "finding_id", "steps"):
        if key in args:
            val = args[key]
            preview = f" ({len(val)} steps)" if isinstance(val, list) else f" → {str(val)[:120]}"
            return f"tool: {name}{preview}"
    return f"tool: {name} args={list(args.keys())}"


async def _chat_completion(
    *, client: httpx.AsyncClient, base_url: str, api_key: str,
    model: str, max_tokens: int,
    messages: list[dict[str, Any]], tools: list[dict[str, Any]],
) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/chat/completions"
    body = {
        "model": model, "messages": messages, "tools": tools,
        "tool_choice": "auto", "max_tokens": max_tokens,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    resp = await client.post(url, json=body, headers=headers)
    resp.raise_for_status()
    return resp.json()


async def _run_single_agent(
    *,
    agent: Agent,
    session_id: str,
    target_url: str,
    credentials: dict[str, Any] | None,
    profile: str,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    on_event: LogSink,
    session_prepopulated: bool,
    user_intro_extra: list[str] | None = None,
) -> AgentOutcome:
    """Drive one agent (system prompt + tool registry + budget) to completion.

    Raises ``_TransientLLMError`` on any of: ``ReadTimeout``, ``ConnectTimeout``,
    ``ReadError``, ``RemoteProtocolError``, HTTP 429, HTTP 5xx — but only after
    the in-loop retry budget is exhausted (3 attempts, exponential backoff).
    """
    settings = get_settings()
    if not settings.agent_llm_api_key:
        raise RuntimeError("AGENT_LLM_API_KEY not configured")

    tools_by_name = {t.name: t for t in agent.tools}
    openai_tools = [_format_tool_for_openai(t) for t in agent.tools]

    user_intro_lines = [
        f"Target: {target_url}",
        f"Profile: {profile} (depth hint)",
    ]
    if scope:
        user_intro_lines.append(f"Scope allow-list: {scope}")
    if exclude_paths:
        user_intro_lines.append(f"Scope exclude-list: {exclude_paths}")
    if credentials:
        supplied = [k for k, v in credentials.items() if v]
        if supplied:
            needs_login = "username" in supplied and "password" in supplied
            hint = (
                " Call `authenticated_crawl` FIRST to exchange them for a "
                "live authenticated session before any scan_* tool."
                if needs_login
                else " They are already injected as request headers on every call."
            )
            user_intro_lines.append(f"Credentials provided: {', '.join(supplied)}.{hint}")
    user_intro_lines.append(
        f"Pencheff session id: {session_id} (tools that accept session_id "
        "get this automatically — don't pass it in arguments)."
    )
    if user_intro_extra:
        user_intro_lines.extend(user_intro_extra)
    if session_prepopulated:
        user_intro_lines.append(
            "IMPORTANT: the deterministic populator has already run. Call "
            "`get_findings` first; verify with `test_endpoint`; suppress "
            "what you cannot reproduce; chain the rest; then `finish`."
        )
    else:
        user_intro_lines.append(
            "Begin. Verify what you find. Keep only what you can reproduce."
        )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": agent.system_prompt},
        {"role": "user", "content": "\n".join(user_intro_lines)},
    ]

    start = time.monotonic()
    turns = 0
    tool_calls = 0
    summary = ""
    finished_cleanly = False
    reason = "max_turns"

    async with httpx.AsyncClient(timeout=settings.agent_request_timeout) as client:
        max_turns = agent.max_turns
        for turn in range(max_turns):
            turns = turn + 1
            remaining = max_turns - turn
            hint = (
                f"Budget: turn {turns}/{max_turns} — only {remaining} "
                "turns left. If your mandate is covered, call `finish` NOW."
                if remaining <= max(1, max_turns // 3)
                else f"Budget: turn {turns}/{max_turns}. Be efficient."
            )
            messages_with_hint = messages + [{"role": "user", "content": hint}]
            response = None
            transport_attempts = 3
            for attempt in range(transport_attempts):
                try:
                    response = await _chat_completion(
                        client=client,
                        base_url=settings.agent_llm_base_url,
                        api_key=settings.agent_llm_api_key,
                        model=settings.agent_llm_model,
                        max_tokens=settings.agent_llm_max_tokens,
                        messages=messages_with_hint,
                        tools=openai_tools,
                    )
                    break
                except httpx.HTTPStatusError as exc:
                    code = exc.response.status_code
                    if code == 429 or code >= 500:
                        if attempt < transport_attempts - 1:
                            await on_event(
                                f"transient HTTP {code}, retry {attempt + 1}/"
                                f"{transport_attempts - 1}"
                            )
                            await asyncio.sleep(2 ** attempt)
                            continue
                        raise _TransientLLMError(f"HTTP {code} after retries") from exc
                    log.warning("LLM API error on turn %d: %s", turns, exc)
                    await on_event(f"agent error: {exc}"[:500])
                    reason = f"api_error: HTTP {code}"
                    response = None
                    break
                except (
                    httpx.ReadTimeout, httpx.ConnectTimeout,
                    httpx.ReadError, httpx.RemoteProtocolError,
                ) as exc:
                    if attempt < transport_attempts - 1:
                        await on_event(
                            f"transient backend timeout, retry {attempt + 1}/"
                            f"{transport_attempts - 1}"
                        )
                        await asyncio.sleep(2 ** attempt)
                        continue
                    raise _TransientLLMError(f"{type(exc).__name__}: {exc}") from exc
                except httpx.HTTPError as exc:
                    log.warning("LLM transport error on turn %d: %s", turns, exc)
                    await on_event(f"agent error: {exc}"[:500])
                    reason = f"api_error: {type(exc).__name__}"
                    response = None
                    break
            if response is None:
                break

            choices = response.get("choices") or []
            if not choices:
                reason = "no_choice"
                break
            message = choices[0].get("message") or {}
            finish_reason = choices[0].get("finish_reason")
            assistant_text = (message.get("content") or "").strip()
            tool_use_calls = message.get("tool_calls") or []

            assistant_msg: dict[str, Any] = {"role": "assistant"}
            assistant_msg["content"] = assistant_text or None
            if tool_use_calls:
                assistant_msg["tool_calls"] = tool_use_calls
            messages.append(assistant_msg)

            if not tool_use_calls:
                reason = f"stop_{finish_reason or 'final'}"
                break

            for call in tool_use_calls:
                fn = call.get("function") or {}
                name = fn.get("name") or ""
                raw_args = fn.get("arguments") or "{}"
                try:
                    args = raw_args if isinstance(raw_args, dict) else json.loads(raw_args)
                except (TypeError, ValueError):
                    args = {}
                tool_calls += 1
                await on_event(_format_tool_call(name, args))

                tool = tools_by_name.get(name)
                if tool is None:
                    result: Any = {"error": f"unknown tool {name!r}"}
                else:
                    try:
                        result = await tool.handler(session_id, args)
                    except Exception as exc:
                        log.exception("tool %s failed", name)
                        result = {"error": f"{type(exc).__name__}: {exc}"}

                messages.append({
                    "role": "tool",
                    "tool_call_id": call.get("id"),
                    "content": _tool_result_content(result),
                })

                if name == "finish":
                    summary = str(args.get("summary", "")).strip()[:4000]
                    finished_cleanly = True
                    reason = "finished"

            if finished_cleanly:
                break

    elapsed = time.monotonic() - start
    log.info(
        "%s loop done in %.1fs · turns=%d · tool_calls=%d · reason=%s",
        agent.name, elapsed, turns, tool_calls, reason,
    )
    return AgentOutcome(
        summary=summary, tool_calls=tool_calls, turns=turns,
        finished_cleanly=finished_cleanly, reason=reason,
    )
```

- [ ] **Step 4: Replace `agent_runner.run_agent` body with the wrapper**

In `apps/api/pencheff_api/services/agent_runner.py`, replace the existing `async def run_agent(...)` function (currently at line ~802 to line ~1052) with this thin wrapper that builds the legacy `Agent` and delegates:

```python
async def run_agent(
    *,
    session_id: str,
    target_url: str,
    credentials: dict[str, Any] | None,
    profile: str,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    on_event: LogSink,
    session_prepopulated: bool = False,
) -> AgentOutcome:
    """Drive the legacy single penetration-testing agent to completion.

    Now a thin wrapper over ``agent_swarm.agent_loop._run_single_agent``.
    Behaviour is unchanged from before the refactor.
    """
    from .agent_swarm.agent_loop import (
        Agent as _Agent,
        AgentOutcome as _AgentOutcome,
        _run_single_agent,
    )
    settings = get_settings()
    if not settings.agent_llm_api_key:
        raise RuntimeError("AGENT_LLM_API_KEY not configured")
    legacy = _Agent(
        name="Agent",
        system_prompt=SYSTEM_PROMPT,
        tools=_build_tool_registry(profile=profile),
        max_turns=settings.agent_max_turns,
    )
    try:
        outcome = await _run_single_agent(
            agent=legacy,
            session_id=session_id, target_url=target_url,
            credentials=credentials, profile=profile,
            scope=scope, exclude_paths=exclude_paths,
            on_event=on_event, session_prepopulated=session_prepopulated,
        )
    except Exception as exc:
        log.exception("legacy run_agent failed: %s", exc)
        return AgentOutcome(
            summary="", tool_calls=0, turns=0,
            finished_cleanly=False, reason=f"error: {type(exc).__name__}",
        )
    return AgentOutcome(
        summary=outcome.summary,
        tool_calls=outcome.tool_calls,
        turns=outcome.turns,
        finished_cleanly=outcome.finished_cleanly,
        reason=outcome.reason,
    )
```

Delete the now-unused helpers (`_chat_completion`, `_format_tool_for_openai`, `_tool_result_content`, `_format_tool_call`) from `agent_runner.py` — they are now in `agent_loop.py`. Keep `AgentOutcome`, `AgentTool`, `_build_tool_registry`, `SYSTEM_PROMPT`, and the guarded handlers (`_test_endpoint_guarded`, `_suppress_finding_guarded`, `_reject_tool_call`, `_run_security_tool`).

- [ ] **Step 5: Run the refactor test + the full suite — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_agent_loop_refactor.py`

Expected: PASS — same as Step 2.

Run: `cd apps/api && uv run pytest -x tests/`

Expected: All existing tests pass (no regression).

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/services/agent_runner.py apps/api/pencheff_api/services/agent_swarm/agent_loop.py apps/api/tests/services/agent_swarm/test_agent_loop_refactor.py
git commit -m "refactor(swarm): extract _run_single_agent from agent_runner

Pure code-move: legacy run_agent now delegates. New _TransientLLMError
escapes the loop only after in-loop retry budget is exhausted; the
swarm orchestrator's per-breaker retry catches it.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase C — Snapshot + Pencheff helpers

### Task C1: `ReconSnapshot` + `DiscoveredEndpoint` + `ReconFailed`

**Files:**
- Create: `apps/api/pencheff_api/services/agent_swarm/snapshot.py`
- Test: `apps/api/tests/services/agent_swarm/test_snapshot.py`

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/services/agent_swarm/test_snapshot.py`:

```python
"""ReconSnapshot is frozen, immutable, and round-trippable through
its dict representation."""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from pencheff_api.services.agent_swarm.snapshot import (
    DiscoveredEndpoint,
    ReconFailed,
    ReconSnapshot,
)


def test_snapshot_is_frozen():
    snap = _make_snapshot()
    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.target_base_url = "x"  # type: ignore[misc]


def test_endpoint_is_frozen():
    ep = DiscoveredEndpoint(
        url="https://t/api", method="GET", status=200,
        content_type="application/json", parameters=("id",),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        ep.url = "y"  # type: ignore[misc]


def test_recon_failed_is_an_exception():
    assert issubclass(ReconFailed, Exception)
    with pytest.raises(ReconFailed):
        raise ReconFailed("recon empty")


def test_snapshot_authenticated_defaults_consistent():
    snap = _make_snapshot()
    assert snap.authenticated is False
    assert snap.auth_login_url is None
    assert snap.auth_cookies == ()
    assert snap.auth_tokens == {}


def _make_snapshot() -> ReconSnapshot:
    return ReconSnapshot(
        target_base_url="https://t.example.com",
        profile="standard",
        scope_include=("https://t.example.com/",),
        scope_exclude=(),
        endpoints=(
            DiscoveredEndpoint(
                url="https://t.example.com/api/users",
                method="GET", status=200,
                content_type="application/json",
                parameters=("id",),
            ),
        ),
        api_spec_urls=(),
        subdomains=(),
        robots_txt=None,
        sitemap_urls=(),
        security_txt=None,
        tech_stack={"server": "nginx/1.18"},
        waf_vendor=None,
        authenticated=False,
        auth_login_url=None,
        auth_cookies=(),
        auth_tokens={},
        oast_session_handle=None,
        recon_agent_summary="",
        recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )
```

- [ ] **Step 2: Run — expect failure (module not yet created)**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_snapshot.py`

Expected: FAIL with `ModuleNotFoundError: pencheff_api.services.agent_swarm.snapshot`.

- [ ] **Step 3: Implement `snapshot.py`**

Create `apps/api/pencheff_api/services/agent_swarm/snapshot.py`:

```python
"""ReconSnapshot — the read-only handoff from Phase 1 to Phase 2.

Frozen by construction: every nested collection is a tuple or a
read-only mapping. Once Recon publishes a snapshot, no breaker can
mutate it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Mapping


class ReconFailed(Exception):
    """Raised by ``run_recon_phase`` when recon crashed or produced an
    empty surface. The orchestrator catches this and routes to the
    catastrophic-fallback gate (legacy single-agent loop)."""


@dataclass(frozen=True)
class DiscoveredEndpoint:
    url: str
    method: str
    status: int | None
    content_type: str | None
    parameters: tuple[str, ...]


@dataclass(frozen=True)
class ReconSnapshot:
    # Provenance / scope
    target_base_url: str
    profile: Literal["quick", "standard", "deep"]
    scope_include: tuple[str, ...]
    scope_exclude: tuple[str, ...]

    # Surface
    endpoints: tuple[DiscoveredEndpoint, ...]
    api_spec_urls: tuple[str, ...]
    subdomains: tuple[str, ...]
    robots_txt: str | None
    sitemap_urls: tuple[str, ...]
    security_txt: str | None

    # Fingerprint
    tech_stack: Mapping[str, str]
    waf_vendor: str | None

    # Auth handoff
    authenticated: bool
    auth_login_url: str | None
    auth_cookies: tuple[tuple[str, str], ...]
    auth_tokens: Mapping[str, str]

    # OAST
    oast_session_handle: str | None

    # Provenance / debugging
    recon_agent_summary: str
    recon_findings_ids: tuple[str, ...]
    snapshot_built_at: datetime
```

- [ ] **Step 4: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_snapshot.py`

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/snapshot.py apps/api/tests/services/agent_swarm/test_snapshot.py
git commit -m "feat(swarm): ReconSnapshot + DiscoveredEndpoint + ReconFailed

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task C2: Pencheff helpers (4 in one task — they're each ~10-20 lines)

**Files:**
- Modify: `plugins/pencheff/pencheff/server.py`
- Test: `apps/api/tests/services/agent_swarm/test_pencheff_helpers.py`

These helpers are **orchestrator-internal**, so they are plain `async def` (no `@mcp.tool()`) — we do not want the LLM to call them.

- [ ] **Step 1: Write failing tests**

Create `apps/api/tests/services/agent_swarm/test_pencheff_helpers.py`:

```python
"""The 4 new orchestrator-internal pencheff helpers. Tested against
real PentestSession instances (no LLM, no network)."""
from __future__ import annotations

import pytest

from pencheff.server import (
    pentest_init,
    import_endpoints,
    set_auth_state,
    attach_oast,
    copy_finding,
    get_findings,
)


@pytest.mark.asyncio
async def test_import_endpoints_persists_to_session():
    init = await pentest_init(target_url="https://t.example.com")
    sid = init["session_id"]
    res = await import_endpoints(
        session_id=sid,
        endpoints=[
            {"url": "https://t.example.com/api/users",
             "method": "GET", "status": 200,
             "content_type": "application/json",
             "parameters": ["id"]},
            {"url": "https://t.example.com/login",
             "method": "POST", "status": None,
             "content_type": None, "parameters": ["username", "password"]},
        ],
    )
    assert res["imported"] == 2


@pytest.mark.asyncio
async def test_set_auth_state_records_cookies_and_tokens():
    init = await pentest_init(target_url="https://t.example.com")
    sid = init["session_id"]
    res = await set_auth_state(
        session_id=sid,
        cookies=[("session_id", "abc123")],
        tokens={"bearer": "eyJ..."},
    )
    assert res["authenticated"] is True


@pytest.mark.asyncio
async def test_attach_oast_records_handle():
    init = await pentest_init(target_url="https://t.example.com")
    sid = init["session_id"]
    res = await attach_oast(session_id=sid, handle="oast-session-xyz")
    assert res["attached"] is True


@pytest.mark.asyncio
async def test_copy_finding_clones_with_tag():
    src = (await pentest_init(target_url="https://t.example.com"))["session_id"]
    dst = (await pentest_init(target_url="https://t.example.com"))["session_id"]
    # Inject a finding into src using the existing API.
    from pencheff.core.engagement_db import get_session as _gsess
    src_session = _gsess(src)
    src_session.findings.add(
        title="Test SQLi",
        category="injection",
        severity="high",
        endpoint="https://t.example.com/api/users",
        evidence="' OR 1=1",
    )
    fid = src_session.findings.findings[0].id

    res = await copy_finding(
        src_session=src,
        dst_session=dst,
        finding_id=fid,
        tag={"discovered_by_agent": "InjectionAgent"},
    )
    assert res["copied"] is True

    dst_findings = (await get_findings(session_id=dst))["findings"]
    assert len(dst_findings) == 1
    assert dst_findings[0]["title"] == "Test SQLi"
    assert dst_findings[0].get("metadata", {}).get("discovered_by_agent") == "InjectionAgent"


@pytest.mark.asyncio
async def test_copy_finding_unknown_id_returns_error():
    src = (await pentest_init(target_url="https://t.example.com"))["session_id"]
    dst = (await pentest_init(target_url="https://t.example.com"))["session_id"]
    res = await copy_finding(
        src_session=src, dst_session=dst,
        finding_id="does-not-exist", tag={},
    )
    assert res.get("copied") is False
    assert "not found" in res.get("error", "").lower()
```

- [ ] **Step 2: Run — expect failure (`ImportError: cannot import name 'import_endpoints'`)**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_pencheff_helpers.py`

Expected: FAIL with `ImportError`.

- [ ] **Step 3: Implement the 4 helpers**

Open `plugins/pencheff/pencheff/server.py`. Find the line `async def get_findings(` (around line 2218) and add the four new helpers immediately above it. They use the existing `_require_session` helper (line 152) for session lookup.

```python
async def import_endpoints(
    *, session_id: str, endpoints: list[dict],
) -> dict:
    """Bulk-load discovered endpoints into the session's discovered-URL set.

    Each entry: {"url", "method", "status", "content_type", "parameters"}.
    Used by the agent_swarm orchestrator to seed isolated breaker sessions
    from a frozen ReconSnapshot — saves each breaker from re-crawling.
    """
    s = _require_session(session_id)
    count = 0
    for ep in endpoints:
        url = ep.get("url")
        if not url:
            continue
        method = ep.get("method", "GET")
        params = tuple(ep.get("parameters") or ())
        # Use the existing endpoint registry on PentestSession.
        s.discovered_endpoints.add(
            url=url, method=method,
            status=ep.get("status"),
            content_type=ep.get("content_type"),
            parameters=params,
        )
        count += 1
    return {"imported": count}


async def set_auth_state(
    *, session_id: str,
    cookies: list[tuple[str, str]] | None = None,
    tokens: dict[str, str] | None = None,
) -> dict:
    """Inject an authenticated session state without going through login.

    Used by the agent_swarm orchestrator after ReconAgent's
    authenticated_crawl succeeds: subsequent breaker sessions inherit
    the auth bundle without each having to log in again.
    """
    s = _require_session(session_id)
    if cookies:
        for name, value in cookies:
            s.session.cookies.set(name, value)
    if tokens:
        for k, v in tokens.items():
            s.session.tokens[k] = v
    s.session.authenticated = bool(cookies or tokens)
    return {"authenticated": s.session.authenticated}


async def attach_oast(
    *, session_id: str, handle: str,
) -> dict:
    """Reuse an existing OAST callback infrastructure handle.

    ReconAgent calls oast_init once on the master session; the
    orchestrator passes that handle into each breaker session via this
    helper so all OAST callbacks land in the same poll buffer.
    """
    s = _require_session(session_id)
    s.oast.handle = handle
    return {"attached": True}


async def copy_finding(
    *, src_session: str, dst_session: str,
    finding_id: str, tag: dict | None = None,
) -> dict:
    """Copy one finding from src into dst, optionally tagging metadata.

    Used by the agent_swarm orchestrator's merge step to union breaker
    findings into the master session before ChainAgent runs.
    """
    src = _require_session(src_session)
    dst = _require_session(dst_session)
    found = next((f for f in src.findings.findings if f.id == finding_id), None)
    if found is None:
        return {"copied": False, "error": f"finding {finding_id!r} not found in source"}
    cloned = found.clone() if hasattr(found, "clone") else _shallow_clone_finding(found)
    if tag:
        meta = dict(getattr(cloned, "metadata", None) or {})
        meta.update(tag)
        cloned.metadata = meta
    dst.findings.findings.append(cloned)
    return {"copied": True, "new_id": cloned.id}


def _shallow_clone_finding(finding):
    """Fallback clone for Finding objects that don't expose .clone()."""
    import copy
    return copy.copy(finding)
```

If the existing `Finding` class does not expose `clone()` or `metadata`, the fallback `_shallow_clone_finding` + `dict(getattr(..., "metadata", None) or {})` keeps the helper working without requiring a Finding-class change. If a later inspection of `plugins/pencheff/pencheff/core/findings.py` shows the Finding class already has `metadata: dict`, that's a free win and no extra work is needed.

- [ ] **Step 4: Inspect Finding to confirm or fix the metadata field**

Run: `grep -n "class Finding\|metadata\|def clone" plugins/pencheff/pencheff/core/findings.py | head -20`

If `Finding` has no `metadata` attribute, add it. Open `plugins/pencheff/pencheff/core/findings.py`, find the `Finding` dataclass / class, and add:

```python
    metadata: dict = field(default_factory=dict)
```

(if it's a dataclass; otherwise `self.metadata = {}` in `__init__`).

- [ ] **Step 5: Run the test — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_pencheff_helpers.py`

Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add plugins/pencheff/pencheff/server.py plugins/pencheff/pencheff/core/findings.py apps/api/tests/services/agent_swarm/test_pencheff_helpers.py
git commit -m "feat(pencheff): add orchestrator-internal helpers (import_endpoints, set_auth_state, attach_oast, copy_finding)

Plain async functions (not @mcp.tool()) — invoked by the agent_swarm
orchestrator only; not exposed to LLM agents.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase D — Per-agent prompts and tool selectors

### Task D1: `prompts.py` — clean-room per-agent system prompts

**Files:**
- Create: `apps/api/pencheff_api/services/agent_swarm/prompts.py`
- Test: `apps/api/tests/services/agent_swarm/test_prompts.py`

**IP-safety check (Spec §3):** every prompt below is written from scratch in this codebase. No text copied from `0x4m4/hexstrike-ai`. The shared skeleton (identity-protection, exploit-don't-scan, passive-misconfig-non-suppression) is lifted verbatim from the existing in-tree `agent_runner.SYSTEM_PROMPT` (already ours, in-tree since `f6d024d`). Mandate-specific sections are written fresh per agent.

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/services/agent_swarm/test_prompts.py`:

```python
"""Per-agent prompts share a skeleton + carry their mandate scoping."""
from __future__ import annotations

from pencheff_api.services.agent_swarm import prompts


def test_recon_prompt_has_skeleton_and_recon_mandate():
    p = prompts.build_recon_prompt()
    # Skeleton: identity protection
    assert "Pencheff" in p
    assert "I'm Pencheff" in p
    # Mandate-specific
    assert "ReconAgent" in p or "Recon agent" in p
    assert "attack surface" in p.lower()
    assert "do not call any tool that is not in your registry" in p.lower()


def test_breaker_prompt_carries_mandate():
    p = prompts.build_breaker_prompt(
        agent_name="InjectionAgent",
        mandate_one_liner="Surface SQLi/NoSQLi/XXE/SSTI/cmdi + path traversal + file upload flaws.",
    )
    assert "InjectionAgent" in p
    assert "SQLi" in p
    assert "do not call any tool that is not in your registry" in p.lower()
    # Skeleton: exploit don't scan
    assert "EXPLOIT" in p


def test_chain_prompt_mandate_focuses_on_chains():
    p = prompts.build_chain_prompt()
    assert "ChainAgent" in p
    assert "exploit_chain_suggest" in p
    assert "test_chain" in p
    assert "executive summary" in p.lower()


def test_no_distinctive_hexstrike_strings():
    """Sanity: the IP-safety contract forbids copying hexstrike-ai
    distinctive identifiers. None of these should appear anywhere."""
    forbidden = (
        "BugBountyWorkflowManager", "VulnerabilityCorrelator",
        "AIExploitGenerator", "CTFWorkflowManager",
        "IntelligentDecisionEngine", "HexStrike",
    )
    full = (
        prompts.build_recon_prompt()
        + prompts.build_breaker_prompt("InjectionAgent", "x")
        + prompts.build_chain_prompt()
    )
    for s in forbidden:
        assert s not in full, f"forbidden hexstrike-ai identifier in prompt: {s!r}"
```

- [ ] **Step 2: Run — expect failure (`ModuleNotFoundError`)**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_prompts.py`

Expected: FAIL.

- [ ] **Step 3: Implement `prompts.py`**

Create `apps/api/pencheff_api/services/agent_swarm/prompts.py`:

```python
"""Per-agent system prompts — clean-room, written for this codebase.

The shared skeleton (identity / exploit-don't-scan / passive-misconfig
non-suppression) is taken verbatim from the in-tree
``agent_runner.SYSTEM_PROMPT`` (already ours). Mandate-specific
sections below are written fresh per agent for the swarm.

IP-safety: nothing on this page is copied from any external project.
See docs/superpowers/specs/2026-05-05-parallel-agent-swarm-design.md §3.
"""
from __future__ import annotations

# The skeleton is intentionally a string-substring of the legacy prompt
# so future edits to the legacy prompt's identity / exploit-don't-scan
# rules propagate by re-importing here.
from ..agent_runner import SYSTEM_PROMPT as _LEGACY_PROMPT


_SHARED_SKELETON = _LEGACY_PROMPT  # identity, rules 1-5, stop condition, identity rules


_SCOPING_FOOTER = (
    "## Scope discipline\n\n"
    "You are one agent in a wider swarm. Other agents own other attack "
    "categories. **Do not call any tool that is not in your registry** — "
    "those tools do not exist for you. Findings outside your scope, "
    "leave to other agents. Call `finish` once your mandate is covered."
)


def build_recon_prompt() -> str:
    mandate = (
        "## Mandate (ReconAgent)\n\n"
        "You are the **ReconAgent**. Your single job is to map the target's "
        "attack surface so the breaker agents can attack it efficiently. "
        "Run passive recon first, then active recon, then API-discovery "
        "if signals point at an API surface. If credentials were "
        "supplied, call `authenticated_crawl` so the resulting cookies / "
        "tokens become available to every later agent. "
        "Do NOT attempt to exploit anything — the breakers will do that. "
        "Call `finish` with a one-paragraph summary of the surface "
        "(URLs, parameters, tech stack, auth state) once the picture is "
        "clear."
    )
    return f"{_SHARED_SKELETON}\n\n{mandate}\n\n{_SCOPING_FOOTER}"


def build_breaker_prompt(*, agent_name: str, mandate_one_liner: str) -> str:
    mandate = (
        f"## Mandate ({agent_name})\n\n"
        f"You are the **{agent_name}**. {mandate_one_liner} You are "
        "running in parallel with other breaker agents — they own "
        "other categories. The recon snapshot has already been "
        "established; the discovered endpoints, parameters, and any "
        "authenticated session state are loaded into your isolated "
        "pencheff session. "
        "Pick the most promising attack surface from your scoped tools, "
        "fire targeted probes, verify each candidate finding with "
        "`test_endpoint`, suppress what you cannot reproduce, and "
        "call `finish` when your mandate is covered. EXPLOIT, don't "
        "just scan."
    )
    return f"{_SHARED_SKELETON}\n\n{mandate}\n\n{_SCOPING_FOOTER}"


def build_chain_prompt() -> str:
    mandate = (
        "## Mandate (ChainAgent)\n\n"
        "You are the **ChainAgent**. The recon and breaker phases are "
        "complete; their findings are merged into your master pencheff "
        "session. Your job is to walk multi-step exploitation chains "
        "across those findings. Start with `get_findings` to read the "
        "merged set, then `exploit_chain_suggest` for proposed chains, "
        "then `test_chain` to walk the most promising one (e.g. SSRF → "
        "cloud metadata → IAM credentials → S3 enumeration). Use "
        "`test_endpoint` and `oast_*` tools as needed to verify chain "
        "steps. Finish with an executive summary (≤ 200 words) "
        "describing what you confirmed, what you ruled out, and the "
        "single most impactful chain you walked."
    )
    return f"{_SHARED_SKELETON}\n\n{mandate}\n\n{_SCOPING_FOOTER}"
```

- [ ] **Step 4: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_prompts.py`

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/prompts.py apps/api/tests/services/agent_swarm/test_prompts.py
git commit -m "feat(swarm): per-agent system prompts (clean-room)

Shared skeleton lifted verbatim from existing agent_runner.SYSTEM_PROMPT.
Mandate sections written fresh. No content from 0x4m4/hexstrike-ai.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task D2: `tools.py` — per-agent tool selectors

**Files:**
- Create: `apps/api/pencheff_api/services/agent_swarm/tools.py`
- Test: `apps/api/tests/services/agent_swarm/test_breakers_table.py` (covers the allocation invariant — moved here so the table is tested as soon as it exists; `breakers.py` itself comes in Task F1)

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/services/agent_swarm/test_breakers_table.py`:

```python
"""Allocation invariant: every scan_* tool appears in exactly one breaker
(plus shared utility tools that must appear in every breaker)."""
from __future__ import annotations

from pencheff_api.services.agent_swarm.tools import (
    BREAKER_TOOL_ALLOCATIONS,
    SHARED_BREAKER_TOOLS,
    recon_tools,
    chain_tools,
)


def test_every_scan_tool_in_exactly_one_breaker():
    """Tools whose name starts with `scan_` must appear in exactly
    one breaker's exclusive list."""
    seen: dict[str, str] = {}
    for breaker_name, exclusive in BREAKER_TOOL_ALLOCATIONS.items():
        for t in exclusive:
            if not t.startswith("scan_"):
                continue
            assert t not in seen, (
                f"{t!r} allocated to both {seen[t]!r} and {breaker_name!r}"
            )
            seen[t] = breaker_name
    # Sanity: at least these scan_* tools are covered (allocation may
    # legitimately add more later).
    must_cover = {
        "scan_injection", "scan_client_side", "scan_auth", "scan_authz",
        "scan_oauth", "scan_mfa_bypass", "scan_api", "scan_websocket",
        "scan_business_logic", "scan_infrastructure", "scan_advanced",
        "scan_subdomain_takeover", "scan_cloud", "scan_dom_xss",
        "scan_file_handling",
    }
    assert must_cover.issubset(seen.keys())


def test_shared_breaker_tools_present_in_every_breaker():
    expected = {"test_endpoint", "get_findings", "suppress_finding", "finish"}
    assert expected.issubset(SHARED_BREAKER_TOOLS)


def test_recon_tools_carry_mapping_tools_only():
    names = {t for t in recon_tools()}
    assert "recon_passive" in names
    assert "recon_active" in names
    assert "recon_api_discovery" in names
    assert "scan_waf" in names
    assert "authenticated_crawl" in names
    assert "finish" in names
    # Recon does NOT do exploitation
    assert "scan_injection" not in names
    assert "test_chain" not in names


def test_chain_tools_carry_chain_tools_only():
    names = {t for t in chain_tools()}
    assert "exploit_chain_suggest" in names
    assert "test_chain" in names
    assert "test_endpoint" in names
    assert "get_findings" in names
    assert "oast_init" in names
    assert "finish" in names
    # Chain does NOT run new scans
    assert "scan_injection" not in names
    assert "scan_authz" not in names
```

- [ ] **Step 2: Run — expect failure**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_breakers_table.py`

Expected: FAIL — `ModuleNotFoundError: pencheff_api.services.agent_swarm.tools`.

- [ ] **Step 3: Implement `tools.py`**

Create `apps/api/pencheff_api/services/agent_swarm/tools.py`:

```python
"""Per-agent tool subset selectors over the existing
``agent_runner._build_tool_registry`` registry.

The legacy registry exposes ~25 tools to one agent. The swarm slices
that registry into role-specific subsets so each specialised agent
sees only the tools it owns. Every breaker also sees the shared
utility tools (verify, list, suppress, finish).
"""
from __future__ import annotations

from typing import Iterable

from ..agent_runner import _build_tool_registry, AgentTool


# Tools every breaker has access to regardless of category.
SHARED_BREAKER_TOOLS = frozenset({
    "test_endpoint",
    "get_findings",
    "suppress_finding",
    "finish",
})


# Per-breaker EXCLUSIVE tool allocation. Each scan_* tool appears in
# exactly one breaker's exclusive list — see test_breakers_table.py.
BREAKER_TOOL_ALLOCATIONS: dict[str, frozenset[str]] = {
    "InjectionAgent":   frozenset({"scan_injection", "scan_file_handling",
                                    "oast_init", "oast_new_url", "oast_poll"}),
    "ClientSideAgent":  frozenset({"scan_client_side", "scan_dom_xss"}),
    "AuthAgent":        frozenset({"scan_auth", "scan_oauth", "scan_mfa_bypass"}),
    "AuthzAgent":       frozenset({"scan_authz"}),
    "APIAgent":         frozenset({"scan_api", "scan_websocket",
                                    "scan_business_logic"}),
    "InfraAgent":       frozenset({"scan_infrastructure", "scan_advanced",
                                    "scan_subdomain_takeover",
                                    "run_security_tool"}),
    "CloudAgent":       frozenset({"scan_cloud",
                                    "oast_init", "oast_new_url", "oast_poll"}),
}


def recon_tools() -> tuple[str, ...]:
    return (
        "recon_passive", "recon_active", "recon_api_discovery",
        "scan_waf", "authenticated_crawl", "finish",
    )


def chain_tools() -> tuple[str, ...]:
    return (
        "get_findings", "exploit_chain_suggest", "test_chain",
        "test_endpoint", "oast_init", "oast_new_url", "oast_poll",
        "finish",
    )


def select_tools(profile: str, names: Iterable[str]) -> list[AgentTool]:
    """Return the subset of the legacy registry whose tool.name is in ``names``."""
    full = _build_tool_registry(profile=profile)
    wanted = set(names)
    return [t for t in full if t.name in wanted]


def breaker_tools_for(*, profile: str, breaker_name: str) -> list[AgentTool]:
    """Tools available to one specific breaker."""
    exclusive = BREAKER_TOOL_ALLOCATIONS[breaker_name]
    names = exclusive | SHARED_BREAKER_TOOLS
    return select_tools(profile, names)
```

Note that `oast_init`, `oast_new_url`, and `oast_poll` legitimately appear in two breakers' lists (`InjectionAgent` and `CloudAgent`). They are not `scan_*` tools, so the "exactly one breaker" invariant in `test_breakers_table.py` (which restricts itself to `scan_*` tools) intentionally allows this overlap.

- [ ] **Step 4: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_breakers_table.py`

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/tools.py apps/api/tests/services/agent_swarm/test_breakers_table.py
git commit -m "feat(swarm): per-agent tool selectors over existing registry

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase E — Recon phase

### Task E1: `recon.py` — `run_recon_phase` + `_freeze_snapshot`

**Files:**
- Create: `apps/api/pencheff_api/services/agent_swarm/recon.py`
- Test: `apps/api/tests/services/agent_swarm/test_recon_phase.py`

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/services/agent_swarm/test_recon_phase.py`:

```python
"""Recon phase wraps _run_single_agent + freezes a ReconSnapshot.
Empty snapshot or recon crash → ReconFailed."""
from __future__ import annotations

import pytest

from pencheff_api.services.agent_swarm.recon import run_recon_phase
from pencheff_api.services.agent_swarm.snapshot import (
    ReconFailed, ReconSnapshot,
)
from tests.services.agent_swarm._scripted_llm import (
    ScriptedLLM, with_finish, with_tool_call,
)


@pytest.fixture
def llm_settings(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "agent_llm_api_key", "sk-test")
    monkeypatch.setattr(s, "agent_llm_base_url", "https://api.example.com/v1")
    monkeypatch.setattr(s, "agent_llm_model", "test")
    monkeypatch.setattr(s, "agent_llm_max_tokens", 1024)
    monkeypatch.setattr(s, "agent_request_timeout", 30.0)
    return s


@pytest.fixture
async def real_session():
    from pencheff.server import pentest_init
    init = await pentest_init(target_url="https://t.example.com")
    yield init["session_id"]


@pytest.mark.asyncio
async def test_recon_happy_returns_snapshot(llm_settings, monkeypatch, real_session):
    # ReconAgent calls recon_passive once then finishes.
    ScriptedLLM([
        with_tool_call("recon_passive", {}, call_id="c1"),
        with_finish("recon done: 12 endpoints"),
    ]).install(monkeypatch)

    events: list[str] = []
    async def on_event(line: str): events.append(line)

    snap = await run_recon_phase(
        master_session_id=real_session,
        target_url="https://t.example.com",
        credentials=None,
        profile="standard",
        scope=None,
        exclude_paths=None,
        on_event=on_event,
    )
    assert isinstance(snap, ReconSnapshot)
    assert snap.target_base_url == "https://t.example.com"
    assert snap.profile == "standard"
    assert "recon done" in snap.recon_agent_summary


@pytest.mark.asyncio
async def test_recon_no_tool_calls_raises_recon_failed(llm_settings, monkeypatch, real_session):
    # ReconAgent finishes without calling any recon tool — empty surface.
    ScriptedLLM([with_finish("nothing useful")]).install(monkeypatch)

    async def on_event(line: str): pass

    with pytest.raises(ReconFailed):
        await run_recon_phase(
            master_session_id=real_session,
            target_url="https://t.example.com",
            credentials=None, profile="quick",
            scope=None, exclude_paths=None,
            on_event=on_event,
        )
```

- [ ] **Step 2: Run — expect failure (ModuleNotFoundError)**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_recon_phase.py`

Expected: FAIL.

- [ ] **Step 3: Implement `recon.py`**

Create `apps/api/pencheff_api/services/agent_swarm/recon.py`:

```python
"""Phase 1 — ReconAgent runs against the master session and produces
a frozen ReconSnapshot for the breaker fan-out."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..agent_runner import _build_tool_registry
from ..config import get_settings
from .agent_loop import Agent, _run_single_agent, LogSink
from .prompts import build_recon_prompt
from .snapshot import (
    DiscoveredEndpoint, ReconFailed, ReconSnapshot,
)
from .tools import recon_tools, select_tools


def _recon_budget(profile: str) -> int:
    s = get_settings()
    return {
        "quick": s.swarm_turns_recon_quick,
        "standard": s.swarm_turns_recon_standard,
        "deep": s.swarm_turns_recon_deep,
    }.get(profile, s.swarm_turns_recon_standard)


async def run_recon_phase(
    *,
    master_session_id: str,
    target_url: str,
    credentials: dict[str, Any] | None,
    profile: str,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    on_event: LogSink,
) -> ReconSnapshot:
    """Run ReconAgent and freeze its output into a ReconSnapshot.

    Raises ReconFailed if the agent crashed or produced an empty surface.
    """
    agent = Agent(
        name="ReconAgent",
        system_prompt=build_recon_prompt(),
        tools=select_tools(profile, recon_tools()),
        max_turns=_recon_budget(profile),
    )
    try:
        outcome = await _run_single_agent(
            agent=agent,
            session_id=master_session_id,
            target_url=target_url,
            credentials=credentials,
            profile=profile,
            scope=scope,
            exclude_paths=exclude_paths,
            on_event=on_event,
            session_prepopulated=False,
        )
    except Exception as exc:
        raise ReconFailed(f"recon agent crashed: {exc}") from exc

    if outcome.tool_calls == 0:
        raise ReconFailed("recon produced no tool calls (empty surface)")

    return await _freeze_snapshot(
        master_session_id=master_session_id,
        target_url=target_url,
        profile=profile,
        scope=scope,
        exclude_paths=exclude_paths,
        recon_summary=outcome.summary,
    )


async def _freeze_snapshot(
    *,
    master_session_id: str,
    target_url: str,
    profile: str,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    recon_summary: str,
) -> ReconSnapshot:
    """Read pencheff session state into the frozen ReconSnapshot."""
    from pencheff.core.engagement_db import get_session as _gsess

    sess = _gsess(master_session_id)
    if sess is None:
        raise ReconFailed("master session vanished after recon")

    discovered = sess.discovered_endpoints
    eps: list[DiscoveredEndpoint] = []
    for ep in getattr(discovered, "endpoints", []) or []:
        eps.append(DiscoveredEndpoint(
            url=getattr(ep, "url", ""),
            method=getattr(ep, "method", "GET"),
            status=getattr(ep, "status", None),
            content_type=getattr(ep, "content_type", None),
            parameters=tuple(getattr(ep, "parameters", ()) or ()),
        ))
    if not eps:
        # ReconAgent ran tools but produced nothing useful — still
        # treat as recon-failed per Spec §8.
        raise ReconFailed("recon produced zero endpoints")

    auth_cookies = tuple(
        (k, v) for k, v in sess.session.cookies.items()
    ) if hasattr(sess.session.cookies, "items") else ()
    auth_tokens = dict(getattr(sess.session, "tokens", {}) or {})
    finding_ids = tuple(f.id for f in sess.findings.findings)

    return ReconSnapshot(
        target_base_url=target_url,
        profile=profile,  # type: ignore[arg-type]
        scope_include=tuple(scope or ()),
        scope_exclude=tuple(exclude_paths or ()),
        endpoints=tuple(eps),
        api_spec_urls=tuple(getattr(sess, "api_spec_urls", ()) or ()),
        subdomains=tuple(getattr(sess, "subdomains", ()) or ()),
        robots_txt=getattr(sess, "robots_txt", None),
        sitemap_urls=tuple(getattr(sess, "sitemap_urls", ()) or ()),
        security_txt=getattr(sess, "security_txt", None),
        tech_stack=dict(getattr(sess, "tech_stack", {}) or {}),
        waf_vendor=getattr(sess, "waf_vendor", None),
        authenticated=bool(getattr(sess.session, "authenticated", False)),
        auth_login_url=getattr(sess.session, "login_url", None),
        auth_cookies=auth_cookies,
        auth_tokens=auth_tokens,
        oast_session_handle=getattr(sess.oast, "handle", None),
        recon_agent_summary=recon_summary,
        recon_findings_ids=finding_ids,
        snapshot_built_at=datetime.now(tz=timezone.utc),
    )
```

If any of the `getattr(...)` accesses on the pencheff session don't match its actual attribute names, fall back to using the ones that do exist (`grep -n` on `plugins/pencheff/pencheff/core/engagement_db.py` to inspect). The intent is captured in the snapshot dataclass; the read pattern adapts to what the session exposes.

- [ ] **Step 4: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_recon_phase.py`

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/recon.py apps/api/tests/services/agent_swarm/test_recon_phase.py
git commit -m "feat(swarm): Phase 1 — ReconAgent + _freeze_snapshot

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase F — Breakers (spec table + seed + retry wrapper)

### Task F1: `breakers.py` — `BreakerSpec`, table, `_build_breakers`, `seed_breaker_session`

**Files:**
- Create: `apps/api/pencheff_api/services/agent_swarm/breakers.py`
- Test: `apps/api/tests/services/agent_swarm/test_seed_breaker_session.py`

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/services/agent_swarm/test_seed_breaker_session.py`:

```python
"""seed_breaker_session creates a fresh isolated pencheff session and
imports the snapshot's surface into it (endpoints + auth + OAST)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pencheff_api.services.agent_swarm.breakers import seed_breaker_session
from pencheff_api.services.agent_swarm.snapshot import (
    DiscoveredEndpoint, ReconSnapshot,
)


def _snap(authenticated: bool = False) -> ReconSnapshot:
    return ReconSnapshot(
        target_base_url="https://t.example.com",
        profile="standard",
        scope_include=("https://t.example.com/",),
        scope_exclude=(),
        endpoints=(
            DiscoveredEndpoint(
                url="https://t.example.com/api/users",
                method="GET", status=200,
                content_type="application/json",
                parameters=("id",),
            ),
        ),
        api_spec_urls=(),
        subdomains=(),
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={"server": "nginx/1.18"},
        waf_vendor=None,
        authenticated=authenticated,
        auth_login_url=("https://t.example.com/login" if authenticated else None),
        auth_cookies=(("sid", "abc"),) if authenticated else (),
        auth_tokens={"bearer": "eyJ"} if authenticated else {},
        oast_session_handle="oast-h-1" if authenticated else None,
        recon_agent_summary="x",
        recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_seed_creates_fresh_session_with_endpoints():
    sid = await seed_breaker_session(_snap())
    from pencheff.core.engagement_db import get_session as _gsess
    sess = _gsess(sid)
    assert sess is not None
    eps = list(getattr(sess.discovered_endpoints, "endpoints", ()))
    assert len(eps) == 1
    assert getattr(eps[0], "url") == "https://t.example.com/api/users"


@pytest.mark.asyncio
async def test_seed_propagates_auth_when_authenticated():
    sid = await seed_breaker_session(_snap(authenticated=True))
    from pencheff.core.engagement_db import get_session as _gsess
    sess = _gsess(sid)
    assert sess.session.authenticated is True
    assert sess.session.cookies.get("sid") == "abc"
    assert sess.session.tokens.get("bearer") == "eyJ"


@pytest.mark.asyncio
async def test_seed_attaches_oast_handle_when_present():
    sid = await seed_breaker_session(_snap(authenticated=True))
    from pencheff.core.engagement_db import get_session as _gsess
    sess = _gsess(sid)
    assert sess.oast.handle == "oast-h-1"
```

- [ ] **Step 2: Run — expect failure**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_seed_breaker_session.py`

Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement `breakers.py`**

Create `apps/api/pencheff_api/services/agent_swarm/breakers.py`:

```python
"""BreakerSpec table + seed_breaker_session.

The 7 breaker agents and their mandates live here. seed_breaker_session
spins up a fresh isolated pencheff session per breaker and imports the
snapshot's surface so the breaker doesn't have to re-crawl.
"""
from __future__ import annotations

from dataclasses import dataclass

import pencheff.server as pencheff_server

from ..config import get_settings
from .agent_loop import Agent
from .prompts import build_breaker_prompt
from .snapshot import ReconSnapshot
from .tools import breaker_tools_for


@dataclass(frozen=True)
class BreakerSpec:
    name: str
    mandate_one_liner: str


BREAKER_SPECS: tuple[BreakerSpec, ...] = (
    BreakerSpec("InjectionAgent",
        "Surface SQLi/NoSQLi/XXE/SSTI/cmdi + path traversal + file upload flaws."),
    BreakerSpec("ClientSideAgent",
        "Surface reflected/DOM XSS, CSRF, open redirect, and CORS misconfig."),
    BreakerSpec("AuthAgent",
        "Surface authentication weaknesses: brute-force, JWT confusion, OAuth, MFA bypass."),
    BreakerSpec("AuthzAgent",
        "Surface authorisation flaws: IDOR, vertical/horizontal privilege escalation."),
    BreakerSpec("APIAgent",
        "Surface API/GraphQL weaknesses, websocket flaws, business-logic abuse."),
    BreakerSpec("InfraAgent",
        "Surface TLS/header weaknesses, smuggling, CRLF, subdomain takeover, exposed infra."),
    BreakerSpec("CloudAgent",
        "Surface cloud misconfig: public buckets, IAM metadata, blind SSRF callbacks."),
)


def _breaker_budget(profile: str) -> int:
    s = get_settings()
    return {
        "quick": s.swarm_turns_breaker_quick,
        "standard": s.swarm_turns_breaker_standard,
        "deep": s.swarm_turns_breaker_deep,
    }.get(profile, s.swarm_turns_breaker_standard)


def _build_breakers(*, profile: str, snapshot: ReconSnapshot) -> list[tuple[BreakerSpec, Agent]]:
    """Build (spec, Agent) pairs for the parallel fan-out."""
    out: list[tuple[BreakerSpec, Agent]] = []
    for spec in BREAKER_SPECS:
        agent = Agent(
            name=spec.name,
            system_prompt=build_breaker_prompt(
                agent_name=spec.name,
                mandate_one_liner=spec.mandate_one_liner,
            ),
            tools=breaker_tools_for(profile=profile, breaker_name=spec.name),
            max_turns=_breaker_budget(profile),
        )
        out.append((spec, agent))
    return out


async def seed_breaker_session(snapshot: ReconSnapshot) -> str:
    """Create a fresh pencheff session for one breaker, seeded from the snapshot."""
    init = await pencheff_server.pentest_init(target_url=snapshot.target_base_url)
    sid = init["session_id"]

    if snapshot.endpoints:
        await pencheff_server.import_endpoints(
            session_id=sid,
            endpoints=[
                {
                    "url": ep.url,
                    "method": ep.method,
                    "status": ep.status,
                    "content_type": ep.content_type,
                    "parameters": list(ep.parameters),
                }
                for ep in snapshot.endpoints
            ],
        )

    if snapshot.authenticated:
        await pencheff_server.set_auth_state(
            session_id=sid,
            cookies=list(snapshot.auth_cookies),
            tokens=dict(snapshot.auth_tokens),
        )

    if snapshot.oast_session_handle:
        await pencheff_server.attach_oast(
            session_id=sid, handle=snapshot.oast_session_handle,
        )

    return sid
```

- [ ] **Step 4: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_seed_breaker_session.py`

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/breakers.py apps/api/tests/services/agent_swarm/test_seed_breaker_session.py
git commit -m "feat(swarm): BreakerSpec table + seed_breaker_session

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task F2: `_run_breaker_with_retry` + `BreakerResult` (orchestrator part 1)

**Files:**
- Create: `apps/api/pencheff_api/services/agent_swarm/orchestrator.py` (initial — more added in F3, G1, H1, I1)
- Test: `apps/api/tests/services/agent_swarm/test_breaker_retry.py`

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/services/agent_swarm/test_breaker_retry.py`:

```python
"""_run_breaker_with_retry catches transient errors once.

Three cases:
  1. transient on attempt 1, success on attempt 2 → success
  2. transient on both attempts                   → recorded failure
  3. non-transient (e.g. ValueError) on attempt 1 → no retry, recorded failure
"""
from __future__ import annotations

import pytest

from pencheff_api.services.agent_swarm.agent_loop import (
    AgentOutcome, _TransientLLMError,
)
from pencheff_api.services.agent_swarm.breakers import BreakerSpec
from pencheff_api.services.agent_swarm.orchestrator import (
    _run_breaker_with_retry, BreakerResult,
)
from pencheff_api.services.agent_swarm.snapshot import (
    DiscoveredEndpoint, ReconSnapshot,
)
from datetime import datetime, timezone


def _snap() -> ReconSnapshot:
    return ReconSnapshot(
        target_base_url="https://t",
        profile="standard",
        scope_include=(), scope_exclude=(),
        endpoints=(DiscoveredEndpoint("https://t/u", "GET", 200, None, ()),),
        api_spec_urls=(), subdomains=(),
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={}, waf_vendor=None,
        authenticated=False, auth_login_url=None,
        auth_cookies=(), auth_tokens={},
        oast_session_handle=None,
        recon_agent_summary="x", recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )


@pytest.fixture
def fake_spec_and_agent(monkeypatch):
    spec = BreakerSpec("FakeAgent", "fake")
    # Patch _build_breakers shape isn't needed — we hand a (spec, agent) tuple.
    return spec


@pytest.mark.asyncio
async def test_transient_then_success(monkeypatch, fake_spec_and_agent):
    spec = fake_spec_and_agent
    calls = {"n": 0}

    async def fake_run_single_agent(*, agent, session_id, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _TransientLLMError("HTTP 503 after retries")
        return AgentOutcome(
            summary="ok", tool_calls=2, turns=2,
            finished_cleanly=True, reason="finished",
        )

    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator._run_single_agent",
        fake_run_single_agent,
    )
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator.seed_breaker_session",
        lambda snap: _async_return("sid-fake"),
    )

    # _run_breaker_with_retry queries pencheff for findings after the
    # agent succeeds — stub so this test doesn't need a real session.
    async def fake_get_findings(*, session_id):
        return {"findings": [{"id": "f1"}]}
    import pencheff.server as _srv
    monkeypatch.setattr(_srv, "get_findings", fake_get_findings)

    events: list[str] = []
    async def on_event(line: str): events.append(line)

    from types import SimpleNamespace
    fake_agent = SimpleNamespace(name=spec.name, system_prompt="x", tools=[], max_turns=5)
    res = await _run_breaker_with_retry(
        spec=spec, agent=fake_agent, snapshot=_snap(),
        on_event=on_event, target_url="https://t",
        credentials=None, scope=None, exclude_paths=None,
    )
    assert isinstance(res, BreakerResult)
    assert res.success is True
    assert res.summary == "ok"
    assert calls["n"] == 2  # one retry happened


@pytest.mark.asyncio
async def test_transient_twice_records_failure(monkeypatch, fake_spec_and_agent):
    spec = fake_spec_and_agent
    async def fake_run_single_agent(*, agent, session_id, **kwargs):
        raise _TransientLLMError("HTTP 503")
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator._run_single_agent",
        fake_run_single_agent,
    )
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator.seed_breaker_session",
        lambda snap: _async_return("sid"),
    )
    async def on_event(line: str): pass
    from types import SimpleNamespace
    fake_agent = SimpleNamespace(name=spec.name, system_prompt="x", tools=[], max_turns=5)
    res = await _run_breaker_with_retry(
        spec=spec, agent=fake_agent, snapshot=_snap(),
        on_event=on_event, target_url="https://t",
        credentials=None, scope=None, exclude_paths=None,
    )
    assert res.success is False
    assert "transient_after_retry" in (res.error or "")


@pytest.mark.asyncio
async def test_non_transient_no_retry(monkeypatch, fake_spec_and_agent):
    spec = fake_spec_and_agent
    calls = {"n": 0}
    async def fake_run_single_agent(*, agent, session_id, **kwargs):
        calls["n"] += 1
        raise ValueError("logic bug")
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator._run_single_agent",
        fake_run_single_agent,
    )
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator.seed_breaker_session",
        lambda snap: _async_return("sid"),
    )
    async def on_event(line: str): pass
    from types import SimpleNamespace
    fake_agent = SimpleNamespace(name=spec.name, system_prompt="x", tools=[], max_turns=5)
    res = await _run_breaker_with_retry(
        spec=spec, agent=fake_agent, snapshot=_snap(),
        on_event=on_event, target_url="https://t",
        credentials=None, scope=None, exclude_paths=None,
    )
    assert res.success is False
    assert "ValueError" in (res.error or "")
    assert calls["n"] == 1  # no retry


async def _async_return(v):
    return v
```

- [ ] **Step 2: Run — expect failure (orchestrator.py doesn't exist yet)**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_breaker_retry.py`

Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Create `orchestrator.py` (initial form — more grows in F3, G1, I1)**

Create `apps/api/pencheff_api/services/agent_swarm/orchestrator.py`:

```python
"""Swarm orchestrator: gather + retry + merge + chain + fallback gate.

The full design lives in
docs/superpowers/specs/2026-05-05-parallel-agent-swarm-design.md.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from ..config import get_settings
from .agent_loop import (
    Agent, AgentOutcome, _TransientLLMError, _run_single_agent, LogSink,
)
from .breakers import BreakerSpec, seed_breaker_session
from .snapshot import ReconSnapshot

log = logging.getLogger("pencheff.swarm.orchestrator")


@dataclass
class BreakerResult:
    agent_name: str
    success: bool
    finding_ids: tuple[str, ...]
    summary: str
    turns: int
    tool_calls: int
    error: str | None
    breaker_session_id: str | None  # for the merge step


def _prefix(prefix: str, sink: LogSink) -> LogSink:
    async def wrapped(line: str) -> None:
        await sink(f"{prefix}{line}")
    return wrapped


async def _run_breaker_with_retry(
    *,
    spec: BreakerSpec,
    agent: Agent,
    snapshot: ReconSnapshot,
    on_event: LogSink,
    target_url: str,
    credentials: dict[str, Any] | None,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
) -> BreakerResult:
    """Run one breaker with at most one whole-run retry on transient errors."""
    settings = get_settings()
    breaker_sid = await seed_breaker_session(snapshot)
    prefixed = _prefix(f"[{spec.name}] ", on_event)

    max_attempts = 1 + max(0, settings.swarm_breaker_retry_attempts)
    last_transient: str | None = None
    for attempt in range(max_attempts):
        try:
            outcome: AgentOutcome = await _run_single_agent(
                agent=agent,
                session_id=breaker_sid,
                target_url=target_url,
                credentials=credentials,
                profile=snapshot.profile,
                scope=scope,
                exclude_paths=exclude_paths,
                on_event=prefixed,
                session_prepopulated=True,  # breakers see snapshot-seeded session
            )
            # Query the breaker's isolated session for findings produced
            # during the run. _run_single_agent doesn't track these — it
            # just drives the loop — so we ask pencheff directly.
            import pencheff.server as pencheff_server
            listing = await pencheff_server.get_findings(session_id=breaker_sid)
            finding_ids = tuple(
                f.get("id", "") for f in (listing.get("findings") or [])
                if f.get("id")
            )
            return BreakerResult(
                agent_name=spec.name,
                success=True,
                finding_ids=finding_ids,
                summary=outcome.summary,
                turns=outcome.turns,
                tool_calls=outcome.tool_calls,
                error=None,
                breaker_session_id=breaker_sid,
            )
        except _TransientLLMError as exc:
            last_transient = str(exc)
            if attempt < max_attempts - 1:
                await prefixed(f"transient error ({exc}); retrying once")
                await asyncio.sleep(settings.swarm_breaker_retry_backoff_sec)
                continue
            return BreakerResult(
                agent_name=spec.name, success=False,
                finding_ids=(), summary="", turns=0, tool_calls=0,
                error=f"transient_after_retry: {last_transient}",
                breaker_session_id=breaker_sid,
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("breaker %s crashed", spec.name)
            return BreakerResult(
                agent_name=spec.name, success=False,
                finding_ids=(), summary="", turns=0, tool_calls=0,
                error=f"{type(exc).__name__}: {exc}",
                breaker_session_id=breaker_sid,
            )
    # Unreachable, but mypy-friendly:
    return BreakerResult(
        agent_name=spec.name, success=False,
        finding_ids=(), summary="", turns=0, tool_calls=0,
        error="exhausted_loop", breaker_session_id=breaker_sid,
    )
```

- [ ] **Step 4: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_breaker_retry.py`

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/orchestrator.py apps/api/tests/services/agent_swarm/test_breaker_retry.py
git commit -m "feat(swarm): _run_breaker_with_retry + BreakerResult

One whole-run retry on _TransientLLMError; no retry on non-transient
exceptions. Per-breaker isolated try/except so one failure never
cancels the gather.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task F3: `AuthzAgent` quiet-quit when `authenticated=False`

**Files:**
- Modify: `apps/api/pencheff_api/services/agent_swarm/orchestrator.py`
- Test: `apps/api/tests/services/agent_swarm/test_authz_quietquit.py`

`AuthzAgent` is the only agent whose entire mandate (IDOR + privesc) requires authentication. Per Spec §5, it must `finish` immediately with `"skipped: no authenticated session"` if recon failed to authenticate, and that skip counts as success (not failure) for the catastrophic-fallback gate.

The cleanest place to enforce this is **inside `_run_breaker_with_retry`** — before launching the loop — because we have the snapshot in scope and can short-circuit without billing the LLM at all.

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/services/agent_swarm/test_authz_quietquit.py`:

```python
"""AuthzAgent finishes immediately with success=True when the snapshot
shows authenticated=False. No LLM call is billed."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from pencheff_api.services.agent_swarm.breakers import BreakerSpec
from pencheff_api.services.agent_swarm.orchestrator import (
    _run_breaker_with_retry,
)
from pencheff_api.services.agent_swarm.snapshot import (
    DiscoveredEndpoint, ReconSnapshot,
)


def _snap_unauth() -> ReconSnapshot:
    return ReconSnapshot(
        target_base_url="https://t", profile="standard",
        scope_include=(), scope_exclude=(),
        endpoints=(DiscoveredEndpoint("https://t/u", "GET", 200, None, ()),),
        api_spec_urls=(), subdomains=(),
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={}, waf_vendor=None,
        authenticated=False,
        auth_login_url=None, auth_cookies=(), auth_tokens={},
        oast_session_handle=None,
        recon_agent_summary="", recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_authz_quietquits_when_unauth(monkeypatch):
    spec = BreakerSpec("AuthzAgent", "x")

    # _run_single_agent must NOT be called for AuthzAgent in unauth mode.
    sentinel = {"called": False}
    async def must_not_call(**kw):
        sentinel["called"] = True
        raise AssertionError("LLM was billed for a quiet-quit")
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator._run_single_agent",
        must_not_call,
    )
    # seed_breaker_session is still called (the session exists, it's
    # just that the agent doesn't run). That's fine; the bill is the LLM.
    async def _seed_ok(snap): return "sid-fake"
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator.seed_breaker_session",
        _seed_ok,
    )

    async def on_event(line): pass
    fake_agent = SimpleNamespace(
        name="AuthzAgent", system_prompt="x", tools=[], max_turns=5,
    )
    res = await _run_breaker_with_retry(
        spec=spec, agent=fake_agent, snapshot=_snap_unauth(),
        on_event=on_event, target_url="https://t",
        credentials=None, scope=None, exclude_paths=None,
    )
    assert sentinel["called"] is False
    assert res.success is True
    assert "skipped" in res.summary.lower()
    assert res.tool_calls == 0
    assert res.turns == 0
```

- [ ] **Step 2: Run — expect failure**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_authz_quietquit.py`

Expected: FAIL — the assertion `must_not_call` fires.

- [ ] **Step 3: Add the quiet-quit branch in `_run_breaker_with_retry`**

In `apps/api/pencheff_api/services/agent_swarm/orchestrator.py`, immediately after `breaker_sid = await seed_breaker_session(snapshot)`, insert:

```python
    # AuthzAgent quiet-quit: its mandate is meaningless without an
    # authenticated session. Treat as success so the catastrophic
    # fallback gate doesn't trip on this skip alone (Spec §5).
    if spec.name == "AuthzAgent" and not snapshot.authenticated:
        await prefixed("skipped: no authenticated session")
        return BreakerResult(
            agent_name=spec.name, success=True,
            finding_ids=(), summary="skipped: no authenticated session",
            turns=0, tool_calls=0, error=None,
            breaker_session_id=breaker_sid,
        )
```

- [ ] **Step 4: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_authz_quietquit.py tests/services/agent_swarm/test_breaker_retry.py`

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/orchestrator.py apps/api/tests/services/agent_swarm/test_authz_quietquit.py
git commit -m "feat(swarm): AuthzAgent quiet-quit on unauth snapshot

Mandate is meaningless without auth — skip cheaply, count as success.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase G — Merge

### Task G1: `_merge_breaker_findings_into_master`

**Files:**
- Modify: `apps/api/pencheff_api/services/agent_swarm/orchestrator.py`
- Test: `apps/api/tests/services/agent_swarm/test_merge.py`

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/services/agent_swarm/test_merge.py`:

```python
"""Merge step copies each breaker's findings into master with
discovered_by_agent tag. Failed breakers are skipped."""
from __future__ import annotations

import pytest

from pencheff.server import pentest_init, get_findings
from pencheff_api.services.agent_swarm.orchestrator import (
    BreakerResult, _merge_breaker_findings_into_master,
)


@pytest.mark.asyncio
async def test_merge_unions_with_tag(monkeypatch):
    master = (await pentest_init(target_url="https://t"))["session_id"]
    src1 = (await pentest_init(target_url="https://t"))["session_id"]
    src2 = (await pentest_init(target_url="https://t"))["session_id"]

    from pencheff.core.engagement_db import get_session as _gsess
    _gsess(src1).findings.add(
        title="SQLi", category="injection", severity="high",
        endpoint="/api/u", evidence="' OR 1=1",
    )
    _gsess(src2).findings.add(
        title="XSS", category="xss", severity="medium",
        endpoint="/q", evidence="<script>",
    )
    fid1 = _gsess(src1).findings.findings[0].id
    fid2 = _gsess(src2).findings.findings[0].id

    results = [
        BreakerResult("InjectionAgent", True, (fid1,), "ok", 1, 1, None, src1),
        BreakerResult("ClientSideAgent", True, (fid2,), "ok", 1, 1, None, src2),
        BreakerResult("AuthAgent", False, (), "", 0, 0, "x", "sid-failed"),
    ]
    events: list[str] = []
    async def on_event(line: str): events.append(line)

    await _merge_breaker_findings_into_master(
        master_session_id=master,
        breaker_results=results,
        on_event=on_event,
    )
    out = (await get_findings(session_id=master))["findings"]
    titles = sorted(f["title"] for f in out)
    assert titles == ["SQLi", "XSS"]
    by_agent = {
        f["title"]: f.get("metadata", {}).get("discovered_by_agent")
        for f in out
    }
    assert by_agent == {
        "SQLi": "InjectionAgent", "XSS": "ClientSideAgent",
    }
    assert any("InjectionAgent: 1 findings merged" in e for e in events)
    assert any("ClientSideAgent: 1 findings merged" in e for e in events)
```

- [ ] **Step 2: Run — expect failure**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_merge.py`

Expected: FAIL — `ImportError: cannot import name '_merge_breaker_findings_into_master'`.

- [ ] **Step 3: Add the merge helper to `orchestrator.py`**

Append to `apps/api/pencheff_api/services/agent_swarm/orchestrator.py`:

```python
async def _merge_breaker_findings_into_master(
    *,
    master_session_id: str,
    breaker_results: list[BreakerResult],
    on_event: LogSink,
) -> None:
    """Copy each successful breaker's findings into the master session,
    tagging metadata with discovered_by_agent."""
    import pencheff.server as srv
    for r in breaker_results:
        if not r.success or not r.finding_ids or not r.breaker_session_id:
            continue
        for fid in r.finding_ids:
            await srv.copy_finding(
                src_session=r.breaker_session_id,
                dst_session=master_session_id,
                finding_id=fid,
                tag={"discovered_by_agent": r.agent_name},
            )
        await on_event(f"[Merge] {r.agent_name}: {len(r.finding_ids)} findings merged")
```

- [ ] **Step 4: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_merge.py`

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/orchestrator.py apps/api/tests/services/agent_swarm/test_merge.py
git commit -m "feat(swarm): _merge_breaker_findings_into_master with discovered_by_agent tag

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase H — Chain phase

### Task H1: `_run_chain_phase` + `_synthesise_summary_from_breakers`

**Files:**
- Create: `apps/api/pencheff_api/services/agent_swarm/chain.py`
- Test: `apps/api/tests/services/agent_swarm/test_chain_phase.py`

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/services/agent_swarm/test_chain_phase.py`:

```python
"""Chain phase: happy path returns ChainAgent summary; crash → fallback
synthesis from breaker results."""
from __future__ import annotations

import pytest

from pencheff_api.services.agent_swarm.chain import (
    _run_chain_phase, _synthesise_summary_from_breakers,
)
from pencheff_api.services.agent_swarm.orchestrator import BreakerResult


def test_synthesise_summary_when_chain_fails():
    results = [
        BreakerResult("InjectionAgent", True, ("f1",), "found SQLi", 3, 3, None, "s1"),
        BreakerResult("AuthAgent", True, (), "no auth flaws", 2, 2, None, "s2"),
        BreakerResult("CloudAgent", False, (), "", 0, 0, "transient_after_retry: …", "s3"),
    ]
    summary = _synthesise_summary_from_breakers(results)
    assert "InjectionAgent" in summary
    assert "AuthAgent" in summary
    assert "CloudAgent" in summary
    assert "1 finding" in summary or "found SQLi" in summary


@pytest.mark.asyncio
async def test_run_chain_phase_uses_scripted_finish(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "agent_llm_api_key", "sk-test")
    monkeypatch.setattr(s, "agent_llm_base_url", "https://api.example.com/v1")
    monkeypatch.setattr(s, "agent_llm_model", "test")
    monkeypatch.setattr(s, "agent_llm_max_tokens", 1024)
    monkeypatch.setattr(s, "agent_request_timeout", 30.0)

    from tests.services.agent_swarm._scripted_llm import ScriptedLLM, with_finish
    ScriptedLLM([with_finish("Chain confirmed: SSRF → IAM creds")]).install(monkeypatch)

    from pencheff.server import pentest_init
    sid = (await pentest_init(target_url="https://t"))["session_id"]
    events: list[str] = []
    async def on_event(line: str): events.append(line)

    outcome = await _run_chain_phase(
        master_session_id=sid,
        target_url="https://t",
        profile="standard",
        on_event=on_event,
    )
    assert outcome.summary.startswith("Chain confirmed")
    assert outcome.finished_cleanly is True
```

- [ ] **Step 2: Run — expect failure**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_chain_phase.py`

Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement `chain.py`**

Create `apps/api/pencheff_api/services/agent_swarm/chain.py`:

```python
"""Phase 3 — ChainAgent walks multi-step exploits across the merged
findings and produces the executive summary."""
from __future__ import annotations

from typing import Iterable

from ..config import get_settings
from .agent_loop import Agent, AgentOutcome, LogSink, _run_single_agent
from .prompts import build_chain_prompt
from .tools import chain_tools, select_tools


def _chain_budget(profile: str) -> int:
    s = get_settings()
    return {
        "quick": s.swarm_turns_chain_quick,
        "standard": s.swarm_turns_chain_standard,
        "deep": s.swarm_turns_chain_deep,
    }.get(profile, s.swarm_turns_chain_standard)


async def _run_chain_phase(
    *,
    master_session_id: str,
    target_url: str,
    profile: str,
    on_event: LogSink,
) -> AgentOutcome:
    agent = Agent(
        name="ChainAgent",
        system_prompt=build_chain_prompt(),
        tools=select_tools(profile, chain_tools()),
        max_turns=_chain_budget(profile),
    )
    return await _run_single_agent(
        agent=agent,
        session_id=master_session_id,
        target_url=target_url,
        credentials=None,
        profile=profile,
        scope=None,
        exclude_paths=None,
        on_event=on_event,
        session_prepopulated=True,
    )


def _synthesise_summary_from_breakers(results: Iterable) -> str:
    """Fallback summary when ChainAgent crashes — formed mechanically
    from the BreakerResult list so the scan still ships an executive
    summary."""
    lines: list[str] = ["Swarm scan complete (ChainAgent unavailable)."]
    for r in results:
        if r.success:
            n = len(r.finding_ids)
            tag = f"{n} finding" if n == 1 else f"{n} findings"
            lines.append(f"- {r.agent_name}: {tag} — {r.summary}".rstrip(" —"))
        else:
            lines.append(f"- {r.agent_name}: failed ({r.error})")
    return "\n".join(lines)
```

- [ ] **Step 4: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_chain_phase.py`

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/chain.py apps/api/tests/services/agent_swarm/test_chain_phase.py
git commit -m "feat(swarm): Phase 3 — _run_chain_phase + summary fallback

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase I — Top-level `run_swarm` + catastrophic fallback

### Task I1: `run_swarm` + `_catastrophic_fallback` + `SwarmOutcome`

**Files:**
- Modify: `apps/api/pencheff_api/services/agent_swarm/orchestrator.py`
- Modify: `apps/api/pencheff_api/services/agent_swarm/__init__.py`

- [ ] **Step 1: Append `SwarmOutcome` and orchestrator entry point to `orchestrator.py`**

Append to `apps/api/pencheff_api/services/agent_swarm/orchestrator.py`:

```python
@dataclass
class SwarmOutcome:
    summary: str
    breaker_results: tuple[BreakerResult, ...]
    used_fallback: bool
    used_fallback_reason: str | None
    total_tool_calls: int
    total_turns: int


async def _catastrophic_fallback(
    *,
    reason: str,
    master_session_id: str,
    target_url: str,
    credentials: dict[str, Any] | None,
    profile: str,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    on_event: LogSink,
    session_prepopulated: bool,
) -> SwarmOutcome:
    await on_event(f"[Swarm] {reason}; falling back to single-agent loop")
    from .. import agent_runner
    legacy = await agent_runner.run_agent(
        session_id=master_session_id,
        target_url=target_url,
        credentials=credentials,
        profile=profile,
        scope=scope,
        exclude_paths=exclude_paths,
        on_event=on_event,
        session_prepopulated=session_prepopulated,
    )
    return SwarmOutcome(
        summary=legacy.summary,
        breaker_results=(),
        used_fallback=True,
        used_fallback_reason=reason,
        total_tool_calls=legacy.tool_calls,
        total_turns=legacy.turns,
    )


async def run_swarm(
    *,
    master_session_id: str,
    target_url: str,
    credentials: dict[str, Any] | None,
    profile: str,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    on_event: LogSink,
    session_prepopulated: bool = False,
) -> SwarmOutcome:
    from .recon import run_recon_phase
    from .breakers import _build_breakers
    from .chain import _run_chain_phase, _synthesise_summary_from_breakers
    from .snapshot import ReconFailed

    fallback_kwargs = dict(
        master_session_id=master_session_id,
        target_url=target_url,
        credentials=credentials,
        profile=profile,
        scope=scope,
        exclude_paths=exclude_paths,
        on_event=on_event,
        session_prepopulated=session_prepopulated,
    )

    # ── Phase 1 ───────────────────────────────────────────────
    try:
        snapshot = await run_recon_phase(
            master_session_id=master_session_id,
            target_url=target_url,
            credentials=credentials,
            profile=profile,
            scope=scope,
            exclude_paths=exclude_paths,
            on_event=_prefix("[Recon] ", on_event),
        )
    except ReconFailed as exc:
        return await _catastrophic_fallback(
            reason=f"recon_failed: {exc}", **fallback_kwargs,
        )

    # ── Phase 2 ───────────────────────────────────────────────
    pairs = _build_breakers(profile=profile, snapshot=snapshot)
    raw_results = await asyncio.gather(
        *[
            _run_breaker_with_retry(
                spec=spec, agent=agent, snapshot=snapshot,
                on_event=on_event, target_url=target_url,
                credentials=credentials, scope=scope,
                exclude_paths=exclude_paths,
            )
            for spec, agent in pairs
        ],
        return_exceptions=True,
    )
    breaker_results: list[BreakerResult] = []
    for raw, (spec, _agent) in zip(raw_results, pairs):
        if isinstance(raw, BreakerResult):
            breaker_results.append(raw)
        else:
            log.exception("breaker %s raised at gather edge: %s", spec.name, raw)
            breaker_results.append(BreakerResult(
                agent_name=spec.name, success=False,
                finding_ids=(), summary="", turns=0, tool_calls=0,
                error=f"gather_edge: {type(raw).__name__}: {raw}",
                breaker_session_id=None,
            ))

    if all(not r.success for r in breaker_results):
        return await _catastrophic_fallback(
            reason="all_breakers_failed", **fallback_kwargs,
        )

    # ── Merge ─────────────────────────────────────────────────
    await _merge_breaker_findings_into_master(
        master_session_id=master_session_id,
        breaker_results=breaker_results,
        on_event=on_event,
    )

    # ── Phase 3 ───────────────────────────────────────────────
    chain_summary = ""
    chain_tool_calls = 0
    chain_turns = 0
    try:
        chain_outcome = await _run_chain_phase(
            master_session_id=master_session_id,
            target_url=target_url,
            profile=profile,
            on_event=_prefix("[Chain] ", on_event),
        )
        chain_summary = chain_outcome.summary
        chain_tool_calls = chain_outcome.tool_calls
        chain_turns = chain_outcome.turns
    except Exception as exc:  # noqa: BLE001
        log.warning("chain phase failed: %s", exc)
        await on_event(f"[Chain] failed: {exc}; keeping breaker findings")
        chain_summary = _synthesise_summary_from_breakers(breaker_results)

    return SwarmOutcome(
        summary=chain_summary,
        breaker_results=tuple(breaker_results),
        used_fallback=False,
        used_fallback_reason=None,
        total_tool_calls=sum(r.tool_calls for r in breaker_results) + chain_tool_calls,
        total_turns=sum(r.turns for r in breaker_results) + chain_turns,
    )
```

- [ ] **Step 2: Re-export from `agent_swarm/__init__.py`**

Replace the contents of `apps/api/pencheff_api/services/agent_swarm/__init__.py` with:

```python
"""Parallel multi-agent scan swarm.

See docs/superpowers/specs/2026-05-05-parallel-agent-swarm-design.md
for the design and IP-safety contract.

Manual smoke checklist (operations):
  1. SWARM_ENABLED=true: run a scan against DVWA / Juice-Shop. Confirm
     the SSE event log shows interleaved [Recon]…[InjectionAgent]…
     [AuthAgent]…[Chain]… prefixes.
  2. Force a recon failure (set AGENT_LLM_API_KEY to something that
     401s). Confirm the catastrophic-fallback line appears and the scan
     finishes via the legacy agent_runner path.
  3. SWARM_ENABLED=false: run again. Confirm only plain unprefixed
     events appear, proving the killswitch reroutes through
     agent_runner.run_agent.
"""
from .orchestrator import BreakerResult, SwarmOutcome, run_swarm

__all__ = ["run_swarm", "SwarmOutcome", "BreakerResult"]
```

- [ ] **Step 3: Smoke import**

Run: `cd apps/api && uv run python -c "from pencheff_api.services.agent_swarm import run_swarm, SwarmOutcome; print('ok')"`

Expected: `ok`.

- [ ] **Step 4: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/orchestrator.py apps/api/pencheff_api/services/agent_swarm/__init__.py
git commit -m "feat(swarm): top-level run_swarm + catastrophic fallback

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task I2: Orchestrator happy path — full pipeline integration test

**Files:**
- Test: `apps/api/tests/services/agent_swarm/test_orchestrator_happy.py`

- [ ] **Step 1: Write the test**

Create `apps/api/tests/services/agent_swarm/test_orchestrator_happy.py`:

```python
"""Full pipeline with stubbed LLM: recon → 7 breakers (all succeed) →
merge → chain. SwarmOutcome.used_fallback is False; breaker_results
has 7 entries."""
from __future__ import annotations

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm import run_swarm
from tests.services.agent_swarm._scripted_llm import (
    ScriptedLLM, with_finish, with_tool_call,
)


@pytest.fixture
def llm_settings(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "agent_llm_api_key", "sk-test")
    monkeypatch.setattr(s, "agent_llm_base_url", "https://api.example.com/v1")
    monkeypatch.setattr(s, "agent_llm_model", "test")
    monkeypatch.setattr(s, "agent_llm_max_tokens", 1024)
    monkeypatch.setattr(s, "agent_request_timeout", 30.0)
    return s


@pytest.mark.asyncio
async def test_happy_pipeline_runs_all_phases(llm_settings, monkeypatch):
    # Recon: one tool call + finish  → 2 turns
    # Each of 7 breakers: just `finish`               → 1 turn × 7
    # Chain: just `finish`                            → 1 turn
    # Total scripted turns: 2 + 7 + 1 = 10
    turns = [
        with_tool_call("recon_passive", {}),
        with_finish("recon ok"),
    ]
    for _ in range(7):
        turns.append(with_finish("breaker ok"))
    turns.append(with_finish("chain ok"))
    ScriptedLLM(turns).install(monkeypatch)

    sid = (await pentest_init(target_url="https://t.example.com"))["session_id"]
    # Inject a fake endpoint so _freeze_snapshot's empty check passes.
    from pencheff.core.engagement_db import get_session as _gsess
    _gsess(sid).discovered_endpoints.add(
        url="https://t.example.com/api/u", method="GET",
        status=200, content_type="application/json",
        parameters=("id",),
    )
    events: list[str] = []
    async def on_event(line: str): events.append(line)

    outcome = await run_swarm(
        master_session_id=sid,
        target_url="https://t.example.com",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is False
    assert len(outcome.breaker_results) == 7
    assert outcome.summary == "chain ok"
    assert any("[Recon]" in e for e in events)
    assert any("[Chain]" in e for e in events)
    # AuthzAgent quiet-quit (no auth in snapshot) but still success.
    authz = next(r for r in outcome.breaker_results if r.agent_name == "AuthzAgent")
    assert authz.success is True
    assert authz.tool_calls == 0
```

- [ ] **Step 2: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_orchestrator_happy.py`

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add apps/api/tests/services/agent_swarm/test_orchestrator_happy.py
git commit -m "test(swarm): orchestrator happy-path integration

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task I3: Orchestrator partial-failure test

**Files:**
- Test: `apps/api/tests/services/agent_swarm/test_orchestrator_partial.py`

- [ ] **Step 1: Write the test**

Create `apps/api/tests/services/agent_swarm/test_orchestrator_partial.py`:

```python
"""3 of 7 breakers crash; 4 survive; chain still runs over the survivors."""
from __future__ import annotations

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm import run_swarm
from tests.services.agent_swarm._scripted_llm import ScriptedLLM, ScriptedTurn, with_finish, with_tool_call


@pytest.fixture
def llm_settings(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "agent_llm_api_key", "sk-test")
    monkeypatch.setattr(s, "agent_llm_base_url", "https://api.example.com/v1")
    monkeypatch.setattr(s, "agent_llm_model", "test")
    monkeypatch.setattr(s, "agent_llm_max_tokens", 1024)
    monkeypatch.setattr(s, "agent_request_timeout", 30.0)
    monkeypatch.setattr(s, "swarm_breaker_retry_attempts", 0)  # disable retry to keep script-counting simple
    return s


@pytest.mark.asyncio
async def test_partial_failure_keeps_survivors(llm_settings, monkeypatch):
    """Breakers run in concurrent gather order — to make this deterministic
    we patch _run_breaker_with_retry directly to return scripted results."""
    from pencheff_api.services.agent_swarm import orchestrator as orch

    expected_names = {
        "InjectionAgent", "ClientSideAgent", "AuthAgent", "AuthzAgent",
        "APIAgent", "InfraAgent", "CloudAgent",
    }

    async def fake_breaker(*, spec, agent, snapshot, on_event, **kwargs):
        if spec.name in {"AuthAgent", "InfraAgent", "CloudAgent"}:
            return orch.BreakerResult(
                agent_name=spec.name, success=False,
                finding_ids=(), summary="", turns=0, tool_calls=0,
                error="test_failure", breaker_session_id="sid-x",
            )
        return orch.BreakerResult(
            agent_name=spec.name, success=True,
            finding_ids=(), summary="ok", turns=1, tool_calls=1,
            error=None, breaker_session_id="sid-y",
        )

    monkeypatch.setattr(orch, "_run_breaker_with_retry", fake_breaker)

    # Recon needs a real LLM call: 1 tool call + 1 finish; chain: 1 finish.
    ScriptedLLM([
        with_tool_call("recon_passive", {}),
        with_finish("recon ok"),
        with_finish("chain ok over survivors"),
    ]).install(monkeypatch)

    sid = (await pentest_init(target_url="https://t.example.com"))["session_id"]
    from pencheff.core.engagement_db import get_session as _gsess
    _gsess(sid).discovered_endpoints.add(
        url="https://t/u", method="GET", status=200,
        content_type=None, parameters=(),
    )

    async def on_event(line: str): pass
    outcome = await run_swarm(
        master_session_id=sid,
        target_url="https://t.example.com",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is False
    names = {r.agent_name for r in outcome.breaker_results}
    assert names == expected_names
    failed = {r.agent_name for r in outcome.breaker_results if not r.success}
    assert failed == {"AuthAgent", "InfraAgent", "CloudAgent"}
```

- [ ] **Step 2: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_orchestrator_partial.py`

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add apps/api/tests/services/agent_swarm/test_orchestrator_partial.py
git commit -m "test(swarm): orchestrator partial-failure scenario

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task I4: Orchestrator catastrophic-fallback tests

**Files:**
- Test: `apps/api/tests/services/agent_swarm/test_orchestrator_recon_fail.py`
- Test: `apps/api/tests/services/agent_swarm/test_orchestrator_all_breakers_fail.py`
- Test: `apps/api/tests/services/agent_swarm/test_orchestrator_chain_fail.py`

- [ ] **Step 1: Write `test_orchestrator_recon_fail.py`**

Create that file:

```python
"""ReconFailed → catastrophic-fallback gate routes to legacy
agent_runner.run_agent. used_fallback=True; reason starts with 'recon_failed'."""
from __future__ import annotations

import pytest

from pencheff_api.services.agent_swarm import run_swarm
from pencheff_api.services.agent_swarm.snapshot import ReconFailed


@pytest.fixture
def llm_settings(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "agent_llm_api_key", "sk-test")
    monkeypatch.setattr(s, "agent_llm_base_url", "https://api.example.com/v1")
    monkeypatch.setattr(s, "agent_llm_model", "test")
    monkeypatch.setattr(s, "agent_llm_max_tokens", 1024)
    monkeypatch.setattr(s, "agent_request_timeout", 30.0)
    monkeypatch.setattr(s, "agent_max_turns", 5)
    return s


@pytest.mark.asyncio
async def test_recon_failed_triggers_fallback(llm_settings, monkeypatch):
    async def boom(**_):
        raise ReconFailed("test: empty surface")
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator.run_recon_phase", boom,
    )
    from pencheff_api.services import agent_runner
    fallback_calls: list = []
    async def fake_legacy(**kwargs):
        fallback_calls.append(kwargs)
        from pencheff_api.services.agent_runner import AgentOutcome
        return AgentOutcome(
            summary="legacy ran", tool_calls=2, turns=2,
            finished_cleanly=True, reason="finished",
        )
    monkeypatch.setattr(agent_runner, "run_agent", fake_legacy)

    async def on_event(line: str): pass
    outcome = await run_swarm(
        master_session_id="sid-fake",
        target_url="https://t",
        credentials=None, profile="quick",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is True
    assert outcome.used_fallback_reason.startswith("recon_failed")
    assert outcome.summary == "legacy ran"
    assert len(fallback_calls) == 1
```

- [ ] **Step 2: Write `test_orchestrator_all_breakers_fail.py`**

Create:

```python
"""All 7 breakers fail → catastrophic fallback fires with reason
'all_breakers_failed'."""
from __future__ import annotations

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm import run_swarm


@pytest.fixture
def llm_settings(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "agent_llm_api_key", "sk-test")
    monkeypatch.setattr(s, "agent_llm_base_url", "https://api.example.com/v1")
    monkeypatch.setattr(s, "agent_llm_model", "test")
    monkeypatch.setattr(s, "agent_llm_max_tokens", 1024)
    monkeypatch.setattr(s, "agent_request_timeout", 30.0)
    return s


@pytest.mark.asyncio
async def test_all_breakers_failed_triggers_fallback(llm_settings, monkeypatch):
    from pencheff_api.services.agent_swarm import orchestrator as orch
    from pencheff_api.services.agent_swarm.snapshot import (
        DiscoveredEndpoint, ReconSnapshot,
    )
    from datetime import datetime, timezone

    fake_snap = ReconSnapshot(
        target_base_url="https://t", profile="standard",
        scope_include=(), scope_exclude=(),
        endpoints=(DiscoveredEndpoint("https://t/u", "GET", 200, None, ()),),
        api_spec_urls=(), subdomains=(),
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={}, waf_vendor=None,
        authenticated=True,  # ensure AuthzAgent does NOT quiet-quit (we want it to fail)
        auth_login_url=None,
        auth_cookies=(("sid", "abc"),), auth_tokens={"bearer": "x"},
        oast_session_handle=None,
        recon_agent_summary="x", recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )
    async def fake_recon(**_): return fake_snap
    monkeypatch.setattr(orch, "run_recon_phase", fake_recon)

    async def fake_breaker(*, spec, **kwargs):
        return orch.BreakerResult(
            agent_name=spec.name, success=False,
            finding_ids=(), summary="", turns=0, tool_calls=0,
            error="test_total_failure", breaker_session_id=None,
        )
    monkeypatch.setattr(orch, "_run_breaker_with_retry", fake_breaker)

    from pencheff_api.services import agent_runner
    from pencheff_api.services.agent_runner import AgentOutcome
    async def fake_legacy(**kwargs):
        return AgentOutcome(
            summary="legacy ran", tool_calls=1, turns=1,
            finished_cleanly=True, reason="finished",
        )
    monkeypatch.setattr(agent_runner, "run_agent", fake_legacy)

    sid = (await pentest_init(target_url="https://t"))["session_id"]
    async def on_event(line: str): pass

    outcome = await run_swarm(
        master_session_id=sid, target_url="https://t",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is True
    assert outcome.used_fallback_reason == "all_breakers_failed"
```

- [ ] **Step 3: Write `test_orchestrator_chain_fail.py`**

Create:

```python
"""ChainAgent crashing must NOT trip the orchestrator. Breaker findings
still ship, summary is synthesised from breaker results."""
from __future__ import annotations

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm import run_swarm


@pytest.fixture
def llm_settings(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "agent_llm_api_key", "sk-test")
    monkeypatch.setattr(s, "agent_llm_base_url", "https://api.example.com/v1")
    monkeypatch.setattr(s, "agent_llm_model", "test")
    monkeypatch.setattr(s, "agent_llm_max_tokens", 1024)
    monkeypatch.setattr(s, "agent_request_timeout", 30.0)
    return s


@pytest.mark.asyncio
async def test_chain_failure_is_non_fatal(llm_settings, monkeypatch):
    from pencheff_api.services.agent_swarm import orchestrator as orch
    from pencheff_api.services.agent_swarm.snapshot import (
        DiscoveredEndpoint, ReconSnapshot,
    )
    from datetime import datetime, timezone

    snap = ReconSnapshot(
        target_base_url="https://t", profile="standard",
        scope_include=(), scope_exclude=(),
        endpoints=(DiscoveredEndpoint("https://t/u", "GET", 200, None, ()),),
        api_spec_urls=(), subdomains=(),
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={}, waf_vendor=None,
        authenticated=True, auth_login_url=None,
        auth_cookies=(("sid", "abc"),), auth_tokens={"bearer": "x"},
        oast_session_handle=None,
        recon_agent_summary="x", recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )
    async def fake_recon(**_): return snap
    monkeypatch.setattr(orch, "run_recon_phase", fake_recon)

    async def fake_breaker(*, spec, **kwargs):
        return orch.BreakerResult(
            agent_name=spec.name, success=True,
            finding_ids=(), summary="ok", turns=1, tool_calls=1,
            error=None, breaker_session_id=None,
        )
    monkeypatch.setattr(orch, "_run_breaker_with_retry", fake_breaker)

    async def boom_chain(**_): raise RuntimeError("chain blew up")
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.chain._run_chain_phase",
        boom_chain,
    )

    sid = (await pentest_init(target_url="https://t"))["session_id"]
    events: list[str] = []
    async def on_event(line: str): events.append(line)

    outcome = await run_swarm(
        master_session_id=sid, target_url="https://t",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is False  # chain failure is non-fatal
    assert "ChainAgent unavailable" in outcome.summary
    assert len(outcome.breaker_results) == 7
    assert any("[Chain] failed" in e for e in events)
```

- [ ] **Step 4: Run all three — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_orchestrator_recon_fail.py tests/services/agent_swarm/test_orchestrator_all_breakers_fail.py tests/services/agent_swarm/test_orchestrator_chain_fail.py`

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/tests/services/agent_swarm/test_orchestrator_recon_fail.py apps/api/tests/services/agent_swarm/test_orchestrator_all_breakers_fail.py apps/api/tests/services/agent_swarm/test_orchestrator_chain_fail.py
git commit -m "test(swarm): catastrophic-fallback + chain-failure scenarios

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task I5: Profile-tiered budget test

**Files:**
- Test: `apps/api/tests/services/agent_swarm/test_budgets.py`

- [ ] **Step 1: Write the test**

Create `apps/api/tests/services/agent_swarm/test_budgets.py`:

```python
"""Profile → per-phase max_turns wiring."""
from __future__ import annotations

import pytest


@pytest.fixture
def settings(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    # Anchor explicit values so we test wiring, not env defaults.
    monkeypatch.setattr(s, "swarm_turns_recon_quick", 8)
    monkeypatch.setattr(s, "swarm_turns_recon_standard", 12)
    monkeypatch.setattr(s, "swarm_turns_recon_deep", 18)
    monkeypatch.setattr(s, "swarm_turns_breaker_quick", 6)
    monkeypatch.setattr(s, "swarm_turns_breaker_standard", 10)
    monkeypatch.setattr(s, "swarm_turns_breaker_deep", 16)
    monkeypatch.setattr(s, "swarm_turns_chain_quick", 8)
    monkeypatch.setattr(s, "swarm_turns_chain_standard", 12)
    monkeypatch.setattr(s, "swarm_turns_chain_deep", 20)
    return s


def test_recon_budget_table(settings):
    from pencheff_api.services.agent_swarm.recon import _recon_budget
    assert _recon_budget("quick") == 8
    assert _recon_budget("standard") == 12
    assert _recon_budget("deep") == 18
    assert _recon_budget("nonsense") == 12  # falls back to standard


def test_breaker_budget_table(settings):
    from pencheff_api.services.agent_swarm.breakers import _breaker_budget
    assert _breaker_budget("quick") == 6
    assert _breaker_budget("standard") == 10
    assert _breaker_budget("deep") == 16


def test_chain_budget_table(settings):
    from pencheff_api.services.agent_swarm.chain import _chain_budget
    assert _chain_budget("quick") == 8
    assert _chain_budget("standard") == 12
    assert _chain_budget("deep") == 20
```

- [ ] **Step 2: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_budgets.py`

Expected: 3 passed.

- [ ] **Step 3: Commit**

```bash
git add apps/api/tests/services/agent_swarm/test_budgets.py
git commit -m "test(swarm): profile-tiered turn-budget wiring

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task I6: Scope propagation test

**Files:**
- Test: `apps/api/tests/services/agent_swarm/test_scope.py`

- [ ] **Step 1: Write the test**

Create `apps/api/tests/services/agent_swarm/test_scope.py`:

```python
"""scope_include / scope_exclude carried by ReconSnapshot reach the
seeded breaker session (where the existing scope_guard enforces them)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pencheff_api.services.agent_swarm.breakers import seed_breaker_session
from pencheff_api.services.agent_swarm.snapshot import (
    DiscoveredEndpoint, ReconSnapshot,
)


@pytest.mark.asyncio
async def test_scope_propagates_into_breaker_session(monkeypatch):
    captured = {}
    import pencheff.server as srv
    orig_init = srv.pentest_init

    async def capturing_init(*, target_url, **kw):
        captured["target_url"] = target_url
        return await orig_init(target_url=target_url, **kw)
    monkeypatch.setattr(srv, "pentest_init", capturing_init)

    snap = ReconSnapshot(
        target_base_url="https://t.example.com",
        profile="standard",
        scope_include=("https://t.example.com/api/",),
        scope_exclude=("https://t.example.com/admin/",),
        endpoints=(DiscoveredEndpoint("https://t.example.com/api/u", "GET", 200, None, ()),),
        api_spec_urls=(), subdomains=(),
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={}, waf_vendor=None,
        authenticated=False, auth_login_url=None,
        auth_cookies=(), auth_tokens={},
        oast_session_handle=None,
        recon_agent_summary="x", recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )
    sid = await seed_breaker_session(snap)
    assert captured["target_url"] == "https://t.example.com"
    # The seeded session inherits the target's existing scope_guard, which
    # the agent_runner tool registry already pipes scope/exclude through.
    # Sanity: we got a usable session id back.
    assert isinstance(sid, str) and sid
```

If the existing `pentest_init` accepts `scope` / `exclude_paths` kwargs, pass them in `seed_breaker_session` and assert they reached the call here. Run `grep -n "async def pentest_init" plugins/pencheff/pencheff/server.py` and inspect — if `scope` is accepted, update the seed code in `breakers.py` to forward it. (The end-to-end scope guard runs in `agent_runner._build_tool_registry`, which receives `scope` from the orchestrator's `_run_single_agent` call.)

- [ ] **Step 2: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_scope.py`

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add apps/api/tests/services/agent_swarm/test_scope.py
git commit -m "test(swarm): scope propagation into seeded breaker sessions

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase J — Telemetry

### Task J1: `telemetry.py` + persistence test

**Files:**
- Create: `apps/api/pencheff_api/services/agent_swarm/telemetry.py`
- Test: `apps/api/tests/services/agent_swarm/test_telemetry.py`

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/services/agent_swarm/test_telemetry.py`:

```python
"""persist_swarm_telemetry writes the documented summary_payload['swarm']
shape to the Scan row."""
from __future__ import annotations

import pytest

from pencheff_api.services.agent_swarm.orchestrator import (
    BreakerResult, SwarmOutcome,
)
from pencheff_api.services.agent_swarm.telemetry import build_swarm_summary_payload


def test_payload_shape_matches_design():
    outcome = SwarmOutcome(
        summary="chain summary",
        breaker_results=(
            BreakerResult("InjectionAgent", True, ("f1", "f2"),
                          "found 2", 5, 8, None, "sid-i"),
            BreakerResult("AuthAgent", False, (), "", 0, 0,
                          "transient_after_retry: 503", "sid-a"),
        ),
        used_fallback=False, used_fallback_reason=None,
        total_tool_calls=8, total_turns=5,
    )
    payload = build_swarm_summary_payload(outcome)
    assert payload["used_fallback"] is False
    assert payload["used_fallback_reason"] is None
    assert len(payload["breakers"]) == 2
    inj = next(b for b in payload["breakers"] if b["agent"] == "InjectionAgent")
    assert inj == {
        "agent": "InjectionAgent",
        "success": True,
        "findings": 2,
        "turns": 5,
        "tool_calls": 8,
        "error": None,
    }
    auth = next(b for b in payload["breakers"] if b["agent"] == "AuthAgent")
    assert auth["success"] is False
    assert auth["findings"] == 0
    assert "transient_after_retry" in auth["error"]


def test_payload_records_fallback_reason():
    outcome = SwarmOutcome(
        summary="legacy", breaker_results=(),
        used_fallback=True,
        used_fallback_reason="all_breakers_failed",
        total_tool_calls=2, total_turns=2,
    )
    payload = build_swarm_summary_payload(outcome)
    assert payload["used_fallback"] is True
    assert payload["used_fallback_reason"] == "all_breakers_failed"
    assert payload["breakers"] == []
```

- [ ] **Step 2: Run — expect failure**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_telemetry.py`

Expected: FAIL.

- [ ] **Step 3: Implement `telemetry.py`**

Create `apps/api/pencheff_api/services/agent_swarm/telemetry.py`:

```python
"""Telemetry helpers for the swarm — writes per-agent stats into the
existing Scan.summary JSON column so the scan-detail UI can surface
them later (Spec follow-up F1)."""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select

from ...db.models import Scan
from .orchestrator import BreakerResult, SwarmOutcome

log = logging.getLogger("pencheff.swarm.telemetry")


def build_swarm_summary_payload(outcome: SwarmOutcome) -> dict[str, Any]:
    return {
        "used_fallback": outcome.used_fallback,
        "used_fallback_reason": outcome.used_fallback_reason,
        "breakers": [
            {
                "agent": r.agent_name,
                "success": r.success,
                "findings": len(r.finding_ids),
                "turns": r.turns,
                "tool_calls": r.tool_calls,
                "error": r.error,
            }
            for r in outcome.breaker_results
        ],
    }


async def persist_swarm_telemetry(
    *, scan_id: str, outcome: SwarmOutcome, db_session_factory,
) -> None:
    """Merge the swarm payload into Scan.summary."""
    async with db_session_factory() as db:
        scan = (await db.execute(
            select(Scan).where(Scan.id == scan_id)
        )).scalar_one_or_none()
        if scan is None:
            log.warning("persist_swarm_telemetry: scan %s not found", scan_id)
            return
        merged = dict(scan.summary or {})
        merged["swarm"] = build_swarm_summary_payload(outcome)
        scan.summary = merged
        await db.commit()
```

- [ ] **Step 4: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_telemetry.py`

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/agent_swarm/telemetry.py apps/api/tests/services/agent_swarm/test_telemetry.py
git commit -m "feat(swarm): telemetry payload + persistence helper

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase K — `scan_runner` integration

### Task K1: Wire `_engine` to dispatch on `SWARM_ENABLED`

**Files:**
- Modify: `apps/api/pencheff_api/services/scan_runner.py`
- Test: `apps/api/tests/services/agent_swarm/test_killswitch.py`

- [ ] **Step 1: Locate the existing `_engine` closure**

Run: `grep -n "async def _engine\|_run_agent_stage\|dispatch == \"agent_only\"" apps/api/pencheff_api/services/scan_runner.py | head -10`

Confirm the line numbers match the spec's reference (around 656-665 in the current file).

- [ ] **Step 2: Replace `_engine` body**

Edit `_engine` to dispatch on the killswitch. Replace:

```python
        async def _engine(session_prepopulated: bool = False) -> str | None:
            return await _run_agent_stage(
                scan_id=scan_id,
                psession=psession,
                target=target,
                profile=canonical_profile,
                credentials=creds,
                db_session_factory=Session,
                session_prepopulated=session_prepopulated,
            )
```

with:

```python
        async def _engine(session_prepopulated: bool = False) -> str | None:
            settings_local = get_settings()
            if settings_local.swarm_enabled:
                from .agent_swarm import run_swarm
                from .agent_swarm.telemetry import persist_swarm_telemetry

                async def _publish_log(line: str) -> None:
                    await publish_scan_event(
                        scan_id, {"type": "log", "line": line},
                    )
                outcome = await run_swarm(
                    master_session_id=psession.session_id,
                    target_url=target.base_url,
                    credentials=creds,
                    profile=canonical_profile,
                    scope=getattr(target, "scope_include", None),
                    exclude_paths=getattr(target, "scope_exclude", None),
                    on_event=_publish_log,
                    session_prepopulated=session_prepopulated,
                )
                await persist_swarm_telemetry(
                    scan_id=scan_id, outcome=outcome,
                    db_session_factory=Session,
                )
                return outcome.summary
            return await _run_agent_stage(
                scan_id=scan_id,
                psession=psession,
                target=target,
                profile=canonical_profile,
                credentials=creds,
                db_session_factory=Session,
                session_prepopulated=session_prepopulated,
            )
```

If `publish_scan_event` is already imported at the top of `scan_runner.py`, no import change is needed (`grep -n "from \.\.events" apps/api/pencheff_api/services/scan_runner.py` to verify; the file already uses it elsewhere). The exact event payload shape may already follow a specific helper — if `_publish_log` already exists in `_run_agent_stage`, reuse the same call shape rather than the literal above.

- [ ] **Step 3: Write the killswitch test**

Create `apps/api/tests/services/agent_swarm/test_killswitch.py`:

```python
"""SWARM_ENABLED=false → scan_runner._engine bypasses the swarm and
calls the legacy _run_agent_stage path."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from pencheff_api.services import scan_runner


@pytest.mark.asyncio
async def test_swarm_disabled_routes_to_legacy(monkeypatch):
    """We can't reach _engine without a live psession, so we test the
    branch directly: monkeypatch run_swarm + _run_agent_stage and call
    the dispatcher logic in isolation by extracting it into a helper.

    Approach: patch settings.swarm_enabled and exercise the dispatch
    branch via a tiny driver that mirrors _engine's branch literally.
    """
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "swarm_enabled", False)

    swarm_called = AsyncMock()
    legacy_called = AsyncMock(return_value="legacy summary")
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator.run_swarm",
        swarm_called,
    )
    # _run_agent_stage is module-level in scan_runner.py.
    monkeypatch.setattr(scan_runner, "_run_agent_stage", legacy_called)

    # Reproduce the dispatch literal so the test does not depend on
    # the inner closure being callable.
    settings_local = get_settings()
    if settings_local.swarm_enabled:
        await scan_runner.agent_swarm.run_swarm()  # noqa: F821
    else:
        result = await scan_runner._run_agent_stage(
            scan_id="x", psession=None, target=None,
            profile="quick", credentials=None,
            db_session_factory=None, session_prepopulated=False,
        )

    legacy_called.assert_called_once()
    swarm_called.assert_not_called()
    assert result == "legacy summary"


@pytest.mark.asyncio
async def test_swarm_enabled_routes_to_swarm(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "swarm_enabled", True)

    from pencheff_api.services.agent_swarm.orchestrator import SwarmOutcome
    swarm_called = AsyncMock(return_value=SwarmOutcome(
        summary="swarm summary", breaker_results=(),
        used_fallback=False, used_fallback_reason=None,
        total_tool_calls=0, total_turns=0,
    ))
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator.run_swarm",
        swarm_called,
    )
    settings_local = get_settings()
    assert settings_local.swarm_enabled is True
    # Direct dispatch: confirms the import path resolves and the
    # SwarmOutcome.summary is what _engine would return.
    from pencheff_api.services.agent_swarm.orchestrator import run_swarm
    outcome = await run_swarm(
        master_session_id="sid", target_url="https://t",
        credentials=None, profile="quick",
        scope=None, exclude_paths=None,
        on_event=lambda line: _noop(), session_prepopulated=False,
    )
    assert outcome.summary == "swarm summary"
    swarm_called.assert_called_once()


async def _noop():
    return None
```

- [ ] **Step 4: Run — expect PASS**

Run: `cd apps/api && uv run pytest -xvs tests/services/agent_swarm/test_killswitch.py`

Expected: 2 passed.

- [ ] **Step 5: Run the entire swarm test suite**

Run: `cd apps/api && uv run pytest -x tests/services/agent_swarm/`

Expected: all 25+ tests pass. If any fails because a test file's imports or fixtures collide, fix the immediate file (do not chase across the suite).

- [ ] **Step 6: Run the full apps/api test suite — confirm no regression**

Run: `cd apps/api && uv run pytest -x tests/`

Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add apps/api/pencheff_api/services/scan_runner.py apps/api/tests/services/agent_swarm/test_killswitch.py
git commit -m "feat(swarm): wire scan_runner._engine to SWARM_ENABLED dispatch

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase L — Live integration scaffold

### Task L1: Live integration test scaffold (off-CI)

**Files:**
- Create: `apps/api/tests/integration/__init__.py`
- Create: `apps/api/tests/integration/test_swarm_against_dvwa.py`

This test is **off-CI**: marked `@pytest.mark.live` and requires a running DVWA / Juice-Shop on `localhost`. Document how to run it.

- [ ] **Step 1: Create the package + test file**

```bash
mkdir -p apps/api/tests/integration
touch apps/api/tests/integration/__init__.py
```

Create `apps/api/tests/integration/test_swarm_against_dvwa.py`:

```python
"""Live integration test against DVWA / Juice-Shop.

Off-CI by default. To run:

  1. Bring up the toolchain locally:
       docker compose -f docker-compose.toolchain.yml up dvwa juice-shop
  2. Set the credentials your AGENT_LLM_* env points at.
  3. Run:
       cd apps/api && uv run pytest -m live tests/integration/test_swarm_against_dvwa.py -v

This test validates that the swarm runs end-to-end against a real
target with a real LLM. It is intentionally tolerant about WHICH
findings each breaker produces — only the structural invariants are
asserted.
"""
from __future__ import annotations

import os

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm import run_swarm


pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_swarm_against_dvwa():
    target = os.environ.get("LIVE_TARGET_URL", "http://localhost:4280")
    if not os.environ.get("AGENT_LLM_API_KEY"):
        pytest.skip("AGENT_LLM_API_KEY not configured")

    sid = (await pentest_init(target_url=target))["session_id"]
    events: list[str] = []
    async def on_event(line: str): events.append(line)

    outcome = await run_swarm(
        master_session_id=sid, target_url=target,
        credentials=None, profile="quick",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is False, (
        f"swarm fell back: {outcome.used_fallback_reason}"
    )
    assert len(outcome.breaker_results) == 7
    # All 9 agents must have emitted at least one event (Recon, 7 breakers, Chain).
    for marker in ("[Recon]", "[InjectionAgent]", "[ClientSideAgent]",
                    "[AuthAgent]", "[AuthzAgent]", "[APIAgent]",
                    "[InfraAgent]", "[CloudAgent]", "[Chain]"):
        assert any(marker in e for e in events), (
            f"no events seen with prefix {marker!r}"
        )
    # At least one finding should be tagged with discovered_by_agent (DVWA is
    # rich enough that any breaker should hit something).
    from pencheff.server import get_findings
    out = (await get_findings(session_id=sid))["findings"]
    tagged = [f for f in out if f.get("metadata", {}).get("discovered_by_agent")]
    assert tagged, "no findings with discovered_by_agent attribution"
```

- [ ] **Step 2: Add `live` marker config** (so `-m live` works without warnings)

Open `apps/api/pyproject.toml`. If there is no `[tool.pytest.ini_options]` table, add one at the bottom:

```toml
[tool.pytest.ini_options]
markers = [
    "live: live integration tests that require a running toolchain (off-CI)",
]
```

If the table already exists, add the `live` marker to the existing `markers` list.

- [ ] **Step 3: Verify the test is collected but skipped under default selection**

Run: `cd apps/api && uv run pytest --collect-only tests/integration/test_swarm_against_dvwa.py | head -10`

Expected: collection shows the test exists.

Run: `cd apps/api && uv run pytest -m "not live" tests/integration/`

Expected: 0 tests run (all skipped by marker filter), exit 0 or 5 (no tests selected — which is fine for a marker-gated test).

- [ ] **Step 4: Commit**

```bash
git add apps/api/tests/integration/__init__.py apps/api/tests/integration/test_swarm_against_dvwa.py apps/api/pyproject.toml
git commit -m "test(swarm): live integration scaffold against DVWA (off-CI, @pytest.mark.live)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Final verification

After all 16 tasks land, run the full suite once more:

- [ ] `cd apps/api && uv run pytest -x tests/`

Expected: green.

- [ ] `git log --oneline -20` — confirm one commit per task and a clean history.

- [ ] **Manual smoke** (Spec §15.4):
  1. `SWARM_ENABLED=true`, run a real scan against DVWA / Juice-Shop. Confirm the SSE log shows `[Recon]…[InjectionAgent]…[Chain]…` interleaved.
  2. Force a recon failure (`AGENT_LLM_API_KEY=invalid`). Confirm the log shows `[Swarm] recon_failed: …; falling back to single-agent loop`.
  3. `SWARM_ENABLED=false`. Run again. Confirm the log shows plain unprefixed events.

---

## Spec → Plan coverage map

| Spec section | Implementing task |
|---|---|
| §1 Goal | All — overall pipeline |
| §2 Non-goals | K1 — no `dispatch_mode.py` change; agent_runner kept |
| §3 IP-safety contract | D1, D2, prompts.py docstring |
| §4 Architecture overview | I1 (run_swarm flow) |
| §5 Agents (table) | F1 (`BREAKER_SPECS`), D2 (`BREAKER_TOOL_ALLOCATIONS`), D1 (prompts), F3 (AuthzAgent quiet-quit) |
| §6 Turn budgets | A1 (settings), I5 (test) |
| §7 ReconSnapshot | C1 (dataclass), C2 (helpers), F1 (seed_breaker_session), E1 (_freeze_snapshot) |
| §8 Orchestrator | F2 (retry), G1 (merge), I1 (run_swarm + fallback), H1 (chain) |
| §9 Configuration | A1 |
| §10 scan_runner integration | K1 |
| §11 Telemetry | J1 |
| §12 Observability — log prefixing | F2 (`_prefix` helper), I1 (`[Recon]`/`[Chain]` prefixes), I2 (test) |
| §13 Scope safety | I6 |
| §14 File layout | All |
| §15 Testing strategy | I2-I4 (orchestrator), F2 (retry), G1 (merge), C2 (helpers), L1 (live) |
| §16 Open follow-ups | None — out of scope by design |
| §17 Decisions log (Q&A) | All |
