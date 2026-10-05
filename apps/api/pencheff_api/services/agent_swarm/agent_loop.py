"""Reusable agent tool-calling loop.

Extracted from ``agent_runner.run_agent`` (which now delegates here) so
the swarm orchestrator can drive multiple specialised agents through
the same loop without duplicating the message-passing / retry logic.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from ...config import get_settings

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
    # When True, agent_loop refuses ``finish`` until every non-suppressed
    # finding in the agent's session has been touched by ``exploit_finding``
    # (i.e. its verification_status is no longer ``unverified``). Set for
    # active-attack breakers + ChainAgent so the report always carries a
    # captured-evidence row per finding; left False for read-only agents
    # (Recon, Compliance, ProofOfImpact, etc.).
    require_per_finding_exploit: bool = False
    # Tools the agent MUST exercise before its work is considered complete.
    # If the model finishes without calling one of these (e.g. GraphQLFuzzAgent
    # skipping run_graphql_cop/run_inql), a post-loop backstop runs the missing
    # ones deterministically so the signature probe always happens.
    mandate_tools: frozenset[str] = frozenset()


@dataclass
class AgentOutcome:
    summary: str
    tool_calls: int
    turns: int
    finished_cleanly: bool
    reason: str


@dataclass(frozen=True)
class _LLMBackend:
    base_url: str
    api_key: str
    model: str
    max_tokens: int


@dataclass
class _UsageWindow:
    started_at: float
    tokens: int


class _InMemoryUsageStore:
    def __init__(self) -> None:
        self._data: dict[str, dict[str, _UsageWindow]] = {}

    def get(self, key: str, kind: str) -> _UsageWindow | None:
        by_kind = self._data.get(key)
        if not by_kind:
            return None
        return by_kind.get(kind)

    def set(self, key: str, kind: str, window: _UsageWindow) -> None:
        self._data.setdefault(key, {})[kind] = window


_USAGE_MEMORY = _InMemoryUsageStore()


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


# Cap how many times we reject a single agent's ``finish`` for missing
# per-finding evidence. After this many rejections we let ``finish`` through
# anyway so a stuck agent can't burn the entire turn budget pinned against an
# un-exploitable finding (e.g. an endpoint that's been taken offline mid-scan).
_MAX_FINISH_REJECTIONS = 3


def _finish_rejection_exhausted(messages: list[dict[str, Any]]) -> bool:
    """True when this agent has already had ``_MAX_FINISH_REJECTIONS`` finishes
    rejected. We detect rejections by counting tool messages whose content
    carries the ``finish_rejected_missing_evidence`` sentinel."""
    n = 0
    for m in messages:
        if m.get("role") != "tool":
            continue
        c = m.get("content")
        if isinstance(c, str) and "finish_rejected_missing_evidence" in c:
            n += 1
            if n >= _MAX_FINISH_REJECTIONS:
                return True
    return False


async def _findings_still_unverified(session_id: str) -> list[dict[str, str]]:
    """Return (id, title, severity, category) for non-suppressed findings whose
    verification_status is still ``unverified`` — i.e. the agent has not yet
    called ``exploit_finding`` (which always flips status to true/false
    positive) for them. Empty list means the per-finding evidence pass is
    complete and ``finish`` is allowed.
    """
    try:
        import pencheff.server as srv
        listing = await srv.get_findings(session_id=session_id)
    except Exception as exc:  # noqa: BLE001
        log.warning("findings lookup for finish-gate failed: %s", exc)
        return []  # fail open — don't block finish if we can't tell.
    pending: list[dict[str, str]] = []
    for f in listing.get("findings") or []:
        if f.get("suppressed"):
            continue
        status = (f.get("verification_status") or "").lower()
        if status in ("true_positive", "false_positive", "true_negative", "false_negative"):
            continue
        # ``unverified`` — needs exploit_finding.
        pending.append({
            "id": str(f.get("id") or ""),
            "title": str(f.get("title") or "")[:100],
            "severity": str(f.get("severity") or ""),
            "category": str(f.get("category") or ""),
        })
    return pending


def _format_tool_call(name: str, args: dict[str, Any]) -> str:
    if not args:
        return f"tool: {name}"
    # Special case for the wrapper around external CLIs — show which CLI ran.
    if name == "run_security_tool" and "tool" in args:
        ext = str(args.get("tool") or "?")[:60]
        return f"tool: {name} → {ext}"
    for key in ("url", "finding_id", "steps"):
        if key in args:
            val = args[key]
            preview = f" ({len(val)} steps)" if isinstance(val, list) else f" → {str(val)[:120]}"
            return f"tool: {name}{preview}"
    return f"tool: {name} args={list(args.keys())}"


# Fallback tool-call parsing for models that emit the call as plain text inside
# ``message.content`` instead of populating ``message.tool_calls``. Kimi-K2 via
# ollama.com/v1 does this: ``<tool_call>name <arg_key>k</arg_key>
# <arg_value>v</arg_value> …</tool_call>``. Left unparsed the loop sees no tool
# call and terminates the agent before it runs its signature tool (GraphQL
# introspection, scan_websocket, …). ``(?:</tool_call>|$)`` also accepts a
# truncated final block (model hit its output-token cap mid-call).
_TOOL_CALL_BLOCK_RE = re.compile(r"<tool_call>\s*(.*?)(?:</tool_call>|$)", re.DOTALL)
_ARG_PAIR_RE = re.compile(
    r"<arg_key>\s*(.*?)\s*</arg_key>\s*<arg_value>\s*(.*?)\s*(?:</arg_value>|$)",
    re.DOTALL,
)


def _coerce_arg_value(raw: str) -> Any:
    """JSON-decode structured arg values ({...}/[...]/numbers/bools); else str.

    ``5d7a6e5526c0`` / ``wss://…`` / ``POST`` are not valid JSON → kept as
    strings; ``{"Content-Type": "application/json"}`` → dict; ``23`` → int.
    """
    s = raw.strip()
    if not s:
        return ""
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return s


def _parse_xml_tool_calls(content: str, turn: int) -> list[dict[str, Any]]:
    """Recover OpenAI-shaped tool calls from an XML-in-content emission.

    Handles the Kimi ``<arg_key>/<arg_value>`` form and the JSON-in-tag form
    ``<tool_call>{"name": …, "arguments": {…}}</tool_call>``. Returns a list of
    ``{id, type, function:{name, arguments}}`` dicts (``arguments`` a JSON
    string, matching the real API shape) so the existing loop can execute them
    and replay them to the model unchanged.
    """
    calls: list[dict[str, Any]] = []
    for i, block in enumerate(_TOOL_CALL_BLOCK_RE.findall(content or "")):
        block = block.strip()
        if not block:
            continue
        name = ""
        args: dict[str, Any] = {}
        if block[0] == "{":  # JSON-in-tag variant.
            try:
                obj = json.loads(block)
                name = str(obj.get("name") or "").strip()
                a = obj.get("arguments")
                args = a if isinstance(a, dict) else {}
            except (TypeError, ValueError):
                name = ""
        if not name:  # Kimi <arg_key>/<arg_value> variant — name is the head token.
            head = block.split("<arg_key>", 1)[0].strip()
            name = head.split()[0] if head else ""
            for k, v in _ARG_PAIR_RE.findall(block):
                key = k.strip()
                if key:
                    args[key] = _coerce_arg_value(v)
        if not name:
            continue
        calls.append({
            "id": f"xmltc_{turn}_{i}",
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)},
        })
    return calls


def _coerce_percent(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip().rstrip("%").strip()
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def _dotted_get(payload: Any, path: str) -> Any:
    cur = payload
    for segment in (path or "").split("."):
        if not segment:
            continue
        if isinstance(cur, dict) and segment in cur:
            cur = cur[segment]
            continue
        return None
    return cur


def _usage_key(api_key: str, model: str) -> str:
    digest = hashlib.sha256((api_key + "|" + model).encode("utf-8")).hexdigest()
    return digest[:16]


def _extract_token_total(response: dict[str, Any]) -> int | None:
    usage = response.get("usage") or {}
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    if isinstance(prompt, int) and isinstance(completion, int):
        return prompt + completion
    if isinstance(prompt, int):
        return prompt
    if isinstance(completion, int):
        return completion
    return None


def _get_window(key: str, kind: str, *, window_sec: float) -> _UsageWindow:
    now = time.time()
    existing = _USAGE_MEMORY.get(key, kind)
    if existing and now - existing.started_at < window_sec:
        return existing
    fresh = _UsageWindow(started_at=now, tokens=0)
    _USAGE_MEMORY.set(key, kind, fresh)
    return fresh


def _usage_percent(tokens: int, tokens_per_percent: float) -> float | None:
    if tokens_per_percent <= 0:
        return None
    return tokens / tokens_per_percent


# Module-level flag so the WARNING-log line emits at most once per process.
_PRIMARY_SWAP_WARNED: bool = False


def _warn_primary_swap_once() -> None:
    """Emit a one-time WARNING when AGENT_FALLBACK_LLM_* is the active primary.

    Feature 001 (multi-target-scan-pipelines) swapped the primary/fallback roles:
    AGENT_FALLBACK_LLM_* is now primary, AGENT_LLM_* is secondary fallback. The
    AGENT_LLM_USAGE_* budget-tracking thresholds (configured for the OLD primary's
    pricing curve) now apply to the NEW primary's token counts — operators must
    review/retune them for the new provider's pricing. See spec §5.7.
    """
    global _PRIMARY_SWAP_WARNED
    if _PRIMARY_SWAP_WARNED:
        return
    _PRIMARY_SWAP_WARNED = True
    log.warning(
        "AGENT_FALLBACK_LLM_API_KEY is now PRIMARY; budget thresholds "
        "AGENT_LLM_USAGE_* are applied to its token counts. Review "
        "AGENT_LLM_USAGE_THRESHOLD_PERCENT / TOKENS_PER_PERCENT for the new "
        "provider's pricing. (Feature 001-multi-target-scan-pipelines.)"
    )


def _primary_backend(settings) -> _LLMBackend | None:
    """Return the active primary LLM backend.

    Per feature 001, AGENT_FALLBACK_LLM_* is preferred as primary. Falls back to
    legacy AGENT_LLM_* when AGENT_FALLBACK_LLM_API_KEY is unset — keeps existing
    deployments working without an env-var change (two-step rollout, spec §5.7).
    """
    # New primary: AGENT_FALLBACK_LLM_*
    if settings.agent_fallback_llm_api_key and settings.agent_fallback_llm_base_url:
        _warn_primary_swap_once()
        return _LLMBackend(
            base_url=settings.agent_fallback_llm_base_url,
            api_key=settings.agent_fallback_llm_api_key,
            model=settings.agent_fallback_llm_model,
            max_tokens=settings.agent_fallback_llm_max_tokens or settings.agent_llm_max_tokens,
        )
    # Legacy primary fallback: AGENT_LLM_* (until operators configure the new env)
    if settings.agent_llm_api_key:
        return _LLMBackend(
            base_url=settings.agent_llm_base_url,
            api_key=settings.agent_llm_api_key,
            model=settings.agent_llm_model,
            max_tokens=settings.agent_llm_max_tokens,
        )
    return None


def _fallback_backend(settings) -> _LLMBackend | None:
    """Return the secondary fallback LLM backend.

    Per feature 001, AGENT_LLM_* now serves as the secondary fallback when
    AGENT_FALLBACK_LLM_* is the active primary. When AGENT_FALLBACK_LLM_API_KEY
    is unset (legacy deployments), this returns None — _primary_backend handles
    the AGENT_LLM_* path directly so there's no double-use.
    """
    # Only expose AGENT_LLM_* as fallback when AGENT_FALLBACK_LLM_* is primary.
    if settings.agent_fallback_llm_api_key and settings.agent_fallback_llm_base_url:
        if settings.agent_llm_api_key:
            return _LLMBackend(
                base_url=settings.agent_llm_base_url,
                api_key=settings.agent_llm_api_key,
                model=settings.agent_llm_model,
                max_tokens=settings.agent_llm_max_tokens,
            )
    return None


async def _fetch_usage(
    *,
    client: httpx.AsyncClient,
    url: str,
    api_key: str,
    session_field: str,
    weekly_field: str,
    timeout: float,
) -> tuple[float | None, float | None]:
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    resp = await client.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    session_pct = _coerce_percent(_dotted_get(data, session_field))
    weekly_pct = _coerce_percent(_dotted_get(data, weekly_field))
    return session_pct, weekly_pct


async def _chat_completion(
    *, client: httpx.AsyncClient, base_url: str, api_key: str,
    model: str, max_tokens: int,
    messages: list[dict[str, Any]], tools: list[dict[str, Any]],
) -> dict[str, Any]:
    """Single chat-completions HTTP call wrapped in an OTel GenAI span.

    Span attributes follow the OpenTelemetry GenAI semantic
    conventions (``gen_ai.system``, ``gen_ai.request.model``,
    ``gen_ai.usage.input_tokens`` etc.). Operators can pivot from a
    ``WHERE name = 'gen_ai.completion'`` query in ``otel_spans``
    straight to per-scan, per-model token spend.

    The auth header is NEVER set as a span attribute (it would land in
    otel_spans for retention_days days). The URL passes through with
    no query string so URL redaction isn't needed here.
    """
    url = base_url.rstrip("/") + "/chat/completions"
    body = {
        "model": model, "messages": messages, "tools": tools,
        "tool_choice": "auto", "max_tokens": max_tokens,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    span_cm = None
    span = None
    try:
        from opentelemetry import trace
        tracer = trace.get_tracer("pencheff.gen_ai")
        host = base_url.split("//", 1)[-1].split("/", 1)[0] if "//" in base_url else base_url
        span_cm = tracer.start_as_current_span(
            "gen_ai.completion",
            attributes={
                "gen_ai.system": host or "unknown",
                "gen_ai.request.model": model,
                "gen_ai.request.max_tokens": max_tokens,
                "gen_ai.request.messages.count": len(messages),
                "gen_ai.request.tools.count": len(tools),
            },
        )
        span = span_cm.__enter__()
    except Exception:
        span_cm = None

    try:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        result = resp.json()
        if span is not None:
            try:
                usage = (result or {}).get("usage") or {}
                if "prompt_tokens" in usage:
                    span.set_attribute(
                        "gen_ai.usage.input_tokens", int(usage.get("prompt_tokens") or 0)
                    )
                if "completion_tokens" in usage:
                    span.set_attribute(
                        "gen_ai.usage.output_tokens",
                        int(usage.get("completion_tokens") or 0),
                    )
                choices = (result or {}).get("choices") or []
                if choices:
                    finish = (choices[0] or {}).get("finish_reason")
                    if finish:
                        span.set_attribute("gen_ai.response.finish_reasons", finish)
                    msg = (choices[0] or {}).get("message") or {}
                    tcs = msg.get("tool_calls") or []
                    if tcs:
                        span.set_attribute("gen_ai.response.tool_calls.count", len(tcs))
                span.set_attribute("http.status_code", resp.status_code)
            except Exception:
                pass
        return result
    finally:
        if span_cm is not None:
            try:
                span_cm.__exit__(None, None, None)
            except Exception:
                pass


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
    scan_id: str | None = None,
    db_session_factory: Any = None,
    llm_override: tuple[str, str, str] | None = None,
) -> AgentOutcome:
    """Drive one agent (system prompt + tool registry + budget) to completion.

    Raises ``_TransientLLMError`` on any of: ``ReadTimeout``, ``ConnectTimeout``,
    ``ReadError``, ``RemoteProtocolError``, HTTP 429, HTTP 5xx — but only after
    the in-loop retry budget is exhausted (3 attempts, exponential backoff).

    ``llm_override``, when set, is a ``(base_url, api_key, model)`` triple that
    replaces the Pencheff-default primary backend.  Only supplied when the org's
    active LLM provider is OpenAI-tool-calling-compatible (openai /
    openai_compatible / azure_openai).  The scan agent uses Pencheff's default
    for anthropic / google providers.
    """
    settings = get_settings()
    primary = _primary_backend(settings)
    fallback = _fallback_backend(settings)
    if primary is None and fallback is None:
        raise RuntimeError("AGENT_LLM_API_KEY not configured")

    # Org-provider override (BYO-LLM): substitute primary backend when the org
    # has an OpenAI-compatible provider configured.  Fail-closed: if the
    # override endpoint errors, existing error-handling in the loop raises
    # _TransientLLMError → caller falls back to the deterministic scan (not
    # to Pencheff's agent key), satisfying the fail-closed requirement.
    if llm_override is not None:
        override_base_url, override_api_key, override_model = llm_override
        primary = _LLMBackend(
            base_url=override_base_url,
            api_key=override_api_key,
            model=override_model,
            max_tokens=primary.max_tokens if primary is not None else settings.agent_llm_max_tokens,
        )
        # BYO run: do not switch to Pencheff's fallback key mid-run if the
        # quota threshold fires.  Fail-closed — the run errors out instead of
        # billing the org against Pencheff's secondary key.
        fallback = None

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
            "IMPORTANT: the deterministic populator has already run on this "
            "session. The findings DB and discovered-endpoint surface are "
            "already filled. Your job is now: (1) call `get_findings` "
            "FIRST to see what's recorded, (2) verify each one with "
            "`test_endpoint` (reproduce the issue with a crafted "
            "request), (3) call `suppress_finding` on anything you "
            "cannot reproduce, (4) call `exploit_chain_suggest` and "
            "walk the most promising chain with `test_chain`, (5) call "
            "`finish` with an executive summary. DO NOT re-run "
            "`recon_passive` / `recon_active` / `recon_api_discovery` "
            "/ `scan_*` modules — that surface is already covered."
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
    called_tools: set[str] = set()
    summary = ""
    finished_cleanly = False
    reason = "max_turns"

    force_fallback = primary is None and fallback is not None
    last_usage_check = -1_000_000_000.0
    usage_key = _usage_key(primary.api_key, primary.model) if primary is not None else ""

    async with httpx.AsyncClient(timeout=settings.agent_request_timeout) as client:
        max_turns = agent.max_turns
        for turn in range(max_turns):
            turns = turn + 1
            remaining = max_turns - turn
            if remaining <= max(1, max_turns // 3):
                hint = (
                    f"Budget: turn {turns}/{max_turns} — only {remaining} "
                    "turns left. If the major categories are covered, call "
                    "`finish` NOW. Do not start new recon."
                )
            else:
                hint = (
                    f"Budget: turn {turns}/{max_turns}. Be efficient — "
                    "verify, chain, then `finish`."
                )
            messages_with_hint = messages + [{"role": "user", "content": hint}]
            response = None
            transport_attempts = 3
            for attempt in range(transport_attempts):
                try:
                    backend = primary
                    if fallback is not None:
                        if force_fallback:
                            backend = fallback
                        elif primary is not None:
                            mode = (settings.agent_llm_usage_mode or "tokens").strip().lower()
                            if mode == "endpoint" and settings.agent_llm_usage_url and settings.agent_llm_usage_poll_interval_sec > 0:
                                now = time.monotonic()
                                if now - last_usage_check >= settings.agent_llm_usage_poll_interval_sec:
                                    try:
                                        session_pct, weekly_pct = await _fetch_usage(
                                            client=client,
                                            url=settings.agent_llm_usage_url,
                                            api_key=primary.api_key,
                                            session_field=settings.agent_llm_usage_session_percent_field,
                                            weekly_field=settings.agent_llm_usage_weekly_percent_field,
                                            timeout=settings.agent_llm_usage_request_timeout,
                                        )
                                        last_usage_check = now
                                        threshold = settings.agent_llm_usage_threshold_percent
                                        if (
                                            (session_pct is not None and session_pct >= threshold)
                                            or (weekly_pct is not None and weekly_pct >= threshold)
                                        ):
                                            force_fallback = True
                                            backend = fallback
                                            await on_event("LLM quota reached; switching to fallback backend")
                                    except Exception as exc:  # noqa: BLE001
                                        log.debug("usage probe failed: %s", exc)
                                        last_usage_check = now
                            elif mode == "tokens":
                                session_window = _get_window(
                                    usage_key,
                                    "session",
                                    window_sec=settings.agent_llm_session_window_sec,
                                )
                                weekly_window = _get_window(
                                    usage_key,
                                    "weekly",
                                    window_sec=settings.agent_llm_weekly_window_sec,
                                )
                                session_pct = _usage_percent(
                                    session_window.tokens,
                                    settings.agent_llm_session_tokens_per_percent,
                                )
                                weekly_pct = _usage_percent(
                                    weekly_window.tokens,
                                    settings.agent_llm_weekly_tokens_per_percent,
                                )
                                threshold = settings.agent_llm_usage_threshold_percent
                                if (
                                    (session_pct is not None and session_pct >= threshold)
                                    or (weekly_pct is not None and weekly_pct >= threshold)
                                ):
                                    force_fallback = True
                                    backend = fallback
                                    await on_event("LLM quota reached; switching to fallback backend")
                    if backend is None:
                        raise RuntimeError("AGENT_LLM_API_KEY not configured")
                    response = await _chat_completion(
                        client=client,
                        base_url=backend.base_url,
                        api_key=backend.api_key,
                        model=backend.model,
                        max_tokens=backend.max_tokens,
                        messages=messages_with_hint,
                        tools=openai_tools,
                    )
                    # Persist trace (no-op if scan_id/db_factory are None).
                    from .llm_trace import record_llm_call
                    await record_llm_call(
                        scan_id=scan_id,
                        db_session_factory=db_session_factory,
                        agent_name=agent.name,
                        turn=turns,
                        request_messages=messages_with_hint,
                        request_tools=openai_tools,
                        response=response,
                        on_event=on_event,
                    )
                    if (
                        not force_fallback
                        and fallback is not None
                        and primary is not None
                        and backend == primary
                        and (settings.agent_llm_usage_mode or "tokens").strip().lower() == "tokens"
                    ):
                        token_total = _extract_token_total(response)
                        if token_total is not None:
                            session_window = _get_window(
                                usage_key,
                                "session",
                                window_sec=settings.agent_llm_session_window_sec,
                            )
                            weekly_window = _get_window(
                                usage_key,
                                "weekly",
                                window_sec=settings.agent_llm_weekly_window_sec,
                            )
                            session_window.tokens += token_total
                            weekly_window.tokens += token_total
                            threshold = settings.agent_llm_usage_threshold_percent
                            session_pct = _usage_percent(
                                session_window.tokens,
                                settings.agent_llm_session_tokens_per_percent,
                            )
                            weekly_pct = _usage_percent(
                                weekly_window.tokens,
                                settings.agent_llm_weekly_tokens_per_percent,
                            )
                            if (
                                (session_pct is not None and session_pct >= threshold)
                                or (weekly_pct is not None and weekly_pct >= threshold)
                            ):
                                force_fallback = True
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
                    # Any other 4xx (400 bad-request, 401 unauthorized, 403,
                    # 404 model-not-found, etc.) means the request never
                    # produced an LLM response. Previously this branch set
                    # ``response = None`` + broke, so ``_run_single_agent``
                    # returned a "graceful stop" AgentOutcome and the
                    # orchestrator marked the breaker ``success=True`` with
                    # empty results — masking a total LLM failure as a
                    # "completed-but-found-nothing" scan. Raise instead so
                    # _run_breaker_with_retry attempts a single backoff retry,
                    # then propagates ``success=False`` upward; when every
                    # breaker fails this way the swarm now triggers
                    # _catastrophic_fallback and Scan.summary.swarm reflects
                    # ``used_fallback=true``.
                    log.warning("LLM API error on turn %d: %s", turns, exc)
                    await on_event(f"agent error: {exc}"[:500])
                    raise _TransientLLMError(f"HTTP {code}") from exc
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
                    # Same rationale as the HTTPStatusError branch above:
                    # any catch-all transport error means no LLM response was
                    # produced, so we must surface it as a breaker failure
                    # rather than masking it as a graceful stop.
                    log.warning("LLM transport error on turn %d: %s", turns, exc)
                    await on_event(f"agent error: {exc}"[:500])
                    raise _TransientLLMError(f"{type(exc).__name__}: {exc}") from exc
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

            # Fallback: the model emitted its tool call as text inside content
            # (Kimi-K2 via ollama.com/v1). Recover it so the agent keeps working
            # instead of terminating on the "no tool call" break below.
            if not tool_use_calls and "<tool_call>" in assistant_text:
                tool_use_calls = _parse_xml_tool_calls(assistant_text, turns)
                if tool_use_calls:
                    assistant_text = _TOOL_CALL_BLOCK_RE.sub("", assistant_text).strip()
                    await on_event(
                        f"recovered {len(tool_use_calls)} XML tool-call(s) from content"
                    )

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
                called_tools.add(name)
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
                    # Per-finding evidence gate. When the agent is a breaker or
                    # ChainAgent (i.e. require_per_finding_exploit=True), reject
                    # ``finish`` while any non-suppressed finding still has
                    # verification_status="unverified". exploit_finding stamps a
                    # finding to true_positive / false_positive, so any
                    # remaining unverified row means evidence is missing. The
                    # rejection turns the ``finish`` tool result into an error
                    # listing the pending finding IDs, so the model knows to
                    # call ``exploit_finding`` on each and try again.
                    if (
                        getattr(agent, "require_per_finding_exploit", False)
                        and not _finish_rejection_exhausted(messages)
                    ):
                        pending = await _findings_still_unverified(session_id)
                        if pending:
                            err = {
                                "error": "finish_rejected_missing_evidence",
                                "message": (
                                    "Cannot finish — these findings still need "
                                    "exploit_finding called on them. Call "
                                    "`exploit_finding(finding_id=…)` on each "
                                    "pending finding, then call `finish` again."
                                ),
                                "pending_findings": pending[:30],
                            }
                            # Overwrite the last tool message (the optimistic
                            # ``finish`` result that was just appended above)
                            # with the rejection so the model sees the error.
                            if messages and messages[-1].get("role") == "tool":
                                messages[-1]["content"] = _tool_result_content(err)
                            await on_event(
                                f"finish rejected: {len(pending)} findings "
                                "still need exploit_finding"
                            )
                            # Do NOT set finished_cleanly — loop continues.
                            continue
                    summary = str(args.get("summary", "")).strip()[:4000]
                    finished_cleanly = True
                    reason = "finished"

            if finished_cleanly:
                break

    # Mandate backstop. Some models (kimi-k2.6) finish a specialist breaker
    # after get_findings→finish without ever invoking its signature probe —
    # e.g. GraphQLFuzzAgent skipping run_graphql_cop/run_inql, so introspection
    # never runs. Run any mandate tool the agent skipped, deterministically,
    # BEFORE the exploit backstop so the findings it surfaces also get evidence
    # stamped. The tools self-persist findings onto this session (args={} falls
    # back to the session-bound kind_config endpoint).
    missing_mandate = [
        t for t in getattr(agent, "mandate_tools", frozenset())
        if t not in called_tools
    ]
    for tname in missing_mandate:
        tool = tools_by_name.get(tname)
        if tool is None:
            continue
        await on_event(f"mandate backstop: running {tname} (agent skipped it)")
        try:
            await tool.handler(session_id, {})
            tool_calls += 1
        except Exception as exc:  # noqa: BLE001 — never let the backstop kill the agent
            log.warning("mandate backstop %s failed: %s", tname, exc)
            await on_event(f"mandate backstop {tname} failed: {exc}"[:300])

    # Post-loop backstop. When the agent had ``require_per_finding_exploit``
    # and exited for ANY reason (max_turns, stop_tool_calls, stop_final, even
    # explicit ``finish`` if the gate exhausted) with unverified findings
    # still on the session, programmatically call ``exploit_finding`` on each
    # so evidence lands regardless of model behavior. The playbooks are
    # deterministic — they don't need model cooperation to produce a real
    # captured request/response. Without this backstop, an agent that gives
    # up on ``stop_tool_calls`` instead of calling ``finish`` would slip past
    # the in-loop gate entirely (which only guards explicit ``finish``).
    if getattr(agent, "require_per_finding_exploit", False):
        try:
            pending = await _findings_still_unverified(session_id)
        except Exception:  # noqa: BLE001
            pending = []
        if pending:
            await on_event(
                f"post-loop backstop: running exploit_finding on "
                f"{len(pending)} unverified finding(s)"
            )
            tool = tools_by_name.get("exploit_finding")
            for f in pending[:30]:  # cap to avoid runaway
                fid = f.get("id")
                if not fid:
                    continue
                try:
                    if tool is not None:
                        await tool.handler(session_id, {"finding_id": fid})
                    else:
                        # Fall back to direct plugin call if the agent didn't
                        # have the tool in its registry.
                        import pencheff.server as srv
                        await srv.exploit_finding(session_id=session_id, finding_id=fid)
                    tool_calls += 1
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "backstop exploit_finding for %s failed: %s", fid, exc
                    )

    elapsed = time.monotonic() - start
    log.info(
        "%s loop done in %.1fs · turns=%d · tool_calls=%d · reason=%s",
        agent.name, elapsed, turns, tool_calls, reason,
    )
    return AgentOutcome(
        summary=summary, tool_calls=tool_calls, turns=turns,
        finished_cleanly=finished_cleanly, reason=reason,
    )
