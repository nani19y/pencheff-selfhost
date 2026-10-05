"""LLM-call trace persistence for swarm agents.

Each swarm chat-completions call lands here as one ``ScanLLMTrace`` row
plus a compact summary line on the scan's assessment log.

Trace persistence is opt-in: callers without ``scan_id`` /
``db_session_factory`` simply skip recording.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select

from ...db.models import ScanLLMTrace
from .agent_loop import LogSink

log = logging.getLogger("pencheff.swarm.llm_trace")


# Cap on how many characters of the assistant content we echo into the
# summary line. The full content lives in the DB row.
_CONTENT_PREVIEW_CHARS = 240


def _extract_tokens(usage: dict | None) -> dict[str, int | None]:
    """Pull token counts out of a chat-completions ``usage`` dict.

    Different providers nest these differently:
      - OpenAI:    usage.prompt_tokens_details.cached_tokens,
                   usage.completion_tokens_details.reasoning_tokens
      - DeepSeek:  usage.prompt_cache_hit_tokens (cached)
      - Anthropic via OpenAI-compat: same as OpenAI
      - Most others: just prompt_tokens / completion_tokens
    Returns dict with all four; missing fields stay None.
    """
    u = usage or {}
    prompt = u.get("prompt_tokens")
    completion = u.get("completion_tokens")
    pt_details = u.get("prompt_tokens_details") or {}
    ct_details = u.get("completion_tokens_details") or {}
    cached = (
        pt_details.get("cached_tokens")
        if isinstance(pt_details, dict)
        else None
    )
    if cached is None:
        cached = u.get("prompt_cache_hit_tokens")  # DeepSeek
    reasoning = (
        ct_details.get("reasoning_tokens")
        if isinstance(ct_details, dict)
        else None
    )
    if reasoning is None:
        reasoning = u.get("reasoning_tokens")  # some providers
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "cached_tokens": cached,
        "reasoning_tokens": reasoning,
    }


def _extract_reasoning(message: dict) -> str | None:
    """Look for thinking / reasoning content under several provider names."""
    for key in ("reasoning_content", "reasoning", "thinking"):
        val = message.get(key)
        if isinstance(val, str) and val.strip():
            return val
        # Anthropic-style structured thinking block list:
        if isinstance(val, list):
            collected = "\n".join(
                b.get("text", "") for b in val
                if isinstance(b, dict) and b.get("text")
            )
            if collected.strip():
                return collected
    return None


def build_summary_line(
    *,
    agent_name: str,
    turn: int,
    tokens: dict[str, int | None],
    tool_calls: list[dict] | None,
    has_reasoning: bool,
    content: str | None,
) -> str:
    """Compact one-liner for the assessment log.

    Caller's ``on_event`` is already wrapped with the orchestrator's
    ``_prefix("[AgentName] ", …)`` adapter, so this line does NOT re-add
    the agent prefix; the outer wrapper takes care of it. ``agent_name``
    is kept in the signature for tests / non-orchestrator callers.
    """
    del agent_name  # outer prefix wrapper provides this
    parts = [f"LLM turn={turn}"]
    if tokens["prompt_tokens"] is not None:
        parts.append(f"in={tokens['prompt_tokens']}t")
    if tokens["completion_tokens"] is not None:
        parts.append(f"out={tokens['completion_tokens']}t")
    if tokens["cached_tokens"]:
        parts.append(f"cached={tokens['cached_tokens']}t")
    if tokens["reasoning_tokens"]:
        parts.append(f"think={tokens['reasoning_tokens']}t")
    if has_reasoning:
        parts.append("(reasoning)")
    if tool_calls:
        names = [
            (tc.get("function", {}).get("name") or "?")
            for tc in tool_calls
        ]
        parts.append(f"calls=[{','.join(names)}]")
    elif content:
        snippet = content.strip().replace("\n", " ")[:_CONTENT_PREVIEW_CHARS]
        if snippet:
            parts.append(f"text={snippet!r}")
    return " · ".join(parts)


async def record_llm_call(
    *,
    scan_id: str | None,
    db_session_factory: Any,
    agent_name: str,
    turn: int,
    request_messages: list[dict],
    request_tools: list[dict],
    response: dict,
    on_event: LogSink,
) -> None:
    """Persist one LLM call's full request/response + emit summary line.

    No-op if scan_id or db_session_factory is None (keeps the swarm
    runnable from tests / contexts that don't have a DB).
    """
    # Pull what we need before any DB work — if the response shape is
    # unexpected, we still want the summary line.
    choices = response.get("choices") or [{}]
    message = (choices[0] or {}).get("message") or {}
    content = message.get("content") or ""
    tool_calls = message.get("tool_calls") or []
    reasoning = _extract_reasoning(message)
    tokens = _extract_tokens(response.get("usage"))

    summary = build_summary_line(
        agent_name=agent_name,
        turn=turn,
        tokens=tokens,
        tool_calls=tool_calls,
        has_reasoning=reasoning is not None,
        content=content,
    )
    try:
        await on_event(summary)
    except Exception as exc:  # noqa: BLE001
        log.warning("llm_trace summary emit failed: %s", exc)

    if not scan_id or db_session_factory is None:
        return

    try:
        async with db_session_factory() as db:
            row = ScanLLMTrace(
                scan_id=scan_id,
                agent_name=agent_name,
                turn=turn,
                request_messages=request_messages,
                request_tools_count=len(request_tools or []),
                response_content=content or None,
                response_tool_calls=tool_calls or None,
                response_reasoning=reasoning,
                prompt_tokens=tokens["prompt_tokens"],
                completion_tokens=tokens["completion_tokens"],
                cached_tokens=tokens["cached_tokens"],
                reasoning_tokens=tokens["reasoning_tokens"],
            )
            db.add(row)
            try:
                from ...db.models import Scan
                from ..credits import debit_credits
                org_id = (await db.execute(
                    select(Scan.org_id).where(Scan.id == scan_id)
                )).scalar_one_or_none()
                if org_id:
                    await debit_credits(
                        db, org_id,
                        input_tokens=tokens["prompt_tokens"],
                        output_tokens=tokens["completion_tokens"],
                        source="scan_ai", ref=f"{scan_id}:{agent_name}:{turn}",
                    )
            except Exception as exc:  # noqa: BLE001
                log.warning("credit debit (scan_ai) failed: %s", exc)
            await db.commit()
    except Exception as exc:  # noqa: BLE001
        # Never let a trace-write failure break the scan.
        log.warning(
            "llm_trace persist failed (scan=%s, agent=%s, turn=%s): %s",
            scan_id, agent_name, turn, exc,
        )
