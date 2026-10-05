"""LLM trace persistence helper."""
from __future__ import annotations

import json

import pytest


def test_extract_tokens_openai_shape():
    from pencheff_api.services.agent_swarm.llm_trace import _extract_tokens
    out = _extract_tokens({
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "prompt_tokens_details": {"cached_tokens": 80},
        "completion_tokens_details": {"reasoning_tokens": 20},
    })
    assert out == {
        "prompt_tokens": 100, "completion_tokens": 50,
        "cached_tokens": 80, "reasoning_tokens": 20,
    }


def test_extract_tokens_deepseek_shape():
    from pencheff_api.services.agent_swarm.llm_trace import _extract_tokens
    out = _extract_tokens({
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "prompt_cache_hit_tokens": 75,
    })
    assert out["cached_tokens"] == 75
    assert out["reasoning_tokens"] is None


def test_extract_tokens_minimal():
    from pencheff_api.services.agent_swarm.llm_trace import _extract_tokens
    out = _extract_tokens({"prompt_tokens": 100, "completion_tokens": 50})
    assert out == {
        "prompt_tokens": 100, "completion_tokens": 50,
        "cached_tokens": None, "reasoning_tokens": None,
    }


def test_extract_reasoning_string_field():
    from pencheff_api.services.agent_swarm.llm_trace import _extract_reasoning
    assert _extract_reasoning({"reasoning_content": "I should call X"}) == "I should call X"
    assert _extract_reasoning({"thinking": "  "}) is None
    assert _extract_reasoning({}) is None


def test_extract_reasoning_anthropic_blocks():
    from pencheff_api.services.agent_swarm.llm_trace import _extract_reasoning
    msg = {"reasoning": [
        {"type": "thinking", "text": "Step 1"},
        {"type": "thinking", "text": "Step 2"},
    ]}
    out = _extract_reasoning(msg)
    assert "Step 1" in out and "Step 2" in out


def test_summary_line_with_tools_and_tokens():
    from pencheff_api.services.agent_swarm.llm_trace import build_summary_line
    line = build_summary_line(
        agent_name="InjectionAgent", turn=3,
        tokens={"prompt_tokens": 1234, "completion_tokens": 567,
                 "cached_tokens": 800, "reasoning_tokens": 50},
        tool_calls=[{"function": {"name": "scan_injection"}}],
        has_reasoning=True,
        content="ignored when tool calls present",
    )
    # No [AgentName] prefix — outer orchestrator on_event wrapper adds that.
    assert "[InjectionAgent]" not in line
    assert "LLM turn=3" in line
    assert "in=1234t" in line
    assert "out=567t" in line
    assert "cached=800t" in line
    assert "think=50t" in line
    assert "(reasoning)" in line
    assert "scan_injection" in line


def test_summary_line_text_response_no_tools():
    from pencheff_api.services.agent_swarm.llm_trace import build_summary_line
    line = build_summary_line(
        agent_name="ChainAgent", turn=15,
        tokens={"prompt_tokens": 2000, "completion_tokens": 100,
                 "cached_tokens": None, "reasoning_tokens": None},
        tool_calls=None, has_reasoning=False,
        content="I confirmed the SSRF chain leads to IAM credential exposure.",
    )
    assert "ChainAgent" not in line  # outer wrapper provides agent prefix
    assert "I confirmed the SSRF chain" in line
    assert "calls=" not in line


@pytest.mark.asyncio
async def test_record_llm_call_no_db_just_emits_summary(monkeypatch):
    """When scan_id/db_session_factory is None, no DB call happens
    but the summary line still emits."""
    from pencheff_api.services.agent_swarm.llm_trace import record_llm_call
    captured: list[str] = []
    async def on_event(line: str): captured.append(line)
    await record_llm_call(
        scan_id=None,
        db_session_factory=None,
        agent_name="ReconAgent", turn=1,
        request_messages=[{"role": "user", "content": "hi"}],
        request_tools=[],
        response={
            "choices": [{"message": {"content": "ok", "tool_calls": None}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        },
        on_event=on_event,
    )
    assert len(captured) == 1
    assert "[ReconAgent]" not in captured[0]  # outer wrapper provides agent prefix
    assert "LLM turn=1" in captured[0]
    assert "in=5t" in captured[0]
