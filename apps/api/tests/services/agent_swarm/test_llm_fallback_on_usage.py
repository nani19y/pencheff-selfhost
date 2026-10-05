from __future__ import annotations

import pytest

from pencheff_api.services import agent_runner
from tests.services.agent_swarm._scripted_llm import ScriptedLLM, ScriptedTurn, with_finish


# NOTE on URL names after feature 001 (multi-target-scan-pipelines):
# The variable family AGENT_FALLBACK_LLM_* is now the ACTIVE PRIMARY, and
# AGENT_LLM_* is now the SECONDARY fallback. The hostnames below keep their
# original suggestive names (primary.example.com / fallback.example.com) but
# the role-to-hostname mapping is now inverted:
#   * Active primary  → fallback.example.com   (AGENT_FALLBACK_LLM_*)
#   * Active fallback → primary.example.com    (AGENT_LLM_*)
# Test assertions below reflect this.


@pytest.fixture
def llm_settings(monkeypatch):
    from pencheff_api.config import get_settings

    s = get_settings()
    # Legacy/secondary credentials (now the FALLBACK after feature 001).
    monkeypatch.setattr(s, "agent_llm_api_key", "sk-primary")
    monkeypatch.setattr(s, "agent_llm_base_url", "https://primary.example.com/v1")
    monkeypatch.setattr(s, "agent_llm_model", "kimi-k2.6:cloud")
    monkeypatch.setattr(s, "agent_llm_max_tokens", 256)
    monkeypatch.setattr(s, "agent_request_timeout", 30.0)
    monkeypatch.setattr(s, "agent_max_turns", 2)

    monkeypatch.setattr(s, "agent_llm_usage_threshold_percent", 90.0)
    monkeypatch.setattr(s, "agent_llm_usage_mode", "tokens")
    monkeypatch.setattr(s, "agent_llm_session_window_sec", 18000.0)
    monkeypatch.setattr(s, "agent_llm_weekly_window_sec", 604800.0)
    monkeypatch.setattr(s, "agent_llm_session_tokens_per_percent", 100.0)
    monkeypatch.setattr(s, "agent_llm_weekly_tokens_per_percent", 100.0)

    # New PRIMARY credentials after feature 001.
    monkeypatch.setattr(s, "agent_fallback_llm_api_key", "sk-fallback")
    monkeypatch.setattr(s, "agent_fallback_llm_base_url", "https://fallback.example.com/v1")
    monkeypatch.setattr(s, "agent_fallback_llm_model", "sarvam-105b")
    monkeypatch.setattr(s, "agent_fallback_llm_max_tokens", 256)
    return s


@pytest.mark.asyncio
async def test_switches_to_fallback_when_usage_at_or_above_threshold(llm_settings, monkeypatch):
    from pencheff_api.services.agent_swarm import agent_loop

    agent_loop._USAGE_MEMORY._data.clear()
    first = ScriptedTurn(
        tool_calls=[{
            "id": "c1",
            "type": "function",
            "function": {"name": "finish", "arguments": '{"summary":"ok"}'},
        }],
        usage={"prompt_tokens": 9100, "completion_tokens": 0},
    )
    stub = ScriptedLLM([first])
    stub.install(monkeypatch)

    async def on_event(line: str) -> None:
        pass

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
    # Active primary is now AGENT_FALLBACK_LLM_* → fallback.example.com.
    assert stub.calls[0]["url"].startswith("https://fallback.example.com/v1/chat/completions")

    second = ScriptedLLM([with_finish("ok")])
    second.install(monkeypatch)
    outcome2 = await agent_runner.run_agent(
        session_id="sid-fake",
        target_url="https://t.example.com",
        credentials=None,
        profile="quick",
        scope=None,
        exclude_paths=None,
        on_event=on_event,
        session_prepopulated=False,
    )
    assert outcome2.finished_cleanly is True
    # After threshold, fall over to AGENT_LLM_* → primary.example.com (the
    # secondary tier after the feature 001 swap).
    assert second.calls[0]["url"].startswith("https://primary.example.com/v1/chat/completions")


@pytest.mark.asyncio
async def test_stays_on_primary_when_usage_below_threshold(llm_settings, monkeypatch):
    from pencheff_api.services.agent_swarm import agent_loop

    agent_loop._USAGE_MEMORY._data.clear()
    stub = ScriptedLLM([with_finish("ok")])
    stub.install(monkeypatch)

    async def on_event(line: str) -> None:
        pass

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
    # Active primary is now AGENT_FALLBACK_LLM_* → fallback.example.com.
    assert stub.calls[0]["url"].startswith("https://fallback.example.com/v1/chat/completions")
