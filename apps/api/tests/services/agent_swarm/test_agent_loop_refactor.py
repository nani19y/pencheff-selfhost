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


def test_format_tool_call_special_cases_run_security_tool():
    from pencheff_api.services.agent_swarm.agent_loop import _format_tool_call
    line = _format_tool_call("run_security_tool", {"tool": "ffuf", "args": ["-u", "x"]})
    assert "ffuf" in line
    assert "args=" not in line  # the dict-keys fallback should NOT fire


def test_format_tool_call_url_short_form():
    from pencheff_api.services.agent_swarm.agent_loop import _format_tool_call
    line = _format_tool_call("test_endpoint", {"url": "https://t/api/u", "method": "GET"})
    assert "https://t/api/u" in line
    assert "→" in line


def test_format_tool_call_no_args():
    from pencheff_api.services.agent_swarm.agent_loop import _format_tool_call
    line = _format_tool_call("get_findings", {})
    assert line == "tool: get_findings"


def test_dangerous_args_includes_dump_flags():
    """Data-extraction sqlmap flags must be blocked by the tool-layer guardrail."""
    from pencheff_api.services.agent_runner import _DANGEROUS_ARG_SUBSTRINGS
    for forbidden in (
        "--dump", "--dump-all", "--search", "--sql-query",
        "--sql-file", "--passwords", "--privileges",
    ):
        assert forbidden in _DANGEROUS_ARG_SUBSTRINGS, (
            f"{forbidden!r} must be in _DANGEROUS_ARG_SUBSTRINGS"
        )


def test_dangerous_args_does_not_include_schema_flags():
    """Schema introspection flags MUST stay allowed for ProofOfImpactAgent."""
    from pencheff_api.services.agent_runner import _DANGEROUS_ARG_SUBSTRINGS
    for allowed in ("--dbs", "--tables", "--columns", "--count"):
        assert allowed not in _DANGEROUS_ARG_SUBSTRINGS, (
            f"{allowed!r} must NOT be in _DANGEROUS_ARG_SUBSTRINGS — "
            "ProofOfImpactAgent needs it for schema introspection"
        )
