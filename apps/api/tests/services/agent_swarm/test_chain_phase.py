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
