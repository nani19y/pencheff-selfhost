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

    # run_swarm does `from .recon import run_recon_phase` locally, so we must
    # patch the recon module directly (not the orchestrator namespace).
    from pencheff_api.services.agent_swarm import recon as recon_mod
    monkeypatch.setattr(recon_mod, "run_recon_phase", boom)

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
