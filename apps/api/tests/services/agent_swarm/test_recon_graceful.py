"""Recon transient errors should not blow up the scan when the session
already has discovered endpoints. The retry-once + degrade path should
keep the scan running with partial recon results."""
from __future__ import annotations

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm.agent_loop import _TransientLLMError
from pencheff_api.services.agent_swarm.recon import run_recon_phase
from pencheff_api.services.agent_swarm.snapshot import ReconFailed, ReconSnapshot


@pytest.fixture
def llm_settings(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "agent_llm_api_key", "sk-test")
    monkeypatch.setattr(s, "agent_llm_base_url", "https://api.example.com/v1")
    monkeypatch.setattr(s, "agent_llm_model", "test")
    monkeypatch.setattr(s, "agent_llm_max_tokens", 1024)
    monkeypatch.setattr(s, "agent_request_timeout", 30.0)
    monkeypatch.setattr(s, "swarm_breaker_retry_attempts", 1)
    monkeypatch.setattr(s, "swarm_breaker_retry_backoff_sec", 0)
    return s


@pytest.mark.asyncio
async def test_recon_transient_with_partial_endpoints_proceeds(llm_settings, monkeypatch):
    """When recon hits transient errors AFTER discovering at least one
    endpoint, the orchestrator should freeze a partial snapshot and
    proceed — NOT trigger catastrophic fallback."""
    sid = (await pentest_init(target_url="https://t.example.com"))["session_id"]

    # Pre-populate one endpoint so the partial-snapshot path has something
    # to freeze. Real ReconAgent would have done this via recon_passive.
    from pencheff.core.session import get_session as _gsess
    _gsess(sid).discovered.endpoints.append({
        "url": "https://t.example.com/api/u", "method": "GET",
        "status": 200, "content_type": "application/json",
        "parameters": ["id"],
    })

    # _run_single_agent raises _TransientLLMError on every call (so retry
    # also fails). Without graceful degradation, run_recon_phase would
    # raise ReconFailed. With it, we should still get a snapshot.
    async def always_transient(**_):
        raise _TransientLLMError("HTTP 503 after retries")
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.recon._run_single_agent",
        always_transient,
    )

    events: list[str] = []
    async def on_event(line: str): events.append(line)

    snap = await run_recon_phase(
        master_session_id=sid,
        target_url="https://t.example.com",
        credentials=None,
        profile="standard",
        scope=None,
        exclude_paths=None,
        on_event=on_event,
    )
    assert isinstance(snap, ReconSnapshot)
    assert len(snap.endpoints) == 1
    # Diagnostic line should mention the transient + the partial-discovery degrade.
    assert any("transient" in e.lower() for e in events)


@pytest.mark.asyncio
async def test_recon_transient_with_no_endpoints_still_fails(llm_settings, monkeypatch):
    """When recon hits transient errors AND no endpoints were discovered,
    ReconFailed must propagate (so the catastrophic-fallback gate fires)."""
    sid = (await pentest_init(target_url="https://t.example.com"))["session_id"]

    async def always_transient(**_):
        raise _TransientLLMError("HTTP 503 after retries")
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.recon._run_single_agent",
        always_transient,
    )

    async def on_event(line: str): pass

    with pytest.raises(ReconFailed):
        await run_recon_phase(
            master_session_id=sid,
            target_url="https://t.example.com",
            credentials=None, profile="standard",
            scope=None, exclude_paths=None,
            on_event=on_event,
        )


@pytest.mark.asyncio
async def test_recon_non_transient_propagates_immediately(llm_settings, monkeypatch):
    """Non-transient errors (e.g. logic bugs) should NOT be retried —
    they go straight to ReconFailed."""
    sid = (await pentest_init(target_url="https://t.example.com"))["session_id"]

    call_count = {"n": 0}
    async def boom(**_):
        call_count["n"] += 1
        raise ValueError("bug")
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.recon._run_single_agent",
        boom,
    )

    async def on_event(line: str): pass

    with pytest.raises(ReconFailed):
        await run_recon_phase(
            master_session_id=sid,
            target_url="https://t.example.com",
            credentials=None, profile="standard",
            scope=None, exclude_paths=None,
            on_event=on_event,
        )
    assert call_count["n"] == 1  # no retry on non-transient
