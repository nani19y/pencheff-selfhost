"""Recon phase wraps _run_single_agent + freezes a ReconSnapshot.
Empty snapshot or recon crash → ReconFailed."""
from __future__ import annotations

import pytest
import pytest_asyncio

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


@pytest_asyncio.fixture
async def real_session():
    from pencheff.server import pentest_init
    init = await pentest_init(target_url="https://t.example.com")
    yield init["session_id"]


@pytest.mark.asyncio
async def test_recon_happy_returns_snapshot(llm_settings, monkeypatch, real_session):
    # ReconAgent calls recon_passive once then finishes. We need to
    # populate at least one endpoint before the freeze runs (recon_passive
    # is real and may not actually populate endpoints in the test
    # environment), so we directly inject one into the session.
    from pencheff.core.session import get_session as _gsess
    sess = _gsess(real_session)
    # Use the real attribute path discovered by C2.
    sess.discovered.endpoints.append({
        "url": "https://t.example.com/api/u", "method": "GET",
        "status": 200, "content_type": "application/json",
        "parameters": ["id"],
    })

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
    assert len(snap.endpoints) >= 1


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
