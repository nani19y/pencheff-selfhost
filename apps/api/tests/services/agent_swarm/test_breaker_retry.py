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


@pytest.fixture(autouse=True)
def zero_backoff(monkeypatch):
    """Make retries instant so tests don't sleep."""
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "swarm_breaker_retry_backoff_sec", 0)


@pytest.fixture
def fake_spec_and_agent(monkeypatch):
    spec = BreakerSpec("FakeAgent", "fake")
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

    async def on_event(line: str): pass

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
