"""AuthzAgent finishes immediately with success=True when the snapshot
shows authenticated=False. No LLM call is billed."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from pencheff_api.services.agent_swarm.breakers import BreakerSpec
from pencheff_api.services.agent_swarm.orchestrator import (
    _run_breaker_with_retry,
)
from pencheff_api.services.agent_swarm.snapshot import (
    DiscoveredEndpoint, ReconSnapshot,
)


def _snap_unauth() -> ReconSnapshot:
    return ReconSnapshot(
        target_base_url="https://t", profile="standard",
        scope_include=(), scope_exclude=(),
        endpoints=(DiscoveredEndpoint("https://t/u", "GET", 200, None, ()),),
        api_spec_urls=(), subdomains=(),
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={}, waf_vendor=None,
        authenticated=False,
        auth_login_url=None, auth_cookies=(), auth_tokens={},
        oast_session_handle=None,
        recon_agent_summary="", recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_authz_quietquits_when_unauth(monkeypatch):
    spec = BreakerSpec("AuthzAgent", "x")

    # _run_single_agent must NOT be called for AuthzAgent in unauth mode.
    sentinel = {"called": False}
    async def must_not_call(**kw):
        sentinel["called"] = True
        raise AssertionError("LLM was billed for a quiet-quit")
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator._run_single_agent",
        must_not_call,
    )
    # seed_breaker_session is still called (the session exists, it's
    # just that the agent doesn't run). That's fine; the bill is the LLM.
    async def _seed_ok(snap): return "sid-fake"
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.orchestrator.seed_breaker_session",
        _seed_ok,
    )

    async def on_event(line): pass
    fake_agent = SimpleNamespace(
        name="AuthzAgent", system_prompt="x", tools=[], max_turns=5,
    )
    res = await _run_breaker_with_retry(
        spec=spec, agent=fake_agent, snapshot=_snap_unauth(),
        on_event=on_event, target_url="https://t",
        credentials=None, scope=None, exclude_paths=None,
    )
    assert sentinel["called"] is False
    assert res.success is True
    assert "skipped" in res.summary.lower()
    assert res.tool_calls == 0
    assert res.turns == 0
