"""All 7 breakers fail → catastrophic fallback fires with reason
'all_breakers_failed'."""
from __future__ import annotations

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm import run_swarm


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


@pytest.mark.asyncio
async def test_all_breakers_failed_triggers_fallback(llm_settings, monkeypatch):
    from pencheff_api.services.agent_swarm import orchestrator as orch
    from pencheff_api.services.agent_swarm import recon as recon_mod
    from pencheff_api.services.agent_swarm.snapshot import (
        DiscoveredEndpoint, ReconSnapshot,
    )
    from datetime import datetime, timezone

    fake_snap = ReconSnapshot(
        target_base_url="https://t", profile="standard",
        scope_include=(), scope_exclude=(),
        endpoints=(DiscoveredEndpoint("https://t/u", "GET", 200, None, ()),),
        api_spec_urls=(), subdomains=(),
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={}, waf_vendor=None,
        authenticated=True,  # ensure AuthzAgent does NOT quiet-quit (we want it to fail)
        auth_login_url=None,
        auth_cookies=(("sid", "abc"),), auth_tokens={"bearer": "x"},
        oast_session_handle=None,
        recon_agent_summary="x", recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )

    # Patch recon module directly — run_swarm imports run_recon_phase locally.
    async def fake_recon(**_): return fake_snap
    monkeypatch.setattr(recon_mod, "run_recon_phase", fake_recon)

    async def fake_breaker(*, spec, **kwargs):
        return orch.BreakerResult(
            agent_name=spec.name, success=False,
            finding_ids=(), summary="", turns=0, tool_calls=0,
            error="test_total_failure", breaker_session_id=None,
        )
    monkeypatch.setattr(orch, "_run_breaker_with_retry", fake_breaker)

    from pencheff_api.services import agent_runner
    from pencheff_api.services.agent_runner import AgentOutcome

    async def fake_legacy(**kwargs):
        return AgentOutcome(
            summary="legacy ran", tool_calls=1, turns=1,
            finished_cleanly=True, reason="finished",
        )
    monkeypatch.setattr(agent_runner, "run_agent", fake_legacy)

    sid = (await pentest_init(target_url="https://t"))["session_id"]
    async def on_event(line: str): pass

    outcome = await run_swarm(
        master_session_id=sid, target_url="https://t",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is True
    assert outcome.used_fallback_reason == "all_breakers_failed"
