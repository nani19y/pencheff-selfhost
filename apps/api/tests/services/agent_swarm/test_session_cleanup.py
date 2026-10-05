"""run_swarm releases all per-breaker pencheff sessions after the
merge phase, on both success and catastrophic-fallback paths."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pencheff.server import pentest_init


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
async def test_breaker_sessions_destroyed_on_happy_path(llm_settings, monkeypatch):
    from pencheff_api.services.agent_swarm import run_swarm, orchestrator as orch
    from pencheff_api.services.agent_swarm import recon as recon_mod
    from pencheff_api.services.agent_swarm.snapshot import (
        DiscoveredEndpoint, ReconSnapshot,
    )

    snap = ReconSnapshot(
        target_base_url="https://t", profile="standard",
        scope_include=(), scope_exclude=(),
        endpoints=(DiscoveredEndpoint("https://t/u", "GET", 200, None, ()),),
        api_spec_urls=(), subdomains=(),
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={}, waf_vendor=None,
        authenticated=True, auth_login_url=None,
        auth_cookies=(("sid", "abc"),), auth_tokens={"bearer": "x"},
        oast_session_handle=None,
        recon_agent_summary="x", recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )

    async def fake_recon(**_): return snap
    monkeypatch.setattr(recon_mod, "run_recon_phase", fake_recon)

    seeded_sids: list[str] = []

    async def fake_breaker(*, spec, **kwargs):
        # Simulate seeding so we have a real SID we can later check
        # for destruction.
        init = await pentest_init(target_url="https://t")
        seeded_sids.append(init["session_id"])
        return orch.BreakerResult(
            agent_name=spec.name, success=True,
            finding_ids=(), summary="ok", turns=1, tool_calls=1,
            error=None, breaker_session_id=init["session_id"],
        )
    monkeypatch.setattr(orch, "_run_breaker_with_retry", fake_breaker)

    # Stub chain + compliance phases to avoid LLM calls.
    from pencheff_api.services.agent_swarm import chain as chain_mod
    from pencheff_api.services.agent_swarm.agent_loop import AgentOutcome
    async def fake_chain(**_):
        return AgentOutcome(
            summary="chain ok", tool_calls=0, turns=0,
            finished_cleanly=True, reason="finished",
        )
    async def fake_compliance(**_):
        return AgentOutcome(
            summary="", tool_calls=0, turns=0,
            finished_cleanly=True, reason="finished",
        )
    monkeypatch.setattr(chain_mod, "_run_chain_phase", fake_chain)
    monkeypatch.setattr(chain_mod, "_run_compliance_phase", fake_compliance)

    async def fake_proof(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_payload(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_evidence(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_admin(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    monkeypatch.setattr(chain_mod, "_run_proof_of_impact_phase", fake_proof)
    monkeypatch.setattr(chain_mod, "_run_payload_crafting_phase", fake_payload)
    monkeypatch.setattr(chain_mod, "_run_evidence_capture_phase", fake_evidence)
    monkeypatch.setattr(chain_mod, "_run_admin_access_phase", fake_admin)

    master = (await pentest_init(target_url="https://t"))["session_id"]
    async def on_event(line: str): pass

    outcome = await run_swarm(
        master_session_id=master, target_url="https://t",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is False
    assert len(seeded_sids) == 13

    # All seeded breaker sessions must be gone from in-memory storage.
    from pencheff.core.session import get_session as _gsess
    for sid in seeded_sids:
        assert _gsess(sid) is None, f"breaker session {sid} not destroyed"


@pytest.mark.asyncio
async def test_breaker_sessions_destroyed_on_all_failed_fallback(llm_settings, monkeypatch):
    from pencheff_api.services.agent_swarm import run_swarm, orchestrator as orch
    from pencheff_api.services.agent_swarm import recon as recon_mod
    from pencheff_api.services.agent_swarm.snapshot import (
        DiscoveredEndpoint, ReconSnapshot,
    )

    snap = ReconSnapshot(
        target_base_url="https://t", profile="standard",
        scope_include=(), scope_exclude=(),
        endpoints=(DiscoveredEndpoint("https://t/u", "GET", 200, None, ()),),
        api_spec_urls=(), subdomains=(),
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={}, waf_vendor=None,
        authenticated=True, auth_login_url=None,
        auth_cookies=(("sid", "abc"),), auth_tokens={"bearer": "x"},
        oast_session_handle=None,
        recon_agent_summary="x", recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )
    async def fake_recon(**_): return snap
    monkeypatch.setattr(recon_mod, "run_recon_phase", fake_recon)

    seeded_sids: list[str] = []
    async def fake_breaker(*, spec, **kwargs):
        init = await pentest_init(target_url="https://t")
        seeded_sids.append(init["session_id"])
        return orch.BreakerResult(
            agent_name=spec.name, success=False,
            finding_ids=(), summary="", turns=0, tool_calls=0,
            error="x", breaker_session_id=init["session_id"],
        )
    monkeypatch.setattr(orch, "_run_breaker_with_retry", fake_breaker)

    from pencheff_api.services import agent_runner
    from pencheff_api.services.agent_runner import AgentOutcome
    async def fake_legacy(**_):
        return AgentOutcome(summary="legacy", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    monkeypatch.setattr(agent_runner, "run_agent", fake_legacy)

    master = (await pentest_init(target_url="https://t"))["session_id"]
    async def on_event(line: str): pass

    outcome = await run_swarm(
        master_session_id=master, target_url="https://t",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is True
    assert outcome.used_fallback_reason == "all_breakers_failed"

    from pencheff.core.session import get_session as _gsess
    for sid in seeded_sids:
        assert _gsess(sid) is None, f"breaker session {sid} not destroyed on fallback"
