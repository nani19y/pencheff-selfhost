"""ProofOfImpactAgent runs in Phase 3 alongside ChainAgent, ComplianceAgent,
and PayloadCraftingAgent — producing a structured impact assessment table."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm import run_swarm
from tests.services.agent_swarm._scripted_llm import (
    ScriptedLLM, with_finish,
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


def _make_snap():
    from pencheff_api.services.agent_swarm.snapshot import (
        DiscoveredEndpoint, ReconSnapshot,
    )
    return ReconSnapshot(
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


@pytest.mark.asyncio
async def test_phase3_includes_proof_of_impact(llm_settings, monkeypatch):
    """ProofOfImpactAgent output appears in the Phase 3 summary under
    the '## Proof of Impact' section header."""
    from pencheff_api.services.agent_swarm import orchestrator as orch

    async def fake_recon(**_): return _make_snap()
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.recon.run_recon_phase",
        fake_recon,
    )

    async def fake_breaker(*, spec, **kwargs):
        return orch.BreakerResult(
            agent_name=spec.name, success=True,
            finding_ids=(), summary="ok", turns=1, tool_calls=1,
            error=None, breaker_session_id=None,
        )
    monkeypatch.setattr(orch, "_run_breaker_with_retry", fake_breaker)

    # Stub payload crafting + evidence + admin so only proof consumes its scripted turn.
    from pencheff_api.services.agent_swarm import chain as chain_mod
    from pencheff_api.services.agent_swarm.agent_loop import AgentOutcome

    async def fake_payload(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_evidence(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_admin(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    monkeypatch.setattr(chain_mod, "_run_payload_crafting_phase", fake_payload)
    monkeypatch.setattr(chain_mod, "_run_evidence_capture_phase", fake_evidence)
    monkeypatch.setattr(chain_mod, "_run_admin_access_phase", fake_admin)

    # Phase 3: chain + compliance + proof = 3 LLM turns
    ScriptedLLM([
        with_finish("chain confirmed"),
        with_finish("PCI-DSS Req 8"),
        with_finish("SQLi | /api/login | yes | 4 tables | 12 cols | ~50000 rows"),
    ]).install(monkeypatch)

    sid = (await pentest_init(target_url="https://t"))["session_id"]
    events: list[str] = []
    async def on_event(line: str): events.append(line)

    outcome = await run_swarm(
        master_session_id=sid, target_url="https://t",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is False
    assert any("[ProofOfImpact]" in e for e in events)
    assert "Proof of Impact" in outcome.summary
    assert "SQLi" in outcome.summary


@pytest.mark.asyncio
async def test_proof_of_impact_failure_does_not_break_scan(llm_settings, monkeypatch):
    """If ProofOfImpactAgent crashes, ChainAgent's summary still ships
    and the scan does not fall back to the legacy runner."""
    from pencheff_api.services.agent_swarm import orchestrator as orch

    async def fake_recon(**_): return _make_snap()
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.recon.run_recon_phase",
        fake_recon,
    )

    async def fake_breaker(*, spec, **kwargs):
        return orch.BreakerResult(
            agent_name=spec.name, success=True,
            finding_ids=(), summary="ok", turns=1, tool_calls=1,
            error=None, breaker_session_id=None,
        )
    monkeypatch.setattr(orch, "_run_breaker_with_retry", fake_breaker)

    from pencheff_api.services.agent_swarm import chain as chain_mod
    from pencheff_api.services.agent_swarm.agent_loop import AgentOutcome

    async def boom_proof(**_): raise RuntimeError("proof blew up")
    monkeypatch.setattr(chain_mod, "_run_proof_of_impact_phase", boom_proof)

    async def fake_payload(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_evidence(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_admin(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    monkeypatch.setattr(chain_mod, "_run_payload_crafting_phase", fake_payload)
    monkeypatch.setattr(chain_mod, "_run_evidence_capture_phase", fake_evidence)
    monkeypatch.setattr(chain_mod, "_run_admin_access_phase", fake_admin)

    # Chain + compliance still run; proof does not consume a turn.
    ScriptedLLM([
        with_finish("chain ok despite proof failure"),
        with_finish("compliance ok"),
    ]).install(monkeypatch)

    sid = (await pentest_init(target_url="https://t"))["session_id"]
    events: list[str] = []
    async def on_event(line: str): events.append(line)

    outcome = await run_swarm(
        master_session_id=sid, target_url="https://t",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is False
    assert "chain ok despite proof failure" in outcome.summary
    assert any("[ProofOfImpact] failed" in e for e in events)
    # Proof failure must NOT inject the section header.
    assert "Proof of Impact" not in outcome.summary
