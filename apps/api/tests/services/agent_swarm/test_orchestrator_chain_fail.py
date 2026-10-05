"""ChainAgent crashing must NOT trip the orchestrator. Breaker findings
still ship, summary is synthesised from breaker results."""
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
async def test_chain_failure_is_non_fatal(llm_settings, monkeypatch):
    from pencheff_api.services.agent_swarm import orchestrator as orch
    from pencheff_api.services.agent_swarm import recon as recon_mod
    from pencheff_api.services.agent_swarm.snapshot import (
        DiscoveredEndpoint, ReconSnapshot,
    )
    from datetime import datetime, timezone

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

    # Patch recon module directly — run_swarm imports run_recon_phase locally.
    async def fake_recon(**_): return snap
    monkeypatch.setattr(recon_mod, "run_recon_phase", fake_recon)

    async def fake_breaker(*, spec, **kwargs):
        return orch.BreakerResult(
            agent_name=spec.name, success=True,
            finding_ids=(), summary="ok", turns=1, tool_calls=1,
            error=None, breaker_session_id=None,
        )
    monkeypatch.setattr(orch, "_run_breaker_with_retry", fake_breaker)

    # run_swarm does `from .chain import _run_chain_phase/_run_compliance_phase`
    # locally, so patch the chain module directly.
    from pencheff_api.services.agent_swarm import chain as chain_mod
    from pencheff_api.services.agent_swarm.agent_loop import AgentOutcome

    async def boom_chain(**_): raise RuntimeError("chain blew up")
    monkeypatch.setattr(chain_mod, "_run_chain_phase", boom_chain)

    # Stub compliance so it doesn't consume an LLM turn.
    async def fake_compliance(**_):
        return AgentOutcome(
            summary="", tool_calls=0, turns=0,
            finished_cleanly=True, reason="finished",
        )
    monkeypatch.setattr(chain_mod, "_run_compliance_phase", fake_compliance)

    # Stub proof + payload so they don't consume LLM turns.
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

    sid = (await pentest_init(target_url="https://t"))["session_id"]
    events: list[str] = []
    async def on_event(line: str): events.append(line)

    outcome = await run_swarm(
        master_session_id=sid, target_url="https://t",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is False  # chain failure is non-fatal
    assert "ChainAgent unavailable" in outcome.summary
    assert len(outcome.breaker_results) == 13
    assert any("[Chain] failed" in e for e in events)
