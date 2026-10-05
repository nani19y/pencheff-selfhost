"""3 of 10 breakers crash; 7 survive; chain still runs over the survivors."""
from __future__ import annotations

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm import run_swarm
from tests.services.agent_swarm._scripted_llm import ScriptedLLM, ScriptedTurn, with_finish, with_tool_call


@pytest.fixture
def llm_settings(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "agent_llm_api_key", "sk-test")
    monkeypatch.setattr(s, "agent_llm_base_url", "https://api.example.com/v1")
    monkeypatch.setattr(s, "agent_llm_model", "test")
    monkeypatch.setattr(s, "agent_llm_max_tokens", 1024)
    monkeypatch.setattr(s, "agent_request_timeout", 30.0)
    monkeypatch.setattr(s, "swarm_breaker_retry_attempts", 0)  # disable retry to keep script-counting simple
    return s


@pytest.mark.asyncio
async def test_partial_failure_keeps_survivors(llm_settings, monkeypatch):
    """Breakers run in concurrent gather order — to make this deterministic
    we patch _run_breaker_with_retry directly to return scripted results."""
    from pencheff_api.services.agent_swarm import orchestrator as orch

    expected_names = {
        "InjectionAgent", "ClientSideAgent", "AuthAgent", "AuthzAgent",
        "APIAgent", "InfraAgent", "CloudAgent",
        "LLMRedTeamAgent", "SupplyChainAgent", "K8sAgent",
        "ActiveDirectoryAgent", "MobileAppAgent", "ThreatModelAgent",
    }

    async def fake_breaker(*, spec, agent, snapshot, on_event, **kwargs):
        if spec.name in {"AuthAgent", "InfraAgent", "CloudAgent"}:
            return orch.BreakerResult(
                agent_name=spec.name, success=False,
                finding_ids=(), summary="", turns=0, tool_calls=0,
                error="test_failure", breaker_session_id="sid-x",
            )
        return orch.BreakerResult(
            agent_name=spec.name, success=True,
            finding_ids=(), summary="ok", turns=1, tool_calls=1,
            error=None, breaker_session_id="sid-y",
        )

    monkeypatch.setattr(orch, "_run_breaker_with_retry", fake_breaker)

    # Stub proof + payload + evidence + admin so they don't consume LLM turns.
    from pencheff_api.services.agent_swarm import chain as chain_mod
    from pencheff_api.services.agent_swarm.agent_loop import AgentOutcome
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

    # Recon needs a real LLM call: 1 tool call + 1 finish; chain: 1 finish;
    # compliance: 1 finish. Proof + payload are stubbed above.
    ScriptedLLM([
        with_tool_call("recon_passive", {}),
        with_finish("recon ok"),
        with_finish("chain ok over survivors"),
        with_finish("compliance ok"),
    ]).install(monkeypatch)

    sid = (await pentest_init(target_url="https://t.example.com"))["session_id"]
    from pencheff.core.session import get_session as _gsess
    _gsess(sid).discovered.endpoints.append({
        "url": "https://t/u", "method": "GET", "status": 200,
        "content_type": None, "parameters": [],
    })

    async def on_event(line: str): pass
    outcome = await run_swarm(
        master_session_id=sid,
        target_url="https://t.example.com",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is False
    names = {r.agent_name for r in outcome.breaker_results}
    assert names == expected_names
    failed = {r.agent_name for r in outcome.breaker_results if not r.success}
    assert failed == {"AuthAgent", "InfraAgent", "CloudAgent"}
