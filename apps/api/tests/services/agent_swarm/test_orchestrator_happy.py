"""Full pipeline with stubbed LLM: recon → 13 breakers (all succeed) →
merge → chain + compliance + proof + payload + evidence + admin (6-way Phase 3).
SwarmOutcome.used_fallback is False; breaker_results has 13 entries."""
from __future__ import annotations

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm import run_swarm
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


@pytest.mark.asyncio
async def test_happy_pipeline_runs_all_phases(llm_settings, monkeypatch):
    # Recon: one tool call + finish  → 2 turns
    # AuthzAgent quiet-quits without consuming a turn (no creds supplied)
    # Each of remaining 12 breakers: just `finish`  → 1 turn × 12
    # Chain: just `finish`                          → 1 turn
    # Compliance: just `finish`                     → 1 turn
    # ProofOfImpact: just `finish`                  → 1 turn
    # PayloadCrafting: just `finish`                → 1 turn
    # EvidenceCapture: just `finish`                → 1 turn
    # AdminAccess: just `finish`                    → 1 turn
    # Total scripted turns: 2 + 12 + 1 + 1 + 1 + 1 + 1 + 1 = 20
    turns = [
        with_tool_call("recon_passive", {}),
        with_finish("recon ok"),
    ]
    for _ in range(12):  # 12 breakers actually run; AuthzAgent quiet-quits
        turns.append(with_finish("breaker ok"))
    turns.append(with_finish("chain ok"))
    turns.append(with_finish("compliance ok"))
    turns.append(with_finish("proof ok"))      # ProofOfImpactAgent
    turns.append(with_finish("payload ok"))    # PayloadCraftingAgent
    turns.append(with_finish("evidence ok"))   # EvidenceCaptureAgent
    turns.append(with_finish("admin ok"))      # AdminAccessAgent
    ScriptedLLM(turns).install(monkeypatch)

    sid = (await pentest_init(target_url="https://t.example.com"))["session_id"]
    # Inject a fake endpoint so _freeze_snapshot's empty check passes.
    from pencheff.core.session import get_session as _gsess
    _gsess(sid).discovered.endpoints.append({
        "url": "https://t.example.com/api/u",
        "method": "GET",
        "status": 200,
        "content_type": "application/json",
        "parameters": ["id"],
    })
    events: list[str] = []
    async def on_event(line: str): events.append(line)

    outcome = await run_swarm(
        master_session_id=sid,
        target_url="https://t.example.com",
        credentials=None, profile="standard",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is False
    assert len(outcome.breaker_results) == 13
    # Chain summary is present in the stitched output.
    assert "chain ok" in outcome.summary
    assert any("[Recon]" in e for e in events)
    assert any("[Chain]" in e for e in events)
    assert any("[Compliance]" in e for e in events)
    assert any("[ProofOfImpact]" in e for e in events)
    assert any("[PayloadCrafting]" in e for e in events)
    assert any("[EvidenceCapture]" in e for e in events)
    assert any("[AdminAccess]" in e for e in events)
    # AuthzAgent quiet-quit (no auth in snapshot) but still success.
    authz = next(r for r in outcome.breaker_results if r.agent_name == "AuthzAgent")
    assert authz.success is True
    assert authz.tool_calls == 0
