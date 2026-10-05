"""AdminAccessAgent runs in Phase 3 — it only acts if a verified
admin-access finding exists; otherwise it emits a skip summary.

Playwright integration is NOT tested here (requires a live browser).
We verify:
  - The agent fires and its summary stitches into the output under
    '## Admin Panel Access (Verified)'.
  - The skip path (no qualifying finding) produces the expected summary text.
  - Failures are isolated: AdminAccessAgent crashing does not break the scan.
  - The agent's tool registry NEVER includes test_endpoint (no POST mutation).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm import run_swarm
from tests.services.agent_swarm._scripted_llm import ScriptedLLM, with_finish


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
async def test_phase3_includes_admin_access(llm_settings, monkeypatch):
    """AdminAccessAgent output appears under '## Admin Panel Access (Verified)'."""
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

    # Stub all other Phase 3 agents except AdminAccess.
    async def fake_proof(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_payload(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_evidence(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    monkeypatch.setattr(chain_mod, "_run_proof_of_impact_phase", fake_proof)
    monkeypatch.setattr(chain_mod, "_run_payload_crafting_phase", fake_payload)
    monkeypatch.setattr(chain_mod, "_run_evidence_capture_phase", fake_evidence)

    # Phase 3: chain + compliance + admin = 3 LLM turns.
    ScriptedLLM([
        with_finish("chain confirmed"),
        with_finish("compliance ok"),
        with_finish(
            "Admin panel accessed via auth_bypass finding f001. "
            "Screenshot: .pencheff/evidence/sid/f001-admin.png. "
            "Links: Dashboard, Users, Settings, Audit Logs, Logout."
        ),
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
    assert any("[AdminAccess]" in e for e in events)
    assert "Admin Panel Access (Verified)" in outcome.summary
    assert "f001-admin.png" in outcome.summary


@pytest.mark.asyncio
async def test_admin_access_skip_path(llm_settings, monkeypatch):
    """When no qualifying finding exists the agent emits the skip summary.
    The skip text must appear in the stitched output."""
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

    async def fake_proof(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_payload(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_evidence(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    monkeypatch.setattr(chain_mod, "_run_proof_of_impact_phase", fake_proof)
    monkeypatch.setattr(chain_mod, "_run_payload_crafting_phase", fake_payload)
    monkeypatch.setattr(chain_mod, "_run_evidence_capture_phase", fake_evidence)

    # The agent's scripted LLM goes straight to finish with the skip message.
    ScriptedLLM([
        with_finish("chain confirmed"),
        with_finish("compliance ok"),
        with_finish("skipped: no verified admin-access finding"),
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
    # The skip summary is non-empty so the section header is injected.
    assert "Admin Panel Access (Verified)" in outcome.summary
    assert "skipped" in outcome.summary


@pytest.mark.asyncio
async def test_admin_access_failure_does_not_break_scan(llm_settings, monkeypatch):
    """If AdminAccessAgent crashes, ChainAgent's summary still ships
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

    async def boom_admin(**_): raise RuntimeError("admin blew up")
    monkeypatch.setattr(chain_mod, "_run_admin_access_phase", boom_admin)

    async def fake_proof(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_payload(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    async def fake_evidence(**_):
        return AgentOutcome(summary="", tool_calls=0, turns=0,
                            finished_cleanly=True, reason="finished")
    monkeypatch.setattr(chain_mod, "_run_proof_of_impact_phase", fake_proof)
    monkeypatch.setattr(chain_mod, "_run_payload_crafting_phase", fake_payload)
    monkeypatch.setattr(chain_mod, "_run_evidence_capture_phase", fake_evidence)

    # Chain + compliance still run; admin does not consume a turn.
    ScriptedLLM([
        with_finish("chain ok despite admin failure"),
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
    assert "chain ok despite admin failure" in outcome.summary
    assert any("[AdminAccess] failed" in e for e in events)
    # Admin failure must NOT inject the section header.
    assert "Admin Panel Access (Verified)" not in outcome.summary


def test_admin_access_tool_registry_excludes_test_endpoint():
    """AdminAccessAgent's tool registry must not include test_endpoint.

    test_endpoint accepts arbitrary HTTP methods (POST, PUT, PATCH,
    DELETE) and could be used to mutate state — it must never appear
    in the admin agent's tool subset.
    """
    from pencheff_api.services.agent_swarm.tools import select_tools

    admin_tool_names = (
        "get_findings",
        "playwright_navigate",
        "playwright_screenshot",
        "playwright_enumerate_links",
        "playwright_logout",
        "finish",
    )
    tools = select_tools("standard", admin_tool_names)
    names = {t.name for t in tools}
    assert "test_endpoint" not in names, (
        "test_endpoint must never be in AdminAccessAgent's tool registry — "
        "it supports POST/PUT/DELETE which would allow state mutation."
    )
    # All expected tools are present.
    for expected in admin_tool_names:
        assert expected in names, f"expected tool {expected!r} missing from registry"
