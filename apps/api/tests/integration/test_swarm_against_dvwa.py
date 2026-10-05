"""Live integration test against DVWA / Juice-Shop.

Off-CI by default. To run:

  1. Bring up the toolchain locally:
       docker compose -f docker-compose.toolchain.yml up dvwa juice-shop
  2. Set the credentials your AGENT_LLM_* env points at.
  3. Run:
       cd apps/api && uv run pytest -m live tests/integration/test_swarm_against_dvwa.py -v

This test validates that the swarm runs end-to-end against a real
target with a real LLM. It is intentionally tolerant about WHICH
findings each breaker produces — only the structural invariants are
asserted.
"""
from __future__ import annotations

import os

import pytest

from pencheff.server import pentest_init
from pencheff_api.services.agent_swarm import run_swarm


pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_swarm_against_dvwa():
    target = os.environ.get("LIVE_TARGET_URL", "http://localhost:4280")
    if not os.environ.get("AGENT_LLM_API_KEY"):
        pytest.skip("AGENT_LLM_API_KEY not configured")

    sid = (await pentest_init(target_url=target))["session_id"]
    events: list[str] = []
    async def on_event(line: str): events.append(line)

    outcome = await run_swarm(
        master_session_id=sid, target_url=target,
        credentials=None, profile="quick",
        scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=False,
    )
    assert outcome.used_fallback is False, (
        f"swarm fell back: {outcome.used_fallback_reason}"
    )
    assert len(outcome.breaker_results) == 7
    # All 9 agents must have emitted at least one event (Recon, 7 breakers, Chain).
    for marker in ("[Recon]", "[InjectionAgent]", "[ClientSideAgent]",
                    "[AuthAgent]", "[AuthzAgent]", "[APIAgent]",
                    "[InfraAgent]", "[CloudAgent]", "[Chain]"):
        assert any(marker in e for e in events), (
            f"no events seen with prefix {marker!r}"
        )
    # At least one finding should be tagged with discovered_by_agent (DVWA is
    # rich enough that any breaker should hit something).
    from pencheff.server import get_findings
    out = (await get_findings(session_id=sid))["findings"]
    tagged = [f for f in out if f.get("metadata", {}).get("discovered_by_agent")]
    assert tagged, "no findings with discovered_by_agent attribution"
