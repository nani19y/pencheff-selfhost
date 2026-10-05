"""Profile → per-phase max_turns wiring."""
from __future__ import annotations

import pytest


@pytest.fixture
def settings(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    # Anchor explicit values so we test wiring, not env defaults.
    monkeypatch.setattr(s, "swarm_turns_recon_quick", 8)
    monkeypatch.setattr(s, "swarm_turns_recon_standard", 12)
    monkeypatch.setattr(s, "swarm_turns_recon_deep", 18)
    monkeypatch.setattr(s, "swarm_turns_breaker_quick", 6)
    monkeypatch.setattr(s, "swarm_turns_breaker_standard", 10)
    monkeypatch.setattr(s, "swarm_turns_breaker_deep", 16)
    monkeypatch.setattr(s, "swarm_turns_chain_quick", 8)
    monkeypatch.setattr(s, "swarm_turns_chain_standard", 12)
    monkeypatch.setattr(s, "swarm_turns_chain_deep", 20)
    return s


def test_recon_budget_table(settings):
    from pencheff_api.services.agent_swarm.recon import _recon_budget
    assert _recon_budget("quick") == 8
    assert _recon_budget("standard") == 12
    assert _recon_budget("deep") == 18
    assert _recon_budget("nonsense") == 12  # falls back to standard


def test_breaker_budget_table(settings):
    from pencheff_api.services.agent_swarm.breakers import _breaker_budget
    assert _breaker_budget("quick") == 6
    assert _breaker_budget("standard") == 10
    assert _breaker_budget("deep") == 16


def test_chain_budget_table(settings):
    from pencheff_api.services.agent_swarm.chain import _chain_budget
    assert _chain_budget("quick") == 8
    assert _chain_budget("standard") == 12
    assert _chain_budget("deep") == 20
