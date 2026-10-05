"""persist_swarm_telemetry writes the documented summary_payload['swarm']
shape to the Scan row."""
from __future__ import annotations

import pytest

from pencheff_api.services.agent_swarm.orchestrator import (
    BreakerResult, SwarmOutcome,
)
from pencheff_api.services.agent_swarm.telemetry import build_swarm_summary_payload


def test_payload_shape_matches_design():
    outcome = SwarmOutcome(
        summary="chain summary",
        breaker_results=(
            BreakerResult("InjectionAgent", True, ("f1", "f2"),
                          "found 2", 5, 8, None, "sid-i"),
            BreakerResult("AuthAgent", False, (), "", 0, 0,
                          "transient_after_retry: 503", "sid-a"),
        ),
        used_fallback=False, used_fallback_reason=None,
        total_tool_calls=8, total_turns=5,
    )
    payload = build_swarm_summary_payload(outcome)
    assert payload["used_fallback"] is False
    assert payload["used_fallback_reason"] is None
    assert len(payload["breakers"]) == 2
    inj = next(b for b in payload["breakers"] if b["agent"] == "InjectionAgent")
    assert inj == {
        "agent": "InjectionAgent",
        "success": True,
        "findings": 2,
        "turns": 5,
        "tool_calls": 8,
        "error": None,
    }
    auth = next(b for b in payload["breakers"] if b["agent"] == "AuthAgent")
    assert auth["success"] is False
    assert auth["findings"] == 0
    assert "transient_after_retry" in auth["error"]


def test_payload_records_fallback_reason():
    outcome = SwarmOutcome(
        summary="legacy", breaker_results=(),
        used_fallback=True,
        used_fallback_reason="all_breakers_failed",
        total_tool_calls=2, total_turns=2,
    )
    payload = build_swarm_summary_payload(outcome)
    assert payload["used_fallback"] is True
    assert payload["used_fallback_reason"] == "all_breakers_failed"
    assert payload["breakers"] == []
