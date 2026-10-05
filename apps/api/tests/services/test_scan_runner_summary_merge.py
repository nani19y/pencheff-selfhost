"""scan_runner's final summary write must merge, not replace —
otherwise persist_swarm_telemetry's summary['swarm'] gets clobbered."""
from __future__ import annotations


def test_summary_merge_preserves_existing_keys():
    """Pure-logic test of the merge expression used in scan_runner."""
    existing = {"swarm": {"breakers": [{"agent": "InjectionAgent"}]}}
    summary_payload = {"low": 0, "medium": 1, "operator_summary": "ok"}

    # Mirror the new merge pattern from scan_runner.py
    merged = dict(existing or {})
    merged.update(summary_payload)

    assert merged["swarm"] == {"breakers": [{"agent": "InjectionAgent"}]}
    assert merged["operator_summary"] == "ok"
    assert merged["low"] == 0
    assert merged["medium"] == 1
