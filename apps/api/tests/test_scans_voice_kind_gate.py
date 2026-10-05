"""The voice 409 'not yet available' gate was removed in Voice Plan 3 (dispatch
wired). This guards against the gate being reintroduced.

Mirrors test_scans_ml_model_kind_gate.py — the shipped guard pattern is pure
source-inspection of start_scan.
"""
from __future__ import annotations

import inspect

from pencheff_api.routers import scans


def test_voice_not_yet_available_gate_is_removed():
    src = inspect.getsource(scans.start_scan)
    assert "voice_kind_scanning_not_yet_available" not in src, (
        "the temporary voice scan gate must be removed once dispatch is wired"
    )
