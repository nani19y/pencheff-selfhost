# apps/api/tests/test_scans_ml_model_kind_gate.py
"""The ml_model 409 'not yet available' gate was removed in ML Plan 3 (dispatch
wired). This guards against the gate being reintroduced.

Mirrors test_scans_rag_kind_gate.py / test_scans_mcp_kind_gate.py — the shipped
guard pattern is pure source-inspection of start_scan.
"""
from __future__ import annotations

import inspect

from pencheff_api.routers import scans


def test_ml_model_not_yet_available_gate_is_removed():
    src = inspect.getsource(scans.start_scan)
    assert "ml_model_kind_scanning_not_yet_available" not in src, (
        "the temporary ml_model scan gate must be removed once dispatch is wired"
    )
