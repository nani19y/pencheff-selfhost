# apps/api/tests/test_scans_mcp_kind_gate.py
"""The mcp 409 'not yet available' gate was removed in Plan 3 (dispatch wired).
This guards against the gate being reintroduced."""
from __future__ import annotations

import inspect

from pencheff_api.routers import scans


def test_mcp_not_yet_available_gate_is_removed():
    src = inspect.getsource(scans.start_scan)
    assert "mcp_kind_scanning_not_yet_available" not in src, (
        "the temporary mcp scan gate must be removed once dispatch is wired"
    )
