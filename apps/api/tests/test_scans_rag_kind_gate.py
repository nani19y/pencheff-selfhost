from __future__ import annotations
import inspect
from pencheff_api.routers import scans


def test_rag_not_yet_available_gate_is_removed():
    assert "rag_kind_scanning_not_yet_available" not in inspect.getsource(scans.start_scan)
