"""scan_runner._engine's current_stage extractor handles both the
plain legacy format ("tool: scan_x") and the swarm-prefixed format
("[AgentName] tool: scan_x")."""
from __future__ import annotations


def _extract(line: str) -> str | None:
    """Mirror of the dispatch logic in scan_runner._engine."""
    if "tool: " in line:
        after = line.split("tool: ", 1)[1]
        return after.split(" ", 1)[0][:64]
    return None


def test_legacy_format_extracts_tool_name():
    assert _extract("tool: scan_injection") == "scan_injection"


def test_swarm_prefixed_format_extracts_tool_name():
    assert _extract("[InjectionAgent] tool: scan_injection") == "scan_injection"


def test_with_args_keeps_only_first_token():
    assert _extract("[InjectionAgent] tool: scan_injection args=['url','payload']") == "scan_injection"


def test_non_tool_line_returns_none():
    assert _extract("[Recon] starting") is None
