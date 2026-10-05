"""MCP plugin pack — load + technique coverage checks."""
from __future__ import annotations

import pytest

from pencheff.modules.llm_red_team.addon_plugins import (
    ADDON_PLUGINS,
    addon_cases,
    reset_cache,
)


@pytest.fixture(autouse=True)
def _reset() -> None:
    reset_cache()


def test_mcp_pack_is_registered() -> None:
    assert "mcp" in ADDON_PLUGINS


def test_mcp_pack_emits_four_techniques() -> None:
    cases = addon_cases({"redteam": {"plugins": ["mcp"]}}, category="LLM06")
    techniques = {c.technique for c in cases}
    assert techniques == {
        "mcp:tool-poisoning",
        "mcp:tool-name-collision",
        "mcp:untrusted-server-prompt",
        "mcp:resource-exfil",
    }


def test_mcp_pack_routes_only_to_llm06() -> None:
    for cat in ("LLM01", "LLM02", "LLM04", "LLM05", "LLM07", "LLM08", "LLM09", "LLM10"):
        rows = addon_cases({"redteam": {"plugins": ["mcp"]}}, category=cat)
        assert all(not c.technique.startswith("mcp:") for c in rows), (
            f"MCP rows leaked into {cat}: {[c.id for c in rows if c.technique.startswith('mcp:')]}"
        )


def test_mcp_pack_severity_distribution() -> None:
    """At least one critical, no info-only padding."""
    from pencheff.config import Severity
    cases = addon_cases({"redteam": {"plugins": ["mcp"]}}, category="LLM06")
    sevs = {c.severity for c in cases}
    assert Severity.CRITICAL in sevs
    assert Severity.INFO not in sevs


def test_mcp_pack_has_deterministic_verdicts() -> None:
    """Every MCP probe carries non-empty success_indicators so verdicts are deterministic."""
    cases = addon_cases({"redteam": {"plugins": ["mcp"]}}, category="LLM06")
    for c in cases:
        assert c.success_indicators, f"{c.id} missing success_indicators"
        assert c.refusal_patterns, f"{c.id} missing refusal_patterns"
