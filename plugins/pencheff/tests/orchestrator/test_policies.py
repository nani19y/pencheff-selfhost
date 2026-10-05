"""Smoke tests for the policy YAML loader."""

from __future__ import annotations

from pencheff.core.orchestrator.policies import load_policies


def test_all_policies_load():
    p = load_policies(reload=True)
    assert p.tool_selection["version"] >= 1
    assert p.parameters["version"] >= 1
    assert p.chains["version"] >= 1
    assert p.fallbacks["version"] >= 1
    assert p.throttle["version"] >= 1
    assert p.cve_correlation["version"] >= 1
    assert p.confidence["version"] >= 1


def test_versions_dict():
    p = load_policies(reload=True)
    versions = p.versions
    assert set(versions.keys()) == {
        "tool_selection",
        "parameters",
        "chains",
        "fallbacks",
        "throttle",
        "cve_correlation",
        "confidence",
    }
    assert all(v >= 1 for v in versions.values())


def test_tool_selection_has_web_profile():
    p = load_policies(reload=True)
    assert "web" in p.tool_selection["profiles"]
    assert "discovery" in p.tool_selection["profiles"]["web"]
