"""Selector returns ordered candidates by confidence."""

from __future__ import annotations

from pencheff.core.orchestrator.selector import Selector


def test_web_discovery_returns_known_tools():
    sel = Selector()
    candidates = sel.candidates("web", "discovery")
    tools = [c.tool for c in candidates]
    assert "subfinder" in tools
    assert "amass" in tools
    assert "httpx" in tools


def test_candidates_sorted_by_confidence_desc():
    sel = Selector()
    candidates = sel.candidates("web", "injection")
    confidences = [c.confidence for c in candidates]
    assert confidences == sorted(confidences, reverse=True)


def test_unknown_combo_returns_empty():
    sel = Selector()
    assert sel.candidates("nonexistent", "discovery") == []
    assert sel.candidates("web", "telepathy") == []


def test_known_profiles_includes_web_and_ctf():
    sel = Selector()
    profiles = sel.known_profiles()
    assert "web" in profiles
    assert "ctf" in profiles


def test_native_flag_propagates():
    sel = Selector()
    crypto = sel.candidates("ctf", "crypto")
    assert any(c.native for c in crypto)
