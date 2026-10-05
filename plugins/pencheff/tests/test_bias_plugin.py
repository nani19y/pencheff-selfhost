"""Bias plugin pack — load + dispatch + dedup checks."""
from __future__ import annotations

import re

import pytest

from pencheff.modules.llm_red_team.addon_plugins import (
    ADDON_PLUGINS,
    addon_cases,
    reset_cache,
)


@pytest.fixture(autouse=True)
def _reset() -> None:
    reset_cache()


def test_bias_pack_is_registered() -> None:
    assert "bias" in ADDON_PLUGINS


def test_bias_pack_emits_four_dimensions() -> None:
    cases = addon_cases({"redteam": {"plugins": ["bias"]}}, category="LLM09")
    techniques = {c.technique for c in cases}
    assert techniques == {"bias:age", "bias:disability", "bias:gender", "bias:race"}


def test_bias_pack_has_at_least_five_per_dimension() -> None:
    cases = addon_cases({"redteam": {"plugins": ["bias"]}}, category="LLM09")
    by_tech: dict[str, int] = {}
    for c in cases:
        by_tech[c.technique] = by_tech.get(c.technique, 0) + 1
    for tech, n in by_tech.items():
        assert n >= 5, f"{tech} has only {n} payloads, want ≥5"


def test_bias_pack_routes_only_to_llm09() -> None:
    # No bias rows should fall into another OWASP bucket.
    for cat in ("LLM01", "LLM02", "LLM05", "LLM06"):
        rows = addon_cases({"redteam": {"plugins": ["bias"]}}, category=cat)
        assert all(c.technique not in {"bias:age", "bias:disability", "bias:gender", "bias:race"} for c in rows)


def test_bias_pack_refusals_match_obvious_refusal() -> None:
    """Sanity check: a clear refusal string should trigger every probe's refusal pattern."""
    refusal_text = "I'm sorry, I can't make that claim — it would be discriminatory."
    cases = addon_cases({"redteam": {"plugins": ["bias"]}}, category="LLM09")
    misses: list[str] = []
    for c in cases:
        if not any(re.search(p, refusal_text) for p in c.refusal_patterns):
            misses.append(c.id)
    assert not misses, f"refusal-pattern blind spot in: {misses}"


def test_default_plugins_includes_bias() -> None:
    """No explicit plugin list ⇒ all add-on packs (including bias) load."""
    cases = addon_cases({}, category="LLM09")
    techniques = {c.technique for c in cases}
    assert "bias:age" in techniques
