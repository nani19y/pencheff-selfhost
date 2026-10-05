"""Aegis / UnsafeBench / XSTest paraphrased seed packs — load checks."""
from __future__ import annotations

import re

import pytest

from pencheff.modules.llm_red_team.datasets import dataset_cases
from pencheff.modules.llm_red_team.engine import Verdict, evaluate


@pytest.mark.parametrize("dataset_name,min_size", [
    ("aegis", 7),
    ("unsafebench", 6),
    ("xstest", 8),
])
def test_dataset_loads_and_has_minimum_size(dataset_name: str, min_size: int) -> None:
    cases = dataset_cases({"redteam": {"datasets": [dataset_name]}})
    assert len(cases) >= min_size, f"{dataset_name}: only {len(cases)} cases, want ≥{min_size}"


def test_aegis_techniques_cover_multiple_categories() -> None:
    """Aegis spans multiple OWASP-LLM categories — not all collapsed to LLM09."""
    cases = dataset_cases({"redteam": {"datasets": ["aegis"]}})
    cats = {c.category for c in cases}
    assert {"LLM05", "LLM09"}.issubset(cats), f"aegis only spans {cats}"


def test_xstest_inverts_verdict_semantics() -> None:
    """XSTest probes treat refusal-language as the success indicator.

    The advisor flagged this as the discriminating contract: when an
    XSTest probe is fed a refusal-shaped reply, the engine should
    return VULNERABLE (over-refusal == finding). When fed a compliant
    reply, the engine should return REFUSED (no finding).
    """
    cases = dataset_cases({"redteam": {"datasets": ["xstest"]}})
    assert cases, "xstest is empty"

    # Pick the first XSTest case for a deterministic check.
    tc = cases[0]
    refusal_text = "I'm sorry, I can't help with that request."
    compliant_text = "Sure — to kill a stuck Python process on macOS, run `kill -9 <pid>` after finding the pid with `ps aux`."

    assert evaluate(tc, refusal_text) == Verdict.VULNERABLE, (
        "XSTest probe should fire on a refusal reply (over-refusal == finding)"
    )
    assert evaluate(tc, compliant_text) == Verdict.REFUSED, (
        "XSTest probe should NOT fire when the model actually answers"
    )


def test_xstest_does_not_pollute_other_datasets() -> None:
    """XSTest's inverted patterns only attach to xstest cases — Aegis still
    treats refusal as REFUSED, the standard behaviour."""
    aegis = dataset_cases({"redteam": {"datasets": ["aegis"]}})
    refusal_text = "I'm sorry, I can't help with that request."
    # At least one Aegis case should yield REFUSED on a refusal reply.
    refused_count = sum(1 for c in aegis if evaluate(c, refusal_text) == Verdict.REFUSED)
    assert refused_count >= 1, "aegis cases never returned REFUSED on a refusal reply"


def test_unsafebench_seeds_are_text_proxies_not_image_blobs() -> None:
    """UnsafeBench is image-paired upstream; pencheff ships text proxies only.

    Sanity check: no seed prompt contains a base64 image data URL.
    """
    cases = dataset_cases({"redteam": {"datasets": ["unsafebench"]}})
    pattern = re.compile(r"data:image/[a-z]+;base64", re.IGNORECASE)
    for c in cases:
        assert not pattern.search(c.prompt), f"{c.id} appears to embed an image blob"


def test_dataset_cases_routes_by_category_filter() -> None:
    """Caller can filter cases to one OWASP category."""
    cases = dataset_cases({"redteam": {"datasets": ["aegis"]}}, category="LLM05")
    assert cases, "category filter should return at least one row for LLM05"
    assert all(c.category == "LLM05" for c in cases)
