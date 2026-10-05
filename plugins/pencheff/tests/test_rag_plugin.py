"""RAG plugin pack — load + routing checks."""
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


def test_rag_pack_is_registered() -> None:
    assert "rag" in ADDON_PLUGINS


def test_rag_pack_emits_three_techniques() -> None:
    cases: list = []
    for cat in ("LLM02", "LLM04", "LLM09"):
        cases.extend(addon_cases({"redteam": {"plugins": ["rag"]}}, category=cat))
    techniques = {c.technique for c in cases}
    assert techniques == {"rag:poisoning", "rag:exfiltration", "rag:source-attribution"}


def test_rag_poisoning_routes_to_llm04() -> None:
    cases = addon_cases({"redteam": {"plugins": ["rag"]}}, category="LLM04")
    assert all(c.technique == "rag:poisoning" for c in cases)
    assert len(cases) >= 4


def test_rag_exfiltration_routes_to_llm02() -> None:
    cases = addon_cases({"redteam": {"plugins": ["rag"]}}, category="LLM02")
    assert all(c.technique == "rag:exfiltration" for c in cases)
    assert len(cases) >= 4


def test_rag_source_attribution_routes_to_llm09() -> None:
    cases = addon_cases({"redteam": {"plugins": ["rag"]}}, category="LLM09")
    rag_cases = [c for c in cases if c.technique.startswith("rag:")]
    assert all(c.technique == "rag:source-attribution" for c in rag_cases)
    assert len(rag_cases) >= 3


def test_rag_payloads_carry_canary_doc_ids() -> None:
    """Every poisoning / exfil case names a synthetic doc-CANARY-RAG-N."""
    canary = re.compile(r"doc-CANARY-RAG-\d+")
    cases: list = []
    for cat in ("LLM02", "LLM04", "LLM09"):
        cases.extend(addon_cases({"redteam": {"plugins": ["rag"]}}, category=cat))
    misses = [c.id for c in cases if not canary.search(c.prompt)]
    # One source-attribution case uses an empty-retrieval pretext — exempt.
    assert all(m.endswith("004") for m in misses), misses


def test_rag_pack_has_exfil_link_and_split_payloads():
    cases = []
    for cat in ("LLM02", "LLM04", "LLM09"):
        cases.extend(addon_cases({"redteam": {"plugins": ["rag"]}}, category=cat))
    ids = {c.id for c in cases}
    assert {"rag-exfil-005", "rag-exfil-006", "rag-poison-005", "rag-poison-006"} <= ids


def test_rag_new_payload_regexes_compile():
    cases = []
    for cat in ("LLM02", "LLM04", "LLM09"):
        cases.extend(addon_cases({"redteam": {"plugins": ["rag"]}}, category=cat))
    for c in cases:
        for pat in list(c.success_indicators) + list(c.refusal_patterns):
            re.compile(pat)  # must not raise


def test_rag_exfiltration_count_grew():
    cases = addon_cases({"redteam": {"plugins": ["rag"]}}, category="LLM02")
    assert len(cases) >= 6  # was 4, +2 new exfil payloads
