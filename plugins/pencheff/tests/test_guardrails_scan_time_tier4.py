"""Scan-time guardrail probes — tier-4 packs (bias / rag / mcp / coding-agent)."""
from __future__ import annotations

import pytest

from pencheff.modules.llm_red_team.guardrails import (
    _BUILTIN_GUARDRAILS,
    guardrail_cases,
)


@pytest.mark.parametrize("gid,expected_category", [
    ("bias", "LLM09"),
    ("rag", "LLM02"),
    ("mcp", "LLM06"),
    ("coding-agent", "LLM05"),
])
def test_tier4_guardrail_pack_is_registered(gid: str, expected_category: str) -> None:
    assert gid in _BUILTIN_GUARDRAILS
    assert _BUILTIN_GUARDRAILS[gid]["category"] == expected_category
    assert _BUILTIN_GUARDRAILS[gid].get("prompts"), f"{gid} pack has no prompts"
    assert _BUILTIN_GUARDRAILS[gid].get("success_indicators")


def test_guardrail_cases_emits_one_case_per_prompt():
    cases = guardrail_cases({"redteam": {"guardrails": ["bias"]}}, category="LLM09")
    assert len(cases) >= 3
    for c in cases:
        assert c.technique == "guardrail:bias"
        assert c.category == "LLM09"


def test_guardrail_cases_with_multiple_packs():
    cfg = {"redteam": {"guardrails": ["bias", "rag", "mcp", "coding-agent"]}}
    all_cases = []
    for cat in ("LLM02", "LLM05", "LLM06", "LLM09"):
        all_cases.extend(guardrail_cases(cfg, category=cat))
    techniques = {c.technique for c in all_cases}
    assert techniques == {
        "guardrail:bias", "guardrail:rag", "guardrail:mcp", "guardrail:coding-agent",
    }


def test_guardrail_bypass_variants_compose_with_tier4_packs():
    cfg = {"redteam": {"guardrails": ["mcp"], "guardrail_bypass": True}}
    cases = guardrail_cases(cfg, category="LLM06")
    base = [c for c in cases if not c.technique.endswith(":bypass")]
    bypass = [c for c in cases if c.technique.endswith(":bypass")]
    assert base
    assert len(bypass) == len(base) * 3  # three bypass templates


def test_tier4_guardrail_packs_include_remediation_and_cwe():
    """Each tier-4 pack ships with the new fields needed by the report."""
    for gid in ("bias", "rag", "mcp", "coding-agent"):
        pack = _BUILTIN_GUARDRAILS[gid]
        assert pack.get("remediation"), f"{gid} missing remediation"
        assert pack.get("cwe"), f"{gid} missing CWE"
