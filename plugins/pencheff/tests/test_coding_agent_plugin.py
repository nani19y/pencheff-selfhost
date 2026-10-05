"""Coding-agent plugin pack — load + technique coverage checks."""
from __future__ import annotations

import pytest

from pencheff.modules.llm_red_team.addon_plugins import (
    ADDON_PLUGINS,
    addon_cases,
    reset_cache,
)


_EXPECTED_TECHNIQUES = {
    "coding-agent:automation-poisoning",
    "coding-agent:delayed-ci-exfil",
    "coding-agent:generated-vulnerabilities",
    "coding-agent:network-egress-bypass",
    "coding-agent:procfs-credential-read",
    "coding-agent:repo-prompt-injection",
    "coding-agent:sandbox-escape",
    "coding-agent:secret-handling",
    "coding-agent:terminal-output-injection",
    "coding-agent:steganographic-exfil",
    "coding-agent:verifier-sabotage",
}

# OWASP categories that coding-agent rows can land in.
_RELEVANT_CATEGORIES = ("LLM01", "LLM02", "LLM05", "LLM06")


@pytest.fixture(autouse=True)
def _reset() -> None:
    reset_cache()


def _all_coding_agent_cases() -> list:
    out: list = []
    for cat in _RELEVANT_CATEGORIES:
        out.extend(addon_cases({"redteam": {"plugins": ["coding-agent"]}}, category=cat))
    return out


def test_coding_agent_pack_is_registered() -> None:
    assert "coding-agent" in ADDON_PLUGINS


def test_coding_agent_pack_emits_eleven_techniques() -> None:
    cases = _all_coding_agent_cases()
    techniques = {c.technique for c in cases}
    assert techniques == _EXPECTED_TECHNIQUES, (
        f"missing: {_EXPECTED_TECHNIQUES - techniques}, extra: {techniques - _EXPECTED_TECHNIQUES}"
    )


def test_coding_agent_pack_minimum_three_per_technique() -> None:
    cases = _all_coding_agent_cases()
    by_tech: dict[str, int] = {}
    for c in cases:
        by_tech[c.technique] = by_tech.get(c.technique, 0) + 1
    for tech, n in sorted(by_tech.items()):
        assert n >= 3, f"{tech} has only {n} payloads, want ≥3"


def test_coding_agent_payloads_have_remediation() -> None:
    """Every probe ships an actionable remediation — not boilerplate."""
    cases = _all_coding_agent_cases()
    for c in cases:
        assert c.remediation and len(c.remediation) > 30, (
            f"{c.id} remediation looks empty / boilerplate: {c.remediation!r}"
        )


def test_coding_agent_payloads_carry_cwe() -> None:
    """Every probe maps to a CWE for downstream compliance rollup."""
    cases = _all_coding_agent_cases()
    misses = [c.id for c in cases if not c.cwe]
    assert not misses, f"missing CWE on: {misses}"


def test_coding_agent_routes_only_to_relevant_categories() -> None:
    for cat in ("LLM03", "LLM04", "LLM07", "LLM08", "LLM09", "LLM10"):
        rows = addon_cases({"redteam": {"plugins": ["coding-agent"]}}, category=cat)
        assert all(not c.technique.startswith("coding-agent:") for c in rows)


def test_default_plugins_includes_coding_agent() -> None:
    cases: list = []
    for cat in _RELEVANT_CATEGORIES:
        cases.extend(addon_cases({}, category=cat))
    techniques = {c.technique for c in cases}
    assert "coding-agent:repo-prompt-injection" in techniques
