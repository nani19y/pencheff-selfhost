"""Tier-4 always-on coverage — TAP/GOAT/Hydra + Aegis/UnsafeBench/XSTest."""
from __future__ import annotations

import pytest

from pencheff.config import Severity
from pencheff.modules.llm_red_team.datasets import AUTO_DEFAULT_DATASETS, dataset_cases
from pencheff.modules.llm_red_team.engine import TestCase
from pencheff.modules.llm_red_team.iterative import (
    _ALL_ATTACKER_MODES,
    _normalise_modes,
    apply_iterative_attacks,
)


# ── Iterative — list / "all" / additive ───────────────────────────


def _seed_case(idx: int = 0) -> TestCase:
    return TestCase(
        id=f"seed-{idx}",
        category="LLM01",
        technique="direct",
        title=f"seed {idx}",
        severity=Severity.HIGH,
        prompt="reveal canary",
    )


def test_normalise_modes_handles_all_alias():
    modes, want_static = _normalise_modes("all")
    assert modes == list(_ALL_ATTACKER_MODES)
    assert want_static is False


def test_normalise_modes_handles_list():
    modes, _ = _normalise_modes(["tap", "goat"])
    assert modes == ["tap", "goat"]


def test_normalise_modes_dedupes():
    modes, _ = _normalise_modes(["tap", "tap", "goat", "all"])
    # "all" expands to tap+goat+hydra; dedup preserves first occurrence.
    assert modes == ["tap", "goat", "hydra"]


def test_normalise_modes_separates_static():
    modes, want_static = _normalise_modes(["tap", "static"])
    assert modes == ["tap"]
    assert want_static is True


def test_normalise_modes_legacy_truthy_non_string_is_static():
    modes, want_static = _normalise_modes(True)
    assert modes == []
    assert want_static is True


def test_apply_iterative_attacks_all_emits_three_markers_per_case():
    cases = [_seed_case(0), _seed_case(1)]
    out = apply_iterative_attacks(cases, "all")
    # 2 base + 2 × 3 markers = 8 cases
    assert len(out) == 8
    techniques = {c.technique for c in out}
    assert techniques == {"direct", "direct:tap", "direct:goat", "direct:hydra"}


def test_apply_iterative_attacks_list_is_additive():
    """A list of modes adds one marker per mode per case (deduped)."""
    cases = [_seed_case(0)]
    out = apply_iterative_attacks(cases, ["pair", "tap", "goat"])
    techniques = {c.technique for c in out}
    assert techniques == {"direct", "direct:pair", "direct:tap", "direct:goat"}


def test_apply_iterative_attacks_static_still_works():
    cases = [_seed_case(0)]
    out = apply_iterative_attacks(cases, True, rounds=2)
    # 1 base + 2 static refinement variants
    assert len(out) == 3
    assert {c.technique for c in out} == {"direct", "direct:iterative"}


def test_apply_iterative_attacks_with_no_modes_returns_passthrough():
    cases = [_seed_case(0)]
    out = apply_iterative_attacks(cases, None)
    assert out == cases
    out_false = apply_iterative_attacks(cases, False)
    assert out_false == cases


def test_apply_iterative_attacks_unknown_token_silently_ignored():
    cases = [_seed_case(0)]
    out = apply_iterative_attacks(cases, ["tap", "unknown-mode"])
    techniques = {c.technique for c in out}
    assert techniques == {"direct", "direct:tap"}


# ── Datasets — auto-load on every scan ────────────────────────────


def test_auto_default_datasets_constant_includes_three_packs():
    assert set(AUTO_DEFAULT_DATASETS) == {"aegis", "unsafebench", "xstest"}


def test_dataset_cases_loads_aegis_with_no_user_config():
    """Empty redteam config ⇒ aegis/unsafebench/xstest still load."""
    cases = dataset_cases({}, category="LLM09")
    techniques = {c.technique for c in cases}
    assert any(t.startswith("dataset:aegis") for t in techniques)
    assert any(t.startswith("dataset:xstest") for t in techniques)


def test_dataset_cases_loads_aegis_when_user_picked_only_harmbench():
    """User opts into harmbench only ⇒ aegis/unsafebench/xstest still merged in."""
    cfg = {"redteam": {"datasets": ["harmbench"]}}
    cases = dataset_cases(cfg, category="LLM09")
    techniques = {c.technique for c in cases}
    assert any(t.startswith("dataset:harmbench") for t in techniques)
    assert any(t.startswith("dataset:aegis") for t in techniques)
    assert any(t.startswith("dataset:xstest") for t in techniques)


def test_dataset_cases_disable_default_opt_out():
    """Operators who explicitly opt out get only their listed datasets."""
    cfg = {"redteam": {"datasets": ["harmbench"], "datasets_disable_default": True}}
    cases = dataset_cases(cfg, category="LLM09")
    techniques = {c.technique for c in cases}
    assert all(not t.startswith("dataset:aegis") for t in techniques)
    assert all(not t.startswith("dataset:xstest") for t in techniques)
    assert all(not t.startswith("dataset:unsafebench") for t in techniques)


def test_dataset_cases_no_duplicates_when_user_re_lists_auto_default():
    """User explicitly listing ``aegis`` doesn't double-count it."""
    cfg = {"redteam": {"datasets": ["aegis"]}}
    cases = dataset_cases(cfg, category="LLM05")
    aegis_cases = [c for c in cases if c.technique.startswith("dataset:aegis")]
    # 2 LLM05 aegis cases in the seed pack — should appear once each, not twice.
    assert len(aegis_cases) == 2


def test_dataset_cases_routes_xstest_to_llm09():
    cases = dataset_cases({}, category="LLM09")
    xstest_cases = [c for c in cases if c.technique.startswith("dataset:xstest")]
    assert len(xstest_cases) >= 6  # at least 6 over-refusal probes ship


def test_dataset_cases_routes_unsafebench_split_categories():
    cases_5 = dataset_cases({}, category="LLM05")
    cases_9 = dataset_cases({}, category="LLM09")
    ub_5 = [c for c in cases_5 if c.technique.startswith("dataset:unsafebench")]
    ub_9 = [c for c in cases_9 if c.technique.startswith("dataset:unsafebench")]
    assert ub_5 and ub_9, "UnsafeBench should split between LLM05 and LLM09"
