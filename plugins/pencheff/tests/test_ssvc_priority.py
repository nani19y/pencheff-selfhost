"""Tests for the SSVC decision tree and the unified priority score that
the dashboard sorts by. Pure-function tests — no I/O, no fixtures.
"""
from __future__ import annotations

from pencheff.intelligence.priority import (
    PriorityInputs,
    compute_priority,
)
from pencheff.intelligence.ssvc import (
    SSVCDecision,
    SSVCInputs,
    exploitation_from,
    exposure_from_category,
    impact_from_cvss,
    ssvc_decision,
)


# ── Exploitation axis ────────────────────────────────────────────────


def test_kev_listed_is_active():
    assert exploitation_from(kev=True, epss=0.0) == "active"
    assert exploitation_from(kev=True, epss=None) == "active"


def test_high_epss_no_kev_is_poc():
    assert exploitation_from(kev=False, epss=0.5) == "poc"
    assert exploitation_from(kev=False, epss=0.97) == "poc"


def test_low_epss_no_kev_is_none():
    assert exploitation_from(kev=False, epss=0.49) == "none"
    assert exploitation_from(kev=False, epss=None) == "none"


# ── Impact axis ──────────────────────────────────────────────────────


def test_impact_thresholds():
    assert impact_from_cvss(9.5) == "very_high"
    assert impact_from_cvss(9.0) == "very_high"
    assert impact_from_cvss(7.0) == "high"
    assert impact_from_cvss(8.9) == "high"
    assert impact_from_cvss(4.0) == "medium"
    assert impact_from_cvss(3.9) == "low"
    assert impact_from_cvss(None) == "low"


# ── Exposure axis ────────────────────────────────────────────────────


def test_dast_findings_are_open_by_default():
    assert exposure_from_category("any", "dast") == "open"


def test_sca_finding_defaults_to_controlled():
    assert exposure_from_category("components", "sast") == "controlled"


def test_sast_injection_assumed_open():
    assert exposure_from_category("injection", "sast") == "open"


# ── Decision tree ────────────────────────────────────────────────────


def test_active_exploitation_is_act():
    """KEV-listed CVE → ACT regardless of impact / exposure."""
    decision = ssvc_decision(SSVCInputs(
        exploitation="active", exposure="small", impact="low",
    ))
    assert decision == SSVCDecision.ACT


def test_poc_with_high_impact_is_attend():
    decision = ssvc_decision(SSVCInputs(
        exploitation="poc", exposure="controlled", impact="high",
    ))
    assert decision == SSVCDecision.ATTEND


def test_poc_open_exposure_is_attend():
    decision = ssvc_decision(SSVCInputs(
        exploitation="poc", exposure="open", impact="medium",
    ))
    assert decision == SSVCDecision.ATTEND


def test_poc_low_impact_controlled_is_track_star():
    decision = ssvc_decision(SSVCInputs(
        exploitation="poc", exposure="controlled", impact="low",
    ))
    assert decision == SSVCDecision.TRACK_STAR


def test_no_exploitation_very_high_impact_is_track_star():
    decision = ssvc_decision(SSVCInputs(
        exploitation="none", exposure="open", impact="very_high",
    ))
    assert decision == SSVCDecision.TRACK_STAR


def test_no_exploitation_low_impact_is_track():
    decision = ssvc_decision(SSVCInputs(
        exploitation="none", exposure="small", impact="low",
    ))
    assert decision == SSVCDecision.TRACK


# ── Priority score ──────────────────────────────────────────────────


def test_kev_critical_dominates():
    """KEV + critical CVSS should produce a near-max priority score."""
    out = compute_priority(PriorityInputs(
        cvss=9.8, epss=0.97, kev=True, category="injection",
        finding_kind="dast",
    ))
    assert out.ssvc == SSVCDecision.ACT
    assert out.score > 75.0


def test_low_severity_no_kev_low_epss_is_low_priority():
    out = compute_priority(PriorityInputs(
        cvss=2.0, epss=0.01, kev=False, category="components",
        finding_kind="sast",
    ))
    assert out.ssvc == SSVCDecision.TRACK
    assert out.score < 15.0


def test_kev_promotes_low_cvss_above_high_cvss_without_kev():
    """The whole point: KEV-listed CVE that's already exploited beats a
    higher-CVSS-but-not-yet-exploited issue. This is what Snyk gets
    wrong by sorting on CVSS alone."""
    kev_low = compute_priority(PriorityInputs(
        cvss=6.0, epss=0.6, kev=True, category="components",
    ))
    nokev_high = compute_priority(PriorityInputs(
        cvss=8.5, epss=0.05, kev=False, category="components",
    ))
    assert kev_low.score > nokev_high.score


def test_reachability_exploited_boosts_score():
    base = compute_priority(PriorityInputs(
        cvss=7.0, epss=0.3, kev=False, category="injection",
        reachability="present",
    ))
    exploited = compute_priority(PriorityInputs(
        cvss=7.0, epss=0.3, kev=False, category="injection",
        reachability="exploited",
    ))
    assert exploited.score > base.score


def test_score_clamped_to_0_100():
    """Even pathological inputs must produce a score in [0, 100]."""
    extreme = compute_priority(PriorityInputs(
        cvss=10.0, epss=1.0, kev=True, category="injection",
        reachability="exploited",
    ))
    assert 0.0 <= extreme.score <= 100.0
    nothing = compute_priority(PriorityInputs(
        cvss=None, epss=None, kev=False, category=None,
    ))
    assert 0.0 <= nothing.score <= 100.0
