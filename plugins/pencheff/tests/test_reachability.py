"""Tests for ``pencheff.intelligence.reachability`` — the per-finding
reachability classifier and the SAST↔DAST upgrade rules.
"""
from __future__ import annotations

from pencheff.intelligence.reachability import (
    Reachability,
    classify,
    upgrade_with_dast_pairs,
)


# ── DAST findings are always exploited ─────────────────────────────


def test_dast_finding_is_exploited():
    assert classify(finding_kind="dast") == Reachability.EXPLOITED
    assert classify(
        finding_kind="dast", category="injection",
    ) == Reachability.EXPLOITED


# ── Active-verifier "true_positive" overrides everything ────────────


def test_true_positive_overrides_to_exploited():
    """Once the active-verifier confirms a SAST hit live, it's exploited."""
    assert classify(
        finding_kind="sast",
        verification_status="true_positive",
        evidence=[],
    ) == Reachability.EXPLOITED


# ── SAST: taint trace presence is the discriminator ────────────────


def test_sast_with_semgrep_taint_trace_is_reachable():
    evidence = [{
        "request_method": "SAST_AUTOFIX",
        "autofix": {"kind": "text_replace", "start_line": 42},
    }]
    assert classify(
        finding_kind="sast", category="injection", evidence=evidence,
    ) == Reachability.REACHABLE


def test_sast_with_codeql_dataflow_is_reachable():
    evidence = [{"request_method": "DATAFLOW",
                 "description": "user input flows to sql exec"}]
    assert classify(
        finding_kind="sast", evidence=evidence,
    ) == Reachability.REACHABLE


def test_sast_without_taint_trace_is_present():
    """Bandit / ruff don't emit taint — the rule just matched a pattern."""
    evidence = [{"request_method": "BANDIT",
                 "description": "hardcoded credential"}]
    assert classify(
        finding_kind="sast", evidence=evidence,
    ) == Reachability.PRESENT


def test_sast_with_no_evidence_is_present():
    assert classify(finding_kind="sast", evidence=None) == Reachability.PRESENT


# ── SCA: defer to verification_notes ───────────────────────────────


def test_sca_with_no_imports_is_present():
    assert classify(
        finding_kind="dast", category="components",
        verification_notes="low_reachability: no imports detected",
    ) == Reachability.PRESENT


def test_sca_default_assumes_reachable():
    """OSV match without a usage probe → assume reachable. False positives
    on reachability are recoverable; false negatives on exploitability are
    incidents."""
    assert classify(
        finding_kind="dast", category="components",
    ) == Reachability.REACHABLE


def test_sca_finding_kind_explicit():
    """Some pipelines record SCA findings with finding_kind="sca"
    explicitly rather than category="components"."""
    assert classify(finding_kind="sca") == Reachability.REACHABLE
    assert classify(
        finding_kind="sca",
        verification_notes="low_reachability",
    ) == Reachability.PRESENT


# ── DAST↔SAST upgrade ──────────────────────────────────────────────


def test_upgrade_via_shared_cwe():
    """A SAST finding gets upgraded to exploited if any DAST finding
    shares its CWE — Pencheff already verified the exact attack pattern."""
    sast = {"cwe": "CWE-89", "endpoint": "src/db/users.py"}
    dast = [{"cwe": "CWE-89", "endpoint": "/api/users",
             "title": "SQLi"}]
    assert upgrade_with_dast_pairs(sast, dast) == Reachability.EXPLOITED


def test_upgrade_via_route_token():
    """A SAST finding in `users.py` gets upgraded if the live `/api/users`
    endpoint also has a finding."""
    sast = {"endpoint": "src/handlers/orders.py"}
    dast = [{"endpoint": "/api/v2/orders/123/refund"}]
    assert upgrade_with_dast_pairs(sast, dast) == Reachability.EXPLOITED


def test_no_upgrade_when_no_match():
    sast = {"cwe": "CWE-79", "endpoint": "src/views/login.tsx"}
    dast = [{"cwe": "CWE-89", "endpoint": "/api/payments"}]
    assert upgrade_with_dast_pairs(sast, dast) is None


def test_no_upgrade_for_short_route_tokens():
    """Short tokens like `db.py` would match too aggressively; require ≥4 chars."""
    sast = {"endpoint": "src/db.py"}
    dast = [{"endpoint": "/api/db"}]
    assert upgrade_with_dast_pairs(sast, dast) is None


# ── Unknown fallback ───────────────────────────────────────────────


def test_unrecognised_finding_kind_is_present():
    """Anything that isn't sast/dast/sca with no clear signal falls
    through to "present" — never to exploited or reachable, since those
    are claims that need evidence."""
    result = classify(finding_kind="audit-log", category="logging")
    assert result == Reachability.PRESENT
