# apps/api/tests/test_repo_fp_triage.py
"""Unit tests for repo (SAST) AI false-positive triage decision logic.

Guards: bandit B608 etc. false positives on parameterized SQL recur every scan
because the agent can't "fix" already-safe code. This triage classifies them
and suppresses verified false positives in Pencheff's DB (code untouched). These
tests cover the pure decision pieces (severity/confidence gate + the
finding->classifier-input mapping). The async DB path is integration-level.
"""
from __future__ import annotations

from dataclasses import dataclass

from pencheff_api.db.models import RepoFinding
from pencheff_api.services.repo_fp_triage import _should_suppress, _to_finding_input


@dataclass
class _V:
    is_false_positive: bool
    confidence: float
    reason: str = "parameterized query; values bound via params"


def test_suppress_medium_fp_high_confidence():
    # The B608-on-parameterized-SQL case: medium, verified FP, high confidence.
    assert _should_suppress("medium", _V(True, 0.92)) is True
    assert _should_suppress("low", _V(True, 0.9)) is True
    assert _should_suppress("info", _V(True, 0.85)) is True


def test_keep_high_and_critical_even_if_flagged_fp():
    # High/critical stay visible for human review even if flagged FP.
    assert _should_suppress("high", _V(True, 0.99)) is False
    assert _should_suppress("critical", _V(True, 0.99)) is False


def test_keep_low_confidence_or_not_fp():
    assert _should_suppress("medium", _V(True, 0.5)) is False    # below threshold
    assert _should_suppress("medium", _V(False, 0.99)) is False  # real finding
    assert _should_suppress("medium", None) is False             # no verdict


def test_to_finding_input_maps_repo_finding_fields():
    r = RepoFinding(
        id="rf-1", repo_scan_id="s1", repository_id="r1",
        scanner="bandit", rule_id="B608", severity="medium",
        title="B608: hardcoded_sql_expressions",
        description="Possible SQL injection via string concatenation",
        file_path="backend/services/observability_service.py",
        line_start=112, line_end=112,
        code_snippet='"SELECT COUNT(*) FROM logs WHERE " + where, params',
    )
    fi = _to_finding_input(r)
    assert fi.id == "rf-1"
    assert fi.severity == "medium"
    assert fi.category == "bandit:B608"
    assert fi.endpoint == "backend/services/observability_service.py"
    assert fi.parameter == "line 112"
    assert "SELECT COUNT(*)" in fi.evidence_excerpt
