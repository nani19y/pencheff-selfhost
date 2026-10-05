"""Tests for ``pencheff_api.services.unified_findings`` — the projection
+ sort logic that powers the dashboard's single-queue finding stream.
DB-level integration is exercised via the existing in-memory tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from pencheff_api.services.unified_findings import (
    UnifiedFindingRow,
    _category_to_source,
    _fallback_risk,
    _project_finding,
    _project_repo_finding,
    _scanner_to_source,
    _sort_key,
)


# ── Lightweight stand-ins for the SQLAlchemy rows ───────────────────


@dataclass
class _F:
    id: str = "f1"
    title: str = "t"
    severity: str = "medium"
    category: str | None = "injection"
    risk_score: float | None = None
    reachability: str | None = None
    ssvc_decision: str | None = None
    epss: float | None = None
    kev: bool = False
    cwe_id: str | None = None
    owasp_category: str | None = None
    endpoint: str | None = None
    suppressed: bool = False
    created_at: datetime = datetime.now(timezone.utc)


@dataclass
class _R:
    id: str = "r1"
    title: str = "t"
    severity: str = "medium"
    scanner: str = "semgrep"
    file_path: str | None = None
    line_start: int | None = None
    package: str | None = None
    fixed_version: str | None = None
    suppressed: bool = False
    repository_id: str = "repo-1"
    created_at: datetime = datetime.now(timezone.utc)


# ── Source mapping ──────────────────────────────────────────────────


def test_scanner_to_source_known():
    # Phase 0.1 SAST replacement scanners — these are the live ones today.
    assert _scanner_to_source("semgrep") == "sast"
    assert _scanner_to_source("bandit") == "sast"
    assert _scanner_to_source("gosec") == "sast"
    assert _scanner_to_source("brakeman") == "sast"
    assert _scanner_to_source("eslint") == "sast"
    # Legacy CodeQL rows can still appear in the DB for scans that
    # predate the v0.7 removal — keep the mapping classified as SAST so
    # historical rollups stay correct.
    assert _scanner_to_source("CodeQL") == "sast"
    assert _scanner_to_source("osv") == "sca"
    assert _scanner_to_source("ghsa") == "sca"
    assert _scanner_to_source("gitleaks") == "secret"
    assert _scanner_to_source("trivy_iac") == "iac"
    assert _scanner_to_source("checkov") == "iac"


def test_scanner_to_source_unknown_defaults_to_sast():
    assert _scanner_to_source("custom-tool") == "sast"
    assert _scanner_to_source(None) == "sast"


def test_category_to_source():
    assert _category_to_source("components") == "sca"
    assert _category_to_source("injection") == "dast"
    assert _category_to_source(None) == "dast"


# ── Severity fallback ───────────────────────────────────────────────


def test_fallback_risk_descending():
    """Critical must outrank high must outrank medium etc., so the merged
    sort produces the expected order even when nothing has risk_score."""
    assert _fallback_risk("critical") > _fallback_risk("high")
    assert _fallback_risk("high") > _fallback_risk("medium")
    assert _fallback_risk("medium") > _fallback_risk("low")
    assert _fallback_risk("low") > _fallback_risk("info")
    assert _fallback_risk("garbage") > 0     # never NULL


# ── Projections ─────────────────────────────────────────────────────


def test_project_dast_finding_uses_risk_score():
    f = _F(id="f1", category="injection", severity="critical",
           risk_score=88.5, reachability="exploited",
           ssvc_decision="act", endpoint="/api/users")
    row = _project_finding(f, workspace_id="w1", target_id="t1")
    assert row.source == "dast"
    assert row.table == "findings"
    assert row.risk_score == 88.5
    assert row.reachability == "exploited"
    assert row.location == "/api/users"
    assert row.target_id == "t1"


def test_project_sca_finding_via_components_category():
    f = _F(category="components", severity="high",
           risk_score=72.0, endpoint="requirements.txt")
    row = _project_finding(f, workspace_id="w1", target_id="t1")
    assert row.source == "sca"


def test_project_dast_finding_falls_back_to_severity_score():
    """Old findings predating the priority engine have NULL risk_score —
    they must still get a deterministic sort key."""
    f = _F(severity="high", risk_score=None)
    row = _project_finding(f, workspace_id="w1", target_id="t1")
    assert row.risk_score == _fallback_risk("high")


def test_project_repo_finding_builds_location():
    r = _R(scanner="semgrep", file_path="src/db/users.py", line_start=42)
    row = _project_repo_finding(r, workspace_id="w1")
    assert row.source == "sast"
    assert row.location == "src/db/users.py:42"


def test_project_repo_finding_no_line_omits_colon():
    r = _R(scanner="osv", file_path="package.json", line_start=None,
           package="lodash", fixed_version="4.17.21")
    row = _project_repo_finding(r, workspace_id="w1")
    assert row.source == "sca"
    assert row.location == "package.json"
    assert row.package == "lodash"


# ── Sort key ────────────────────────────────────────────────────────


def _row(rid: str, score: float, severity: str = "medium",
         created: datetime | None = None) -> UnifiedFindingRow:
    return UnifiedFindingRow(
        id=rid, source="dast", table="findings", title="t",
        severity=severity, risk_score=score, reachability=None,
        ssvc_decision=None, epss=None, kev=False, cwe_id=None,
        owasp_category=None, location="", package=None, fixed_version=None,
        suppressed=False, created_at=created or datetime.now(timezone.utc),
        workspace_id="w1", target_id=None, repository_id=None,
    )


def test_sort_orders_by_risk_score_desc():
    rows = [_row("a", 30), _row("b", 90), _row("c", 60)]
    rows.sort(key=_sort_key)
    assert [r.id for r in rows] == ["b", "c", "a"]


def test_sort_breaks_ties_on_severity():
    rows = [
        _row("a", 50, "low"),
        _row("b", 50, "critical"),
        _row("c", 50, "high"),
    ]
    rows.sort(key=_sort_key)
    assert [r.id for r in rows] == ["b", "c", "a"]


def test_sort_breaks_severity_ties_on_recency():
    older = datetime(2025, 1, 1, tzinfo=timezone.utc)
    newer = datetime(2026, 5, 1, tzinfo=timezone.utc)
    rows = [
        _row("old", 50, "medium", older),
        _row("new", 50, "medium", newer),
    ]
    rows.sort(key=_sort_key)
    assert rows[0].id == "new"  # newer wins on ties
