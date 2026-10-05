from __future__ import annotations

from types import SimpleNamespace

from pencheff_api.tasks.security_lake_ingest_task import run_ingest


SAST = {"scanner": "semgrep", "rule_id": "py.sqli", "severity": "high", "title": "SQLi",
        "description": "x", "file_path": "app/db.py", "line_start": 10, "line_end": 12,
        "code_snippet": "e", "cve": None, "package": None, "installed_version": None,
        "fixed_version": None, "raw": {"cwe": "CWE-89"}}


def _settings(tmp_path):
    return SimpleNamespace(
        lake_catalog_type="sql",
        lake_catalog_uri=f"sqlite:///{tmp_path}/cat.db",
        lake_warehouse=f"file://{tmp_path}/wh",
        lake_namespace="pencheff",
        lake_table="findings",
    )


def test_run_ingest_appends_and_reports(tmp_path):
    res = run_ingest([("sast", SAST)], scan_id="s1", source_label="repo",
                     org_id="o1", asset_id="r1", time_ms=1_700_000_000_000,
                     settings=_settings(tmp_path))
    assert res.appended == 1
    assert res.quarantined == []


def test_run_ingest_quarantines_bad_finding(tmp_path):
    res = run_ingest([("bogus", {})], scan_id="s2", source_label="repo",
                     org_id="o1", asset_id="r1", time_ms=1_700_000_000_000,
                     settings=_settings(tmp_path))
    assert res.appended == 0
    assert len(res.quarantined) == 1
