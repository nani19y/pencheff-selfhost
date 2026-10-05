# tests/test_security_lake_ingest.py
from __future__ import annotations

from pencheff_api.services.security_lake.ingest import ingest_findings, IngestResult
from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog


def _writer(tmp_path):
    cat = build_local_catalog(uri=f"sqlite:///{tmp_path}/cat.db", warehouse=f"file://{tmp_path}/wh")
    w = LakeWriter(cat, namespace="pencheff", table="findings")
    w.ensure_table()
    return w


SAST = {"scanner": "semgrep", "rule_id": "py.sqli", "severity": "high", "title": "SQLi",
        "description": "x", "file_path": "app/db.py", "line_start": 10, "line_end": 12,
        "code_snippet": "e", "cve": None, "package": None, "installed_version": None,
        "fixed_version": None, "raw": {"cwe": "CWE-89"}}
IAC = {"scanner": "checkov", "rule_id": "CKV_AWS_20", "severity": "medium", "title": "S3",
       "description": "x", "file_path": "s3.tf", "line_start": 1, "line_end": 8,
       "code_snippet": None, "cve": None, "package": None, "installed_version": None,
       "fixed_version": None, "raw": {}}


def test_ingest_valid_findings_appends_rows(tmp_path):
    w = _writer(tmp_path)
    res = ingest_findings(w, [("sast", SAST), ("iac", IAC)],
                          org_id="o1", asset_id="r1", time_ms=1_700_000_000_000)
    assert isinstance(res, IngestResult)
    assert res.appended == 2
    assert res.quarantined == []
    assert w.load_table().scan().to_arrow().num_rows == 2


def test_invalid_finding_is_quarantined_not_appended(tmp_path):
    w = _writer(tmp_path)
    # An unknown source makes map_finding raise -> quarantined, not fatal.
    res = ingest_findings(w, [("sast", SAST), ("bogus", {})],
                          org_id="o1", asset_id="r1", time_ms=1_700_000_000_000)
    assert res.appended == 1
    assert len(res.quarantined) == 1
    assert res.quarantined[0].source == "bogus"
    assert res.quarantined[0].error  # non-empty reason
    assert w.load_table().scan().to_arrow().num_rows == 1


def test_all_invalid_appends_nothing(tmp_path):
    w = _writer(tmp_path)
    res = ingest_findings(w, [("bogus", {})], org_id="o1", asset_id="r1",
                          time_ms=1_700_000_000_000)
    assert res.appended == 0
    assert len(res.quarantined) == 1
    assert w.load_table().scan().to_arrow().num_rows == 0


def test_one_snapshot_per_ingest_call(tmp_path):
    w = _writer(tmp_path)
    res = ingest_findings(w, [("sast", SAST), ("iac", IAC)],
                          org_id="o1", asset_id="r1", time_ms=1_700_000_000_000)
    assert res.appended == 2
    assert len(w.load_table().metadata.snapshots) == 1  # one batch -> one snapshot
