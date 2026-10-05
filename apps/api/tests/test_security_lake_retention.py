from __future__ import annotations

from types import SimpleNamespace

from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog
from pencheff_api.services.security_lake.lake_schema import to_lake_row
from pencheff_api.services.security_lake import map_finding, validate_ocsf, LakeContext
from pencheff_api.services.security_lake.lake_query import query_findings
from pencheff_api.tasks.security_lake_ingest_task import purge_org_lake


def _settings(tmp_path):
    return SimpleNamespace(
        lake_catalog_type="sql", lake_catalog_uri=f"sqlite:///{tmp_path}/cat.db",
        lake_warehouse=f"file://{tmp_path}/wh", lake_namespace="pencheff", lake_table="findings")


def _seed(tmp_path):
    w = LakeWriter(build_local_catalog(uri=f"sqlite:///{tmp_path}/cat.db",
                                       warehouse=f"file://{tmp_path}/wh"),
                   namespace="pencheff", table="findings")
    w.ensure_table()
    base = {"scanner": "osv", "rule_id": None, "severity": "high", "title": "x",
            "description": "d", "file_path": "p", "line_start": None, "line_end": None,
            "code_snippet": None, "package": "p", "installed_version": "1",
            "fixed_version": "2", "raw": {}}
    rows = []
    for org, cve in [("orgA", "CVE-A1"), ("orgA", "CVE-A2"), ("orgB", "CVE-B1")]:
        r = dict(base); r["cve"] = cve
        ctx = LakeContext(org_id=org, asset_id="a", source="sca",
                          time_ms=1_700_000_000_000, is_new=True)
        e = map_finding("sca", r, ctx); validate_ocsf(e)
        rows.append(to_lake_row(e, org_id=org, source="sca", asset_id="a"))
    w.append_rows(rows)


def test_purge_org_lake_removes_only_that_org(tmp_path):
    _seed(tmp_path)
    s = _settings(tmp_path)
    purge_org_lake(s, org_id="orgA")
    _, ta = query_findings(s, org_id="orgA", limit=50, offset=0)
    _, tb = query_findings(s, org_id="orgB", limit=50, offset=0)
    assert ta == 0
    assert tb == 1


def test_purge_org_lake_no_table_is_noop(tmp_path):
    purge_org_lake(_settings(tmp_path), org_id="orgX")
