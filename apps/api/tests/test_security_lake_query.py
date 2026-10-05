# tests/test_security_lake_query.py
from __future__ import annotations

import datetime as dt
import json
from types import SimpleNamespace

import pyarrow as pa

from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog
from pencheff_api.services.security_lake.lake_schema import to_lake_row
from pencheff_api.services.security_lake import map_finding, validate_ocsf, LakeContext
from pencheff_api.services.security_lake.lake_query import (
    query_findings, query_trends, query_correlate,
)


def _settings(tmp_path):
    return SimpleNamespace(
        lake_catalog_type="sql",
        lake_catalog_uri=f"sqlite:///{tmp_path}/cat.db",
        lake_warehouse=f"file://{tmp_path}/wh",
        lake_namespace="pencheff", lake_table="findings",
    )


def _seed(tmp_path):
    w = LakeWriter(build_local_catalog(uri=f"sqlite:///{tmp_path}/cat.db",
                                       warehouse=f"file://{tmp_path}/wh"),
                   namespace="pencheff", table="findings")
    w.ensure_table()
    sca = {"scanner": "osv", "rule_id": None, "severity": "critical", "title": "lodash",
           "description": "d", "file_path": "pl.json", "line_start": None, "line_end": None,
           "code_snippet": None, "cve": "CVE-2020-8203", "package": "lodash",
           "installed_version": "4.1", "fixed_version": "4.2", "raw": {}}

    def row(org, asset, cve, t):
        r = dict(sca); r["cve"] = cve
        ctx = LakeContext(org_id=org, asset_id=asset, source="sca", time_ms=t, is_new=True)
        e = map_finding("sca", r, ctx); validate_ocsf(e)
        return to_lake_row(e, org_id=org, source="sca", asset_id=asset)

    w.append_rows([
        row("o1", "r1", "CVE-2020-8203", 1_700_000_000_000),
        row("o1", "r2", "CVE-2020-8203", 1_700_000_000_000),
        row("o1", "r1", "CVE-2021-1111", 1_700_086_400_000),
        row("o2", "r9", "CVE-2020-8203", 1_700_000_000_000),
    ])


def test_query_findings_org_scoped_and_deduped(tmp_path):
    _seed(tmp_path)
    items, total = query_findings(_settings(tmp_path), org_id="o1", limit=50, offset=0)
    # 3 distinct findings in o1 (two CVEs on r1 + one on r2); o2 excluded
    assert total == 3
    assert len(items) == 3
    assert all(it["org_id"] == "o1" for it in items)
    assert {it["asset_id"] for it in items} == {"r1", "r2"}


def test_query_findings_severity_filter(tmp_path):
    _seed(tmp_path)
    items, total = query_findings(_settings(tmp_path), org_id="o1", severity_id=5,
                                  limit=50, offset=0)
    assert total == 3  # all seeded findings are critical (severity_id 5)
    items2, total2 = query_findings(_settings(tmp_path), org_id="o1", severity_id=2,
                                    limit=50, offset=0)
    assert total2 == 0


def test_query_findings_empty_org(tmp_path):
    _seed(tmp_path)
    items, total = query_findings(_settings(tmp_path), org_id="o-none", limit=50, offset=0)
    assert total == 0 and items == []


def test_query_trends_counts_by_day(tmp_path):
    _seed(tmp_path)
    rows = query_trends(_settings(tmp_path), org_id="o1")
    by_day = {r["dt"]: r["open_findings"] for r in rows}
    assert by_day["2023-11-14"] == 2   # two CVEs observed that day
    assert by_day["2023-11-15"] == 1


def test_query_correlate_cve_across_assets(tmp_path):
    _seed(tmp_path)
    rows = query_correlate(_settings(tmp_path), org_id="o1", min_assets=2)
    assert rows == [{"cve": "CVE-2020-8203", "assets": 2, "findings": 2}]


def test_query_findings_accepts_uuid_org_id(tmp_path):
    import uuid
    from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog
    from pencheff_api.services.security_lake.lake_schema import to_lake_row
    from pencheff_api.services.security_lake import map_finding, validate_ocsf, LakeContext
    oid = uuid.uuid4()
    w = LakeWriter(build_local_catalog(uri=f"sqlite:///{tmp_path}/cat.db",
                                       warehouse=f"file://{tmp_path}/wh"),
                   namespace="pencheff", table="findings")
    w.ensure_table()
    sca = {"scanner": "osv", "rule_id": None, "severity": "high", "title": "x",
           "description": "d", "file_path": "p", "line_start": None, "line_end": None,
           "code_snippet": None, "cve": "CVE-U", "package": "p",
           "installed_version": "1", "fixed_version": "2", "raw": {}}
    ctx = LakeContext(org_id=str(oid), asset_id="a", source="sca",
                      time_ms=1_700_000_000_000, is_new=True)
    e = map_finding("sca", sca, ctx); validate_ocsf(e)
    w.append_rows([to_lake_row(e, org_id=str(oid), source="sca", asset_id="a")])
    # pass a uuid.UUID object (not a str) — must be coerced and still match
    _, total = query_findings(_settings(tmp_path), org_id=oid, limit=10, offset=0)
    assert total == 1
