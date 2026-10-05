# tests/test_security_lake_export.py
from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pyarrow.parquet as pq

from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog
from pencheff_api.services.security_lake.lake_schema import to_lake_row
from pencheff_api.services.security_lake import map_finding, validate_ocsf, LakeContext
from pencheff_api.services.security_lake.lake_query import (
    export_org_ndjson, export_org_parquet,
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
    base = {"scanner": "osv", "rule_id": None, "severity": "high", "title": "x",
            "description": "d", "file_path": "p", "line_start": None, "line_end": None,
            "code_snippet": None, "package": "p", "installed_version": "1",
            "fixed_version": "2", "raw": {}}
    rows = []
    # o1: two distinct findings (CVE-O1A on a1, CVE-O1B on a2); o2: CVE-O2X on a9
    for org, asset, cve in [("o1", "a1", "CVE-O1A"), ("o1", "a2", "CVE-O1B"),
                            ("o2", "a9", "CVE-O2X")]:
        r = dict(base); r["cve"] = cve
        ctx = LakeContext(org_id=org, asset_id=asset, source="sca",
                          time_ms=1_700_000_000_000, is_new=True)
        e = map_finding("sca", r, ctx); validate_ocsf(e)
        rows.append(to_lake_row(e, org_id=org, source="sca", asset_id=asset))
    w.append_rows(rows)


def test_export_ndjson_org_scoped_valid_ocsf(tmp_path):
    _seed(tmp_path)
    text = export_org_ndjson(_settings(tmp_path), org_id="o1")
    lines = text.splitlines()
    assert len(lines) == 2                                  # only o1's two findings
    events = [json.loads(l) for l in lines]
    assert all(ev["class_uid"] == 2002 for ev in events)    # valid OCSF
    cves = {ev["vulnerabilities"][0]["cve"]["uid"] for ev in events}
    assert cves == {"CVE-O1A", "CVE-O1B"}
    assert "CVE-O2X" not in text                            # other org excluded (structural)


def test_export_ndjson_empty_org(tmp_path):
    _seed(tmp_path)
    assert export_org_ndjson(_settings(tmp_path), org_id="o-none") == ""


def test_export_parquet_org_scoped(tmp_path):
    _seed(tmp_path)
    blob = export_org_parquet(_settings(tmp_path), org_id="o1")
    table = pq.read_table(io.BytesIO(blob))
    assert table.num_rows == 2
    assert set(table.column("org_id").to_pylist()) == {"o1"}
    assert "o2" not in set(table.column("org_id").to_pylist())
