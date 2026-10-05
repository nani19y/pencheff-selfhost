# tests/test_security_lake_writer.py
from __future__ import annotations

import json

from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog
from pencheff_api.services.security_lake.lake_schema import to_lake_row


def _event(uid="fp1", cls=2002):
    return {"class_uid": cls, "time": 1_700_000_000_000, "severity_id": 4, "status_id": 1,
            "finding_info": {"uid": uid, "title": "x"}}


def _writer(tmp_path):
    cat = build_local_catalog(
        uri=f"sqlite:///{tmp_path}/cat.db",
        warehouse=f"file://{tmp_path}/wh",
    )
    return LakeWriter(cat, namespace="pencheff", table="findings")


def test_append_and_scan_roundtrip(tmp_path):
    w = _writer(tmp_path)
    w.ensure_table()
    w.append_rows([to_lake_row(_event("a"), org_id="o1", source="sast", asset_id="r1")])
    w.append_rows([to_lake_row(_event("b", 2003), org_id="o1", source="iac", asset_id="r1")])
    tbl = w.load_table()
    assert tbl.scan().to_arrow().num_rows == 2
    # append-only: two batches -> two snapshots
    assert len(tbl.metadata.snapshots) == 2


def test_ensure_table_is_idempotent(tmp_path):
    w = _writer(tmp_path)
    w.ensure_table()
    w.ensure_table()  # must not raise
    assert w.load_table() is not None


def test_partition_filter_scopes_by_org_and_class(tmp_path):
    w = _writer(tmp_path)
    w.ensure_table()
    w.append_rows([to_lake_row(_event("a"), org_id="o1", source="sast", asset_id="r1")])
    w.append_rows([to_lake_row(_event("c"), org_id="o2", source="sast", asset_id="r1")])
    got = w.load_table().scan(row_filter="org_id == 'o1'").to_arrow()
    assert got.num_rows == 1
    assert json.loads(got.column("ocsf_json")[0].as_py())["finding_info"]["uid"] == "a"


def test_append_empty_is_noop(tmp_path):
    w = _writer(tmp_path)
    w.ensure_table()
    w.append_rows([])  # must not raise, no snapshot
    assert w.load_table().scan().to_arrow().num_rows == 0
    assert len(w.load_table().metadata.snapshots) == 0


def test_build_catalog_sql_wires_r2_s3_props(tmp_path):
    from types import SimpleNamespace
    from pencheff_api.services.security_lake.lake_writer import build_catalog
    s = SimpleNamespace(
        lake_catalog_type="sql",
        lake_catalog_uri=f"sqlite:///{tmp_path}/cat.db",
        lake_warehouse="s3://pencheff-lake/warehouse",
        lake_namespace="pencheff", lake_table="findings",
        r2_endpoint_url="https://acct.r2.cloudflarestorage.com",
        r2_access_key_id="AKID", r2_secret_access_key="SECRET",
    )
    p = build_catalog(s).properties
    assert p["s3.endpoint"] == "https://acct.r2.cloudflarestorage.com"
    assert p["s3.region"] == "auto"
    assert p["s3.access-key-id"] == "AKID"
    assert p["s3.secret-access-key"] == "SECRET"


def test_build_catalog_sql_no_r2_has_no_s3_props(tmp_path):
    from types import SimpleNamespace
    from pencheff_api.services.security_lake.lake_writer import build_catalog
    s = SimpleNamespace(
        lake_catalog_type="sql",
        lake_catalog_uri=f"sqlite:///{tmp_path}/cat.db",
        lake_warehouse=f"file://{tmp_path}/wh",
        lake_namespace="pencheff", lake_table="findings",
    )
    p = build_catalog(s).properties
    assert not any(k.startswith("s3.") for k in p)
