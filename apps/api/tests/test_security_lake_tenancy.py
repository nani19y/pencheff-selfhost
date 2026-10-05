from __future__ import annotations

from types import SimpleNamespace

import pytest

from pencheff_api.services.security_lake.tenancy import org_data_prefix
from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog
from pencheff_api.services.security_lake.lake_schema import to_lake_row
from pencheff_api.services.security_lake import map_finding, validate_ocsf, LakeContext
from pencheff_api.services.security_lake.lake_query import query_findings


def _settings(tmp_path):
    return SimpleNamespace(
        lake_catalog_type="sql",
        lake_catalog_uri=f"sqlite:///{tmp_path}/cat.db",
        lake_warehouse=f"file://{tmp_path}/wh",
        lake_namespace="pencheff", lake_table="findings",
    )


def test_org_data_prefix_is_per_org_and_ends_with_slash():
    s = _settings("/tmp/x")
    p = org_data_prefix(s, "o1")
    assert p.endswith("/data/org_id=o1/")


def test_org_data_prefix_rejects_unsafe_org_id():
    s = _settings("/tmp/x")
    for bad in ("", "../o2", "o1/../o2", "a/b"):
        with pytest.raises(ValueError):
            org_data_prefix(s, bad)


def test_org_prefixes_are_disjoint_no_string_prefix_collision():
    # The classic trap: "o1" must NOT be a prefix of "o10".
    s = _settings("/tmp/x")
    p1, p10 = org_data_prefix(s, "o1"), org_data_prefix(s, "o10")
    assert p1 != p10
    assert not p10.startswith(p1)
    assert not p1.startswith(p10)


def _seed_two_orgs(tmp_path):
    w = LakeWriter(build_local_catalog(uri=f"sqlite:///{tmp_path}/cat.db",
                                       warehouse=f"file://{tmp_path}/wh"),
                   namespace="pencheff", table="findings")
    w.ensure_table()
    sca = {"scanner": "osv", "rule_id": None, "severity": "critical", "title": "x",
           "description": "d", "file_path": "p", "line_start": None, "line_end": None,
           "code_snippet": None, "cve": "CVE-1", "package": "p",
           "installed_version": "1", "fixed_version": "2", "raw": {}}
    rows = []
    for org in ("o1", "o2"):
        ctx = LakeContext(org_id=org, asset_id="a", source="sca",
                          time_ms=1_700_000_000_000, is_new=True)
        e = map_finding("sca", sca, ctx); validate_ocsf(e)
        rows.append(to_lake_row(e, org_id=org, source="sca", asset_id=org))
    w.append_rows(rows)


def test_query_never_returns_another_orgs_rows(tmp_path):
    _seed_two_orgs(tmp_path)
    s = _settings(tmp_path)
    items_o1, total_o1 = query_findings(s, org_id="o1", limit=50, offset=0)
    assert total_o1 == 1
    assert all(i["org_id"] == "o1" for i in items_o1)
    assert all(i["asset_id"] == "o1" for i in items_o1)   # o2's asset must not leak
    # a non-member / unknown org sees nothing
    _, total_none = query_findings(s, org_id="o-attacker", limit=50, offset=0)
    assert total_none == 0


def test_physical_partition_dirs_are_per_org(tmp_path):
    import os
    _seed_two_orgs(tmp_path)
    data_dir = os.path.join(tmp_path, "wh", "pencheff", "findings", "data")
    org_dirs = sorted(os.listdir(data_dir))
    assert org_dirs == ["org_id=o1", "org_id=o2"]   # physically segregated
