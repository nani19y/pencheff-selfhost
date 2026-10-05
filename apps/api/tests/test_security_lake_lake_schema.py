from __future__ import annotations

import json

from pencheff_api.services.security_lake.lake_schema import (
    LAKE_SCHEMA, LAKE_PARTITION_SPEC, to_lake_row, dt_from_ms,
)


def _event():
    return {
        "class_uid": 2002, "time": 1_700_000_000_000, "severity_id": 4, "status_id": 1,
        "finding_info": {"uid": "fp123", "title": "x"},
    }


def test_dt_from_ms_is_utc_date_string():
    assert dt_from_ms(1_700_000_000_000) == "2023-11-14"


def test_to_lake_row_projects_columns():
    row = to_lake_row(_event(), org_id="o1", source="sast", asset_id="r1")
    assert row["org_id"] == "o1"
    assert row["asset_id"] == "r1"
    assert row["status_id"] == 1
    assert row["class_uid"] == 2002
    assert row["finding_uid"] == "fp123"
    assert row["dt"] == "2023-11-14"
    import json
    assert json.loads(row["ocsf_json"])["finding_info"]["uid"] == "fp123"


def test_row_keys_match_schema_fields():
    row = to_lake_row(_event(), org_id="o1", source="sast", asset_id="r1")
    assert set(row.keys()) == {f.name for f in LAKE_SCHEMA.fields}


def test_partition_spec_partitions_on_org_class_dt():
    names = {pf.name for pf in LAKE_PARTITION_SPEC.fields}
    assert names == {"org_id", "class_uid", "dt"}


def test_to_lake_row_requires_uid():
    import pytest
    bad = {"class_uid": 2002, "time": 1_700_000_000_000, "severity_id": 4, "status_id": 1,
           "finding_info": {"title": "no uid"}}
    with pytest.raises(ValueError):
        to_lake_row(bad, org_id="o1", source="sast", asset_id="r1")
