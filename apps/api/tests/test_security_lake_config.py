from __future__ import annotations

from pencheff_api.config import get_settings


def test_lake_settings_have_local_defaults():
    s = get_settings()
    assert s.lake_catalog_type in {"sql", "rest"}
    assert s.lake_catalog_type == "sql"           # safe local default
    assert s.lake_namespace == "pencheff"
    assert s.lake_table == "findings"
    assert s.lake_catalog_uri.startswith("sqlite://")
    assert s.lake_warehouse.startswith("file://")
