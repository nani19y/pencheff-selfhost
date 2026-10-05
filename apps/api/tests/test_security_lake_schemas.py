# tests/test_security_lake_schemas.py
from __future__ import annotations

from pencheff_api.schemas.security_lake import (
    LakeFindingItem, LakeFindingsPage, LakeTrendPoint, LakeCorrelation,
)


def test_findings_page_shape():
    item = LakeFindingItem(finding_uid="u1", class_uid=2002, source="sca",
                           severity_id=5, status_id=1, asset_id="r1",
                           time=1_700_000_000_000, dt="2023-11-14", org_id="o1")
    page = LakeFindingsPage(items=[item], total=1, limit=100, offset=0)
    assert page.items[0].finding_uid == "u1"
    assert page.total == 1


def test_trend_point_and_correlation():
    tp = LakeTrendPoint(dt="2023-11-14", open_findings=2, high_critical=1)
    co = LakeCorrelation(cve="CVE-2020-8203", assets=2, findings=2)
    assert tp.open_findings == 2 and co.assets == 2
