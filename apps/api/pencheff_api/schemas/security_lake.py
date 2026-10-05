# pencheff_api/schemas/security_lake.py
from __future__ import annotations

from pydantic import BaseModel


class LakeFindingItem(BaseModel):
    finding_uid: str
    class_uid: int
    source: str
    severity_id: int
    status_id: int
    asset_id: str
    time: int
    dt: str
    org_id: str
    ocsf_json: str | None = None


class LakeFindingsPage(BaseModel):
    items: list[LakeFindingItem]
    total: int
    limit: int
    offset: int


class LakeTrendPoint(BaseModel):
    dt: str
    open_findings: int
    high_critical: int


class LakeCorrelation(BaseModel):
    cve: str
    assets: int
    findings: int
