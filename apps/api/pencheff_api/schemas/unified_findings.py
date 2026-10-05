"""Pydantic shapes for the unified-findings endpoint."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class UnifiedFindingItem(BaseModel):
    id: str
    source: str                      # sast | dast | sca | iac | secret
    table: str                       # findings | repo_findings — for the
                                     # frontend to deep-link to the right detail page
    title: str
    severity: str
    risk_score: float
    reachability: str | None = None
    ssvc_decision: str | None = None
    epss: float | None = None
    kev: bool = False
    cwe_id: str | None = None
    owasp_category: str | None = None
    location: str
    package: str | None = None
    fixed_version: str | None = None
    suppressed: bool
    created_at: datetime
    workspace_id: str
    target_id: str | None = None
    repository_id: str | None = None


class UnifiedFindingsPage(BaseModel):
    items: list[UnifiedFindingItem]
    total: int
    limit: int
    offset: int
