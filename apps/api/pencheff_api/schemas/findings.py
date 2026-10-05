from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class FindingTriageOut(BaseModel):
    """AI Triage 2.0 — DeepSeek-backed exploitability walkthrough."""
    walkthrough: str | None = None
    blast_radius: str | None = None
    exploit_scenario: str | None = None
    fix_outline: str | None = None
    confidence: str | None = None         # low | medium | high
    model: str | None = None


class FindingOut(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: str
    category: str
    owasp_category: str | None = None
    cwe_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    endpoint: str | None = None
    parameter: str | None = None
    description: str | None = None
    remediation: str | None = None
    evidence: list | None = None
    references: list[str] | None = None
    verification_status: str
    # AI-agent exploitability verdict: True = verified exploitable ("hackable"),
    # False = verified false-positive, null = not yet determined.
    hackable: bool | None = None
    suppressed: bool
    suppress_reason: str | None = None
    last_rechecked_at: datetime | None = None
    recheck_status: str | None = None
    ai_triage: FindingTriageOut | None = None
    # Prioritisation surface — Pencheff sorts finding lists by risk_score
    # (CVSS × EPSS × KEV × SSVC), so the dashboard exposes the components.
    risk_score: float | None = None
    ssvc_decision: str | None = None
    reachability: str | None = None
    epss: float | None = None
    kev: bool = False
    created_at: datetime


class SuppressRequest(BaseModel):
    reason: Literal["accepted_risk", "wont_fix", "false_positive", "duplicate", "out_of_scope"]
    notes: str | None = None


class StatusUpdate(BaseModel):
    verification_status: Literal["unverified", "true_positive", "false_positive", "fixed"]
