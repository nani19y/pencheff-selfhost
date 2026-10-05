from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


FindingKind = Literal["sast", "dast"]
ProposalStatus = Literal["draft", "applied", "failed", "superseded"]
ProposalSource = Literal["scanner", "llm"]


class ProposeFixRequest(BaseModel):
    """Body for ``POST /findings/{kind}/{id}/propose_fix``."""
    allow_payg: bool = False
    # Reserved for the upcoming "regenerate" flow — re-runs the LLM with
    # the previous proposal's diff included as anti-context. Ignored for
    # scanner-source proposals.
    regenerate: bool = False


class FixProposalOut(BaseModel):
    id: str
    finding_kind: FindingKind
    finding_id: str
    repository_id: str | None = None
    status: ProposalStatus
    source: ProposalSource
    diff: str
    target_files: list[str] = Field(default_factory=list)
    provenance_confidence: float | None = None
    provenance_reasoning: str | None = None
    llm_input_tokens: int | None = None
    llm_output_tokens: int | None = None
    cost_usd: float | None = None
    branch_name: str | None = None
    pr_url: str | None = None
    commit_sha: str | None = None
    error: str | None = None
    # Informational message surfaced once when the proposal is generated —
    # e.g. the deterministic-fallback notice when the org is over its monthly
    # AI allotment. Not persisted; only set on the live propose response.
    notice: str | None = None
    created_at: datetime
    applied_at: datetime | None = None


class ApplyResultOut(BaseModel):
    proposal_id: str
    status: ProposalStatus
    branch_name: str | None
    commit_sha: str | None
    pr_url: str | None
    error: str | None = None


class FixUsageOut(BaseModel):
    """Returned by ``GET /usage/fix-llm``. Drives the UI quota strip.

    Monthly hard-cap model: one flat per-org fix counter that resets on the
    calendar-month boundary. ``has_fix_access`` is True for every plan that
    has a non-zero allotment (all plans today).
    """
    plan: str
    has_fix_access: bool
    monthly_cap: int
    monthly_used: int
    monthly_remaining: int
    period_resets_at: str
    beta: bool = False
