"""Stakeholder-Specific Vulnerability Categorization (SSVC) — CISA's
deployer-profile decision tree, simplified for deterministic scoring.

Reference: CISA Stakeholder-Specific Vulnerability Categorization Guide,
v2.1 (https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide.pdf).

The full tree has four inputs (Exploitation × Exposure × Utility ×
Human Impact) producing a 4-way action class (Track / Track* / Attend /
Act). Pencheff doesn't have ground truth for Utility ("super effective"
vs "efficient" vs "laborious") — that's a humans-in-the-loop judgement —
so we use a published-CISA-derived shortcut that reads:

    Exploitation = active   ⇒ Act
    Exploitation = poc      AND Impact ≥ high       ⇒ Attend
    Exploitation = poc      AND Exposure = open     ⇒ Attend
    Exploitation = none     AND Impact = very_high  ⇒ Track*
    everything else                                 ⇒ Track

This matches CISA's 'top of the tree' guidance for KEV/EPSS-driven
prioritisation and gives Pencheff a defensible default. Operators who
need the full deployer matrix can override the result through the
manual-triage UI.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal


# ── Inputs ───────────────────────────────────────────────────────────


Exploitation = Literal["none", "poc", "active"]
Exposure = Literal["small", "controlled", "open"]
Impact = Literal["low", "medium", "high", "very_high"]


def exploitation_from(kev: bool, epss: float | None) -> Exploitation:
    """Derive the SSVC ``Exploitation`` axis.

    * KEV-listed CVEs map to ``active`` — CISA has confirmed in-the-wild
      exploitation, that's the strongest signal.
    * EPSS ≥ 0.5 (50% chance of exploitation in the next 30 days) maps
      to ``poc`` — proof-of-concept code is almost certainly published.
    * Everything else maps to ``none``.
    """
    if kev:
        return "active"
    if epss is not None and epss >= 0.5:
        return "poc"
    return "none"


def impact_from_cvss(cvss: float | None) -> Impact:
    if cvss is None:
        return "low"
    if cvss >= 9.0:
        return "very_high"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def exposure_from_category(category: str | None, finding_kind: str = "dast") -> Exposure:
    """Best-effort exposure read from finding metadata.

    DAST findings come from internet-facing scans by definition → ``open``.
    SCA / SAST findings live in source code that may or may not be
    deployed externally → default to ``controlled``. The category-level
    bumps below catch the obvious "internet-facing service" categories.
    """
    if finding_kind == "dast":
        return "open"
    cat = (category or "").lower()
    if cat in {"infrastructure", "cors", "headers", "ssl_tls", "components"}:
        return "controlled"
    if cat in {"injection", "xss", "auth", "authz", "ssrf", "deserialization"}:
        # Source-code findings on classic injection sinks usually do
        # surface internet-facing handlers. Assume open unless triage
        # downgrades it.
        return "open"
    return "controlled"


# ── Output ───────────────────────────────────────────────────────────


class SSVCDecision(str, Enum):
    TRACK = "track"          # Routine; track in the backlog.
    TRACK_STAR = "track_star"  # Track with elevated attention.
    ATTEND = "attend"        # Plan a fix in the current cycle.
    ACT = "act"              # Drop everything; remediate now.


@dataclass(frozen=True)
class SSVCInputs:
    exploitation: Exploitation
    exposure: Exposure
    impact: Impact


def ssvc_decision(inputs: SSVCInputs) -> SSVCDecision:
    """Apply the simplified SSVC decision tree (see module docstring)."""
    if inputs.exploitation == "active":
        return SSVCDecision.ACT
    if inputs.exploitation == "poc":
        if inputs.impact in ("high", "very_high"):
            return SSVCDecision.ATTEND
        if inputs.exposure == "open":
            return SSVCDecision.ATTEND
        return SSVCDecision.TRACK_STAR
    # exploitation == "none"
    if inputs.impact == "very_high":
        return SSVCDecision.TRACK_STAR
    return SSVCDecision.TRACK
