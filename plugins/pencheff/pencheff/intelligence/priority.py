"""Unified priority score combining CVSS × EPSS × KEV × SSVC × reachability.

The output is a 0..100 number that the dashboard sorts by. Components:

  * **CVSS** (0..10)               → 50% baseline
  * **EPSS** (0..1)                → up to 25% boost when EPSS ≥ 0.9
  * **KEV** (bool)                 → fixed 15% boost when listed
  * **SSVC**                       → action class flat-multiplier
  * **Reachability** ('exploited'/'reachable'/'present'/'unknown')
                                   → up to 10% boost when DAST-verified

The formula is intentionally simple — the value of priority sorting
comes from the combination of inputs, not the precise weights. Operators
who want stricter ordering can override via SSVC re-classification in
the triage UI.

Math is deterministic and pure; the same inputs always produce the same
score. Rounded to 2 decimals so equal-priority findings sort
deterministically by their secondary key (severity → created_at).
"""
from __future__ import annotations

from dataclasses import dataclass

from .ssvc import (
    SSVCDecision,
    SSVCInputs,
    exploitation_from,
    exposure_from_category,
    impact_from_cvss,
    ssvc_decision,
)


_SSVC_MULTIPLIER: dict[SSVCDecision, float] = {
    SSVCDecision.TRACK:      0.50,
    SSVCDecision.TRACK_STAR: 0.70,
    SSVCDecision.ATTEND:     0.85,
    SSVCDecision.ACT:        1.00,
}


@dataclass(frozen=True)
class PriorityInputs:
    cvss: float | None
    epss: float | None
    kev: bool
    category: str | None
    finding_kind: str = "dast"             # sast | dast
    reachability: str = "unknown"          # exploited | reachable | present | unknown


@dataclass(frozen=True)
class PriorityOutputs:
    score: float                           # 0..100
    ssvc: SSVCDecision
    epss: float | None
    kev: bool


def _reachability_boost(state: str) -> float:
    return {
        "exploited": 0.10,   # Pencheff verified the exploit live → max boost.
        "reachable": 0.05,   # Taint reaches sink, no live PoC.
        "present":   0.00,
        "unknown":   0.00,
    }.get(state, 0.0)


def compute_priority(inputs: PriorityInputs) -> PriorityOutputs:
    cvss = (inputs.cvss or 0.0) / 10.0       # 0..1
    epss = inputs.epss or 0.0                 # 0..1
    kev_boost = 0.15 if inputs.kev else 0.0
    epss_boost = 0.25 * epss if epss >= 0.5 else 0.0
    reach_boost = _reachability_boost(inputs.reachability)

    impact = impact_from_cvss(inputs.cvss)
    exposure = exposure_from_category(inputs.category, inputs.finding_kind)
    exploitation = exploitation_from(inputs.kev, inputs.epss)
    decision = ssvc_decision(SSVCInputs(
        exploitation=exploitation, exposure=exposure, impact=impact,
    ))
    ssvc_factor = _SSVC_MULTIPLIER[decision]

    raw = (
        0.50 * cvss
        + epss_boost
        + kev_boost
        + reach_boost
    ) * ssvc_factor
    score = max(0.0, min(1.0, raw)) * 100.0
    return PriorityOutputs(
        score=round(score, 2),
        ssvc=decision,
        epss=inputs.epss,
        kev=inputs.kev,
    )
