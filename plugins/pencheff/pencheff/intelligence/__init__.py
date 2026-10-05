"""Vulnerability prioritisation intelligence — EPSS lookups, SSVC
decision tree, and the unified priority score that the dashboard sorts
by. Pure functions; no I/O beyond the EPSS feed (which lives in
``pencheff.core.cve_feed``).
"""

from .priority import PriorityInputs, PriorityOutputs, compute_priority
from .reachability import Reachability, classify as classify_reachability
from .ssvc import SSVCDecision, ssvc_decision

__all__ = [
    "PriorityInputs",
    "PriorityOutputs",
    "Reachability",
    "SSVCDecision",
    "classify_reachability",
    "compute_priority",
    "ssvc_decision",
]
