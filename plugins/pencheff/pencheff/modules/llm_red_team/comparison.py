"""A/B comparison helpers for LLM red-team runs."""
from __future__ import annotations

from typing import Any

from .reporting import build_red_team_summary, diff_red_team_findings, finding_key


def compare_red_team_runs(
    baseline_findings: list[Any],
    candidate_findings: list[Any],
    *,
    baseline_name: str = "baseline",
    candidate_name: str = "candidate",
) -> dict[str, Any]:
    """Compare two model/target runs of the same suite.

    The return shape is intentionally API/UI-friendly: summaries for
    each side plus candidate-only regressions, baseline-only fixes, and
    common failures keyed by the same stable finding dimensions used by
    normal red-team regression diffs.
    """
    diff = diff_red_team_findings(baseline_findings, candidate_findings)
    return {
        "baseline": {
            "name": baseline_name,
            "summary": build_red_team_summary(baseline_findings),
        },
        "candidate": {
            "name": candidate_name,
            "summary": build_red_team_summary(candidate_findings),
        },
        "regressions": diff["new"],
        "fixes": diff["resolved"],
        "common_failures": diff["unchanged"],
        "counts": {
            "regressions": diff["counts"]["new"],
            "fixes": diff["counts"]["resolved"],
            "common_failures": diff["counts"]["unchanged"],
        },
        "keys": {
            "regressions": [finding_key(f) for f in diff["new"]],
            "fixes": [finding_key(f) for f in diff["resolved"]],
            "common_failures": [finding_key(f) for f in diff["unchanged"]],
        },
    }
