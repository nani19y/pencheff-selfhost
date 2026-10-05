"""Per-finding reachability classifier — the moat.

Snyk says "this dependency has a CVE" — Pencheff says "this CVE is actually
**exploited** in your live deployment." That gap is the entire reason
this module exists. The classifier emits one of four states:

  * **exploited**  — Pencheff DAST verified the issue is live and reachable
                     from the public surface. Strongest possible signal.
                     Drop everything.
  * **reachable**  — Static taint analysis (Semgrep / CodeQL) traces user
                     input to a vulnerable sink, OR a vulnerable dependency
                     is actually imported in code reachable from public
                     entrypoints. Fix in the current sprint.
  * **present**    — Vulnerable code or dependency exists but no usage /
                     taint trace was found. Track in the backlog.
  * **unknown**    — Insufficient signal to classify. Default for findings
                     that pre-date the reachability engine.

The output is persisted on every finding and feeds the priority score
(see ``pencheff.intelligence.priority``). The dashboard renders this as
a coloured badge next to each finding so reviewers can scan a 1000-row
list and spot the ten things they actually need to act on.
"""
from __future__ import annotations

from enum import Enum
from typing import Any


class Reachability(str, Enum):
    EXPLOITED = "exploited"
    REACHABLE = "reachable"
    PRESENT = "present"
    UNKNOWN = "unknown"


# ── Single-finding classifier ───────────────────────────────────────


def classify(
    *,
    finding_kind: str,                       # "dast" | "sast" | "sca"
    category: str | None = None,
    evidence: list[dict] | None = None,
    verification_notes: str | None = None,
    verification_status: str | None = None,
) -> Reachability:
    """Classify a single finding from the metadata that's already on it.

    The function is intentionally pure — pass in the data you have, get
    back a classification. The cross-finding upgrade (SAST + matching
    DAST → exploited) lives in ``upgrade_with_dast_pairs``.
    """
    # Already-verified findings short-circuit. The active-verifier sets
    # `verification_status="true_positive"` after replaying the exploit
    # against the live target — that's the strongest signal we have.
    if (verification_status or "").lower() == "true_positive":
        return Reachability.EXPLOITED

    # SCA findings are routed through the same `findings` table as DAST
    # (so finding_kind would be "dast"), but they need a different
    # classifier because OSV matches don't prove live exploitation. Detect
    # them by category="components" / explicit kind="sca" and branch off
    # BEFORE the DAST short-circuit fires.
    if (category or "").lower() == "components" or finding_kind == "sca":
        notes = (verification_notes or "").lower()
        if "low_reachability" in notes or "no imports detected" in notes:
            return Reachability.PRESENT
        # OSV match without a usage probe — assume reachable until proven
        # otherwise. This is the right default: false positives on
        # reachability waste an engineer's time, false negatives on
        # exploitability cause incidents.
        return Reachability.REACHABLE

    # DAST findings (everything else with finding_kind="dast") are by
    # definition live-verified; the scanner only emits them when the
    # request/response pair confirmed the issue.
    if finding_kind == "dast":
        return Reachability.EXPLOITED

    # SAST: reachable if the rule emitted a taint trace, present otherwise.
    # Semgrep encodes traces as ``autofix.kind == "text_replace"`` with
    # explicit ``start_line``/``end_line`` — the rule authors only set
    # those when dataflow connected source to sink. Bandit / ruff don't
    # do dataflow, so they default to "present".
    for ev in evidence or []:
        autofix = ev.get("autofix") or {}
        if autofix.get("kind") == "text_replace" and autofix.get("start_line"):
            return Reachability.REACHABLE
        # CodeQL planted dataflow traces under request_method=="DATAFLOW".
        if ev.get("request_method") == "DATAFLOW":
            return Reachability.REACHABLE
    return Reachability.PRESENT


# ── Cross-finding upgrade ───────────────────────────────────────────


def upgrade_with_dast_pairs(
    sast_finding: dict[str, Any],
    dast_findings: list[dict[str, Any]],
) -> Reachability | None:
    """Upgrade a SAST finding to ``exploited`` if there's a DAST finding
    that hits the same CWE or shares a route token with the SAST file
    path. Returns ``None`` when no upgrade applies (caller keeps the
    original classification).

    Mirrors the heuristics in ``services.finding_correlation`` so a
    finding that's already been linked there gets a reachability bump
    even if the engagement-level UnifiedFinding row hasn't been written
    yet.
    """
    sast_cwe = (sast_finding.get("cwe") or sast_finding.get("cwe_id") or "").strip()
    sast_file = (sast_finding.get("endpoint") or sast_finding.get("file_path") or "").lower()
    sast_token = _route_token(sast_file)

    for d in dast_findings:
        d_cwe = (d.get("cwe") or d.get("cwe_id") or "").strip()
        if sast_cwe and d_cwe and sast_cwe == d_cwe:
            return Reachability.EXPLOITED
        # Match on ANY path segment, not just the last one — DAST URLs
        # commonly look like `/api/v2/orders/{id}/refund` where the
        # resource token (`orders`) is mid-path, not at the tail.
        d_endpoint = (d.get("endpoint") or "").lower().rstrip("/")
        if sast_token and len(sast_token) >= 4 and d_endpoint:
            for seg in d_endpoint.split("/"):
                if not seg:
                    continue
                if _route_token(seg) == sast_token:
                    return Reachability.EXPLOITED
    return None


def _route_token(path: str) -> str | None:
    """Mirrors ``services.finding_correlation._route_basename`` so
    the upgrade rules match the engagement-level correlator."""
    if not path:
        return None
    base = path.rsplit("/", 1)[-1]
    base = base.split(".", 1)[0]
    base = base.replace("_", "-").lower()
    return base or None
