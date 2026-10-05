"""Attack-chain planner.

Reads ``chains.yaml`` and matches each chain's preconditions against the
current Finding set. Chains whose every precondition is satisfied are
returned ordered by severity, then by the chain's index in the YAML
(authoring order) — keeps planner output deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from pencheff.core.orchestrator.policies import Policies, load_policies


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class ChainPlan:
    id: str
    name: str
    severity: str
    steps: list[dict[str, Any]]
    postcondition_type: str
    matched_findings: tuple[str, ...]  # finding ids that satisfied preconditions


class ChainPlanner:
    def __init__(self, policies: Policies | None = None) -> None:
        self._policies = policies or load_policies()

    def plan(self, findings: Iterable[Any]) -> list[ChainPlan]:
        """Return chains whose preconditions are all met by ``findings``."""
        findings_list = list(findings)
        out: list[tuple[int, ChainPlan]] = []
        for idx, chain in enumerate(self._policies.chains.get("chains", [])):
            matched = self._match_preconditions(chain.get("preconditions", []), findings_list)
            if matched is None:
                continue
            plan = ChainPlan(
                id=chain["id"],
                name=chain.get("name", chain["id"]),
                severity=chain.get("severity", "medium"),
                steps=list(chain.get("steps", [])),
                postcondition_type=chain.get("postcondition_type", ""),
                matched_findings=tuple(matched),
            )
            out.append((idx, plan))
        out.sort(key=lambda pair: (SEVERITY_ORDER.get(pair[1].severity, 99), pair[0]))
        return [plan for _, plan in out]

    @staticmethod
    def _match_preconditions(
        preconditions: list[dict[str, Any]],
        findings: list[Any],
    ) -> list[str] | None:
        """Return the list of finding ids that satisfy every precondition.

        ``None`` means at least one precondition couldn't be matched.
        """
        matched_ids: list[str] = []
        for cond in preconditions:
            need_type = cond.get("finding_type")
            need_attr = cond.get("attribute")
            hit = None
            for f in findings:
                # Findings expose a ``category`` (e.g. ssrf, xss_reflected) and
                # an optional ``attributes`` dict. The lookup is generous —
                # category may also be reported via ``finding_type`` or
                # ``type`` on dict-shaped findings.
                ftype = (
                    getattr(f, "finding_type", None)
                    or getattr(f, "category", None)
                    or (f.get("finding_type") if isinstance(f, dict) else None)
                    or (f.get("category") if isinstance(f, dict) else None)
                )
                if ftype != need_type:
                    continue
                if need_attr:
                    attrs = (
                        getattr(f, "attributes", None)
                        or (f.get("attributes") if isinstance(f, dict) else None)
                        or {}
                    )
                    if not attrs.get(need_attr):
                        continue
                fid = (
                    getattr(f, "id", None)
                    or (f.get("id") if isinstance(f, dict) else None)
                    or ""
                )
                hit = fid
                break
            if hit is None:
                return None
            matched_ids.append(hit)
        return matched_ids
