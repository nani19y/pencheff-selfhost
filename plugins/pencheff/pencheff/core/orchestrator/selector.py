"""Tool selector — replaces a learned-model decision engine with a lookup.

Given ``(target_profile, objective)``, returns an ordered list of
``ToolCandidate``\\ s sorted by confidence. The orchestrator consumes the
list head-first; ``FallbackResolver`` walks deeper if the head is missing or
fails.
"""

from __future__ import annotations

from dataclasses import dataclass

from pencheff.core.orchestrator.policies import Policies, load_policies


@dataclass(frozen=True)
class ToolCandidate:
    tool: str
    confidence: float
    ttl: int = 3600          # cache TTL the orchestrator should apply
    notes: str = ""
    native: bool = False     # True → tool is implemented in pencheff itself


class Selector:
    def __init__(self, policies: Policies | None = None) -> None:
        self._policies = policies or load_policies()

    def candidates(
        self,
        target_profile: str,
        objective: str,
    ) -> list[ToolCandidate]:
        profiles = self._policies.tool_selection.get("profiles", {})
        bucket = profiles.get(target_profile, {})
        rows = bucket.get(objective, [])
        out: list[ToolCandidate] = []
        for row in rows:
            out.append(
                ToolCandidate(
                    tool=row["tool"],
                    confidence=float(row.get("confidence", 0.5)),
                    ttl=int(row.get("ttl", 3600)),
                    notes=row.get("notes", "") or "",
                    native=bool(row.get("native", False)),
                )
            )
        # Already authored in priority order; sort defensively by confidence
        # descending while keeping a stable secondary key on tool name.
        return sorted(out, key=lambda c: (-c.confidence, c.tool))

    def known_profiles(self) -> list[str]:
        return sorted(self._policies.tool_selection.get("profiles", {}).keys())

    def known_objectives(self, target_profile: str) -> list[str]:
        return sorted(
            self._policies.tool_selection.get("profiles", {})
            .get(target_profile, {})
            .keys()
        )
