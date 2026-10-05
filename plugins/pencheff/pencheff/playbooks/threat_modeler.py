"""threat-modeler — Tier 1 advisory.

STRIDE / DREAD generator backed by the deterministic rubric in
``data/stride_dread.json``. No LLM, no network egress.
"""

from __future__ import annotations

from typing import Any

from pencheff.core import threat_model
from pencheff.core.tier import tier_1
from pencheff.playbooks.base import Playbook, RunResult


class ThreatModelerPlaybook(Playbook):
    name = "threat_modeler"
    tier = 1
    phase = "scope"
    noise = "quiet"
    mitre = []
    handoff_to = ["attack_planner", "detection_engineer"]
    requires_scope = False
    description = "STRIDE / DREAD threat model from scope."

    @tier_1
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  scope: dict[str, Any] | None = None, method: str = "stride", **kwargs: Any) -> RunResult:
        scope = scope or {}
        model = threat_model.model_for_scope(scope, method=method)
        self._log(eng_db, engagement_id, "threat_model",
                  summary=f"{method.upper()} model: {len(model.get('assets', []))} asset(s)")
        return RunResult(
            playbook=self.name,
            summary=f"Threat model ({method.upper()}) for {len(model.get('assets', []))} asset(s).",
            handoffs=list(self.handoff_to),
            artifacts={"model": model},
        )
