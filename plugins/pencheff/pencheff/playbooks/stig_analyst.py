"""stig-analyst — Tier 1 advisory.

DISA STIG catalog lookup (deterministic). Matches asset hints to
STIG IDs and emits remediation snippets.
"""

from __future__ import annotations

from typing import Any

from pencheff.core import stig
from pencheff.core.tier import tier_1
from pencheff.playbooks.base import Playbook, RunResult


class StigAnalystPlaybook(Playbook):
    name = "stig_analyst"
    tier = 1
    phase = "vuln"
    noise = "quiet"
    mitre = []
    handoff_to = ["report_generator"]
    requires_scope = False
    description = "DISA STIG lookup + remediation."

    @tier_1
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  asset: str = "webapp", stig_id: str | None = None, **kwargs: Any) -> RunResult:
        if stig_id:
            text = stig.render(stig_id)
            self._log(eng_db, engagement_id, "stig_lookup", summary=stig_id)
            return RunResult(playbook=self.name,
                             summary=f"STIG {stig_id} rendered.",
                             handoffs=list(self.handoff_to),
                             artifacts={"render": text, "stig_id": stig_id})
        items = stig.for_asset(asset)
        rendered = [stig.render(i["id"]) for i in items]
        self._log(eng_db, engagement_id, "stig_lookup",
                  summary=f"{len(items)} STIGs for {asset}")
        return RunResult(
            playbook=self.name,
            summary=f"{len(items)} STIG(s) for asset '{asset}'.",
            handoffs=list(self.handoff_to),
            artifacts={"items": items, "rendered": rendered, "asset": asset},
        )
