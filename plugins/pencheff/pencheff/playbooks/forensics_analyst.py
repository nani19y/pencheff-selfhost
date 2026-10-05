"""forensics-analyst — defaults to Tier 1 advisory; promotes to Tier 2
when --image / --evidence is supplied (then drives the gap module)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pencheff.core.tier import tier_1
from pencheff.playbooks.base import Playbook, RunResult

_CARD = Path(__file__).resolve().parents[1] / "data" / "methodology" / "forensics.md"


class ForensicsAnalystPlaybook(Playbook):
    name = "forensics_analyst"
    tier = 1
    phase = "postex"
    noise = "quiet"
    mitre = []
    handoff_to = ["report_generator"]
    requires_scope = False
    description = "Forensics methodology + memory/timeline/disk wrapper invocation."

    @tier_1
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  image: str | None = None, evidence_dir: str | None = None,
                  mode: str = "advisor", **kwargs: Any) -> RunResult:
        card = _CARD.read_text() if _CARD.exists() else ""
        actions: list[dict[str, Any]] = []
        if mode == "memory" and image:
            from pencheff.modules.forensics import volatility
            actions.append(await volatility.triage(image))
        elif mode == "timeline" and evidence_dir:
            from pencheff.modules.forensics import timeline
            actions.append(await timeline.build(evidence_dir))
        elif mode == "disk" and image:
            from pencheff.modules.forensics import disk
            actions.append(await disk.triage(image))
        self._log(eng_db, engagement_id, "forensics",
                  summary=f"mode={mode}, actions={len(actions)}")
        return RunResult(
            playbook=self.name,
            summary=f"Forensics ({mode}) — {len(actions)} action(s).",
            actions=actions,
            handoffs=list(self.handoff_to),
            artifacts={"card": card, "mode": mode},
        )
