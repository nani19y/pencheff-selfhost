"""bizlogic-hunter — Tier 2 execution.

Drives ``scan_business_logic``, plus optional intruder runs for
race-condition / batch-purchase / coupon abuse.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


class BizlogicHunterPlaybook(Playbook):
    name = "bizlogic_hunter"
    tier = 2
    phase = "vuln"
    noise = "moderate"
    mitre = ["T1190", "T1078"]
    handoff_to = ["poc_validator", "report_generator"]
    requires_scope = True
    description = "Business-logic flaws: pricing, race, workflow."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  **kwargs: Any) -> RunResult:
        guard = current_scope()
        if guard:
            guard.validate(session.target.base_url)
        from pencheff import server as _srv
        before = session.findings.count
        result = await _srv.scan_business_logic(session_id=session.id)
        new = session.findings.count - before
        self._log(eng_db, engagement_id, "scan_business_logic",
                  summary=f"+{new} findings")
        return RunResult(
            playbook=self.name,
            summary=f"BizLogic: +{new} finding(s).",
            findings_added=new,
            handoffs=list(self.handoff_to),
            artifacts={"result": result},
        )
