"""cloud-security — Tier 2 execution.

scan_cloud + optional Pacu / ScoutSuite via run_security_tool.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


class CloudSecurityPlaybook(Playbook):
    name = "cloud_security"
    tier = 2
    phase = "vuln"
    noise = "moderate"
    mitre = ["T1078.004", "T1530", "T1602"]
    handoff_to = ["exploit_chainer", "report_generator"]
    requires_scope = True
    description = "Cloud (AWS/Azure/GCP) recon + IAM analysis."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  provider: str = "aws", **kwargs: Any) -> RunResult:
        guard = current_scope()
        # Cloud scope check is account-based, not URL-based — defer to scan_cloud's own checks.
        from pencheff import server as _srv
        before = session.findings.count
        results = await _srv.scan_cloud(session_id=session.id, provider=provider)
        new_findings = session.findings.count - before
        self._log(eng_db, engagement_id, "scan_cloud",
                  summary=f"{provider}: +{new_findings} findings")
        return RunResult(
            playbook=self.name,
            summary=f"Cloud ({provider}): +{new_findings} finding(s).",
            findings_added=new_findings,
            handoffs=list(self.handoff_to),
            artifacts={"provider": provider, "results": results},
        )
