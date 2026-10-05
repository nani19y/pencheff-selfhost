"""vuln-scanner — Tier 2 execution.

Drives the broad vulnerability scanners: ``scan_pulse``, ``scan_infrastructure``,
plus optional external tools (nuclei, nikto) via ``run_security_tool``.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


class VulnScannerPlaybook(Playbook):
    name = "vuln_scanner"
    tier = 2
    phase = "vuln"
    noise = "moderate"
    mitre = ["T1190", "T1595"]
    handoff_to = ["web_hunter", "exploit_chainer", "poc_validator"]
    requires_scope = True
    description = "Pulse + infrastructure + nuclei/nikto scanning."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  use_external: bool = True, **kwargs: Any) -> RunResult:
        guard = current_scope()
        if guard:
            guard.validate(session.target.base_url)
        from pencheff import server as _srv
        before = session.findings.count
        results: dict[str, Any] = {}
        results["pulse"] = await _srv.scan_pulse(session_id=session.id)
        results["infra"] = await _srv.scan_infrastructure(session_id=session.id)
        results["waf"] = await _srv.scan_waf(session_id=session.id)
        if use_external:
            try:
                results["nuclei"] = await _srv.run_security_tool(
                    session_id=session.id, tool="nuclei",
                    args=["-u", session.target.base_url, "-silent"],
                )
            except Exception:
                pass
        new_findings = session.findings.count - before
        # Mirror to engagement DB
        if eng_db and engagement_id:
            for f in session.findings.get_all()[-new_findings:]:
                eng_db.add_vuln(
                    engagement_id, title=f.title, severity=f.severity.value,
                    cvss=f.cvss_score, description=f.description,
                    mitre_id=f.mitre_id, found_by=self.name,
                    status="unconfirmed",
                )
        self._log(eng_db, engagement_id, "scan_pulse",
                  summary=f"+{new_findings} findings")
        return RunResult(
            playbook=self.name, summary=f"Vuln scan: +{new_findings} finding(s).",
            findings_added=new_findings, handoffs=list(self.handoff_to),
            artifacts=results,
        )
