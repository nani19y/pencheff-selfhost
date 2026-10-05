"""recon-advisor — Tier 2 execution.

Drives ``recon_passive``, ``recon_active``, and ``recon_api_discovery``
from the existing MCP server. Validates target against scope before
each call, mirrors hosts/services into the engagement DB.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


class ReconAdvisorPlaybook(Playbook):
    name = "recon_advisor"
    tier = 2
    phase = "recon"
    noise = "moderate"
    mitre = ["T1595", "T1590", "T1592", "T1046"]
    handoff_to = ["vuln_scanner", "web_hunter", "api_security"]
    requires_scope = True
    description = "Passive + active recon, port/service discovery."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  active: bool = True, port_range: str = "top-1000",
                  **kwargs: Any) -> RunResult:
        guard = current_scope()
        if guard:
            guard.validate(session.target.base_url)
        from pencheff import server as _srv
        before = session.findings.count
        results: dict[str, Any] = {}
        try:
            results["passive"] = await _srv.recon_passive(session_id=session.id)
        except Exception as exc:
            results["passive"] = {"error": str(exc)}
        if active:
            try:
                results["active"] = await _srv.recon_active(
                    session_id=session.id, port_range=port_range,
                )
            except Exception as exc:
                # browser_crawler / Playwright is optional — keep recon useful
                # even when the headless browser is unavailable.
                results["active"] = {"error": str(exc)[:200]}
        try:
            results["api"] = await _srv.recon_api_discovery(session_id=session.id)
        except Exception as exc:
            results["api"] = {"error": str(exc)}
        new_findings = session.findings.count - before

        # Mirror hosts/services to engagement DB
        if eng_db and engagement_id:
            host = urlparse(session.target.base_url).hostname or session.target.base_url
            host_id = eng_db.add_host(engagement_id, hostname=host,
                                      discovered_by=self.name)
            for sd in session.discovered.subdomains or []:
                eng_db.add_host(engagement_id, hostname=sd,
                                discovered_by=self.name)
            for port in session.discovered.open_ports or []:
                eng_db.add_service(host_id, port=port.get("port", 0),
                                   protocol=port.get("protocol", "tcp"),
                                   service=port.get("service"),
                                   version=port.get("version"))
        self._log(eng_db, engagement_id, "recon_active",
                  summary=f"+{new_findings} findings, {len(session.discovered.subdomains)} subdomains")
        return RunResult(
            playbook=self.name,
            summary=f"Recon: +{new_findings} finding(s).",
            findings_added=new_findings,
            handoffs=list(self.handoff_to),
            artifacts=results,
        )
