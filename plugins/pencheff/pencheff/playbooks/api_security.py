"""api-security — Tier 2 execution.

Discovery + scan_api covering REST / GraphQL / WebSocket per OWASP API
Top 10 (2023). Imports OpenAPI / Swagger / Postman specs when given.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


class ApiSecurityPlaybook(Playbook):
    name = "api_security"
    tier = 2
    phase = "vuln"
    noise = "moderate"
    mitre = ["T1190", "T1078"]
    handoff_to = ["exploit_chainer", "poc_validator"]
    requires_scope = True
    description = "API discovery + OWASP API Top 10 testing."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  spec: str | None = None, **kwargs: Any) -> RunResult:
        guard = current_scope()
        if guard:
            guard.validate(session.target.base_url)
        from pencheff import server as _srv
        before = session.findings.count
        results: dict[str, Any] = {}
        if spec:
            try:
                results["import"] = await _srv.import_api_spec(
                    session_id=session.id, spec_path=spec,
                )
            except Exception:
                pass
        results["discovery"] = await _srv.recon_api_discovery(session_id=session.id)
        results["scan"] = await _srv.scan_api(session_id=session.id)
        try:
            results["websocket"] = await _srv.scan_websocket(session_id=session.id)
        except Exception:
            pass
        new_findings = session.findings.count - before
        self._log(eng_db, engagement_id, "scan_api",
                  summary=f"+{new_findings} findings")
        return RunResult(
            playbook=self.name,
            summary=f"API security: +{new_findings} finding(s).",
            findings_added=new_findings,
            handoffs=list(self.handoff_to),
            artifacts=results,
        )
