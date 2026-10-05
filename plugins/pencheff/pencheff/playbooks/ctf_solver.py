"""ctf-solver — Tier 2 execution.

Heuristic CTF playbook: nmap → service enumeration → web/exploit attempt.
Designed for HTB-/PicoCTF-style targets where scope is the explicit IP.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


class CtfSolverPlaybook(Playbook):
    name = "ctf_solver"
    tier = 2
    phase = "vuln"
    noise = "moderate"
    mitre = ["T1595", "T1190"]
    handoff_to = ["exploit_chainer", "poc_validator", "report_generator"]
    requires_scope = True
    description = "CTF-style sweep: nmap → enum → exploit attempt."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  target: str | None = None, **kwargs: Any) -> RunResult:
        guard = current_scope()
        target = target or session.target.base_url
        if guard:
            guard.validate(target)
        from pencheff import server as _srv
        results: dict[str, Any] = {}
        try:
            results["nmap"] = await _srv.run_security_tool(
                session_id=session.id, tool="nmap",
                args=["-sV", "-sC", "-T4", "-p-", "--min-rate", "1000", target],
            )
        except Exception as exc:
            results["nmap"] = {"error": str(exc)}
        try:
            results["pulse"] = await _srv.scan_pulse(session_id=session.id)
        except Exception:
            pass
        self._log(eng_db, engagement_id, "ctf_solver",
                  summary=f"target={target}")
        return RunResult(
            playbook=self.name,
            summary="CTF sweep complete.",
            handoffs=list(self.handoff_to),
            artifacts=results,
        )
