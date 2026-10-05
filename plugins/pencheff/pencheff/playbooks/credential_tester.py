"""credential-tester — Tier 2 execution.

Hash cracking + brute-force via hydra/john/hashcat. No native Python
re-implementation — thin wrapper around proven external tools.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


class CredentialTesterPlaybook(Playbook):
    name = "credential_tester"
    tier = 2
    phase = "exploit"
    noise = "loud"
    mitre = ["T1110", "T1110.003", "T1003"]
    handoff_to = ["exploit_chainer", "report_generator"]
    requires_scope = True
    description = "Hashcat / John hash cracking; Hydra brute-force."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  hashes: str | None = None, hash_mode: str = "0",
                  wordlist: str = "/usr/share/wordlists/rockyou.txt",
                  hydra_target: str | None = None, hydra_service: str | None = None,
                  users: str | None = None, **kwargs: Any) -> RunResult:
        guard = current_scope()
        from pencheff import server as _srv
        results: dict[str, Any] = {}
        if hashes:
            try:
                results["hashcat"] = await _srv.run_security_tool(
                    session_id=session.id, tool="hashcat",
                    args=["-m", hash_mode, "-a", "0", hashes, wordlist, "--quiet"],
                )
            except Exception:
                results["hashcat"] = {"error": "hashcat unavailable"}
        if hydra_target and hydra_service and users:
            if guard:
                guard.validate(hydra_target)
            try:
                results["hydra"] = await _srv.run_security_tool(
                    session_id=session.id, tool="hydra",
                    args=["-L", users, "-P", wordlist, hydra_target, hydra_service],
                )
            except Exception:
                results["hydra"] = {"error": "hydra unavailable"}
        self._log(eng_db, engagement_id, "credential_test",
                  summary=f"hashcat={'yes' if hashes else 'no'} hydra={'yes' if hydra_target else 'no'}")
        return RunResult(
            playbook=self.name,
            summary="Credential tests executed.",
            handoffs=list(self.handoff_to),
            artifacts=results,
        )
