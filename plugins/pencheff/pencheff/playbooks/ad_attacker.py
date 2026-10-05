"""ad-attacker — Tier 2 execution.

Drives the AD gap module (BloodHound / Impacket / NetExec / Certipy).
Operations: bloodhound | secretsdump | kerberoast | asreproast | adcs.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


class AdAttackerPlaybook(Playbook):
    name = "ad_attacker"
    tier = 2
    phase = "exploit"
    noise = "loud"
    mitre = ["T1558", "T1558.003", "T1558.004", "T1003.006", "T1649", "T1187"]
    handoff_to = ["credential_tester", "exploit_chainer"]
    requires_scope = True
    description = "Active Directory exploitation: BH, Impacket, NXC, Certipy."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  op: str = "bloodhound", domain: str | None = None,
                  user: str | None = None, password: str | None = None,
                  dc: str | None = None, **kwargs: Any) -> RunResult:
        guard = current_scope()
        if guard and domain:
            guard.validate_domain(domain)
        from pencheff.modules.ad import bloodhound, impacket, crackmapexec, certipy
        result: dict[str, Any] = {"op": op}
        if op == "bloodhound":
            result.update(await bloodhound.collect(domain or "", user or "", password or "", dc or ""))
        elif op == "secretsdump":
            result.update(await impacket.secretsdump(domain or "", user or "", password or "", dc or ""))
        elif op == "kerberoast":
            result.update(await impacket.kerberoast(domain or "", user or "", password or "", dc or ""))
        elif op == "asreproast":
            result.update(await impacket.asreproast(domain or "", dc or "", users=kwargs.get("users", "")))
        elif op == "adcs":
            result.update(await certipy.find(domain or "", user or "", password or "", dc or ""))
        elif op == "smb":
            result.update(await crackmapexec.smb(kwargs.get("target", ""), user or "", password or ""))
        else:
            result["error"] = f"unknown op '{op}'"
        # Persist creds if returned
        if eng_db and engagement_id:
            for c in result.get("credentials", []):
                eng_db.add_credential(engagement_id, username=c.get("username"),
                                      secret=c.get("secret"), secret_type=c.get("type", "ntlm"),
                                      domain=domain, source=self.name)
        self._log(eng_db, engagement_id, f"ad_{op}",
                  summary=result.get("summary", op))
        return RunResult(
            playbook=self.name,
            summary=f"AD: {op} executed.",
            handoffs=list(self.handoff_to),
            artifacts=result,
        )
