"""privesc-advisor — Tier 1 advisory.

Renders the privilege-escalation methodology card and parses
linpeas / winpeas output if provided.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pencheff.core.tier import tier_1
from pencheff.playbooks.base import Playbook, RunResult

_CARD = Path(__file__).resolve().parents[1] / "data" / "methodology" / "privesc.md"


class PrivescAdvisorPlaybook(Playbook):
    name = "privesc_advisor"
    tier = 1
    phase = "postex"
    noise = "quiet"
    mitre = ["T1068", "T1548", "T1574"]
    handoff_to = ["report_generator"]
    requires_scope = False
    description = "Linux/Windows privesc methodology + linpeas output triage."

    @tier_1
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  peas_output: str | None = None, **kwargs: Any) -> RunResult:
        card = _CARD.read_text() if _CARD.exists() else ""
        observations: list[str] = []
        if peas_output:
            for marker, text in [
                ("[+] [CVE-", "kernel CVE candidate"),
                (" sudo ", "sudo entry — cross-ref GTFOBins"),
                ("SUID", "SUID binary — cross-ref GTFOBins"),
                ("SeImpersonatePrivilege", "Potato-family token impersonation viable"),
                ("Unquoted Service Path", "unquoted service path → exec hijack"),
                ("AlwaysInstallElevated", "AlwaysInstallElevated set → MSI privesc"),
            ]:
                if marker in peas_output:
                    observations.append(text)
        self._log(eng_db, engagement_id, "privesc_advisor",
                  summary=f"{len(observations)} privesc observation(s)")
        return RunResult(
            playbook=self.name,
            summary=f"Privesc methodology + {len(observations)} observation(s).",
            handoffs=list(self.handoff_to),
            artifacts={"card": card, "observations": observations},
        )
