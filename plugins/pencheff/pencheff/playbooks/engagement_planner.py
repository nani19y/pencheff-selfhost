"""engagement-planner — Tier 1 advisory.

Produces a phased pentest plan for the engagement scope, with
MITRE ATT&CK technique coverage filtered by engagement type.
"""

from __future__ import annotations

from typing import Any

from pencheff.core import mitre_attack
from pencheff.core.tier import tier_1
from pencheff.playbooks.base import Playbook, RunResult


_PHASES = [
    ("Scoping",            "scope",   "Confirm targets, exclusions, timing windows, oast callbacks, OPSEC profile."),
    ("Reconnaissance",     "recon",   "Passive + active discovery of attack surface."),
    ("Vulnerability Assessment", "vuln", "Run scanners across web/api/cloud/network categories."),
    ("Exploitation",       "exploit", "Verify findings with PoCs, chain low-severity issues into full compromise paths."),
    ("Post-Exploitation",  "postex",  "Privilege escalation, lateral movement, persistence (within scope)."),
    ("Detection Engineering", "detect", "Generate Sigma / SPL / KQL rules for observed TTPs."),
    ("Reporting",          "report",  "Deliverables, evidence packaging, stakeholder briefing."),
]

_TYPE_TACTICS = {
    "external":  ["reconnaissance", "initial-access", "credential-access", "discovery"],
    "internal":  ["discovery", "credential-access", "lateral-movement", "privilege-escalation"],
    "webapp":    ["initial-access", "execution", "credential-access"],
    "cloud":     ["initial-access", "credential-access", "discovery", "collection"],
    "wireless":  ["reconnaissance", "credential-access"],
    "mobile":    ["reconnaissance", "credential-access", "collection"],
}


class EngagementPlannerPlaybook(Playbook):
    name = "engagement_planner"
    tier = 1
    phase = "scope"
    noise = "quiet"
    mitre = []
    handoff_to = ["recon_advisor", "osint_collector", "threat_modeler"]
    requires_scope = False
    description = "Phased engagement plan + MITRE coverage map."

    @tier_1
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  scope: dict[str, Any] | None = None, **kwargs: Any) -> RunResult:
        scope = scope or {}
        etype = scope.get("type", "external")
        tactics = _TYPE_TACTICS.get(etype, _TYPE_TACTICS["external"])

        plan_lines: list[str] = [
            f"# Engagement Plan — {scope.get('client', 'unknown')} ({etype})",
            f"_Authorized by:_ {scope.get('authorized_by', '(unspecified)')}",
            f"_OPSEC posture:_ {scope.get('opsec', 'standard')}",
            "",
            "## Phases",
        ]
        for label, key, desc in _PHASES:
            plan_lines.append(f"### {label} ({key})")
            plan_lines.append(desc)
            plan_lines.append("")

        plan_lines.append("## MITRE ATT&CK coverage")
        for tac in tactics:
            techs = mitre_attack.by_tactic(tac)
            plan_lines.append(f"### {tac}")
            for t in techs[:6]:
                plan_lines.append(f"- **{t['id']}** {t['name']} — {t.get('description', '')}")
            plan_lines.append("")

        plan = "\n".join(plan_lines)

        self._log(eng_db, engagement_id, "engagement_plan",
                  summary=f"plan for {etype} engagement", detail={"phases": len(_PHASES)})

        return RunResult(
            playbook=self.name,
            summary=f"Generated phased plan for '{etype}' engagement.",
            handoffs=list(self.handoff_to),
            artifacts={"plan_markdown": plan, "tactics": tactics},
        )
