"""attack-planner — Tier 1 advisory.

Graph algorithm over the engagement DB ``vulns`` + observed services.
Suggests chains by walking MITRE technique relationships.
"""

from __future__ import annotations

from typing import Any

from pencheff.core import mitre_attack
from pencheff.core.tier import tier_1
from pencheff.playbooks.base import Playbook, RunResult


_TACTIC_ORDER = [
    "reconnaissance",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


class AttackPlannerPlaybook(Playbook):
    name = "attack_planner"
    tier = 1
    phase = "exploit"
    noise = "quiet"
    mitre = []
    handoff_to = ["exploit_chainer"]
    requires_scope = False
    description = "Graph findings into MITRE-ordered attack chains."

    @tier_1
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  **kwargs: Any) -> RunResult:
        chains: list[dict[str, Any]] = []
        if eng_db and engagement_id:
            data = eng_db.show(engagement_id) or {}
            vulns = data.get("vulns", [])
            # Group vulns by tactic
            buckets: dict[str, list[dict[str, Any]]] = {t: [] for t in _TACTIC_ORDER}
            for v in vulns:
                mids = (v.get("mitre_id") or "").split(",")
                for mid in mids:
                    t = mitre_attack.get(mid.strip())
                    if not t:
                        continue
                    for tac in t.get("tactics", []):
                        buckets.setdefault(tac, []).append(v)
            # Build a chain by selecting the most-severe vuln per tactic
            chain_steps: list[str] = []
            chain_mitre: list[str] = []
            for tac in _TACTIC_ORDER:
                vs = buckets.get(tac, [])
                if not vs:
                    continue
                vs.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                                       .get((x.get("severity") or "").lower(), 9))
                top = vs[0]
                chain_steps.append(f"[{tac}] {top.get('title', '')}")
                if top.get("mitre_id"):
                    chain_mitre.append(top["mitre_id"].split(",")[0])
            if chain_steps:
                score = min(100, 10 * len(chain_steps))
                chains.append({
                    "name": "MITRE-ordered chain",
                    "steps": chain_steps,
                    "score": score,
                    "mitre_ids": chain_mitre,
                })
                if eng_db:
                    eng_db.add_chain(engagement_id, name=chains[-1]["name"],
                                     steps=chain_steps, score=score, mitre_ids=chain_mitre)
        self._log(eng_db, engagement_id, "attack_plan",
                  summary=f"{len(chains)} chain(s) suggested")
        return RunResult(
            playbook=self.name,
            summary=f"Suggested {len(chains)} chain(s).",
            handoffs=list(self.handoff_to),
            artifacts={"chains": chains},
        )
