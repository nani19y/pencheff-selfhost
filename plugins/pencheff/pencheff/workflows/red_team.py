"""MITRE ATT&CK red-team narrative workflow.

For each finding, looks up its MITRE technique ID(s) via existing
``core.mitre_attack`` mapping, then groups findings by tactic to produce a
narrative outline. No LLM — the narrative is a fixed set of section
templates filled with finding metadata.
"""

from __future__ import annotations

import json
from collections import defaultdict
from importlib import resources
from typing import Any


_TACTIC_ORDER = (
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
)


def _load_attack_map() -> dict[str, Any]:
    try:
        text = (
            resources.files("pencheff.data") / "mitre_attack.json"
        ).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


async def run(findings: list[dict[str, Any]] | None = None, **_: Any) -> dict[str, Any]:
    findings = findings or []
    attack = _load_attack_map()

    by_tactic: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        tids = f.get("mitre_id") or []
        for tid in tids:
            tactic = _tactic_for(tid, attack)
            by_tactic[tactic].append(
                {"id": tid, "title": f.get("title"),
                 "severity": f.get("severity"), "endpoint": f.get("endpoint")}
            )

    narrative = []
    for tactic in _TACTIC_ORDER:
        if tactic not in by_tactic:
            continue
        bullets = [
            f"- {b['id']} :: {b['title']} (severity={b['severity']})"
            for b in by_tactic[tactic]
        ]
        narrative.append(f"## {tactic}\n" + "\n".join(bullets))

    return {
        "workflow": "red_team",
        "findings": findings,
        "by_tactic": {k: list(v) for k, v in by_tactic.items()},
        "narrative_md": "\n\n".join(narrative) if narrative else "No MITRE-tagged findings.",
    }


def _tactic_for(technique_id: str, attack: dict[str, Any]) -> str:
    techniques = attack.get("techniques", {})
    entry = techniques.get(technique_id)
    if not entry:
        return "Unknown"
    tactics = entry.get("tactics") or []
    if isinstance(tactics, list) and tactics:
        return tactics[0]
    if isinstance(tactics, str):
        return tactics
    return "Unknown"
