"""detection-engineer — Tier 1 advisory.

For every observed finding (and its MITRE mapping), look up matching
Sigma / SPL / KQL templates and render them with concrete IOCs from
the engagement DB.
"""

from __future__ import annotations

import uuid
from datetime import date
from pathlib import Path
from typing import Any

from pencheff.core.tier import tier_1
from pencheff.playbooks.base import Playbook, RunResult

_TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "data" / "detection_templates"


def render_template(text: str, ctx: dict[str, str]) -> str:
    out = text
    for k, v in ctx.items():
        out = out.replace("{{" + k + "}}", v)
    return out


class DetectionEngineerPlaybook(Playbook):
    name = "detection_engineer"
    tier = 1
    phase = "detect"
    noise = "quiet"
    mitre = []
    handoff_to = ["report_generator"]
    requires_scope = False
    description = "Generate Sigma / SPL / KQL detection rules from findings."

    @tier_1
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  fmt: str = "sigma", target: str = "TARGET",
                  findings: list[dict] | None = None, **kwargs: Any) -> RunResult:
        # Pull findings from session OR explicit list OR engagement DB
        if findings is None:
            if session and getattr(session, "findings", None) is not None:
                findings = [f.to_dict() for f in session.findings.get_all()]
            elif eng_db and engagement_id:
                data = eng_db.show(engagement_id) or {}
                findings = data.get("vulns", [])
            else:
                findings = []

        ext = {"sigma": ".yml", "spl": ".spl", "kql": ".kql"}.get(fmt, ".yml")
        rendered: list[dict[str, str]] = []
        for f in findings:
            mitre_field = f.get("mitre") if isinstance(f.get("mitre"), list) else f.get("mitre_id")
            mids: list[str] = []
            if isinstance(mitre_field, list):
                mids = list(mitre_field)
            elif isinstance(mitre_field, str) and mitre_field:
                mids = [m.strip() for m in mitre_field.split(",") if m.strip()]
            if not mids:
                continue
            for tid in mids:
                tpl_path = _TEMPLATE_DIR / fmt / f"{tid}{ext}"
                if not tpl_path.exists():
                    continue
                ctx = {
                    "rule_uuid": uuid.uuid4().hex[:12],
                    "generated_date": date.today().isoformat(),
                    "target": target,
                    "indicator_paths": '\n      - "/admin"\n      - "/.env"\n      - "/.git/"',
                }
                rendered.append({
                    "format": fmt,
                    "technique": tid,
                    "finding": f.get("title", ""),
                    "rule": render_template(tpl_path.read_text(), ctx),
                })

        self._log(eng_db, engagement_id, "detection_rule_synthesis",
                  summary=f"{len(rendered)} {fmt} rule(s)")
        return RunResult(
            playbook=self.name,
            summary=f"{len(rendered)} {fmt} rule(s) generated.",
            handoffs=list(self.handoff_to),
            artifacts={"format": fmt, "rules": rendered},
        )
