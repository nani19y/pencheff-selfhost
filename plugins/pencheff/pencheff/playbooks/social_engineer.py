"""social-engineer — Tier 1 advisory.

Generates phishing pretext drafts from bundled templates. Never sends.
The generated text is for tabletop / authorized phishing exercises only.
"""

from __future__ import annotations

import string
from pathlib import Path
from typing import Any

from pencheff.core.tier import tier_1
from pencheff.playbooks.base import Playbook, RunResult

_TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "data" / "phishing_templates"


class SocialEngineerPlaybook(Playbook):
    name = "social_engineer"
    tier = 1
    phase = "exploit"
    noise = "quiet"
    mitre = ["T1566"]
    handoff_to = ["report_generator"]
    requires_scope = False
    description = "Phishing pretext template generator (drafts only, never sends)."

    @tier_1
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  pretext: str = "spear-phish", variables: dict[str, str] | None = None,
                  **kwargs: Any) -> RunResult:
        variables = variables or {}
        path = _TEMPLATE_DIR / f"{pretext}.txt"
        if not path.exists():
            return RunResult(playbook=self.name, error=f"unknown pretext: {pretext}")
        raw = path.read_text()
        rendered = string.Template(raw.replace("{{", "${").replace("}}", "}")).safe_substitute(variables)
        self._log(eng_db, engagement_id, "social_engineer",
                  summary=f"rendered pretext '{pretext}'")
        return RunResult(
            playbook=self.name,
            summary=f"Pretext '{pretext}' rendered ({len(rendered)} chars).",
            handoffs=list(self.handoff_to),
            artifacts={"pretext": pretext, "draft": rendered},
        )
