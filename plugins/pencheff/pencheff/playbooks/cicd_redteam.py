"""cicd-redteam — Tier 1 advisory by default; Tier 2 when --workflow is provided.

Parses GitHub Actions / GitLab CI / Jenkinsfile content and flags
common DevSecOps risks (secrets in env, pull_request_target injection,
self-hosted runner takeover, GITHUB_TOKEN write scope, etc.).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pencheff.core.tier import tier_1
from pencheff.playbooks.base import Playbook, RunResult


_CHECKS = [
    (r"pull_request_target",
     "high", "T1190",
     "pull_request_target gives the PR write access to secrets — verify checkouts."),
    (r"\$\{\{\s*github\.event\.[\w_.]+\s*\}\}",
     "high", "T1059",
     "Untrusted github.event interpolation — script injection risk."),
    (r"runs-on:\s*self-hosted",
     "medium", "T1133",
     "Self-hosted runner — fork PRs can execute on your infrastructure."),
    (r"persist-credentials:\s*true|GITHUB_TOKEN",
     "medium", "T1552.001",
     "GITHUB_TOKEN exposed — restrict permissions: in workflow YAML."),
    (r"docker run.*--privileged",
     "high", "T1611",
     "--privileged Docker run — container escape vector."),
    (r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|password\s*=",
     "critical", "T1552.001",
     "Hard-coded credential pattern in pipeline."),
]


class CicdRedteamPlaybook(Playbook):
    name = "cicd_redteam"
    tier = 1
    phase = "vuln"
    noise = "quiet"
    mitre = ["T1190", "T1133", "T1552", "T1611"]
    handoff_to = ["report_generator"]
    requires_scope = False
    description = "Static analysis of CI/CD workflow files."

    @tier_1
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  workflow: str | None = None, provider: str = "github",
                  **kwargs: Any) -> RunResult:
        text = ""
        if workflow:
            p = Path(workflow).expanduser()
            if p.is_dir():
                files = list(p.rglob("*.yml")) + list(p.rglob("*.yaml")) + list(p.rglob("Jenkinsfile"))
                text = "\n".join(f.read_text() for f in files if f.is_file())
            elif p.is_file():
                text = p.read_text()
            else:
                text = workflow  # assume raw text
        findings: list[dict[str, Any]] = []
        for pat, sev, mitre, msg in _CHECKS:
            if re.search(pat, text):
                findings.append({"severity": sev, "mitre": mitre, "message": msg, "pattern": pat})
                if eng_db and engagement_id:
                    eng_db.add_vuln(engagement_id, title=f"CI/CD: {msg}",
                                    severity=sev, mitre_id=mitre, found_by=self.name)
        self._log(eng_db, engagement_id, "cicd_redteam",
                  summary=f"{provider}: {len(findings)} pattern hit(s)")
        return RunResult(
            playbook=self.name,
            summary=f"CI/CD ({provider}): {len(findings)} pattern hit(s).",
            handoffs=list(self.handoff_to),
            artifacts={"provider": provider, "findings": findings},
        )
