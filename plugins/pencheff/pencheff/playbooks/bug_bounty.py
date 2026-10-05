"""bug-bounty — Tier 2 execution.

Drives a bug-bounty-flavoured workflow: aggressive recon, vuln scan,
chain proof, then formats the writeup in HackerOne / Bugcrowd template.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


_H1_TEMPLATE = """\
# {title}

**Severity:** {severity}    **CVSS:** {cvss}

## Summary
{summary}

## Steps to reproduce
{steps}

## Proof of concept
```
{poc}
```

## Impact
{impact}

## Remediation
{remediation}
"""

_BC_TEMPLATE = """\
## Title
{title}

## Vulnerability Details
- **Type:** {category}
- **CVSS:** {cvss}
- **Endpoint:** {endpoint}

## Reproduction Steps
{steps}

## Impact
{impact}

## Suggested Fix
{remediation}
"""


class BugBountyPlaybook(Playbook):
    name = "bug_bounty"
    tier = 2
    phase = "report"
    noise = "moderate"
    mitre = []
    handoff_to = ["report_generator"]
    requires_scope = True
    description = "HackerOne / Bugcrowd writeup formatter."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  platform: str = "h1", **kwargs: Any) -> RunResult:
        tpl = _H1_TEMPLATE if platform == "h1" else _BC_TEMPLATE
        writeups: list[dict[str, str]] = []
        if session and getattr(session, "findings", None):
            for f in session.findings.get_all():
                d = f.to_dict()
                writeups.append({
                    "title": d["title"],
                    "writeup": tpl.format(
                        title=d["title"],
                        severity=d["severity"],
                        cvss=d.get("cvss_score") or "n/a",
                        summary=d.get("description", "")[:400],
                        steps="See evidence in attached engagement export.",
                        poc=(d.get("evidence") or [{}])[0].get("request", "(no PoC captured)"),
                        impact=d.get("description", "")[:200],
                        remediation=d.get("remediation", ""),
                        category=d.get("category", ""),
                        endpoint=d.get("endpoint", ""),
                    ),
                })
        self._log(eng_db, engagement_id, "bug_bounty_format",
                  summary=f"{len(writeups)} writeup(s) on {platform}")
        return RunResult(
            playbook=self.name,
            summary=f"{len(writeups)} {platform} writeup(s).",
            handoffs=list(self.handoff_to),
            artifacts={"platform": platform, "writeups": writeups},
        )
