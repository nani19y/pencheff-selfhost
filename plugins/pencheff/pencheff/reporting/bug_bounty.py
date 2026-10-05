"""Bug bounty writeup formatters (HackerOne / Bugcrowd)."""

from __future__ import annotations

from typing import Any


_H1 = """\
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

_BC = """\
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


def format_finding(finding: dict[str, Any], platform: str = "h1") -> str:
    tpl = _H1 if platform == "h1" else _BC
    poc = "(no PoC captured)"
    evidence = finding.get("evidence") or []
    if evidence:
        poc = evidence[0].get("request", poc)
    return tpl.format(
        title=finding.get("title", ""),
        severity=finding.get("severity", "unknown"),
        cvss=finding.get("cvss_score", "n/a"),
        summary=(finding.get("description") or "")[:500],
        steps="See the engagement report for full reproduction trace.",
        poc=poc,
        impact=(finding.get("description") or "")[:300],
        remediation=finding.get("remediation", ""),
        category=finding.get("category", ""),
        endpoint=finding.get("endpoint", ""),
    )


def format_findings(findings: list[dict[str, Any]], platform: str = "h1") -> str:
    return "\n\n---\n\n".join(format_finding(f, platform) for f in findings)
