"""LLM red-team reporting helpers.

These helpers turn Pencheff Finding objects (or finding dictionaries)
into a CI/report-friendly structure similar to Promptfoo's red-team
summary: category/plugin breakdowns, strategy breakdowns, top failures,
and guardrail suggestions.
"""
from __future__ import annotations

from collections import Counter
from typing import Any
from xml.sax.saxutils import escape

from .guardrails import suggested_guardrails


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _severity_value(value: Any) -> str:
    if hasattr(value, "value"):
        return str(value.value)
    return str(value or "info")


def _owasp_code(finding: Any) -> str:
    raw = _get(finding, "owasp_category")
    if raw:
        return str(raw)
    raw = _get(finding, "owasp")
    if raw:
        return str(raw).split(":", 1)[0]
    return "unknown"


def _technique(finding: Any) -> str:
    category = str(_get(finding, "category", "") or "")
    if category.startswith("llm_"):
        return category[4:]
    return category or "unknown"


def _strategy(technique: str) -> str:
    if ":" in technique:
        return technique.split(":", 1)[1]
    if technique.startswith("dataset:"):
        return technique
    if technique.startswith("guardrail:"):
        return technique
    return "base"


def build_red_team_summary(findings: list[Any]) -> dict[str, Any]:
    """Build a deterministic red-team summary from LLM findings."""
    llm_findings = [f for f in findings if _owasp_code(f).startswith("LLM")]
    by_category = Counter(_owasp_code(f) for f in llm_findings)
    by_technique = Counter(_technique(f) for f in llm_findings)
    by_strategy = Counter(_strategy(_technique(f)) for f in llm_findings)
    by_severity = Counter(_severity_value(_get(f, "severity")).lower() for f in llm_findings)

    top = []
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(
        llm_findings,
        key=lambda x: (
            sev_rank.get(_severity_value(_get(x, "severity")).lower(), 5),
            str(_get(x, "title", "")),
        ),
    )[:10]:
        top.append({
            "id": str(_get(f, "id", "")),
            "title": str(_get(f, "title", "")),
            "severity": _severity_value(_get(f, "severity")).lower(),
            "owasp_category": _owasp_code(f),
            "technique": _technique(f),
            "endpoint": str(_get(f, "endpoint", "") or ""),
        })

    return {
        "total_failures": len(llm_findings),
        "by_category": dict(sorted(by_category.items())),
        "by_technique": dict(sorted(by_technique.items())),
        "by_strategy": dict(sorted(by_strategy.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "top_failures": top,
        "guardrail_suggestions": suggested_guardrails([
            {
                "title": str(_get(f, "title", "")),
                "owasp_category": _owasp_code(f),
                "category": _technique(f),
            }
            for f in llm_findings
        ]),
    }


def render_red_team_markdown(summary: dict[str, Any]) -> str:
    """Render a compact Markdown block for CI comments and reports."""
    lines = ["### LLM Red-Team Summary", ""]
    lines.append(f"**Technique failures:** {summary.get('total_failures', 0)}")
    lines.append("")

    by_category = summary.get("by_category") or {}
    if by_category:
        lines.append("| OWASP LLM Category | Failures |")
        lines.append("|---|---:|")
        for cat, count in by_category.items():
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    by_strategy = summary.get("by_strategy") or {}
    if by_strategy:
        lines.append("| Strategy | Failures |")
        lines.append("|---|---:|")
        for strategy, count in by_strategy.items():
            lines.append(f"| {strategy} | {count} |")
        lines.append("")

    top = summary.get("top_failures") or []
    if top:
        lines.append("#### Top LLM failures")
        for row in top[:5]:
            lines.append(
                f"- **{str(row.get('severity', 'info')).upper()}** "
                f"{row.get('owasp_category', 'LLM?')} / `{row.get('technique', '-')}` "
                f"- {row.get('title', '')}"
            )
        lines.append("")

    suggestions = summary.get("guardrail_suggestions") or []
    if suggestions:
        lines.append("#### Guardrail Suggestions")
        seen: set[str] = set()
        for item in suggestions:
            policy = str(item.get("policy", ""))
            if not policy or policy in seen:
                continue
            seen.add(policy)
            lines.append(f"- {policy}")
        lines.append("")
    return "\n".join(lines).rstrip()


def finding_key(finding: Any) -> str:
    """Stable regression key matching FindingsDB's dedup dimensions."""
    return "|".join([
        str(_get(finding, "endpoint", "") or ""),
        str(_get(finding, "parameter", "") or ""),
        _technique(finding),
        str(_get(finding, "title", "") or ""),
    ])


def diff_red_team_findings(previous: list[Any], current: list[Any]) -> dict[str, Any]:
    """Compare two LLM red-team finding sets."""
    prev = {finding_key(f): f for f in previous if _owasp_code(f).startswith("LLM")}
    cur = {finding_key(f): f for f in current if _owasp_code(f).startswith("LLM")}
    new_keys = sorted(set(cur) - set(prev))
    resolved_keys = sorted(set(prev) - set(cur))
    unchanged_keys = sorted(set(prev) & set(cur))
    return {
        "new": [cur[k] for k in new_keys],
        "resolved": [prev[k] for k in resolved_keys],
        "unchanged": [cur[k] for k in unchanged_keys],
        "counts": {
            "new": len(new_keys),
            "resolved": len(resolved_keys),
            "unchanged": len(unchanged_keys),
        },
    }


def render_junit_xml(findings: list[Any], *, suite_name: str = "pencheff-llm-redteam") -> str:
    """Render LLM red-team failures as JUnit XML test failures."""
    llm_findings = [f for f in findings if _owasp_code(f).startswith("LLM")]
    failures = len(llm_findings)
    lines = [
        f'<testsuite name="{escape(suite_name)}" tests="{failures}" failures="{failures}">',
    ]
    for f in llm_findings:
        name = f"{_owasp_code(f)} {_technique(f)} {str(_get(f, 'title', ''))}"
        sev = _severity_value(_get(f, "severity")).lower()
        message = f"{sev.upper()} {_owasp_code(f)} {_technique(f)}"
        body = "\n\n".join([
            str(_get(f, "description", "") or ""),
            "Remediation: " + str(_get(f, "remediation", "") or ""),
        ]).strip()
        lines.append(
            f'  <testcase classname="llm.redteam.{escape(_owasp_code(f))}" '
            f'name="{escape(name)}">'
        )
        lines.append(
            f'    <failure type="{escape(sev)}" message="{escape(message)}">'
            f"{escape(body)}</failure>"
        )
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    return "\n".join(lines)


def _metric_label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render_prometheus_metrics(findings: list[Any], *, prefix: str = "pencheff_llm_redteam") -> str:
    """Render LLM red-team metrics for Prometheus/Grafana scraping."""
    summary = build_red_team_summary(findings)
    lines = [
        f"# HELP {prefix}_failures_total LLM red-team failures.",
        f"# TYPE {prefix}_failures_total counter",
        f"{prefix}_failures_total {int(summary['total_failures'])}",
        f"# HELP {prefix}_failures_by_category LLM red-team failures by OWASP LLM category.",
        f"# TYPE {prefix}_failures_by_category gauge",
    ]
    for category, count in summary.get("by_category", {}).items():
        lines.append(f'{prefix}_failures_by_category{{category="{_metric_label(category)}"}} {int(count)}')
    lines.extend([
        f"# HELP {prefix}_failures_by_strategy LLM red-team failures by attack strategy.",
        f"# TYPE {prefix}_failures_by_strategy gauge",
    ])
    for strategy, count in summary.get("by_strategy", {}).items():
        lines.append(f'{prefix}_failures_by_strategy{{strategy="{_metric_label(strategy)}"}} {int(count)}')
    lines.extend([
        f"# HELP {prefix}_failures_by_severity LLM red-team failures by severity.",
        f"# TYPE {prefix}_failures_by_severity gauge",
    ])
    for severity, count in summary.get("by_severity", {}).items():
        lines.append(f'{prefix}_failures_by_severity{{severity="{_metric_label(severity)}"}} {int(count)}')
    return "\n".join(lines) + "\n"
