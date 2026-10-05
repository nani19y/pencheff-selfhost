"""HTML + CSV exporters for LLM red-team scans.

Kept in a separate module so the small set of generic renderers
(``reporting.py``: markdown / JUnit / Prometheus / diff) stays focused
on machine-readable formats. HTML and CSV are humans-and-spreadsheets
formats with their own concerns (escaping, embedded styles, BOM).
"""
from __future__ import annotations

import csv
import io
from html import escape
from typing import Any

from .reporting import (
    _get,
    _owasp_code,
    _severity_value,
    _technique,
    build_red_team_summary,
)


# ── CSV ─────────────────────────────────────────────────────────────


_CSV_COLUMNS = [
    "id",
    "owasp_category",
    "technique",
    "strategy",
    "severity",
    "title",
    "endpoint",
    "parameter",
    "description",
    "remediation",
    "cwe",
]


def _strategy_part(technique: str) -> str:
    if ":" in technique:
        return technique.split(":", 1)[1]
    return ""


def render_csv(findings: list[Any]) -> str:
    """Return a CSV (RFC 4180-ish) representation of LLM findings.

    One row per Finding. Columns are stable across runs so CI tools
    can diff them. Newlines inside fields are CRLF-escaped by the
    csv module — Excel and Python both round-trip cleanly."""
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(_CSV_COLUMNS)
    for f in findings:
        if not _owasp_code(f).startswith("LLM"):
            continue
        technique = _technique(f)
        writer.writerow([
            str(_get(f, "id", "") or ""),
            _owasp_code(f),
            technique,
            _strategy_part(technique),
            _severity_value(_get(f, "severity")).lower(),
            str(_get(f, "title", "") or ""),
            str(_get(f, "endpoint", "") or ""),
            str(_get(f, "parameter", "") or ""),
            str(_get(f, "description", "") or "").replace("\n", " "),
            str(_get(f, "remediation", "") or "").replace("\n", " "),
            str(_get(f, "cwe_id", _get(f, "cwe", "")) or ""),
        ])
    return buf.getvalue()


# ── HTML ────────────────────────────────────────────────────────────


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Pencheff — LLM Red Team Report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, system-ui, sans-serif;
          max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1f2328;
          background: #fafafa; }}
  h1 {{ font-weight: 600; letter-spacing: -0.01em; }}
  h2 {{ margin-top: 2.5rem; font-weight: 500; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid #e5e7eb; text-align: left;
            vertical-align: top; font-size: 13px; }}
  th {{ font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; font-size: 11px;
        color: #555; }}
  .sev-critical {{ color: #b91c1c; font-weight: 600; }}
  .sev-high     {{ color: #c2410c; font-weight: 600; }}
  .sev-medium   {{ color: #a16207; }}
  .sev-low      {{ color: #1d4ed8; }}
  .sev-info     {{ color: #6b7280; }}
  .pill {{ display: inline-block; padding: 1px 8px; border-radius: 999px;
           font-size: 11px; background: #e5e7eb; color: #374151; }}
  details {{ margin: 0.5rem 0; }}
  summary {{ cursor: pointer; }}
  .meta {{ color: #6b7280; font-size: 12px; margin-bottom: 1.5rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                   gap: 0.75rem; margin: 1.25rem 0; }}
  .summary-card {{ background: #fff; border: 1px solid #e5e7eb; padding: 0.75rem;
                   border-radius: 6px; }}
  .summary-card .num {{ font-size: 22px; font-weight: 600; }}
  .summary-card .label {{ font-size: 11px; text-transform: uppercase;
                          letter-spacing: 0.08em; color: #6b7280; }}
</style>
</head>
<body>
<h1>Pencheff — LLM Red Team Report</h1>
<p class="meta">{meta}</p>

<h2>Summary</h2>
<div class="summary-grid">
{cards}
</div>

<h2>Findings by OWASP LLM category</h2>
<table>
<thead><tr><th>Category</th><th>Count</th></tr></thead>
<tbody>
{category_rows}
</tbody>
</table>

<h2>Findings by attack strategy</h2>
<table>
<thead><tr><th>Strategy</th><th>Count</th></tr></thead>
<tbody>
{strategy_rows}
</tbody>
</table>

<h2>Findings ({n_findings})</h2>
<table>
<thead>
<tr>
  <th>Severity</th><th>OWASP</th><th>Technique</th><th>Title</th>
</tr>
</thead>
<tbody>
{finding_rows}
</tbody>
</table>

<h2>Guardrail suggestions</h2>
<ul>
{guardrails}
</ul>
</body>
</html>
"""


def render_html(findings: list[Any], *, summary: dict[str, Any] | None = None,
                meta: str = "") -> str:
    """Self-contained HTML report — embedded CSS, no external assets,
    no JS. Safe to email or open offline."""
    summary = summary or build_red_team_summary(findings)
    cards_html = "".join(
        f'<div class="summary-card"><div class="num">{int(summary.get(k, 0))}</div>'
        f'<div class="label">{escape(label)}</div></div>'
        for k, label in [
            ("total_failures", "Total"),
            ("by_severity", "—"),  # placeholder; severity cards rendered separately below
        ]
        if isinstance(summary.get(k), int)
    )
    # Render severity cards explicitly.
    sev_counts = summary.get("by_severity") or {}
    cards_html += "".join(
        f'<div class="summary-card"><div class="num sev-{escape(sev)}">{int(count)}</div>'
        f'<div class="label">{escape(sev.title())}</div></div>'
        for sev, count in sev_counts.items()
    )

    by_category = summary.get("by_category") or {}
    cat_rows = "".join(
        f"<tr><td>{escape(str(cat))}</td><td>{int(count)}</td></tr>"
        for cat, count in by_category.items()
    ) or '<tr><td colspan="2"><em>No category breakdowns.</em></td></tr>'

    by_strategy = summary.get("by_strategy") or {}
    strat_rows = "".join(
        f"<tr><td>{escape(str(s))}</td><td>{int(count)}</td></tr>"
        for s, count in by_strategy.items()
    ) or '<tr><td colspan="2"><em>No strategies detected.</em></td></tr>'

    finding_rows: list[str] = []
    llm_findings = [f for f in findings if _owasp_code(f).startswith("LLM")]
    for f in llm_findings:
        sev = _severity_value(_get(f, "severity")).lower()
        finding_rows.append(
            "<tr>"
            f'<td><span class="sev-{escape(sev)}">{escape(sev.upper())}</span></td>'
            f'<td><span class="pill">{escape(_owasp_code(f))}</span></td>'
            f"<td><code>{escape(_technique(f))}</code></td>"
            f"<td><details><summary>{escape(str(_get(f, 'title', '') or ''))}</summary>"
            f"<p>{escape(str(_get(f, 'description', '') or ''))}</p>"
            f"<p><strong>Remediation:</strong> {escape(str(_get(f, 'remediation', '') or ''))}</p>"
            f"</details></td>"
            "</tr>"
        )

    suggestions = summary.get("guardrail_suggestions") or []
    seen: set[str] = set()
    guard_lis: list[str] = []
    for item in suggestions:
        policy = str(item.get("policy", "") if isinstance(item, dict) else item)
        if not policy or policy in seen:
            continue
        seen.add(policy)
        guard_lis.append(f"<li>{escape(policy)}</li>")

    return _HTML_TEMPLATE.format(
        meta=escape(meta) or "Generated by Pencheff LLM red-team engine.",
        cards=cards_html or '<div class="summary-card"><div class="num">0</div><div class="label">Total</div></div>',
        category_rows=cat_rows,
        strategy_rows=strat_rows,
        n_findings=len(llm_findings),
        finding_rows="\n".join(finding_rows) or '<tr><td colspan="4"><em>No findings.</em></td></tr>',
        guardrails="\n".join(guard_lis) or "<li><em>No guardrail suggestions for this run.</em></li>",
    )
