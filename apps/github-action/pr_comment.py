"""Post a Pencheff scan summary as a PR comment via `gh`.

Reads the JSON report produced by `pencheff scan --format json`,
renders a compact Markdown summary, and posts it (idempotently — by header
match) to the pull request.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HEADER = "<!-- pencheff-scan-summary -->"
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _find_report(report_dir: Path) -> Path | None:
    candidates = list(report_dir.glob("*.json"))
    return candidates[0] if candidates else None


def _summarize(data: dict) -> tuple[dict[str, int], list[dict]]:
    counts = {k: 0 for k in SEV_ORDER}
    rows = []
    for f in data.get("findings", []):
        sev = (f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
        rows.append(f)
    return counts, rows


def _render(data: dict, target: str, fail_on: str) -> str:
    counts, rows = _summarize(data)
    meta = data.get("report_metadata", {})
    lines = [HEADER, "", "## 🛡️ Pencheff scan results", ""]
    lines.append(f"**Target**: `{target}`")
    if meta.get("grade"):
        lines.append(f"**Grade**: **{meta['grade']}** ({meta.get('score', 0)}/100)")
    lines.append(f"**Fail-on**: `{fail_on}`")
    lines.append("")
    lines.append("| Critical | High | Medium | Low | Info |")
    lines.append("|---|---|---|---|---|")
    lines.append(
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | "
        f"{counts['low']} | {counts['info']} |"
    )
    if rows:
        lines.append("")
        lines.append("### Top findings")
        ordered = sorted(rows, key=lambda f: SEV_ORDER.index((f.get("severity") or "info").lower()))
        for f in ordered[:10]:
            sev = (f.get("severity") or "info").upper()
            lines.append(f"- **{sev}** — {f.get('title', '?')} (`{f.get('endpoint') or '-'}`)")
        if len(rows) > 10:
            lines.append(f"- _…and {len(rows) - 10} more_")

    redteam = data.get("llm_redteam") or data.get("redteam_summary")
    if redteam and redteam.get("total_failures"):
        lines.append("")
        lines.append("### LLM red-team")
        lines.append(f"**Technique failures**: {redteam.get('total_failures', 0)}")
        by_category = redteam.get("by_category") or {}
        if by_category:
            lines.append("")
            lines.append("| OWASP LLM | Failures |")
            lines.append("|---|---:|")
            for cat, count in sorted(by_category.items()):
                lines.append(f"| {cat} | {count} |")
        by_strategy = redteam.get("by_strategy") or {}
        if by_strategy:
            lines.append("")
            lines.append("| Strategy | Failures |")
            lines.append("|---|---:|")
            for strategy, count in sorted(by_strategy.items()):
                lines.append(f"| {strategy} | {count} |")
        suggestions = redteam.get("guardrail_suggestions") or []
        if suggestions:
            lines.append("")
            lines.append("**Guardrail suggestions**")
            seen = set()
            for item in suggestions[:5]:
                policy = item.get("policy")
                if policy and policy not in seen:
                    seen.add(policy)
                    lines.append(f"- {policy}")
    return "\n".join(lines)


def _post(repo: str, pr: int, body: str) -> None:
    if shutil.which("gh") is None:
        print("gh not available; skipping PR comment", file=sys.stderr)
        return
    # List existing comments and replace ours.
    res = subprocess.run(
        ["gh", "api", f"repos/{repo}/issues/{pr}/comments"],
        capture_output=True, text=True, check=False,
    )
    existing_id = None
    if res.returncode == 0:
        try:
            for c in json.loads(res.stdout):
                if HEADER in (c.get("body") or ""):
                    existing_id = c.get("id")
                    break
        except json.JSONDecodeError:
            pass
    if existing_id:
        subprocess.run(
            ["gh", "api", "-X", "PATCH",
             f"repos/{repo}/issues/comments/{existing_id}",
             "-f", f"body={body}"],
            check=False,
        )
    else:
        subprocess.run(
            ["gh", "pr", "comment", str(pr), "--repo", repo, "--body", body],
            check=False,
        )


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--report-dir", required=True)
    p.add_argument("--pr", type=int, required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--fail-on", default="high")
    args = p.parse_args()

    report = _find_report(Path(args.report_dir))
    if report is None:
        print("no report found in", args.report_dir, file=sys.stderr)
        return 0
    data = json.loads(report.read_text())
    body = _render(data, args.target, args.fail_on)
    _post(args.repo, args.pr, body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
