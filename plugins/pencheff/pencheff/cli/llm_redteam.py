"""CLI handler for ``pencheff llm-redteam``.

Headless entry point: configures an in-memory PentestSession with
``llm_config``, runs every OWASP LLM module, optionally diffs against
a prior JSON snapshot, and writes a chosen format to stdout / file.
Exits non-zero when ``--fail-on`` is set and any finding meets or
exceeds the threshold severity.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _parse_headers(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            continue
        k, _, v = item.partition("=")
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    parts = [v.strip() for v in value.split(",") if v.strip()]
    return parts or None


def _profile_cap(profile: str) -> int:
    return {"quick": 25, "standard": 75, "deep": 250}.get(profile, 75)


async def _run(args: argparse.Namespace) -> int:
    from pencheff.core.session import create_session
    from pencheff.core.findings import FindingsDB
    from pencheff.modules.llm_red_team import LLM_RED_TEAM_MODULES
    from pencheff.modules.llm_red_team.reporting import (
        build_red_team_summary,
        diff_red_team_findings,
        render_junit_xml,
        render_prometheus_metrics,
        render_red_team_markdown,
    )

    headers = _parse_headers(args.header)
    llm_config: dict[str, Any] = {
        "provider": args.provider,
        "model": args.model,
        "system_prompt": args.system_prompt,
        "timeout_s": int(args.timeout_s),
        "concurrency": int(args.concurrency),
        "retries": int(args.retries),
    }
    if args.max_rps is not None:
        llm_config["max_rps"] = float(args.max_rps)
    if args.max_cost_usd is not None:
        llm_config["budget"] = {"max_cost_usd": float(args.max_cost_usd)}

    redteam: dict[str, Any] = {}
    strategies = _csv(args.strategies)
    if strategies:
        redteam["strategies"] = strategies
    datasets = _csv(args.datasets)
    if datasets:
        redteam["datasets"] = datasets
    guardrails = _csv(args.guardrails)
    if guardrails:
        redteam["guardrails"] = guardrails
    plugins = _csv(getattr(args, "plugins", None))
    if plugins:
        redteam["plugins"] = plugins
    iterative = getattr(args, "iterative", None)
    if iterative:
        redteam["iterative"] = iterative
    attacker_endpoint = getattr(args, "attacker_endpoint", None)
    attacker_provider = getattr(args, "attacker_provider", None) or "openai-chat"
    if attacker_endpoint or attacker_provider == "executable":
        attacker_headers: dict[str, str] = {}
        for raw in getattr(args, "attacker_header", []) or []:
            if "=" in raw:
                k, v = raw.split("=", 1)
                attacker_headers[k.strip()] = v.strip()
        redteam["attacker"] = {
            "enabled": True,
            "provider": attacker_provider,
            "endpoint": attacker_endpoint,
            "model": getattr(args, "attacker_model", None),
            "headers": attacker_headers or None,
        }
    if args.judge_endpoint or args.judge_provider in {"executable"}:
        redteam["judge"] = {
            "enabled": True,
            "provider": args.judge_provider,
            "endpoint": args.judge_endpoint,
            "model": args.judge_model,
        }
    if redteam:
        llm_config["redteam"] = redteam

    session = create_session(
        target_url=args.target,
        credentials={"headers": headers} if headers else None,
        llm_config=llm_config,
    )

    cap = int(args.max_payloads) if args.max_payloads else _profile_cap(args.profile)
    print(f"[pencheff] llm-redteam target={args.target} provider={args.provider} "
          f"profile={args.profile} cap={cap} session={session.id}", file=sys.stderr)

    findings: list[Any] = []
    for cat, mod_cls in LLM_RED_TEAM_MODULES.items():
        mod = mod_cls()
        try:
            new = await mod.run(session, http=None, config={"max_payloads": cap})
        except Exception as exc:  # noqa: BLE001
            print(f"[pencheff] {cat} module failed: {exc}", file=sys.stderr)
            continue
        findings.extend(new)
        session.findings.add_many(new)

    summary = build_red_team_summary([f.to_dict() if hasattr(f, "to_dict") else f for f in findings])

    # Optional regression diff against a prior --output-format json file.
    if args.compare_to:
        baseline_path = Path(args.compare_to)
        if not baseline_path.exists():
            print(f"[pencheff] --compare-to file not found: {baseline_path}", file=sys.stderr)
            return 2
        try:
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"[pencheff] --compare-to is not valid JSON: {exc}", file=sys.stderr)
            return 2
        baseline_findings = baseline.get("findings", baseline) if isinstance(baseline, dict) else baseline
        current = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
        diff = diff_red_team_findings(baseline_findings, current)
        summary["regression"] = {
            "new": diff["counts"]["new"],
            "resolved": diff["counts"]["resolved"],
            "unchanged": diff["counts"]["unchanged"],
        }

    # Render output.
    fmt = args.output_format
    if fmt == "json":
        rendered = json.dumps({
            "summary": summary,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in findings],
        }, indent=2)
    elif fmt == "junit":
        rendered = render_junit_xml(findings)
    elif fmt == "prometheus":
        rendered = render_prometheus_metrics(findings)
    elif fmt == "csv":
        from pencheff.modules.llm_red_team.reporting_extras import render_csv  # added in tier 3.6
        rendered = render_csv(findings)
    elif fmt == "html":
        from pencheff.modules.llm_red_team.reporting_extras import render_html  # added in tier 3.6
        rendered = render_html(findings, summary=summary)
    else:
        rendered = render_red_team_markdown(summary)

    if args.output_file:
        Path(args.output_file).write_text(rendered, encoding="utf-8")
        print(f"[pencheff] wrote {fmt} report to {args.output_file}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")

    # Exit code: gated on --fail-on.
    if args.fail_on:
        threshold = _SEV_RANK[args.fail_on]
        worst = -1
        for f in findings:
            sev = getattr(f, "severity", None)
            sev_value = sev.value if hasattr(sev, "value") else (str(sev) if sev else "info")
            worst = max(worst, _SEV_RANK.get(str(sev_value).lower(), 0))
        if worst >= threshold:
            print(f"[pencheff] fail-on={args.fail_on} → worst finding severity rank {worst} ≥ {threshold}",
                  file=sys.stderr)
            return 1
    return 0


def cmd_llm_redteam(args: argparse.Namespace) -> int:
    return asyncio.run(_run(args))
