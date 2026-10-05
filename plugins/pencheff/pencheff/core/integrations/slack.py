"""Slack Incoming Webhook integration."""

from __future__ import annotations

from typing import Any

from pencheff.core.findings import Finding
from pencheff.core.integrations._base import post_json


async def send(
    webhook_url: str,
    findings: list[Finding],
    summary_prefix: str = "Pencheff scan update",
) -> dict[str, Any]:
    if not findings:
        ok, code, body = await post_json(webhook_url, {"text": f"{summary_prefix}: no new findings."})
        return {"ok": ok, "status": code, "response": body}
    buckets: dict[str, int] = {}
    for f in findings:
        buckets[f.severity.value] = buckets.get(f.severity.value, 0) + 1
    header = f"*{summary_prefix}* — " + " • ".join(
        f"{v} {k}" for k, v in buckets.items() if v
    )
    top = sorted(findings, key=lambda f: f.cvss_score, reverse=True)[:5]
    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
        {"type": "divider"},
    ]
    for f in top:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*[{f.severity.value.upper()}] {f.title}*\n"
                    f"`{f.endpoint}` — CVSS {f.cvss_score} — {f.owasp_category}\n"
                    f"{f.description[:280]}"
                ),
            },
        })
    ok, code, body = await post_json(webhook_url, {"text": header, "blocks": blocks})
    return {"ok": ok, "status": code, "response": body}
