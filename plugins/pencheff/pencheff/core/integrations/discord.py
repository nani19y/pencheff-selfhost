"""Discord webhook integration."""

from __future__ import annotations

from typing import Any

from pencheff.core.findings import Finding
from pencheff.core.integrations._base import post_json


async def send(webhook_url: str, findings: list[Finding]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    summary = " • ".join(f"{v} {k}" for k, v in counts.items() if v) or "no findings"
    top = sorted(findings, key=lambda f: f.cvss_score, reverse=True)[:5]
    embeds = [{
        "title": f"[{f.severity.value.upper()}] {f.title[:250]}",
        "description": f.description[:500],
        "color": _color(f.severity.value),
        "fields": [
            {"name": "Endpoint", "value": f.endpoint[:900] or "-", "inline": False},
            {"name": "CVSS", "value": str(f.cvss_score), "inline": True},
            {"name": "OWASP", "value": f.owasp_category, "inline": True},
        ],
    } for f in top]
    ok, code, body = await post_json(webhook_url, {
        "content": f"**Pencheff scan** — {summary}",
        "embeds": embeds,
    })
    return {"ok": ok, "status": code, "response": body}


def _color(sev: str) -> int:
    return {
        "critical": 0xDC2626, "high": 0xEF4444, "medium": 0xF59E0B,
        "low": 0x3B82F6, "info": 0x6B7280,
    }.get(sev, 0x6B7280)
