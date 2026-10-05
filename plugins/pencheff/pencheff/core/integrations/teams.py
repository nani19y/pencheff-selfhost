"""Microsoft Teams Incoming Webhook (Connector)."""

from __future__ import annotations

from typing import Any

from pencheff.core.findings import Finding
from pencheff.core.integrations._base import post_json


async def send(webhook_url: str, findings: list[Finding]) -> dict[str, Any]:
    card: dict[str, Any] = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "DC2626" if any(f.severity.value == "critical" for f in findings) else "F59E0B",
        "summary": "Pencheff scan update",
        "sections": [],
    }
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    card["sections"].append({
        "activityTitle": "Pencheff Scan Results",
        "activitySubtitle": " • ".join(f"{v} {k}" for k, v in counts.items() if v) or "no findings",
        "facts": [{"name": k.capitalize(), "value": str(v)} for k, v in counts.items()],
    })
    for f in sorted(findings, key=lambda x: x.cvss_score, reverse=True)[:5]:
        card["sections"].append({
            "activityTitle": f"**[{f.severity.value.upper()}] {f.title}**",
            "activitySubtitle": f"{f.endpoint} — CVSS {f.cvss_score}",
            "text": f.description[:500],
        })
    ok, code, body = await post_json(webhook_url, card)
    return {"ok": ok, "status": code, "response": body}
