"""PagerDuty Events API v2 — create/resolve alerts."""

from __future__ import annotations

from typing import Any

from pencheff.core.findings import Finding
from pencheff.core.integrations._base import post_json

EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


async def send(
    routing_key: str,
    findings: list[Finding],
    source: str = "pencheff",
) -> list[dict[str, Any]]:
    """Create one event per critical/high finding. Returns list of results."""
    out: list[dict[str, Any]] = []
    for f in findings:
        if f.severity.value not in {"critical", "high"}:
            continue
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": f"pencheff:{f.id}",
            "payload": {
                "summary": f"[{f.severity.value.upper()}] {f.title}",
                "severity": {"critical": "critical", "high": "error",
                             "medium": "warning", "low": "info",
                             "info": "info"}.get(f.severity.value, "warning"),
                "source": source,
                "component": f.endpoint,
                "group": f.category,
                "class": f.owasp_category,
                "custom_details": {
                    "cvss": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "cwe": f.cwe_id,
                    "parameter": f.parameter,
                    "remediation": f.remediation,
                    "description": f.description[:500],
                },
            },
        }
        ok, code, body = await post_json(EVENTS_URL, payload)
        out.append({"finding_id": f.id, "ok": ok, "status": code, "body": body})
    return out
