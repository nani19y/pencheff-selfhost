"""Opsgenie alerts API."""

from __future__ import annotations

from typing import Any

from pencheff.core.findings import Finding
from pencheff.core.integrations._base import post_json

API_URL = "https://api.opsgenie.com/v2/alerts"


async def send(api_key: str, findings: list[Finding]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    headers = {"Authorization": f"GenieKey {api_key}"}
    for f in findings:
        if f.severity.value not in {"critical", "high"}:
            continue
        priority = {"critical": "P1", "high": "P2", "medium": "P3",
                    "low": "P4", "info": "P5"}[f.severity.value]
        payload = {
            "message": f"[{f.severity.value.upper()}] {f.title}"[:130],
            "alias": f"pencheff:{f.id}",
            "description": f.description[:15000],
            "entity": f.endpoint[:512],
            "priority": priority,
            "tags": [f.category, f.owasp_category, "pencheff"],
            "details": {
                "cvss": str(f.cvss_score),
                "cvss_vector": f.cvss_vector,
                "cwe": f.cwe_id or "",
                "remediation": f.remediation[:4000],
            },
        }
        ok, code, body = await post_json(API_URL, payload, headers=headers)
        out.append({"finding_id": f.id, "ok": ok, "status": code, "body": body})
    return out
