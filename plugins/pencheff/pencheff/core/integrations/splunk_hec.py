"""Splunk HTTP Event Collector (HEC) integration."""

from __future__ import annotations

import time
from typing import Any

from pencheff.core.findings import Finding
from pencheff.core.integrations._base import post_json


async def send(
    hec_url: str,
    token: str,
    findings: list[Finding],
    sourcetype: str = "pencheff:finding",
) -> dict[str, Any]:
    """POST one ``events`` payload containing one HEC line per finding."""
    lines: list[dict[str, Any]] = []
    for f in findings:
        lines.append({
            "time": time.time(),
            "sourcetype": sourcetype,
            "source": "pencheff",
            "host": "pencheff",
            "event": f.to_dict(),
        })
    if not lines:
        return {"ok": True, "sent": 0}
    # HEC expects concatenated JSON (newline-separated)
    import json
    body = "\n".join(json.dumps(line) for line in lines)
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json",
    }
    # We use our post_json helper wrapper but need raw body — use httpx directly
    import httpx
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(hec_url, content=body, headers=headers)
        return {"ok": 200 <= r.status_code < 300, "status": r.status_code,
                "response": r.text[:300], "sent": len(lines)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
