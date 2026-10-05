"""Generic signed webhook.

The payload contains the raw dict form of every finding plus a scan summary.
The receiver verifies ``X-Pencheff-Signature: sha256=...`` over the JSON body.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.findings import Finding
from pencheff.core.integrations._base import post_json


async def send(
    webhook_url: str,
    findings: list[Finding],
    hmac_secret: str | None = None,
    extra_headers: dict[str, str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "tool": "pencheff",
        "version": "1.0",
        "metadata": metadata or {},
        "summary": _counts(findings),
        "findings": [f.to_dict() for f in findings],
    }
    ok, code, body = await post_json(
        webhook_url, payload,
        headers=extra_headers, hmac_secret=hmac_secret,
    )
    return {"ok": ok, "status": code, "response": body, "sent": len(findings)}


def _counts(findings: list[Finding]) -> dict[str, int]:
    d: dict[str, int] = {}
    for f in findings:
        d[f.severity.value] = d.get(f.severity.value, 0) + 1
    return d
