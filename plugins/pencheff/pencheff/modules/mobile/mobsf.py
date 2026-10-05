"""MobSF REST API wrapper — static & dynamic mobile scanning."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


async def scan(apk: str, base_url: str = "http://127.0.0.1:8000",
               api_key: str | None = None) -> dict[str, Any]:
    api_key = api_key or os.environ.get("MOBSF_API_KEY", "")
    if not api_key:
        return {"error": "MOBSF_API_KEY env var not set",
                "install_hint": "Run MobSF locally and copy the API key from /api_docs"}
    try:
        import httpx
    except ImportError:  # pragma: no cover
        return {"error": "httpx is required (already in pencheff deps)"}
    p = Path(apk)
    if not p.is_file():
        return {"error": f"APK not found: {apk}"}
    headers = {"Authorization": api_key}
    async with httpx.AsyncClient(timeout=300) as c:
        with p.open("rb") as f:
            up = await c.post(f"{base_url}/api/v1/upload",
                              files={"file": (p.name, f)}, headers=headers)
        if up.status_code != 200:
            return {"error": f"upload failed: {up.status_code}", "body": up.text[:300]}
        meta = up.json()
        scan_resp = await c.post(f"{base_url}/api/v1/scan",
                                 data={"hash": meta["hash"], "scan_type": meta["scan_type"],
                                       "file_name": meta["file_name"]},
                                 headers=headers)
    return {"summary": "MobSF scan triggered",
            "hash": meta.get("hash"),
            "scan_status": scan_resp.status_code}
