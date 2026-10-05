"""iOS triage — class-dump / otool / IPA inspection."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any


async def triage(ipa: str) -> dict[str, Any]:
    p = Path(ipa)
    if not p.is_file():
        return {"error": f"IPA not found: {ipa}"}
    out: dict[str, Any] = {"summary": "IPA triage"}
    try:
        with zipfile.ZipFile(p, "r") as z:
            members = z.namelist()
        out["binary"] = next((m for m in members if "/Payload/" in m and m.endswith(".app/Info.plist")), None)
        out["entitlements_present"] = any("embedded.mobileprovision" in m for m in members)
        out["frameworks"] = [m for m in members if m.endswith(".framework/")][:20]
    except zipfile.BadZipFile:
        out["error"] = "not a valid zip/ipa"
    return out
