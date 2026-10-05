"""apktool wrapper — APK decompile + smali."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


async def decompile(apk: str, output: str | None = None) -> dict[str, Any]:
    if not tool_available("apktool"):
        return {"error": "apktool not installed",
                "install_hint": "brew install apktool / apt install apktool"}
    out = output or tempfile.mkdtemp(prefix="pencheff-apk-")
    res = await run_tool(["apktool", "d", apk, "-o", out, "-f"], timeout=300)
    manifest = Path(out) / "AndroidManifest.xml"
    return {
        "summary": f"apktool d → {out}",
        "output_dir": out,
        "manifest_present": manifest.exists(),
        "stdout_tail": res.stdout[-500:],
        "returncode": res.returncode,
    }
