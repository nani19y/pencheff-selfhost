"""jadx wrapper — Java source recovery from APK."""

from __future__ import annotations

import tempfile
from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


async def recover(apk: str, output: str | None = None) -> dict[str, Any]:
    if not tool_available("jadx"):
        return {"error": "jadx not installed",
                "install_hint": "brew install jadx / sdkmanager 'cmdline-tools;latest'"}
    out = output or tempfile.mkdtemp(prefix="pencheff-jadx-")
    res = await run_tool(["jadx", "-d", out, apk], timeout=600)
    return {
        "summary": f"jadx → {out}",
        "output_dir": out,
        "stdout_tail": res.stdout[-500:],
        "returncode": res.returncode,
    }
