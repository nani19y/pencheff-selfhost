"""Sleuth Kit disk triage (mmls / fls / icat)."""

from __future__ import annotations

from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


async def triage(image: str) -> dict[str, Any]:
    if not tool_available("mmls"):
        return {"error": "sleuthkit not installed",
                "install_hint": "brew install sleuthkit / apt install sleuthkit"}
    res = await run_tool(["mmls", image], timeout=120)
    return {"summary": f"mmls {image}",
            "stdout_tail": res.stdout[-1500:],
            "returncode": res.returncode}
