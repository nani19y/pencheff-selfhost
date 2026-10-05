"""Certipy wrapper for ADCS abuse (ESC1-ESC15)."""

from __future__ import annotations

from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


async def find(domain: str, user: str, password: str, dc: str) -> dict[str, Any]:
    if not tool_available("certipy"):
        return {"error": "certipy not installed",
                "install_hint": "pipx install certipy-ad"}
    args = ["certipy", "find", "-u", f"{user}@{domain}", "-p", password,
            "-dc-ip", dc, "-vulnerable", "-stdout"]
    res = await run_tool(args, timeout=180)
    return {"summary": "Certipy ESC scan",
            "stdout_tail": res.stdout[-3000:],
            "stderr_tail": res.stderr[-300:],
            "returncode": res.returncode}
