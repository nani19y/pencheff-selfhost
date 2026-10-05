"""Volatility 3 wrapper — memory image triage."""

from __future__ import annotations

from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


async def triage(image: str, plugins: list[str] | None = None) -> dict[str, Any]:
    if not tool_available("vol") and not tool_available("vol.py"):
        return {"error": "volatility3 not installed",
                "install_hint": "pipx install volatility3"}
    bin_name = "vol" if tool_available("vol") else "vol.py"
    plugins = plugins or ["windows.info.Info", "windows.pslist.PsList",
                          "windows.netstat.NetStat"]
    out: dict[str, Any] = {"image": image, "plugins": {}}
    for plug in plugins:
        res = await run_tool([bin_name, "-f", image, plug], timeout=600)
        out["plugins"][plug] = {
            "stdout_tail": res.stdout[-1500:],
            "returncode": res.returncode,
        }
    out["summary"] = f"volatility3: {len(plugins)} plugin(s)"
    return out
