"""bettercap wrapper — evil twin / 802.1X harness."""

from __future__ import annotations

from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


async def evil_twin(interface: str, ssid: str = "free-wifi") -> dict[str, Any]:
    if not tool_available("bettercap"):
        return {"error": "bettercap not installed",
                "install_hint": "apt install bettercap"}
    # We only validate invocation; sustained run is via run_security_tool.
    caplet = (
        f"set wifi.interface {interface}; "
        f"set wifi.ap.ssid {ssid}; "
        "wifi.recon on; "
    )
    res = await run_tool(["bettercap", "-iface", interface, "-eval", caplet],
                         timeout=5)
    return {"summary": f"bettercap evil-twin '{ssid}'",
            "stdout_tail": res.stdout[-500:],
            "stderr_tail": res.stderr[-300:]}
