"""hcxdumptool / hcxpcapngtool wrappers for PMKID capture."""

from __future__ import annotations

from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


async def capture(interface: str, output: str = "/tmp/pmkid.pcapng") -> dict[str, Any]:
    if not tool_available("hcxdumptool"):
        return {"error": "hcxdumptool not installed",
                "install_hint": "apt install hcxdumptool"}
    res = await run_tool(["hcxdumptool", "-i", interface, "-o", output,
                          "--enable_status=1"], timeout=10)
    return {"summary": f"hcxdumptool on {interface}",
            "stdout_tail": res.stdout[-500:]}


async def to_hash(pcap: str, output: str = "/tmp/wpa.hc22000") -> dict[str, Any]:
    if not tool_available("hcxpcapngtool"):
        return {"error": "hcxpcapngtool not installed",
                "install_hint": "apt install hcxtools"}
    res = await run_tool(["hcxpcapngtool", "-o", output, pcap], timeout=60)
    return {"summary": f"hcxpcapngtool → {output}",
            "stdout_tail": res.stdout[-500:]}
