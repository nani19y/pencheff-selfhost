"""aircrack-ng suite wrapper (airodump capture + aircrack-ng crack)."""

from __future__ import annotations

from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


async def capture(interface: str, bssid: str | None = None,
                  channel: int | None = None, output: str = "/tmp/wifi-cap") -> dict[str, Any]:
    if not tool_available("airodump-ng"):
        return {"error": "airodump-ng not installed",
                "install_hint": "apt install aircrack-ng"}
    args = ["airodump-ng", "-w", output, interface]
    if bssid:
        args[1:1] = ["--bssid", bssid]
    if channel:
        args[1:1] = ["--channel", str(channel)]
    # We don't actually run a long capture here — just exec for ~5s to
    # validate setup. Real use is via ``run_security_tool`` from the CLI.
    res = await run_tool(args, timeout=5)
    return {"summary": f"airodump-ng on {interface}",
            "stdout_tail": res.stdout[-500:],
            "stderr_tail": res.stderr[-300:]}


async def crack(cap_path: str, wordlist: str) -> dict[str, Any]:
    if not tool_available("aircrack-ng"):
        return {"error": "aircrack-ng not installed",
                "install_hint": "apt install aircrack-ng"}
    res = await run_tool(["aircrack-ng", "-w", wordlist, cap_path], timeout=600)
    cracked = "KEY FOUND" in res.stdout
    return {"summary": "aircrack-ng crack",
            "cracked": cracked,
            "stdout_tail": res.stdout[-1500:]}
