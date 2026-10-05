"""bloodhound-python wrapper — collect AD relationships."""

from __future__ import annotations

from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


async def collect(domain: str, user: str, password: str, dc: str = "",
                  collect: str = "All") -> dict[str, Any]:
    if not tool_available("bloodhound-python"):
        return {"error": "bloodhound-python not installed",
                "install_hint": "pip install bloodhound"}
    args = ["bloodhound-python", "-d", domain, "-u", user, "-p", password,
            "--collect", collect, "--zip"]
    if dc:
        args.extend(["-ns", dc, "-dc", dc])
    res = await run_tool(args, timeout=300)
    return {
        "summary": "BloodHound collection",
        "stdout_tail": res.stdout[-1500:],
        "stderr_tail": res.stderr[-500:],
        "returncode": res.returncode,
    }
