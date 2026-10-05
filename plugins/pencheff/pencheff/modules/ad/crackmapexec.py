"""NetExec / CrackMapExec wrapper (smb / winrm / mssql / ldap)."""

from __future__ import annotations

from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


def _binary() -> str | None:
    if tool_available("nxc"):
        return "nxc"
    if tool_available("crackmapexec"):
        return "crackmapexec"
    return None


async def smb(target: str, user: str = "", password: str = "",
              hash_: str = "", domain: str = "") -> dict[str, Any]:
    b = _binary()
    if not b:
        return {"error": "nxc / crackmapexec not installed",
                "install_hint": "pipx install netexec  (or)  pip install crackmapexec"}
    args = [b, "smb", target]
    if user:
        args.extend(["-u", user])
    if password:
        args.extend(["-p", password])
    if hash_:
        args.extend(["-H", hash_])
    if domain:
        args.extend(["-d", domain])
    res = await run_tool(args, timeout=120)
    return {"summary": f"{b} smb", "stdout_tail": res.stdout[-2000:],
            "stderr_tail": res.stderr[-300:], "returncode": res.returncode}
