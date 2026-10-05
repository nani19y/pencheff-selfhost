"""Tunnel command builders (chisel / ssh / socat / ligolo).

Returns shell commands the tester runs themselves. We do not invoke them.
Source: each tool's own README.
"""

from __future__ import annotations

import shlex


def chisel_reverse_socks(*, listener_host: str, listener_port: int = 8443) -> dict[str, str]:
    """Build commands for a reverse SOCKS tunnel via chisel."""
    return {
        "operator": shlex.join(
            ["chisel", "server", "--reverse", "--port", str(listener_port)]
        ),
        "agent": shlex.join(
            [
                "chisel", "client",
                f"{listener_host}:{listener_port}",
                "R:1080:socks",
            ]
        ),
        "notes": "Listener exposes SOCKS5 on 127.0.0.1:1080 once the agent connects.",
    }


def ssh_dynamic_forward(*, user: str, jump_host: str, local_port: int = 1080) -> dict[str, str]:
    return {
        "command": shlex.join(
            ["ssh", "-fN", "-D", str(local_port), f"{user}@{jump_host}"]
        ),
        "notes": f"SOCKS5 dynamic forward on 127.0.0.1:{local_port}.",
    }


def socat_port_forward(*, local_port: int, remote_host: str, remote_port: int) -> dict[str, str]:
    return {
        "command": shlex.join(
            [
                "socat",
                f"TCP-LISTEN:{local_port},reuseaddr,fork",
                f"TCP:{remote_host}:{remote_port}",
            ]
        ),
        "notes": "TCP-only relay; use chisel/ssh for SOCKS.",
    }


def ligolo_tunnel(*, listener_host: str, listener_port: int = 11601) -> dict[str, str]:
    return {
        "operator": shlex.join(["ligolo-ng", "-selfcert", "-laddr", f"0.0.0.0:{listener_port}"]),
        "agent": shlex.join(["ligolo-ng-agent", "-connect", f"{listener_host}:{listener_port}", "-ignore-cert"]),
        "notes": "Use the operator's `start` command to switch context to the agent.",
    }
