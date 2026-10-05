"""Low-impact script-style checks for open services.

These checks summarize already-observed exposure and banners. They do not
attempt authentication bypass, brute force, exploit payloads, or destructive
protocol behavior.
"""

from __future__ import annotations

import re


RISKY_PORTS = {
    21: "ftp exposed",
    23: "telnet exposed",
    445: "smb exposed",
    1433: "mssql exposed",
    3306: "mysql exposed",
    3389: "rdp exposed",
    5432: "postgres exposed",
    5900: "vnc exposed",
    6379: "redis exposed",
    9200: "elasticsearch exposed",
    11211: "memcached exposed",
    27017: "mongodb exposed",
}


def run_safe_scripts(host: str, port: int, service: str, banner: str) -> dict[str, str]:
    scripts: dict[str, str] = {}
    if service.startswith("HTTP"):
        title = re.search(r"<title[^>]*>(.*?)</title>", banner, flags=re.IGNORECASE)
        if title:
            scripts["http-title"] = " ".join(title.group(1).split())[:120]
        server = _server_header(banner)
        if server:
            scripts["http-server-header"] = server
    if service == "SSH" and banner:
        scripts["ssh-banner"] = banner
    if port in RISKY_PORTS:
        scripts["exposure-check"] = RISKY_PORTS[port]
    if not scripts:
        scripts["port-state"] = f"{host}:{port} accepts TCP connections"
    return scripts


def _server_header(banner: str) -> str | None:
    match = re.search(r"\bServer:\s*([^\\r\\n]+?)(?:\s+(?:Date|Content-|Connection):|$)", banner)
    return match.group(1).strip() if match else None
