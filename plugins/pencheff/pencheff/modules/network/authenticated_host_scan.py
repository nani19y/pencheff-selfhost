"""Authenticated host scans — read installed packages / OS version over SSH, SMB, or WinRM.

Each protocol backend is optional (requires its own dependency). Callers get
``None`` back from ``collect_packages`` when the backend is missing, and the
calling module surfaces a clear "dependency missing" Finding.

Credentials are sourced from the session's CredentialStore by name.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pencheff.core.credentials import CredentialSet


@dataclass
class PackageSnapshot:
    os_name: str = ""
    os_version: str = ""
    packages: list[tuple[str, str]] = field(default_factory=list)  # (name, version)
    transport: str = ""


def _try_import(name: str) -> Any:
    try:
        return __import__(name)
    except ImportError:
        return None


async def collect_packages(
    host: str,
    creds: CredentialSet,
    protocol: str = "ssh",
    port: int | None = None,
) -> PackageSnapshot | None:
    if protocol == "ssh":
        return await _ssh_collect(host, creds, port or 22)
    if protocol in {"smb", "winrm"}:
        return await _winrm_collect(host, creds, port or 5985)
    return None


async def _ssh_collect(host: str, creds: CredentialSet, port: int) -> PackageSnapshot | None:
    paramiko = _try_import("paramiko")
    if paramiko is None:
        return None
    snap = PackageSnapshot(transport="ssh")
    username = creds.username.get() if creds.username else ""
    password = creds.password.get() if creds.password else None
    ssh_key_secret = (creds.custom_headers or {}).get("ssh_key_path")
    key_filename = ssh_key_secret.get() if ssh_key_secret else None

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=username, password=password,
            key_filename=key_filename, timeout=15.0, allow_agent=True,
            look_for_keys=True,
        )
    except Exception:  # noqa: BLE001
        client.close()
        return None
    try:
        for cmd, parser in (
            ("cat /etc/os-release", _parse_os_release),
            ("dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null || rpm -qa --qf '%{NAME} %{VERSION}\\n' 2>/dev/null || apk info -vv 2>/dev/null",
             _parse_package_list),
        ):
            stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
            output = stdout.read().decode("utf-8", errors="replace")
            parser(output, snap)
    finally:
        client.close()
    return snap


async def _winrm_collect(host: str, creds: CredentialSet, port: int) -> PackageSnapshot | None:
    winrm = _try_import("winrm")
    if winrm is None:
        return None
    try:
        s = winrm.Session(
            f"http://{host}:{port}/wsman",
            auth=(
                creds.username.get() if creds.username else "",
                creds.password.get() if creds.password else "",
            ),
            transport="ntlm",
        )
    except Exception:  # noqa: BLE001
        return None
    snap = PackageSnapshot(transport="winrm")
    try:
        r = s.run_ps("Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version | ConvertTo-Json")
        import json
        try:
            j = json.loads(r.std_out.decode())
            snap.os_name = j.get("Caption", "")
            snap.os_version = j.get("Version", "")
        except Exception:  # noqa: BLE001
            pass
        r = s.run_ps(
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
            "Select-Object DisplayName, DisplayVersion | ConvertTo-Json"
        )
        try:
            items = json.loads(r.std_out.decode())
            if isinstance(items, dict):
                items = [items]
            for it in items or []:
                name = (it.get("DisplayName") or "").strip()
                ver = (it.get("DisplayVersion") or "").strip()
                if name:
                    snap.packages.append((name, ver))
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001
        return snap
    return snap


def _parse_os_release(text: str, snap: PackageSnapshot) -> None:
    for line in text.splitlines():
        if line.startswith("NAME="):
            snap.os_name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("VERSION_ID="):
            snap.os_version = line.split("=", 1)[1].strip().strip('"')


def _parse_package_list(text: str, snap: PackageSnapshot) -> None:
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            snap.packages.append((parts[0], parts[1]))
