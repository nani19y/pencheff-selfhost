"""Persistence-template generator.

Returns config templates intended for inclusion in the engagement *report*
(under "what an attacker could do next") — NOT for autonomous execution.
"""

from __future__ import annotations

from textwrap import dedent


def linux_systemd_unit(*, name: str, command: str) -> str:
    return dedent(
        f"""\
        [Unit]
        Description={name}
        After=network.target

        [Service]
        ExecStart={command}
        Restart=always
        RestartSec=10
        User=root

        [Install]
        WantedBy=multi-user.target
        """
    )


def linux_cron_root(*, schedule: str, command: str) -> str:
    return f"{schedule} root {command}\n"


def windows_run_key(*, name: str, command: str) -> str:
    return dedent(
        f"""\
        Windows Registry Editor Version 5.00

        [HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
        "{name}"="{command}"
        """
    )


def windows_scheduled_task(*, name: str, command: str, schedule: str = "ONLOGON") -> str:
    return (
        f'schtasks /Create /SC {schedule} /TN "{name}" '
        f'/TR "{command}" /RL HIGHEST /F'
    )
