"""Shared subprocess wrapper for IaC scanners — safe, bounded, optional."""

from __future__ import annotations

import json
import shutil
import subprocess  # noqa: S404 — safe: allowlisted tools only
from typing import Any


def tool_available(tool: str) -> bool:
    return shutil.which(tool) is not None


def run_json(tool: str, args: list[str], timeout: float = 120.0) -> dict[str, Any] | list[Any] | None:
    """Run a tool expected to emit JSON on stdout. Returns parsed JSON or None."""
    if not tool_available(tool):
        return None
    try:
        p = subprocess.run(  # noqa: S603 — args is list, no shell=True
            [tool, *args],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    if not p.stdout.strip():
        return None
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        # Tools like checkov stream multiple JSON docs; try last valid
        for line in reversed(p.stdout.splitlines()):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


def run_text(tool: str, args: list[str], timeout: float = 120.0) -> str:
    if not tool_available(tool):
        return ""
    try:
        p = subprocess.run(  # noqa: S603
            [tool, *args],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        return p.stdout + p.stderr
    except (FileNotFoundError, subprocess.SubprocessError):
        return ""
