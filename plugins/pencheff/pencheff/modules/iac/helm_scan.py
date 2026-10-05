"""Helm chart scan — ``helm template`` → pipe into kubernetes_scan."""

from __future__ import annotations

import subprocess  # noqa: S404 — allowlisted
import tempfile
from pathlib import Path

from pencheff.core.findings import Finding
from pencheff.modules.iac import kubernetes_scan
from pencheff.modules.iac._tool_runner import tool_available


def scan(chart_path: Path, values_file: Path | None = None) -> list[Finding]:
    if not tool_available("helm"):
        # Helm chart without the CLI — still scan raw templates directory
        tpl = chart_path / "templates"
        return kubernetes_scan.scan(tpl) if tpl.exists() else []
    args = ["helm", "template", "pencheff-scan", str(chart_path)]
    if values_file and values_file.exists():
        args += ["-f", str(values_file)]
    try:
        p = subprocess.run(  # noqa: S603
            args, capture_output=True, text=True, timeout=60, check=False
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
    if p.returncode != 0 or not p.stdout.strip():
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
        tmp.write(p.stdout)
        tmp_path = Path(tmp.name)
    try:
        return kubernetes_scan.scan(tmp_path)
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass
