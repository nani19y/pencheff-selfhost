"""checksec wrapper — parses ELF protection flags.

Source: ``checksec --help`` (https://github.com/slimm609/checksec.sh).
"""

from __future__ import annotations

from pencheff.core.findings import Finding
from pencheff.modules.wrapper_base import run_wrapper


async def run(binary_path: str) -> list[Finding]:
    _, _, findings = await run_wrapper(
        "checksec",
        binary_path,
        extra_args=["--output=json", "--file"],
        target_position="tail",
        timeout=30.0,
    )
    return findings
