"""Deterministic CTF auto-solver.

Reads a file or text blob, classifies it via ``modules.ctf.solver``, then
walks the candidate-tools list. For text challenges, runs ``auto_decode``
chain. For file-based challenges, runs the suggested binary chain through
``run_tool_with_fallback``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pencheff.core.orchestrator.engine import Orchestrator
from pencheff.modules.ctf.solver import (
    candidate_tools,
    classify_file,
    classify_text,
    solve_text,
)


_FLAG_RE = r"(?:flag|ctf|pwn|hsf|hktw|sec|win)\{[^}\s]{2,}\}"


async def run(challenge: str, *, intensity: str = "default", **_: Any) -> dict[str, Any]:
    """``challenge`` is either a filesystem path or a literal text blob."""
    import re

    target_path = Path(challenge)
    is_file = target_path.is_file()
    kind = classify_file(target_path) if is_file else classify_text(challenge)

    decoded_chains: list[tuple[str, str]] = []
    flags: set[str] = set()
    tool_runs: list[dict[str, str]] = []

    if not is_file:
        decoded_chains = solve_text(challenge, depth=4)
        for _, decoded in decoded_chains:
            for match in re.findall(_FLAG_RE, decoded, re.IGNORECASE):
                flags.add(match)

    if kind:
        tools = list(candidate_tools(kind))
        if is_file:
            orch = Orchestrator()
            for tool in tools:
                if tool.startswith("pencheff_"):
                    continue  # native solver — handled inline above
                resolved, result, findings = await orch.run_tool_with_fallback(
                    primary_tool=tool,
                    target=str(target_path),
                    target_profile="ctf",
                    objective="triage" if tool in ("file", "exiftool") else "stego",
                )
                tool_runs.append({"tool": resolved, "rc": str(result.returncode)})
                for match in re.findall(_FLAG_RE, result.stdout or "", re.IGNORECASE):
                    flags.add(match)

    return {
        "workflow": "ctf_solve",
        "challenge": challenge,
        "kind": kind.name if kind else None,
        "rationale": kind.rationale if kind else "",
        "decoded_chains": [{"chain": c, "decoded": d[:500]} for c, d in decoded_chains[:50]],
        "tool_runs": tool_runs,
        "flags_found": sorted(flags),
    }
