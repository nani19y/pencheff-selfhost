"""Plaso / log2timeline wrapper."""

from __future__ import annotations

from typing import Any

from pencheff.core.tool_runner import run_tool, tool_available


async def build(evidence_dir: str, output: str = "/tmp/timeline.plaso") -> dict[str, Any]:
    if not tool_available("log2timeline.py") and not tool_available("log2timeline"):
        return {"error": "plaso not installed",
                "install_hint": "pipx install plaso"}
    bin_name = "log2timeline.py" if tool_available("log2timeline.py") else "log2timeline"
    res = await run_tool([bin_name, "-q", output, evidence_dir], timeout=1800)
    return {"summary": f"plaso → {output}",
            "stdout_tail": res.stdout[-1500:],
            "stderr_tail": res.stderr[-300:],
            "returncode": res.returncode}
