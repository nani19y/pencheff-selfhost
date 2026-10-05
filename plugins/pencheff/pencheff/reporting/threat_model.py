"""Render STRIDE / DREAD threat-model output."""

from __future__ import annotations

from typing import Any


def render_stride(model: dict[str, Any]) -> str:
    lines: list[str] = ["# STRIDE Threat Model", ""]
    for asset in model.get("assets", []):
        lines.append(f"## {asset.get('name', '')} ({asset.get('type', '')})")
    lines.append("")
    lines.append("| Asset | Category | Threats | Mitigations |")
    lines.append("|---|---|---|---|")
    for row in model.get("table", []):
        threats = "<br>".join(row.get("threats", []))
        mits = "<br>".join(row.get("mitigations", []))
        lines.append(
            f"| {row.get('asset', '')} | {row.get('category', '')} | {threats} | {mits} |"
        )
    return "\n".join(lines) + "\n"


def render_dread(model: dict[str, Any]) -> str:
    lines: list[str] = ["# DREAD Threat Model", "",
                        "| Threat | D | R | E | A | Disc | Score | Priority |",
                        "|---|---|---|---|---|---|---|---|"]
    for t in model.get("threats", []):
        lines.append(
            f"| {t['threat']} | {t['damage']} | {t['reproducibility']} | "
            f"{t['exploitability']} | {t['affected_users']} | "
            f"{t['discoverability']} | {t['score']} | {t['priority']} |"
        )
    return "\n".join(lines) + "\n"


def render(model: dict[str, Any]) -> str:
    if model.get("method") == "DREAD":
        return render_dread(model)
    return render_stride(model)
