"""DISA STIG catalog lookup + remediation templates.

Reads ``data/stig_catalog.json`` (a curated subset; full STIGs are
GB-scale and out of scope). Maps observed OS / service hints to STIG
group/rule IDs and renders remediation snippets.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "stig_catalog.json"


@lru_cache(maxsize=1)
def _catalog() -> list[dict[str, Any]]:
    if not DATA_FILE.exists():
        return []
    return json.loads(DATA_FILE.read_text())


def for_asset(asset_type: str) -> list[dict[str, Any]]:
    asset = asset_type.lower()
    return [s for s in _catalog() if asset in [x.lower() for x in s.get("assets", [])]]


def get(stig_id: str) -> dict[str, Any] | None:
    sid = stig_id.upper()
    for s in _catalog():
        if s["id"].upper() == sid:
            return s
    return None


def all_ids() -> list[str]:
    return [s["id"] for s in _catalog()]


def render(stig_id: str) -> str:
    s = get(stig_id)
    if not s:
        return f"# STIG {stig_id} not found\n"
    lines = [
        f"# {s['id']} — {s.get('title', '')}",
        f"- Severity: {s.get('severity', 'medium')}",
        f"- Asset(s): {', '.join(s.get('assets', []))}",
        "",
        "## Description",
        s.get("description", ""),
        "",
        "## Check",
        s.get("check", ""),
        "",
        "## Fix",
        s.get("fix", ""),
    ]
    return "\n".join(lines) + "\n"
