"""Minimal MITRE ATT&CK technique lookup.

Loads the bundled ``data/mitre_attack.json`` (a curated subset of the
Enterprise matrix — full STIX export is ~30MB and out of scope for the
plugin). Each entry has technique id, name, tactic(s), and a short
description suitable for report inclusion.

Lookups are by technique id (``T1190``), tactic (``initial-access``),
or free-text keyword.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "mitre_attack.json"


@lru_cache(maxsize=1)
def _catalog() -> list[dict[str, Any]]:
    if not DATA_FILE.exists():
        return []
    return json.loads(DATA_FILE.read_text())


def get(technique_id: str) -> dict[str, Any] | None:
    tid = technique_id.upper()
    for t in _catalog():
        if t["id"].upper() == tid:
            return t
    return None


def by_tactic(tactic: str) -> list[dict[str, Any]]:
    tac = tactic.lower().replace(" ", "-")
    return [t for t in _catalog() if tac in [x.lower() for x in t.get("tactics", [])]]


def search(keyword: str) -> list[dict[str, Any]]:
    kw = keyword.lower()
    return [
        t for t in _catalog()
        if kw in t["name"].lower() or kw in t.get("description", "").lower()
    ]


def all_techniques() -> list[dict[str, Any]]:
    return list(_catalog())


def coverage_map(mitre_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Group techniques by tactic for coverage reports."""
    by_tac: dict[str, list[dict[str, Any]]] = {}
    for tid in mitre_ids:
        t = get(tid)
        if not t:
            continue
        for tac in t.get("tactics", []):
            by_tac.setdefault(tac, []).append(t)
    return by_tac
