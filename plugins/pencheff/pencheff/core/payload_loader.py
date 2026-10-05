"""Centralized payload loader for all test modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any


_PAYLOADS_DIR = Path(__file__).resolve().parent.parent / "payloads"


def get_payload_path(filename: str) -> Path:
    """Return the absolute path to a payload file."""
    return _PAYLOADS_DIR / filename


def load_payloads(filename: str) -> list[str]:
    """Load payloads from a file in the payloads directory.

    Strips comments (lines starting with #), blank lines, and leading/trailing whitespace.
    """
    path = get_payload_path(filename)
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]


def load_payloads_with_metadata(filename: str, delimiter: str = "\t") -> list[dict[str, Any]]:
    """Load payloads with tab-separated metadata.

    Each line: payload<delimiter>description<delimiter>tags
    Returns list of dicts with keys: payload, description, tags.
    """
    path = get_payload_path(filename)
    if not path.exists():
        return []
    results = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(delimiter)
        entry: dict[str, Any] = {"payload": parts[0]}
        if len(parts) > 1:
            entry["description"] = parts[1]
        if len(parts) > 2:
            entry["tags"] = parts[2]
        results.append(entry)
    return results
