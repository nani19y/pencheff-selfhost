"""Injection test modules."""
from __future__ import annotations

from typing import Any


def param_names(params: list[Any] | None) -> list[str]:
    """Normalize an endpoint's ``params`` to a flat list of name strings.

    ``params`` may be a list of name strings (crawler.py, browser_crawler query
    keys, the DAST kind seed) OR a list of ``{"name": ...}`` dicts (form inputs,
    imported API specs) — the shape depends on the discovery source. Every
    injection module reads through this so a bare string never reaches ``.get``
    and a dict never reaches ``.lower`` (the 'str'/'dict' AttributeError class).
    """
    names: list[str] = []
    for item in params or []:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict) and item.get("name"):
            names.append(str(item["name"]))
    return names
