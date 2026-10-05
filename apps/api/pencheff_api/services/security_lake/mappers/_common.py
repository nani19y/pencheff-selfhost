from __future__ import annotations

from typing import Any

# Valid OCSF cwe.uid when a scanner provides no CWE (NVD's catch-all value).
CWE_NONE = "NVD-CWE-noinfo"


def field(row: Any, name: str):
    """Read a field from a dict or an object (ORM row / SimpleNamespace)."""
    return row.get(name) if isinstance(row, dict) else getattr(row, name, None)
