from __future__ import annotations

from typing import Any


def org_data_prefix(settings: Any, org_id: str) -> str:
    """The object-key prefix holding exactly one org's lake data files.

    An external read token / export job MUST be scoped to this prefix to isolate
    an org's row content. The trailing slash is load-bearing: it prevents org
    "o1" from being a string-prefix of org "o10".

    ``org_id`` is server-derived in all current callers, but this primitive may
    feed an access-token boundary, so reject values that could escape the prefix
    (path separators / traversal) defensively.
    """
    if not org_id or "/" in org_id or ".." in org_id:
        raise ValueError(f"unsafe org_id for lake prefix: {org_id!r}")
    base = settings.lake_warehouse.rstrip("/")
    return f"{base}/{settings.lake_namespace}/{settings.lake_table}/data/org_id={org_id}/"
