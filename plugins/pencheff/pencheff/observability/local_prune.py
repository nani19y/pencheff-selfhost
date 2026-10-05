"""Local-only retention for plugin-side OTel JSONL files.

The MCP plugin has no scheduler. This is invoked lazily on ``server.py``
startup. Worst case the prune is delayed until the next plugin
restart, which is fine — the operator's disk only grows by one file
per UTC day until then.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("pencheff.observability.prune")

_FNAME = re.compile(r"^otel-(\d{8})\.jsonl$")


def prune_local_logs(retention_days: int = 7) -> int:
    """Delete ``~/.pencheff/logs/otel-YYYYMMDD.jsonl`` older than the
    horizon. Returns the count of files removed.
    """
    base = os.environ.get("PENCHEFF_OBSERVABILITY_LOCAL_DIR", "").strip()
    log_dir = Path(base) if base else Path.home() / ".pencheff" / "logs"
    if not log_dir.exists():
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    removed = 0
    for path in log_dir.iterdir():
        m = _FNAME.match(path.name)
        if not m:
            continue
        try:
            day = datetime.strptime(m.group(1), "%Y%m%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if day < cutoff:
            try:
                path.unlink()
                removed += 1
            except OSError as exc:
                log.warning("could not remove %s: %s", path, exc)
    return removed
