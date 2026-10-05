from __future__ import annotations

import datetime as dt
from typing import Any

PURGE_GRACE_DAYS = 7


def apply_lake_toggle(org: Any, *, enabled: bool, now: dt.datetime) -> bool:
    """Apply an enable/disable to an org. Returns True if the flag changed.

    enable->disable starts the purge clock (disabled_at=now); disable->enable
    clears it (disabled_at=None). No-op if unchanged.
    """
    before = bool(org.security_lake_enabled)
    if before == enabled:
        return False
    org.security_lake_enabled = enabled
    org.security_lake_disabled_at = None if enabled else now
    return True


def purge_due(*, enabled: bool, disabled_at: dt.datetime | None, now: dt.datetime) -> bool:
    """Due for purge iff disabled, clock running, and the grace window elapsed.

    `disabled_at` and `now` must both be timezone-aware UTC (the column is
    DateTime(timezone=True), so DB rows always are). The boundary is strict:
    an org exactly PURGE_GRACE_DAYS old is not yet due.
    """
    if enabled or disabled_at is None:
        return False
    return disabled_at < now - dt.timedelta(days=PURGE_GRACE_DAYS)
