"""Cron expression parser + next-run computation.

Uses croniter (a hard dependency since 2026-05-16 — previously missing,
which made every daily schedule silently fall back to ``+1 hour`` and fire
hourly off a drifting offset).

Timezone handling: cron expressions are interpreted in the supplied
``tz`` (default UTC for backward compat). FE-created schedules pass the
operator's IANA timezone (e.g. ``Asia/Kolkata``) so that ``"30 21 * * *"``
fires at 21:30 in that zone, not 21:30 UTC.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

log = logging.getLogger("pencheff.scheduler")


def compute_next_run(
    cron_expr: str,
    base: datetime | None = None,
    tz: str | None = None,
) -> datetime:
    """Return the next fire time for ``cron_expr``.

    Args:
        cron_expr: Standard 5-field cron expression.
        base: Reference time. Defaults to ``datetime.now(timezone.utc)``.
            If ``base`` is naive, it's treated as UTC.
        tz: Optional IANA timezone name. When set, the cron expression is
            interpreted in this zone (e.g. ``"30 21 * * *"`` with
            ``tz="Asia/Kolkata"`` → 21:30 IST every day, regardless of
            where the API server runs). The returned datetime is converted
            back to UTC so callers can compare against ``now(timezone.utc)``.
            When unset, the cron is interpreted in UTC (legacy behavior).

    Returns:
        A timezone-aware UTC ``datetime``. Callers should compare against
        ``datetime.now(timezone.utc)`` for due-time checks.
    """
    base = base or datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)

    try:
        from croniter import croniter
    except ImportError:
        log.warning(
            "croniter missing — schedule '%s' falls back to +1h. "
            "Add croniter to apps/api/pyproject.toml.",
            cron_expr,
        )
        return base + timedelta(hours=1)

    # When a timezone is supplied, interpret the cron in that zone by
    # converting ``base`` first; the result comes out in the same zone,
    # which we then convert back to UTC for the caller.
    if tz:
        try:
            zone = ZoneInfo(tz)
        except Exception:  # noqa: BLE001 — bad TZ string falls back to UTC
            log.warning("Unknown timezone %r — using UTC", tz)
            zone = timezone.utc
        local_base = base.astimezone(zone)
        try:
            next_local = croniter(cron_expr, local_base).get_next(datetime)
        except Exception as exc:  # noqa: BLE001 — bad cron falls back
            log.warning("Invalid cron %r: %s — falling back to +1h", cron_expr, exc)
            return base + timedelta(hours=1)
        # croniter inherits tzinfo from local_base, so next_local is
        # already timezone-aware in ``zone``. Convert back to UTC.
        return next_local.astimezone(timezone.utc)

    try:
        return croniter(cron_expr, base).get_next(datetime)
    except Exception as exc:  # noqa: BLE001
        log.warning("Invalid cron %r: %s — falling back to +1h", cron_expr, exc)
        return base + timedelta(hours=1)
