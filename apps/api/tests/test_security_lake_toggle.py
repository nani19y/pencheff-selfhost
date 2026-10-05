from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

from pencheff_api.services.security_lake.toggle import (
    apply_lake_toggle, purge_due, PURGE_GRACE_DAYS,
)


def _org(enabled, disabled_at):
    return SimpleNamespace(security_lake_enabled=enabled, security_lake_disabled_at=disabled_at)


NOW = dt.datetime(2026, 6, 13, tzinfo=dt.timezone.utc)


def test_enable_to_disable_starts_clock():
    org = _org(True, None)
    assert apply_lake_toggle(org, enabled=False, now=NOW) is True
    assert org.security_lake_enabled is False
    assert org.security_lake_disabled_at == NOW


def test_disable_to_enable_clears_clock():
    org = _org(False, NOW)
    assert apply_lake_toggle(org, enabled=True, now=NOW) is True
    assert org.security_lake_enabled is True
    assert org.security_lake_disabled_at is None


def test_no_change_returns_false_and_leaves_clock():
    org = _org(False, NOW)
    assert apply_lake_toggle(org, enabled=False, now=NOW) is False
    assert org.security_lake_disabled_at == NOW


def test_purge_due_only_after_grace_and_disabled():
    assert PURGE_GRACE_DAYS == 7
    old = NOW - dt.timedelta(days=8)
    recent = NOW - dt.timedelta(days=3)
    assert purge_due(enabled=False, disabled_at=old, now=NOW) is True
    assert purge_due(enabled=False, disabled_at=recent, now=NOW) is False
    assert purge_due(enabled=False, disabled_at=None, now=NOW) is False
    assert purge_due(enabled=True, disabled_at=old, now=NOW) is False
    exactly_7d = NOW - dt.timedelta(days=7)
    assert purge_due(enabled=False, disabled_at=exactly_7d, now=NOW) is False  # strict: needs >7d


def test_enable_to_enable_is_noop():
    org = _org(True, None)
    assert apply_lake_toggle(org, enabled=True, now=NOW) is False
    assert org.security_lake_enabled is True
    assert org.security_lake_disabled_at is None
