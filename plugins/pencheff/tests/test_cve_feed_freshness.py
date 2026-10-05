"""Tests for the per-scan freshness layer.

Every SCA scan must pull live CVE data:
  * Stale per-package OSV cache rows trigger a live re-fetch.
  * Stale or missing EPSS/KEV feeds trigger a refresh at scan start.
  * Network failure falls back to the stale row rather than dropping
    findings — the intent fails open.
  * TTL knobs are env-var driven and respected at runtime.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from pencheff.core import cve_feed as cf
from pencheff.core.cve_feed import CveFeed, _age_hours, _is_stale


@pytest.fixture
def tmp_feed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CveFeed:
    monkeypatch.setattr(cf, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(cf, "CACHE_DB", tmp_path / "cve_cache.db")
    monkeypatch.setattr(cf, "_feed", None)
    feed = CveFeed()
    yield feed
    feed.close()


# ─── _is_stale / _age_hours pure helpers ─────────────────────────────────


def test_is_stale_treats_zero_as_always_stale():
    """``hours=0`` is the operator's escape hatch for forcing a live
    fetch on every scan — must short-circuit before any timestamp math."""
    fresh = datetime.now(timezone.utc).isoformat()
    assert _is_stale(fresh, hours=0) is True


def test_is_stale_returns_false_for_fresh_timestamp():
    fresh = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    assert _is_stale(fresh, hours=24) is False


def test_is_stale_returns_true_for_old_timestamp():
    old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    assert _is_stale(old, hours=24) is True


def test_is_stale_returns_true_for_unparseable():
    assert _is_stale("not-a-date", hours=24) is True
    assert _is_stale(None, hours=24) is True
    assert _is_stale("", hours=24) is True


def test_is_stale_handles_naive_timestamp_as_utc():
    """SQLite's ``datetime('now')`` stores naive timestamps; the helper
    must treat them as UTC rather than crashing on a tz-mismatch compare."""
    naive = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(tzinfo=None).isoformat()
    assert _is_stale(naive, hours=24) is False


def test_age_hours_returns_none_for_unset():
    assert _age_hours(None) is None
    assert _age_hours("") is None


def test_age_hours_returns_positive_value_for_past_timestamp():
    ts = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
    age = _age_hours(ts)
    assert age is not None
    assert 4.5 < age < 5.5


# ─── osv_query freshness ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_osv_query_uses_fresh_cache_without_network(tmp_feed):
    """Cached row younger than the TTL must NOT trigger a live fetch."""
    fresh = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    payload = json.dumps([
        {
            "id": "CVE-2024-9999",
            "summary": "test",
            "severity": "high",
            "cvss_score": 7.5,
            "cvss_vector": "",
            "affected_versions": [],
            "fixed_versions": ["1.0.1"],
            "references": [],
        }
    ])
    tmp_feed.conn.execute(
        "INSERT INTO osv_cache VALUES (?, ?, ?, ?, ?)",
        ("npm", "lodash", "4.17.20", payload, fresh),
    )
    tmp_feed.conn.commit()

    failing = AsyncMock(side_effect=AssertionError("network was hit on a fresh-cache lookup"))
    with patch("pencheff.core.cve_feed.httpx.AsyncClient", failing):
        out = await tmp_feed.osv_query("npm", "lodash", "4.17.20")
    assert len(out) == 1
    assert out[0].id == "CVE-2024-9999"


@pytest.mark.asyncio
async def test_osv_query_re_fetches_when_cache_stale(tmp_feed):
    """A stale cache row must trigger a live OSV.dev fetch."""
    stale = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    tmp_feed.conn.execute(
        "INSERT INTO osv_cache VALUES (?, ?, ?, ?, ?)",
        ("npm", "lodash", "4.17.20", json.dumps([]), stale),
    )
    tmp_feed.conn.commit()

    fresh_payload = {"vulns": [{"id": "CVE-2024-NEW", "summary": "fresh hit"}]}
    mock_client = AsyncMock()
    mock_response = AsyncMock()
    mock_response.raise_for_status = lambda: None
    mock_response.json = lambda: fresh_payload
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("pencheff.core.cve_feed.httpx.AsyncClient", return_value=mock_client):
        out = await tmp_feed.osv_query("npm", "lodash", "4.17.20")

    # Live data wins — the empty cached payload was overwritten by the
    # fresh OSV response.
    assert len(out) == 1
    assert out[0].id == "CVE-2024-NEW"


@pytest.mark.asyncio
async def test_osv_query_falls_back_to_stale_row_on_network_failure(tmp_feed):
    """Network down on a refresh must NOT drop SCA findings — the
    stale-but-known cached row is returned."""
    stale = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    payload = json.dumps([
        {
            "id": "CVE-2024-9999",
            "summary": "stale hit",
            "severity": "high",
            "cvss_score": 7.5,
            "cvss_vector": "",
            "affected_versions": [],
            "fixed_versions": [],
            "references": [],
        }
    ])
    tmp_feed.conn.execute(
        "INSERT INTO osv_cache VALUES (?, ?, ?, ?, ?)",
        ("npm", "lodash", "4.17.20", payload, stale),
    )
    tmp_feed.conn.commit()

    boom = AsyncMock(side_effect=ConnectionError("offline"))
    boom.__aenter__ = boom
    boom.__aexit__ = AsyncMock(return_value=False)
    boom.post = AsyncMock(side_effect=ConnectionError("offline"))

    class _Boom:
        def __init__(self, *_a, **_kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def post(self, *_a, **_kw):
            raise ConnectionError("offline")

    with patch("pencheff.core.cve_feed.httpx.AsyncClient", _Boom):
        out = await tmp_feed.osv_query("npm", "lodash", "4.17.20")
    assert len(out) == 1
    assert out[0].id == "CVE-2024-9999"


@pytest.mark.asyncio
async def test_osv_query_returns_empty_when_no_cache_and_network_fails(tmp_feed):
    """No cache row + network failure → empty list (not an exception)."""

    class _Boom:
        def __init__(self, *_a, **_kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def post(self, *_a, **_kw):
            raise ConnectionError("offline")

    with patch("pencheff.core.cve_feed.httpx.AsyncClient", _Boom):
        out = await tmp_feed.osv_query("npm", "lodash", "4.17.20")
    assert out == []


@pytest.mark.asyncio
async def test_osv_ttl_zero_forces_live_every_call(tmp_feed, monkeypatch):
    """PENCHEFF_OSV_TTL_HOURS=0 makes every scan a live fetch."""
    monkeypatch.setattr(cf, "OSV_CACHE_TTL_HOURS", 0)
    fresh = datetime.now(timezone.utc).isoformat()
    tmp_feed.conn.execute(
        "INSERT INTO osv_cache VALUES (?, ?, ?, ?, ?)",
        ("npm", "lodash", "4.17.20", json.dumps([]), fresh),
    )
    tmp_feed.conn.commit()

    fresh_payload = {"vulns": [{"id": "CVE-2024-LIVE", "summary": "live"}]}
    mock_client = AsyncMock()
    mock_response = AsyncMock()
    mock_response.raise_for_status = lambda: None
    mock_response.json = lambda: fresh_payload
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("pencheff.core.cve_feed.httpx.AsyncClient", return_value=mock_client):
        out = await tmp_feed.osv_query("npm", "lodash", "4.17.20")
    assert out[0].id == "CVE-2024-LIVE"


# ─── ensure_feeds_fresh ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ensure_feeds_fresh_skips_when_recently_refreshed(tmp_feed):
    """Both feeds within the TTL → no network call, no error."""
    fresh = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    tmp_feed.conn.executemany(
        "INSERT INTO feed_meta VALUES (?, ?, ?, ?)",
        [("epss", fresh, 100, None), ("kev", fresh, 50, None)],
    )
    tmp_feed.conn.commit()

    boom = AsyncMock(side_effect=AssertionError("network was hit on fresh feed"))
    with patch("pencheff.core.cve_feed.httpx.AsyncClient", boom):
        out = await tmp_feed.ensure_feeds_fresh()
    assert out["epss_refreshed"] is False
    assert out["kev_refreshed"] is False
    assert out["errors"] == []


@pytest.mark.asyncio
async def test_ensure_feeds_fresh_refreshes_when_no_meta_rows(tmp_feed):
    """First-ever scan — no feed_meta rows yet — must trigger a refresh."""
    fake_refresh = AsyncMock(return_value={"epss": 200_000, "kev": 1_500, "errors": []})
    with patch.object(tmp_feed, "refresh", fake_refresh):
        out = await tmp_feed.ensure_feeds_fresh()
    assert out["epss_refreshed"] is True
    assert out["kev_refreshed"] is True
    fake_refresh.assert_awaited_once()
    # Meta rows are now persisted so the next scan won't refresh.
    rows = {r[0]: r[1] for r in tmp_feed.conn.execute("SELECT feed, refreshed_at FROM feed_meta")}
    assert "epss" in rows
    assert "kev" in rows


@pytest.mark.asyncio
async def test_ensure_feeds_fresh_swallows_refresh_failure(tmp_feed):
    """Network failure during refresh must NOT raise — scan continues."""
    fake_refresh = AsyncMock(side_effect=ConnectionError("offline"))
    with patch.object(tmp_feed, "refresh", fake_refresh):
        out = await tmp_feed.ensure_feeds_fresh()
    assert out["epss_refreshed"] is False
    assert out["kev_refreshed"] is False
    assert any("offline" in e for e in out["errors"])


@pytest.mark.asyncio
async def test_ensure_feeds_fresh_refreshes_when_stale(tmp_feed):
    """Cache older than TTL → refresh fires."""
    stale = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    tmp_feed.conn.executemany(
        "INSERT INTO feed_meta VALUES (?, ?, ?, ?)",
        [("epss", stale, 100, None), ("kev", stale, 50, None)],
    )
    tmp_feed.conn.commit()
    fake_refresh = AsyncMock(return_value={"epss": 200_000, "kev": 1_500, "errors": []})
    with patch.object(tmp_feed, "refresh", fake_refresh):
        out = await tmp_feed.ensure_feeds_fresh()
    assert out["epss_refreshed"] is True
    fake_refresh.assert_awaited_once()


@pytest.mark.asyncio
async def test_ensure_feeds_fresh_honours_explicit_max_age(tmp_feed):
    """Caller can override the configured TTL per-call (e.g. force a
    fresh pull from a CI runner that wants always-live)."""
    one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    tmp_feed.conn.executemany(
        "INSERT INTO feed_meta VALUES (?, ?, ?, ?)",
        [("epss", one_hour_ago, 100, None), ("kev", one_hour_ago, 50, None)],
    )
    tmp_feed.conn.commit()
    # Default TTL would let this skip — caller asks for max 0 hours.
    fake_refresh = AsyncMock(return_value={"epss": 100, "kev": 50, "errors": []})
    with patch.object(tmp_feed, "refresh", fake_refresh):
        out = await tmp_feed.ensure_feeds_fresh(max_age_hours=0)
    assert out["epss_refreshed"] is True


# ─── scan_deps wires everything together ────────────────────────────────


@pytest.mark.asyncio
async def test_scan_deps_calls_ensure_feeds_fresh(tmp_feed, monkeypatch):
    """Every SCA scan starts by refreshing stale feeds — the load-bearing
    contract for 'every scan pulls latest live CVE data'."""
    from pencheff.modules.sca import dependency_scan as ds

    monkeypatch.setattr(ds, "get_feed", lambda: tmp_feed)
    ensure_called = AsyncMock(return_value={"epss_refreshed": True, "kev_refreshed": True, "errors": []})
    monkeypatch.setattr(tmp_feed, "ensure_feeds_fresh", ensure_called)
    # No deps — we don't care about findings here, only that the
    # freshness call ran.
    findings = await ds.scan_deps([], nvd_enrich=False)
    ensure_called.assert_awaited_once()
    assert findings == []


@pytest.mark.asyncio
async def test_scan_deps_continues_when_ensure_fresh_blows_up(tmp_feed, monkeypatch):
    """Refresh failure must NOT abort the scan — fail open on enrichment."""
    from pencheff.modules.sca import dependency_scan as ds

    monkeypatch.setattr(ds, "get_feed", lambda: tmp_feed)
    boom = AsyncMock(side_effect=ConnectionError("offline"))
    monkeypatch.setattr(tmp_feed, "ensure_feeds_fresh", boom)
    findings = await ds.scan_deps([], nvd_enrich=False)
    boom.assert_awaited_once()
    assert findings == []


@pytest.mark.asyncio
async def test_scan_deps_skips_freshness_when_disabled(tmp_feed, monkeypatch):
    """Tests / advanced callers can opt out via ensure_fresh=False."""
    from pencheff.modules.sca import dependency_scan as ds

    monkeypatch.setattr(ds, "get_feed", lambda: tmp_feed)
    ensure = AsyncMock()
    monkeypatch.setattr(tmp_feed, "ensure_feeds_fresh", ensure)
    await ds.scan_deps([], ensure_fresh=False, nvd_enrich=False)
    ensure.assert_not_awaited()
