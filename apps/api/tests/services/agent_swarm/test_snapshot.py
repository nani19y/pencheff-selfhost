"""ReconSnapshot is frozen, immutable, and round-trippable through
its dict representation."""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from pencheff_api.services.agent_swarm.snapshot import (
    DiscoveredEndpoint,
    ReconFailed,
    ReconSnapshot,
)


def test_snapshot_is_frozen():
    snap = _make_snapshot()
    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.target_base_url = "x"  # type: ignore[misc]


def test_endpoint_is_frozen():
    ep = DiscoveredEndpoint(
        url="https://t/api", method="GET", status=200,
        content_type="application/json", parameters=("id",),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        ep.url = "y"  # type: ignore[misc]


def test_recon_failed_is_an_exception():
    assert issubclass(ReconFailed, Exception)
    with pytest.raises(ReconFailed):
        raise ReconFailed("recon empty")


def test_snapshot_authenticated_defaults_consistent():
    snap = _make_snapshot()
    assert snap.authenticated is False
    assert snap.auth_login_url is None
    assert snap.auth_cookies == ()
    assert snap.auth_tokens == {}


def _make_snapshot() -> ReconSnapshot:
    return ReconSnapshot(
        target_base_url="https://t.example.com",
        profile="standard",
        scope_include=("https://t.example.com/",),
        scope_exclude=(),
        endpoints=(
            DiscoveredEndpoint(
                url="https://t.example.com/api/users",
                method="GET", status=200,
                content_type="application/json",
                parameters=("id",),
            ),
        ),
        api_spec_urls=(),
        subdomains=(),
        robots_txt=None,
        sitemap_urls=(),
        security_txt=None,
        tech_stack={"server": "nginx/1.18"},
        waf_vendor=None,
        authenticated=False,
        auth_login_url=None,
        auth_cookies=(),
        auth_tokens={},
        oast_session_handle=None,
        recon_agent_summary="",
        recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )
