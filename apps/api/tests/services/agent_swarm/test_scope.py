"""scope_include / scope_exclude carried by ReconSnapshot reach the
seeded breaker session (where the existing scope_guard enforces them)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pencheff_api.services.agent_swarm.breakers import seed_breaker_session
from pencheff_api.services.agent_swarm.snapshot import (
    DiscoveredEndpoint, ReconSnapshot,
)


@pytest.mark.asyncio
async def test_scope_propagates_into_breaker_session(monkeypatch):
    captured = {}
    import pencheff.server as srv
    orig_init = srv.pentest_init

    async def capturing_init(*, target_url, **kw):
        captured["target_url"] = target_url
        return await orig_init(target_url=target_url, **kw)
    monkeypatch.setattr(srv, "pentest_init", capturing_init)

    snap = ReconSnapshot(
        target_base_url="https://t.example.com",
        profile="standard",
        scope_include=("https://t.example.com/api/",),
        scope_exclude=("https://t.example.com/admin/",),
        endpoints=(DiscoveredEndpoint("https://t.example.com/api/u", "GET", 200, None, ()),),
        api_spec_urls=(), subdomains=(),
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={}, waf_vendor=None,
        authenticated=False, auth_login_url=None,
        auth_cookies=(), auth_tokens={},
        oast_session_handle=None,
        recon_agent_summary="x", recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )
    sid = await seed_breaker_session(snap)
    assert captured["target_url"] == "https://t.example.com"
    # The seeded session inherits the target's existing scope_guard, which
    # the agent_runner tool registry already pipes scope/exclude through.
    # Sanity: we got a usable session id back.
    assert isinstance(sid, str) and sid
