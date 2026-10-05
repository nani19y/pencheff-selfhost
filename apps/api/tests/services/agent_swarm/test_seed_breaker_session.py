"""seed_breaker_session creates a fresh isolated pencheff session and
imports the snapshot's surface into it (endpoints + auth + OAST)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from pencheff_api.services.agent_swarm.breakers import seed_breaker_session
from pencheff_api.services.agent_swarm.snapshot import (
    DiscoveredEndpoint, ReconSnapshot,
)


def _snap(authenticated: bool = False) -> ReconSnapshot:
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
        robots_txt=None, sitemap_urls=(), security_txt=None,
        tech_stack={"server": "nginx/1.18"},
        waf_vendor=None,
        authenticated=authenticated,
        auth_login_url=("https://t.example.com/login" if authenticated else None),
        auth_cookies=(("sid", "abc"),) if authenticated else (),
        auth_tokens={"bearer": "eyJ"} if authenticated else {},
        oast_session_handle="oast-h-1" if authenticated else None,
        recon_agent_summary="x",
        recon_findings_ids=(),
        snapshot_built_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_seed_creates_fresh_session_with_endpoints():
    sid = await seed_breaker_session(_snap())
    from pencheff.core.session import get_session as _gsess
    sess = _gsess(sid)
    assert sess is not None
    eps = list(getattr(sess.discovered, "endpoints", ()))
    assert len(eps) == 1
    assert eps[0]["url"] == "https://t.example.com/api/users"


@pytest.mark.asyncio
async def test_seed_propagates_auth_when_authenticated():
    sid = await seed_breaker_session(_snap(authenticated=True))
    from pencheff.core.session import get_session as _gsess
    sess = _gsess(sid)
    assert sess.authenticated is True
    # auth_cookies is list of (name, value) tuples on PentestSession
    cookie_dict = dict(sess.auth_cookies)
    assert cookie_dict.get("sid") == "abc"
    assert sess.auth_tokens.get("bearer") == "eyJ"


@pytest.mark.asyncio
async def test_seed_attaches_oast_handle_when_present():
    sid = await seed_breaker_session(_snap(authenticated=True))
    from pencheff.core.session import get_session as _gsess
    sess = _gsess(sid)
    assert sess.oast_handle == "oast-h-1"
