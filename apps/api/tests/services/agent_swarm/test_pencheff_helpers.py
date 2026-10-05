"""The 4 new orchestrator-internal pencheff helpers. Tested against
real PentestSession instances (no LLM, no network).

CORRECTIONS applied to the task-spec test template:
  1. `from pencheff.core.engagement_db import get_session` → the real symbol
     lives in `pencheff.core.session`; `engagement_db` has no `get_session`.
  2. `src_session.findings.add(title=..., category=..., ...)` → `FindingsDB.add()`
     accepts only a `Finding` instance, not keyword args. Replaced with a proper
     `Finding(...)` constructor call.
  3. `src_session.findings.findings[0]` → the list attribute is `._findings`
     (private). Public accessor is `.get_all()` which returns a list.
  All three are setup-code typos; the behavioral contract (what each helper
  returns) is unchanged.
"""
from __future__ import annotations

import pytest

from pencheff.server import (
    pentest_init,
    import_endpoints,
    set_auth_state,
    attach_oast,
    copy_finding,
    get_findings,
)


@pytest.mark.asyncio
async def test_import_endpoints_persists_to_session():
    init = await pentest_init(target_url="https://t.example.com")
    sid = init["session_id"]
    res = await import_endpoints(
        session_id=sid,
        endpoints=[
            {"url": "https://t.example.com/api/users",
             "method": "GET", "status": 200,
             "content_type": "application/json",
             "parameters": ["id"]},
            {"url": "https://t.example.com/login",
             "method": "POST", "status": None,
             "content_type": None, "parameters": ["username", "password"]},
        ],
    )
    assert res["imported"] == 2


@pytest.mark.asyncio
async def test_set_auth_state_records_cookies_and_tokens():
    init = await pentest_init(target_url="https://t.example.com")
    sid = init["session_id"]
    res = await set_auth_state(
        session_id=sid,
        cookies=[("session_id", "abc123")],
        tokens={"bearer": "eyJ..."},
    )
    assert res["authenticated"] is True


@pytest.mark.asyncio
async def test_attach_oast_records_handle():
    init = await pentest_init(target_url="https://t.example.com")
    sid = init["session_id"]
    res = await attach_oast(session_id=sid, handle="oast-session-xyz")
    assert res["attached"] is True


@pytest.mark.asyncio
async def test_copy_finding_clones_with_tag():
    src = (await pentest_init(target_url="https://t.example.com"))["session_id"]
    dst = (await pentest_init(target_url="https://t.example.com"))["session_id"]

    # Inject a finding into src.
    # Correction: get_session is in pencheff.core.session, not engagement_db.
    from pencheff.core.session import get_session as _gsess
    from pencheff.core.findings import Finding
    from pencheff.config import Severity

    src_session = _gsess(src)
    # Correction: FindingsDB.add() takes a Finding instance, not keyword args.
    src_session.findings.add(Finding(
        title="Test SQLi",
        category="injection",
        severity=Severity.HIGH,
        owasp_category="A03",
        description="SQL injection in id param",
        remediation="Use parameterized queries",
        endpoint="https://t.example.com/api/users",
        evidence=[],
    ))
    # Correction: attribute is _findings (private list); use get_all() publicly.
    fid = src_session.findings.get_all()[0].id

    res = await copy_finding(
        src_session=src,
        dst_session=dst,
        finding_id=fid,
        tag={"discovered_by_agent": "InjectionAgent"},
    )
    assert res["copied"] is True

    dst_findings = (await get_findings(session_id=dst))["findings"]
    assert len(dst_findings) == 1
    assert dst_findings[0]["title"] == "Test SQLi"
    assert dst_findings[0].get("metadata", {}).get("discovered_by_agent") == "InjectionAgent"


@pytest.mark.asyncio
async def test_copy_finding_unknown_id_returns_error():
    src = (await pentest_init(target_url="https://t.example.com"))["session_id"]
    dst = (await pentest_init(target_url="https://t.example.com"))["session_id"]
    res = await copy_finding(
        src_session=src, dst_session=dst,
        finding_id="does-not-exist", tag={},
    )
    assert res.get("copied") is False
    assert "not found" in res.get("error", "").lower()
