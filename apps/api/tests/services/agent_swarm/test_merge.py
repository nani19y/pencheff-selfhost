"""Merge step copies each breaker's findings into master with
discovered_by_agent tag. Failed breakers are skipped."""
from __future__ import annotations

import pytest

from pencheff.server import pentest_init, get_findings
from pencheff_api.services.agent_swarm.orchestrator import (
    BreakerResult, _merge_breaker_findings_into_master,
)


@pytest.mark.asyncio
async def test_merge_unions_with_tag(monkeypatch):
    master = (await pentest_init(target_url="https://t"))["session_id"]
    src1 = (await pentest_init(target_url="https://t"))["session_id"]
    src2 = (await pentest_init(target_url="https://t"))["session_id"]

    # Inject findings into src1 and src2 using the real Finding API.
    # Canonical reference: test_pencheff_helpers.py (C2) uses get_session from
    # pencheff.core.session, Finding constructor with a Finding instance passed
    # to FindingsDB.add(), and Severity from pencheff.config.
    from pencheff.core.session import get_session as _gsess
    from pencheff.core.findings import Finding, Severity

    f1 = Finding(
        title="SQLi", category="injection", severity=Severity.HIGH,
        owasp_category="A03",
        description="payload reflected", remediation="parameterise",
        endpoint="/api/u", evidence=[],
    )
    _gsess(src1).findings.add(f1)
    fid1 = _gsess(src1).findings.get_all()[0].id

    f2 = Finding(
        title="XSS", category="xss", severity=Severity.MEDIUM,
        owasp_category="A03",
        description="reflected payload", remediation="encode",
        endpoint="/q", evidence=[],
    )
    _gsess(src2).findings.add(f2)
    fid2 = _gsess(src2).findings.get_all()[0].id

    results = [
        BreakerResult("InjectionAgent", True, (fid1,), "ok", 1, 1, None, src1),
        BreakerResult("ClientSideAgent", True, (fid2,), "ok", 1, 1, None, src2),
        BreakerResult("AuthAgent", False, (), "", 0, 0, "x", "sid-failed"),
    ]
    events: list[str] = []
    async def on_event(line: str): events.append(line)

    await _merge_breaker_findings_into_master(
        master_session_id=master,
        breaker_results=results,
        on_event=on_event,
    )
    out = (await get_findings(session_id=master))["findings"]
    titles = sorted(f["title"] for f in out)
    assert titles == ["SQLi", "XSS"]
    by_agent = {
        f["title"]: f.get("metadata", {}).get("discovered_by_agent")
        for f in out
    }
    assert by_agent == {
        "SQLi": "InjectionAgent", "XSS": "ClientSideAgent",
    }
    assert any("InjectionAgent: 1 findings merged" in e for e in events)
    assert any("ClientSideAgent: 1 findings merged" in e for e in events)
