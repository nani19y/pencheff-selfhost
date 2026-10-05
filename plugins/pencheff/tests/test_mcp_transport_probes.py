from pencheff.modules.mcp_scan.manifest import McpManifest
from pencheff.modules.mcp_scan import transport_probes as tp


def _mf(**kw):
    base = dict(transport="sse", endpoint="http://localhost:9000/sse")
    base.update(kw); return McpManifest(**base)


def test_session_id_entropy_flags_pointer_like_id():
    # A pointer-cast integer string (oatpp-mcp CVE-2025-6515 pattern)
    assert tp._session_id_is_weak("140234176823920") is True
    assert tp._session_id_is_weak("0x7f3a1c2d") is True


def test_session_id_entropy_accepts_random_uuid():
    assert tp._session_id_is_weak("9f1c2e7a-3b4d-4f5e-8a9b-0c1d2e3f4a5b") is False


def test_rebind_verdict_flags_missing_host_validation():
    # No Host/Origin validation → server accepts a foreign Host header
    assert tp._accepts_foreign_host(status_code=200) is True
    assert tp._accepts_foreign_host(status_code=403) is False


def test_audience_verdict_flags_accepted_wrong_audience():
    assert tp._accepts_wrong_audience(status_code=200) is True
    assert tp._accepts_wrong_audience(status_code=401) is False


def test_only_runs_for_http_transports():
    stdio = McpManifest(transport="stdio", endpoint="stdio:x")
    # build_transport_findings returns [] for stdio (nothing to probe)
    import asyncio
    assert asyncio.run(tp.build_transport_findings(stdio, http_get=None)) == []
