import asyncio
import httpx
from pencheff.modules.mcp_scan.module import _make_http_probe_getter


def test_getter_returns_status_and_session_id():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Mcp-Session-Id": "abc-123"}, text="ok")
    transport = httpx.MockTransport(handler)
    getter = _make_http_probe_getter(transport=transport)
    resp = asyncio.run(getter("http://localhost:9000/sse", headers={"Host": "evil.example"}))
    assert resp.status_code == 200
    assert resp.session_id == "abc-123"


def test_getter_handles_403_no_session():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")
    getter = _make_http_probe_getter(transport=httpx.MockTransport(handler))
    resp = asyncio.run(getter("http://localhost:9000/sse"))
    assert resp.status_code == 403
    assert resp.session_id is None


def test_getter_timeout_treated_as_accepted_streaming():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("stream open", request=request)
    getter = _make_http_probe_getter(transport=httpx.MockTransport(handler))
    resp = asyncio.run(getter("http://localhost:9000/sse"))
    assert resp.status_code == 200
