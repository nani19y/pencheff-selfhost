import asyncio
from types import SimpleNamespace

from pencheff.modules.mcp_scan import client as cl
from pencheff.modules.mcp_scan.manifest import McpManifest


def _tool(name, desc, schema):
    return SimpleNamespace(name=name, description=desc, inputSchema=schema)


def test_normalize_tools_maps_fields():
    raw = [_tool("t1", "desc1", {"type": "object"}), _tool("t2", None, None)]
    tools = cl._normalize_tools(raw)
    assert tools[0].name == "t1" and tools[0].description == "desc1"
    assert tools[0].input_schema == {"type": "object"}
    assert tools[1].description == ""  # None coerced to empty
    assert tools[1].input_schema == {}


def test_normalize_resources_and_prompts():
    res = cl._normalize_resources([SimpleNamespace(uri="file:///x", name="x", description="d", mimeType="text/plain")])
    assert res[0].uri == "file:///x" and res[0].mime_type == "text/plain"
    pr = cl._normalize_prompts([SimpleNamespace(name="p", description="d", arguments=[])])
    assert pr[0].name == "p"


def test_connect_and_enumerate_with_fake_session(monkeypatch):
    # A fake MCP ClientSession that returns canned list_* results.
    class _Res:
        def __init__(self, **kw): self.__dict__.update(kw)
    class FakeSession:
        async def initialize(self):
            return _Res(serverInfo=_Res(name="fake-srv", version="1.2.3"))
        async def list_tools(self):
            return _Res(tools=[_tool("a", "d", {"type": "object"})])
        async def list_resources(self):
            return _Res(resources=[])
        async def list_prompts(self):
            return _Res(prompts=[])
        async def list_resource_templates(self):
            return _Res(resourceTemplates=[])
    mf = asyncio.run(cl.enumerate_session(FakeSession(), transport="stdio", endpoint="stdio:fake"))
    assert isinstance(mf, McpManifest)
    assert mf.server_name == "fake-srv" and mf.server_version == "1.2.3"
    assert len(mf.tools) == 1 and mf.tools[0].name == "a"


def test_enumerate_session_raises_on_failed_handshake():
    """A target that fails the MCP initialize handshake (e.g. a 404 because it
    isn't an MCP server) must raise, not return an empty manifest that grades
    clean."""
    import pytest
    from pencheff.modules.mcp_scan.client import McpHandshakeError

    class FailingSession:
        async def initialize(self):
            raise RuntimeError("HTTP 404 Route not found")

    with pytest.raises(McpHandshakeError):
        asyncio.run(cl.enumerate_session(FailingSession(), transport="streamable_http",
                                         endpoint="https://example.com/agent"))
