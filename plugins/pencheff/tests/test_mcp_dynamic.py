import asyncio

from pencheff.modules.mcp_scan.manifest import McpTool
from pencheff.modules.mcp_scan import dynamic as dyn


def test_classify_destructive_tool():
    assert dyn.is_destructive(McpTool(name="delete_file", description="Delete a file")) is True
    assert dyn.is_destructive(McpTool(name="get_weather", description="Return weather")) is False


def test_injection_payloads_include_oast_and_traversal():
    payloads = dyn.injection_payloads(oast_url="http://oast.example/abc")
    joined = " ".join(payloads)
    assert "oast.example" in joined
    assert any(".." in p for p in payloads)
    assert any(";" in p or "|" in p for p in payloads)


def test_response_indicates_injection_on_oast_hit():
    assert dyn.response_indicates_injection("...root:x:0:0:...", oast_hit=False)
    assert dyn.response_indicates_injection("ok", oast_hit=True)


def test_select_tools_respects_allow_deny_and_gating():
    tools = [McpTool(name="read_x", description="read"), McpTool(name="delete_x", description="delete")]
    sel = dyn.select_tools(tools, allow=[], deny=["read_x"], dynamic=True, destructive=False)
    assert sel == []
    sel2 = dyn.select_tools(tools, allow=[], deny=[], dynamic=True, destructive=True)
    assert {t.name for t in sel2} == {"read_x", "delete_x"}
    assert dyn.select_tools(tools, allow=[], deny=[], dynamic=False, destructive=False) == []


class _FakeResult:
    def __init__(self, text): self.text = text
    def __str__(self): return self.text


def test_fuzz_tools_emits_finding_on_lfi_marker():
    tool = McpTool(name="read_file", description="read a file",
                   input_schema={"type": "object", "properties": {"path": {"type": "string"}}})

    class FakeSession:
        async def call_tool(self, name, args):
            # Echo a classic LFI marker when a traversal payload is sent
            val = " ".join(str(v) for v in (args or {}).values())
            return _FakeResult("root:x:0:0:root:/root:/bin/bash" if ".." in val else "ok")

    findings = asyncio.run(dyn.fuzz_tools(
        FakeSession(), [tool], oast=None, allow=[], deny=[],
        dynamic=True, destructive=False, endpoint="stdio:test", max_calls=20,
    ))
    assert len(findings) >= 1
    assert any("LLM05" == f.owasp_category for f in findings)


def test_fuzz_tools_noop_when_not_dynamic():
    tool = McpTool(name="read_file", description="read", input_schema={"type": "object", "properties": {"p": {"type": "string"}}})

    class FakeSession:
        async def call_tool(self, name, args): return "ok"

    findings = asyncio.run(dyn.fuzz_tools(
        FakeSession(), [tool], oast=None, allow=[], deny=[],
        dynamic=False, destructive=False, endpoint="x", max_calls=20,
    ))
    assert findings == []
