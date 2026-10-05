import asyncio
from pencheff.modules.mcp_scan.module import _OastAdapter


class _FakeManager:
    def __init__(self): self._polled = 0
    def new_url(self, label=""): return f"http://probe.oast.example/{label}"
    async def poll(self): self._polled += 1; return [{"hit": 1}] if self._polled > 1 else []


def test_adapter_exposes_url_and_async_poll():
    m = _FakeManager()
    a = _OastAdapter(m, label="mcp-fuzz")
    assert a.url == "http://probe.oast.example/mcp-fuzz"
    assert asyncio.run(a.poll()) == []
    assert asyncio.run(a.poll()) == [{"hit": 1}]
