from pencheff.modules.mcp_scan.manifest import McpTool
from pencheff.modules.mcp_scan import agent_probe as ap


def test_lethal_trifecta_present_when_all_three_buckets():
    # untrusted-input + private-data access + exfiltration/egress
    tools = [
        McpTool(name="fetch_url", description="fetch a web page (untrusted content)"),
        McpTool(name="read_private_repo", description="read private repository files"),
        McpTool(name="send_email", description="send an email to an external address"),
    ]
    assert ap.lethal_trifecta_present(tools) is True


def test_lethal_trifecta_absent_when_missing_a_bucket():
    tools = [
        McpTool(name="read_private_repo", description="read private repository files"),
        McpTool(name="send_email", description="send an email externally"),
    ]  # no untrusted-input source
    assert ap.lethal_trifecta_present(tools) is False


def test_build_agent_probe_config_http():
    cfg = {"kind": "mcp", "source_type": "agent_http", "provider": "openai-chat",
           "model": "gpt-4", "url": "http://agent.example/chat"}
    out = ap.build_agent_probe_config(cfg, base_url="http://agent.example/chat")
    assert out["provider"] == "openai-chat"
    # The mcp attack pack must be selected
    assert out.get("redteam", {}).get("plugins") == ["mcp"]


def test_build_agent_probe_config_browser():
    cfg = {"kind": "mcp", "source_type": "agent_browser", "url": "http://a/",
           "prompt_selector": "#in", "send_selector": "#go", "response_selector": "#out"}
    out = ap.build_agent_probe_config(cfg, base_url="http://a/")
    assert out["provider"] == "browser"
    assert out.get("redteam", {}).get("plugins") == ["mcp"]


import asyncio


def test_run_agent_probe_invokes_llm_pack(monkeypatch):
    # Updated for Task 3: agent_probe now calls run_red_team_categories (multi-module)
    # instead of the LLM06-only path.
    from pencheff.modules.mcp_scan import agent_probe as ap

    calls = {}

    class _FakeFinding:
        owasp_category = "LLM06"; title = "probe finding"; metadata = {}

    async def _fake_run_red_team_categories(session, categories, max_payloads, module_label=None):
        calls["ran"] = True
        calls["llm_config"] = getattr(session, "llm_config", None)
        calls["categories"] = categories
        calls["module_label"] = module_label
        return [_FakeFinding()]

    # Pre-import runner so it's in sys.modules, then patch its attribute.
    # The `from ... import run_red_team_categories` inside agent_probe's try-block
    # re-uses the cached module object, so patching the attr intercepts the call.
    import pencheff.modules.llm_red_team.runner as _runner_mod
    monkeypatch.setattr(_runner_mod, "run_red_team_categories", _fake_run_red_team_categories)

    class _Discovered:
        running_module = None
        completed_modules: list = []

    class _Sess:
        llm_config = None
        discovered = _Discovered()
        target = type("T", (), {"base_url": "http://agent.example/chat"})()

    cfg = {"kind": "mcp", "source_type": "agent_http", "provider": "openai-chat",
           "model": "gpt-4", "url": "http://agent.example/chat"}
    findings = asyncio.run(ap.run_agent_probe(_Sess(), cfg))
    assert calls.get("ran") is True
    assert calls.get("llm_config") is not None
    assert calls.get("module_label") == "agent_red_team"
    # Curated default: LLM06 is one of the 6 categories
    assert "LLM06" in calls.get("categories", [])
    assert any(f.owasp_category == "LLM06" for f in findings)
