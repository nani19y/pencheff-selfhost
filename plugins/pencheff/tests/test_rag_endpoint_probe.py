from pencheff.modules.rag_scan import endpoint_probe as ep


def test_build_rag_probe_config_maps_fields():
    cfg = {"kind": "rag", "source_type": "rag_endpoint", "provider_llm": "openai-chat",
           "url": "http://rag.example/query", "request_template": None, "response_path": None}
    out = ep.build_rag_probe_config(cfg)
    assert out["provider"] == "openai-chat"
    assert out.get("redteam", {}).get("plugins") == ["rag"]


def test_build_rag_probe_config_custom_provider():
    cfg = {"kind": "rag", "source_type": "rag_endpoint", "provider_llm": "custom",
           "url": "http://r/q", "request_template": "{\"q\":\"{{prompt}}\"}", "response_path": "$.answer"}
    out = ep.build_rag_probe_config(cfg)
    assert out["provider"] == "custom" and out["request_template"] and out["response_path"]


def test_web_native_carriers_present():
    cs = ep.web_native_carriers()
    j = " ".join(cs)
    # hidden-span / zero-width / html-comment style carriers for document-poisoning probes
    assert any("<" in c or "​" in c or "style" in c.lower() for c in cs)
    assert len(cs) >= 2


def test_resolve_rag_redteam_default():
    cats, rt = ep._resolve_rag_redteam({})
    assert cats == ["LLM01", "LLM02", "LLM04", "LLM09"]
    assert rt["plugins"] == ["rag"]


def test_resolve_rag_redteam_override_categories():
    cats, rt = ep._resolve_rag_redteam({"redteam": {"categories": ["LLM02"], "plugins": ["rag", "bias"]}})
    assert cats == ["LLM02"]
    assert rt["plugins"] == ["rag", "bias"]


def test_resolve_rag_redteam_empty_categories_fall_back():
    cats, _ = ep._resolve_rag_redteam({"redteam": {"categories": []}})
    assert cats == ["LLM01", "LLM02", "LLM04", "LLM09"]
