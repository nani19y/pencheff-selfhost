import asyncio
import pytest
import httpx
from pencheff_api.services.llm_providers.base import (
    ChatMessage, ChatResult, run_sync,
)


def test_chatresult_holds_text_and_raw():
    r = ChatResult(text="hi", raw={"x": 1})
    assert r.text == "hi" and r.raw == {"x": 1}


def test_run_sync_executes_coroutine_with_no_running_loop():
    async def coro():
        return 42
    assert run_sync(coro()) == 42


def test_run_sync_works_inside_a_running_loop():
    async def coro():
        return "ok"
    async def outer():
        # calling run_sync while a loop is already running must NOT raise
        return run_sync(coro())
    assert asyncio.run(outer()) == "ok"


from pencheff_api.services.llm_providers.openai_compat import OpenAICompatClient


def _transport(capture):
    def handler(req):
        capture["url"] = str(req.url)
        capture["headers"] = dict(req.headers)
        import json as _j
        capture["body"] = _j.loads(req.content)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "hello"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1},
        })
    return httpx.MockTransport(handler)


def test_openai_compat_builds_chat_completions_request():
    cap = {}
    c = OpenAICompatClient(provider="openai", model="gpt-5-mini",
                           base_url="https://api.openai.com/v1", api_key="sk-1",
                           transport=_transport(cap))
    res = asyncio.run(c.chat([ChatMessage("system", "s"), ChatMessage("user", "u")],
                             json=True, max_tokens=10))
    assert res.text == "hello"
    assert cap["url"].endswith("/chat/completions")
    assert cap["headers"]["authorization"] == "Bearer sk-1"
    assert cap["body"]["model"] == "gpt-5-mini"
    assert cap["body"]["response_format"] == {"type": "json_object"}
    assert res.input_tokens == 3 and res.output_tokens == 1


def test_azure_uses_deployment_url_and_api_key_header():
    cap = {}
    c = OpenAICompatClient(provider="azure_openai", model="gpt-5",
                           base_url="https://my.openai.azure.com", api_key="az-1",
                           azure_deployment="dep1", azure_api_version="2024-02-01",
                           transport=_transport(cap))
    asyncio.run(c.chat([ChatMessage("user", "u")]))
    assert "/openai/deployments/dep1/chat/completions" in cap["url"]
    assert "api-version=2024-02-01" in cap["url"]
    assert cap["headers"]["api-key"] == "az-1"
    assert "authorization" not in cap["headers"]


def test_openai_compat_raises_on_http_error():
    def handler(req):
        return httpx.Response(401, json={"error": "bad key"})
    c = OpenAICompatClient(provider="openai", model="m",
                           base_url="https://h/v1", api_key="x",
                           transport=httpx.MockTransport(handler))
    with pytest.raises(Exception):
        asyncio.run(c.chat([ChatMessage("user", "u")]))


from pencheff_api.services.llm_providers.anthropic import AnthropicClient


def test_anthropic_messages_request_shape():
    cap = {}
    def handler(req):
        import json as _j
        cap["url"] = str(req.url)
        cap["headers"] = dict(req.headers)
        cap["body"] = _j.loads(req.content)
        return httpx.Response(200, json={
            "content": [{"type": "text", "text": "yo"}],
            "usage": {"input_tokens": 5, "output_tokens": 2},
        })
    c = AnthropicClient(model="claude-opus-4-8", api_key="sk-ant",
                        base_url=None, transport=httpx.MockTransport(handler))
    res = asyncio.run(c.chat([ChatMessage("system", "be brief"),
                              ChatMessage("user", "hi")], max_tokens=16))
    assert res.text == "yo"
    assert cap["url"].endswith("/v1/messages")
    assert cap["headers"]["x-api-key"] == "sk-ant"
    assert "anthropic-version" in cap["headers"]
    # system is hoisted out of messages into the top-level field
    assert cap["body"]["system"] == "be brief"
    assert all(m["role"] != "system" for m in cap["body"]["messages"])
    assert res.input_tokens == 5 and res.output_tokens == 2


from pencheff_api.services.llm_providers.google import GeminiClient


def test_gemini_generatecontent_request_shape():
    cap = {}
    def handler(req):
        import json as _j
        cap["url"] = str(req.url)
        cap["body"] = _j.loads(req.content)
        return httpx.Response(200, json={
            "candidates": [{"content": {"parts": [{"text": "hey"}]}}],
            "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 2},
        })
    c = GeminiClient(model="gemini-2.5-flash", api_key="g-key",
                     base_url=None, transport=httpx.MockTransport(handler))
    res = asyncio.run(c.chat([ChatMessage("system", "sys"),
                              ChatMessage("user", "hi")], json=True))
    assert res.text == "hey"
    assert "generateContent" in cap["url"]
    assert "key=g-key" in cap["url"]
    assert cap["body"]["system_instruction"]["parts"][0]["text"] == "sys"
    assert cap["body"]["generationConfig"]["responseMimeType"] == "application/json"
    assert res.input_tokens == 4 and res.output_tokens == 2
