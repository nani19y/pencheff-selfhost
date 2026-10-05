# Custom LLM Providers — Plan B (Data Plane) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every AI feature run on the org's active LLM provider (from Plan A) when one is set — via native adapters (OpenAI-compatible, Anthropic, Gemini, Azure) behind one `ChatClient` interface and one resolver — falling back to Pencheff's env defaults when none is set, failing **closed** on provider errors, and **bypassing quotas** when a BYO provider is active.

**Architecture:** A `services/llm_providers/` adapter package: a `ChatClient` async interface (+ a safe sync bridge for the one sync call site), three adapters, a factory, and `resolve_chat_client(org_id, session)`. Each of the six AI services gains a small guard: resolve → use org client (no quota) → else current env behavior. The `/llm-providers/{id}/test` endpoint (deferred from Plan A) lands here since it needs the adapters.

**Tech Stack:** httpx (async), Pydantic, FastAPI, asyncio. Reuses Plan A's `LlmProvider` model, `Org.active_llm_provider_id`, `catalog.py`, and `services/credentials.decrypt_credentials`. Tests: pure-unit with monkeypatched httpx transports / fake clients (no network, no DB), per repo convention.

**Spec:** `docs/superpowers/specs/2026-06-14-custom-llm-providers-design.md`.
**Depends on:** Plan A (`2026-06-14-custom-llm-providers-plan-a-management.md`) — data model + catalog must exist.

## Prerequisite check

Before Task 1, confirm Plan A is merged: `LlmProvider` model, `Org.active_llm_provider_id`, and `services/llm_providers/catalog.py` exist. If not, stop — Plan B has nothing to resolve.

## Design decisions locked here

- **Interface:** `ChatClient.chat(messages, *, temperature, max_tokens, json, timeout) -> ChatResult` is **async**. Async call sites (`fix_llm`, `triage_llm`, agentic fixer, scan agent) await it directly. The one sync call site (`services/llm.py`) uses the provided `run_sync(...)` bridge, which runs the coroutine on a dedicated thread+loop when a loop is already running (avoids `asyncio.run` reentrancy errors).
- **Fail-closed:** if `client.chat` raises, the calling service takes its existing no-AI path; it does NOT fall back to the Pencheff env client.
- **Quota bypass:** when an org client is resolved, the service skips its quota/free-tier checks.
- **Resolution caching:** none in v1 (one extra indexed PK lookup + decrypt per AI call is negligible relative to an LLM round-trip).

## File structure

| File                                                                                                        | Responsibility                                                        |
| ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `services/llm_providers/base.py`                                                                            | `ChatMessage`, `ChatResult`, `ChatClient` protocol, `run_sync` bridge |
| `services/llm_providers/openai_compat.py`                                                                   | Adapter for `openai`, `openai_compatible`, `azure_openai`             |
| `services/llm_providers/anthropic.py`                                                                       | Adapter for `anthropic` (`/v1/messages`)                              |
| `services/llm_providers/google.py`                                                                          | Adapter for `google` (Gemini `generateContent`)                       |
| `services/llm_providers/factory.py`                                                                         | `build_client(provider_row) -> ChatClient`                            |
| `services/llm_providers/resolver.py`                                                                        | `resolve_chat_client(org_id, session) -> ChatClient \| None`          |
| `routers/llm_providers.py` (modify)                                                                         | add `POST /{id}/test`                                                 |
| `services/llm.py`, `fix_llm.py`, `triage_llm.py`, `agentic_fixer/llm_client.py`, scan-agent caller (modify) | resolver guard + fail-closed + quota bypass                           |
| `tests/test_llm_adapters.py`, `test_llm_resolver.py`, `test_llm_provider_wiring.py`                         | unit tests                                                            |

---

## Task 1: `ChatClient` interface + sync bridge (`base.py`)

**Files:**

- Create: `apps/api/pencheff_api/services/llm_providers/base.py`
- Test: `apps/api/tests/test_llm_adapters.py`

- [ ] **Step 1: Write the failing test**

`tests/test_llm_adapters.py`:

```python
import asyncio
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
```

- [ ] **Step 2: Run to confirm failure**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_llm_adapters.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement `base.py`**

```python
from __future__ import annotations

import asyncio
import concurrent.futures
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ChatMessage:
    role: str          # "system" | "user" | "assistant"
    content: str


@dataclass
class ChatResult:
    text: str
    raw: dict = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0


class ChatClient(Protocol):
    provider: str
    model: str

    async def chat(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        json: bool = False,
        timeout: float = 60.0,
    ) -> ChatResult:
        ...


def run_sync(coro):
    """Run an async coroutine from sync code, safely even if an event loop is
    already running on this thread (which would make asyncio.run raise).

    Used by the single sync AI call site (services/llm.py). When no loop is
    running, asyncio.run is used directly. When one IS running, the coroutine
    is executed on a fresh loop in a worker thread and the result awaited.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # A loop is already running on this thread → offload to a thread.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(lambda: asyncio.run(coro)).result()
```

- [ ] **Step 4: Run tests to pass**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_llm_adapters.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/llm_providers/base.py apps/api/tests/test_llm_adapters.py
git commit -m "feat(llm-providers): ChatClient interface + run_sync bridge"
```

---

## Task 2: OpenAI-compatible adapter (`openai_compat.py`)

Covers `openai`, `openai_compatible`, and `azure_openai`. This is the existing request
shape the services already use; azure swaps the URL + auth header + `api-version`.

**Files:**

- Create: `apps/api/pencheff_api/services/llm_providers/openai_compat.py`
- Test: `apps/api/tests/test_llm_adapters.py` (extend)

- [ ] **Step 1: Write failing tests** (append)

```python
import pytest
import httpx
from pencheff_api.services.llm_providers.base import ChatMessage
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
```

- [ ] **Step 2: Run to confirm failure**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_llm_adapters.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement**

```python
from __future__ import annotations

import httpx

from .base import ChatMessage, ChatResult


class OpenAICompatClient:
    """OpenAI chat-completions shape. Handles openai / openai_compatible /
    azure_openai (azure swaps URL + auth header + api-version)."""

    def __init__(self, *, provider: str, model: str, base_url: str | None,
                 api_key: str, azure_deployment: str | None = None,
                 azure_api_version: str | None = None,
                 extra: dict | None = None,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.provider = provider
        self.model = model
        self._base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self._api_key = api_key
        self._azure_deployment = azure_deployment
        self._azure_api_version = azure_api_version
        self._extra = extra or {}
        self._transport = transport  # tests inject a MockTransport

    def _url(self) -> str:
        if self.provider == "azure_openai":
            return (f"{self._base_url}/openai/deployments/{self._azure_deployment}"
                    f"/chat/completions?api-version={self._azure_api_version}")
        return f"{self._base_url}/chat/completions"

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.provider == "azure_openai":
            h["api-key"] = self._api_key
        else:
            h["Authorization"] = f"Bearer {self._api_key}"
        for k, v in (self._extra.get("headers") or {}).items():
            h[k] = v
        return h

    async def chat(self, messages, *, temperature: float = 0.0,
                   max_tokens: int = 1024, json: bool = False,
                   timeout: float = 60.0) -> ChatResult:
        body: dict = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json:
            body["response_format"] = {"type": "json_object"}
        async with httpx.AsyncClient(timeout=timeout, transport=self._transport) as cli:
            r = await cli.post(self._url(), json=body, headers=self._headers())
        r.raise_for_status()
        data = r.json()
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
        usage = data.get("usage") or {}
        return ChatResult(text=text, raw=data,
                          input_tokens=int(usage.get("prompt_tokens", 0)),
                          output_tokens=int(usage.get("completion_tokens", 0)))
```

- [ ] **Step 4: Run tests to pass**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_llm_adapters.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/llm_providers/openai_compat.py apps/api/tests/test_llm_adapters.py
git commit -m "feat(llm-providers): OpenAI-compatible adapter (openai/compat/azure)"
```

---

## Task 3: Anthropic adapter (`anthropic.py`)

**Files:**

- Create: `apps/api/pencheff_api/services/llm_providers/anthropic.py`
- Test: `apps/api/tests/test_llm_adapters.py` (extend)

- [ ] **Step 1: Write failing tests** (append)

```python
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
```

- [ ] **Step 2: Run to confirm failure** — `pytest tests/test_llm_adapters.py -v` → FAIL.

- [ ] **Step 3: Implement**

```python
from __future__ import annotations

import httpx

from .base import ChatResult

ANTHROPIC_VERSION = "2023-06-01"


class AnthropicClient:
    """Anthropic Messages API. System prompt is hoisted to the top-level
    `system` field; assistant text comes from content[].text blocks."""

    def __init__(self, *, model: str, api_key: str, base_url: str | None = None,
                 extra: dict | None = None,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.provider = "anthropic"
        self.model = model
        self._api_key = api_key
        self._base_url = (base_url or "https://api.anthropic.com").rstrip("/")
        self._extra = extra or {}
        self._transport = transport

    async def chat(self, messages, *, temperature: float = 0.0,
                   max_tokens: int = 1024, json: bool = False,
                   timeout: float = 60.0) -> ChatResult:
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        convo = [{"role": m.role, "content": m.content}
                 for m in messages if m.role != "system"]
        if json:
            # Messages API has no response_format; instruct + rely on caller parse.
            system = (system + "\n\nRespond with valid JSON only, no prose.").strip()
        body: dict = {"model": self.model, "max_tokens": max_tokens,
                      "temperature": temperature, "messages": convo}
        if system:
            body["system"] = system
        headers = {"x-api-key": self._api_key,
                   "anthropic-version": ANTHROPIC_VERSION,
                   "Content-Type": "application/json"}
        for k, v in (self._extra.get("headers") or {}).items():
            headers[k] = v
        async with httpx.AsyncClient(timeout=timeout, transport=self._transport) as cli:
            r = await cli.post(f"{self._base_url}/v1/messages", json=body, headers=headers)
        r.raise_for_status()
        data = r.json()
        text = "".join(b.get("text", "") for b in (data.get("content") or [])
                       if b.get("type") == "text")
        usage = data.get("usage") or {}
        return ChatResult(text=text, raw=data,
                          input_tokens=int(usage.get("input_tokens", 0)),
                          output_tokens=int(usage.get("output_tokens", 0)))
```

- [ ] **Step 4: Run tests to pass** — PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/llm_providers/anthropic.py apps/api/tests/test_llm_adapters.py
git commit -m "feat(llm-providers): Anthropic Messages adapter"
```

---

## Task 4: Gemini adapter (`google.py`)

**Files:**

- Create: `apps/api/pencheff_api/services/llm_providers/google.py`
- Test: `apps/api/tests/test_llm_adapters.py` (extend)

- [ ] **Step 1: Write failing tests** (append)

```python
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
```

- [ ] **Step 2: Run to confirm failure** — FAIL.

- [ ] **Step 3: Implement**

```python
from __future__ import annotations

import httpx

from .base import ChatResult

_DEFAULT_BASE = "https://generativelanguage.googleapis.com/v1beta"


class GeminiClient:
    """Google Gemini generateContent. Roles map user->user, assistant->model;
    system hoisted to system_instruction."""

    def __init__(self, *, model: str, api_key: str, base_url: str | None = None,
                 extra: dict | None = None,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.provider = "google"
        self.model = model
        self._api_key = api_key
        self._base_url = (base_url or _DEFAULT_BASE).rstrip("/")
        self._extra = extra or {}
        self._transport = transport

    async def chat(self, messages, *, temperature: float = 0.0,
                   max_tokens: int = 1024, json: bool = False,
                   timeout: float = 60.0) -> ChatResult:
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        contents = [
            {"role": "model" if m.role == "assistant" else "user",
             "parts": [{"text": m.content}]}
            for m in messages if m.role != "system"
        ]
        gen_cfg: dict = {"temperature": temperature, "maxOutputTokens": max_tokens}
        if json:
            gen_cfg["responseMimeType"] = "application/json"
        body: dict = {"contents": contents, "generationConfig": gen_cfg}
        if system:
            body["system_instruction"] = {"parts": [{"text": system}]}
        url = (f"{self._base_url}/models/{self.model}:generateContent"
               f"?key={self._api_key}")
        async with httpx.AsyncClient(timeout=timeout, transport=self._transport) as cli:
            r = await cli.post(url, json=body, headers={"Content-Type": "application/json"})
        r.raise_for_status()
        data = r.json()
        parts = (((data.get("candidates") or [{}])[0]
                  .get("content") or {}).get("parts") or [])
        text = "".join(p.get("text", "") for p in parts)
        um = data.get("usageMetadata") or {}
        return ChatResult(text=text, raw=data,
                          input_tokens=int(um.get("promptTokenCount", 0)),
                          output_tokens=int(um.get("candidatesTokenCount", 0)))
```

- [ ] **Step 4: Run tests to pass** — PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/llm_providers/google.py apps/api/tests/test_llm_adapters.py
git commit -m "feat(llm-providers): Gemini adapter"
```

---

## Task 5: Factory + resolver

**Files:**

- Create: `apps/api/pencheff_api/services/llm_providers/factory.py`
- Create: `apps/api/pencheff_api/services/llm_providers/resolver.py`
- Test: `apps/api/tests/test_llm_resolver.py`

- [ ] **Step 1: Write failing tests** (`tests/test_llm_resolver.py`)

```python
import asyncio
import pytest

from pencheff_api.db.models import LlmProvider, Org
from pencheff_api.services.credentials import encrypt_credentials
from pencheff_api.services.llm_providers.factory import build_client
from pencheff_api.services.llm_providers.resolver import resolve_chat_client
from pencheff_api.services.llm_providers.openai_compat import OpenAICompatClient
from pencheff_api.services.llm_providers.anthropic import AnthropicClient
from pencheff_api.services.llm_providers.google import GeminiClient


def _prov(provider, **kw):
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider=provider,
                    model=kw.get("model", "m"), base_url=kw.get("base_url"))
    p.api_key_encrypted = encrypt_credentials({"api_key": "k"})
    p.azure_deployment = kw.get("azure_deployment")
    p.azure_api_version = kw.get("azure_api_version")
    p.extra = None
    return p


def test_factory_maps_kind_to_adapter():
    assert isinstance(build_client(_prov("openai", base_url="https://h/v1")), OpenAICompatClient)
    assert isinstance(build_client(_prov("openai_compatible", base_url="https://h/v1")), OpenAICompatClient)
    assert isinstance(build_client(_prov("azure_openai", base_url="https://h",
                                         azure_deployment="d", azure_api_version="v")), OpenAICompatClient)
    assert isinstance(build_client(_prov("anthropic")), AnthropicClient)
    assert isinstance(build_client(_prov("google")), GeminiClient)
    assert build_client(_prov("openai")).model == "m"


class _FakeSession:
    def __init__(self, org, provider): self._org, self._p = org, provider
    async def get(self, cls, pk):
        if cls is Org: return self._org
        if cls is LlmProvider: return self._p
        return None


def test_resolver_returns_none_when_no_active_provider():
    org = Org(id="org-1", name="o", plan="pro"); org.active_llm_provider_id = None
    assert asyncio.run(resolve_chat_client("org-1", _FakeSession(org, None))) is None


def test_resolver_builds_client_for_active_provider():
    org = Org(id="org-1", name="o", plan="pro"); org.active_llm_provider_id = "p-1"
    p = _prov("anthropic")
    client = asyncio.run(resolve_chat_client("org-1", _FakeSession(org, p)))
    assert isinstance(client, AnthropicClient)


def test_resolver_none_when_org_missing():
    assert asyncio.run(resolve_chat_client("nope", _FakeSession(None, None))) is None
```

- [ ] **Step 2: Run to confirm failure** — FAIL (modules missing).

- [ ] **Step 3: Implement `factory.py`**

```python
from __future__ import annotations

from ..credentials import decrypt_credentials
from .anthropic import AnthropicClient
from .base import ChatClient
from .google import GeminiClient
from .openai_compat import OpenAICompatClient


def _api_key(p) -> str:
    creds = decrypt_credentials(p.api_key_encrypted) if p.api_key_encrypted else None
    return (creds or {}).get("api_key", "") if creds else ""


def build_client(p) -> ChatClient:
    """Construct the adapter for an LlmProvider row. Raises ValueError on an
    unknown provider kind (should never happen — schema validates the kind)."""
    key = _api_key(p)
    if p.provider in ("openai", "openai_compatible", "azure_openai"):
        return OpenAICompatClient(
            provider=p.provider, model=p.model, base_url=p.base_url, api_key=key,
            azure_deployment=p.azure_deployment, azure_api_version=p.azure_api_version,
            extra=p.extra)
    if p.provider == "anthropic":
        return AnthropicClient(model=p.model, api_key=key, base_url=p.base_url, extra=p.extra)
    if p.provider == "google":
        return GeminiClient(model=p.model, api_key=key, base_url=p.base_url, extra=p.extra)
    raise ValueError(f"unknown provider kind {p.provider!r}")
```

- [ ] **Step 4: Implement `resolver.py`**

```python
from __future__ import annotations

from ...db.models import LlmProvider, Org
from .base import ChatClient
from .factory import build_client


async def resolve_chat_client(org_id: str | None, session) -> ChatClient | None:
    """Return the org's active provider as a ChatClient, or None to signal
    'use Pencheff defaults'. Never raises for the common cases (missing org,
    no active provider, deleted provider)."""
    if not org_id:
        return None
    org = await session.get(Org, org_id)
    if org is None or not org.active_llm_provider_id:
        return None
    p = await session.get(LlmProvider, org.active_llm_provider_id)
    if p is None:
        return None
    return build_client(p)
```

> **Note on import depth:** `resolver.py` is at `services/llm_providers/resolver.py`, so models are `from ...db.models import ...` (three dots). `factory.py` reaches credentials via `from ..credentials import ...` (two dots, sibling package). Verify against the actual tree before committing.

- [ ] **Step 5: Run tests to pass** — PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/services/llm_providers/factory.py apps/api/pencheff_api/services/llm_providers/resolver.py apps/api/tests/test_llm_resolver.py
git commit -m "feat(llm-providers): adapter factory + org resolver"
```

---

## Task 6: `/llm-providers/{id}/test` endpoint

**Files:**

- Modify: `apps/api/pencheff_api/routers/llm_providers.py`
- Test: `apps/api/tests/test_llm_providers_router.py` (extend)

- [ ] **Step 1: Write a failing test** (append to the Plan A router test file)

```python
def test_test_endpoint_returns_ok_on_success(monkeypatch):
    import asyncio
    from pencheff_api.routers import llm_providers as mod
    from pencheff_api.db.models import LlmProvider, Org

    org = Org(id="org-1", name="o", plan="pro"); org.active_llm_provider_id = None
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai",
                    model="gpt-5-mini", base_url="https://h/v1")
    from pencheff_api.services.credentials import encrypt_credentials
    p.api_key_encrypted = encrypt_credentials({"api_key": "k"})

    class _S:
        async def get(self, cls, pk):
            return org if cls is Org else (p if pk == "p-1" else None)

    class _FakeClient:
        provider = "openai"; model = "gpt-5-mini"
        async def chat(self, *a, **k):
            from pencheff_api.services.llm_providers.base import ChatResult
            return ChatResult(text="ok")

    monkeypatch.setattr(mod, "build_client", lambda _p: _FakeClient())
    out = asyncio.run(mod.test_provider(
        "p-1", ctx=(type("U", (), {"id": "u"})(), type("M", (), {"role": "admin"})()),
        session=_S(), workspace=type("W", (), {"org_id": "org-1"})()))
    assert out["ok"] is True and out["model"] == "gpt-5-mini"


def test_test_endpoint_returns_error_on_failure(monkeypatch):
    import asyncio
    from pencheff_api.routers import llm_providers as mod
    from pencheff_api.db.models import LlmProvider, Org
    org = Org(id="org-1", name="o", plan="pro")
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai",
                    model="m", base_url="https://h/v1")
    class _S:
        async def get(self, cls, pk): return org if cls is Org else p
    class _Boom:
        provider="openai"; model="m"
        async def chat(self, *a, **k): raise RuntimeError("bad key")
    monkeypatch.setattr(mod, "build_client", lambda _p: _Boom())
    out = asyncio.run(mod.test_provider(
        "p-1", ctx=(type("U", (), {"id": "u"})(), type("M", (), {"role": "admin"})()),
        session=_S(), workspace=type("W", (), {"org_id": "org-1"})()))
    assert out["ok"] is False and "bad key" in out["error"]
```

- [ ] **Step 2: Run to confirm failure** — FAIL (`test_provider` missing / `build_client` not imported in router).

- [ ] **Step 3: Implement — add to `routers/llm_providers.py`**

Add near the top imports:

```python
import time
from .. .services.llm_providers.factory import build_client  # fix dots: from ..services.llm_providers.factory import build_client
from ..services.llm_providers.base import ChatMessage
```

(Use `from ..services.llm_providers.factory import build_client` — the line above shows the intent; write it correctly.)

Add the endpoint:

```python
@router.post("/{provider_id}/test")
async def test_provider(
    provider_id: str,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner", "admin")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> dict:
    p = await _load(session, provider_id, workspace.org_id)
    client = build_client(p)
    start = time.monotonic()
    try:
        res = await client.chat([ChatMessage("user", "Reply with the word ok.")],
                                max_tokens=8, timeout=20.0)
    except Exception as exc:  # noqa: BLE001 — surfaced to the UI, not raised
        return {"ok": False, "latency_ms": int((time.monotonic() - start) * 1000),
                "error": str(exc)[:300], "model": p.model}
    return {"ok": True, "latency_ms": int((time.monotonic() - start) * 1000),
            "error": None, "model": p.model, "sample": (res.text or "")[:80]}
```

- [ ] **Step 4: Run tests to pass** — `pytest tests/test_llm_providers_router.py -v` → PASS.

- [ ] **Step 5: Add the web "Test" action**

In `apps/web/lib/llm-providers.ts` add:

```ts
export const testProvider = (id: string) =>
  api<{
    ok: boolean;
    latency_ms: number;
    error: string | null;
    model: string;
    sample?: string;
  }>(`/llm-providers/${id}/test`, { method: "POST" });
```

Wire a **Test** button per row in the Settings UI that calls `testProvider(id)` and shows
`ok ✓ (Nms)` or the error inline.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/routers/llm_providers.py apps/api/tests/test_llm_providers_router.py apps/web/lib/llm-providers.ts
git commit -m "feat(llm-providers): /test endpoint (live cred check) + web Test action"
```

---

## Task 7: Wire `services/llm.py` (FP triage + grading + advisory)

`llm.py` is the **sync** singleton; `advisory_ai.py` rides on it via `get_client()`. The
guard goes in `LLMClient._chat`, using `run_sync`. `org_id` must be threaded to the call
site; where triage/grade is invoked per-scan, the scan carries `org_id`.

**Files:**

- Modify: `apps/api/pencheff_api/services/llm.py` (`__init__` ~76, `_chat` ~113)
- Test: `apps/api/tests/test_llm_provider_wiring.py`

- [ ] **Step 1: Write the failing test** (`tests/test_llm_provider_wiring.py`)

```python
from pencheff_api.services.llm_providers.base import ChatResult, ChatMessage
from pencheff_api.services import llm as llm_mod


def test_llm_chat_routes_through_org_client_when_set(monkeypatch):
    calls = {}
    class _Org:
        provider="anthropic"; model="claude-opus-4-8"
        async def chat(self, messages, **kw):
            calls["used"] = True
            return ChatResult(text="ORG-ANSWER")
    c = llm_mod.LLMClient()
    c.set_org_client(_Org())          # new injection hook
    out = c._chat("sys", "user")
    assert out == "ORG-ANSWER"
    assert calls["used"] is True


def test_llm_chat_failclosed_when_org_client_raises(monkeypatch):
    class _Boom:
        provider="openai"; model="m"
        async def chat(self, *a, **k): raise RuntimeError("down")
    c = llm_mod.LLMClient()
    c.set_org_client(_Boom())
    # Fail-closed: returns None (AI unavailable), does NOT fall back to env client.
    assert c._chat("s", "u") is None
```

- [ ] **Step 2: Run to confirm failure** — FAIL (`set_org_client` missing).

- [ ] **Step 3: Implement the guard in `llm.py`**

In `LLMClient.__init__`, after the existing attributes, add:

```python
        self._org_client = None  # set per-request via set_org_client(); BYO override
```

Add the setter method:

```python
    def set_org_client(self, client) -> None:
        """Inject the org's active ChatClient (from resolve_chat_client). When
        set, _chat routes through it (fail-closed) instead of the env client."""
        self._org_client = client
```

At the very top of `_chat`, before the `if not self._enabled` check, add:

```python
        if self._org_client is not None:
            from .llm_providers.base import ChatMessage, run_sync
            try:
                res = run_sync(self._org_client.chat(
                    [ChatMessage("system", system), ChatMessage("user", user)],
                    temperature=0.1, max_tokens=2048))
                return res.text or None
            except Exception as exc:  # noqa: BLE001 — fail-closed, no env fallback
                _log.warning("org LLM provider failed (fail-closed): %s", exc)
                return None
```

- [ ] **Step 4: Thread `org_id` at the call sites**

Find the callers that construct/use the grading/triage `LLMClient` / `get_client()` per
scan (grep `get_client(` and `LLMClient(` under `services/` and `tasks/`). At each
per-scan call site that has a DB session + the scan's `org_id`, resolve and inject:

```python
from .llm_providers.resolver import resolve_chat_client
org_client = await resolve_chat_client(org_id, session)   # async sites
# or: org_client = run_sync(resolve_chat_client(org_id, sync_session_wrapper))  # if sync
if org_client is not None:
    client.set_org_client(org_client)
    # BYO active → skip Pencheff's free-tier AI quota/gate for this call
```

> **Implementer note:** This is the part with the most surface area. Enumerate every
> `get_client()`/`LLMClient()` use that processes a specific org's scan/findings, and inject
> there. For uses with no org context (e.g. a global cache warmer), leave them on the env
> default. Where `advisory_ai.explain_advisory(..., client=...)` is called per scan, pass a
> client that has had `set_org_client` applied. Document any call site intentionally left on
> the default.

- [ ] **Step 5: Run tests to pass** — `pytest tests/test_llm_provider_wiring.py -v` → PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/services/llm.py apps/api/tests/test_llm_provider_wiring.py
git commit -m "feat(llm-providers): route FP-triage/grading/advisory through org provider (fail-closed)"
```

---

## Task 8: Wire `fix_llm.py` (fix proposals) + quota bypass

**Files:**

- Modify: `apps/api/pencheff_api/services/fix_llm.py` (`__init__` ~40, `_chat` ~61)
- Modify: the fix-proposal caller that enforces quota (grep `fix_quota`)
- Test: `apps/api/tests/test_llm_provider_wiring.py` (extend)

- [ ] **Step 1: Failing test** (append)

```python
import asyncio
from pencheff_api.services import fix_llm as fix_mod


def test_fix_llm_routes_through_org_client(monkeypatch):
    class _Org:
        provider="openai"; model="gpt-5"
        async def chat(self, messages, **kw):
            return ChatResult(text="PATCH", input_tokens=1, output_tokens=1)
    c = fix_mod.FixLLMClient()
    c.set_org_client(_Org())
    res = asyncio.run(c._chat("sys", "user"))
    assert res.text == "PATCH"


def test_fix_llm_failclosed(monkeypatch):
    class _Boom:
        provider="openai"; model="m"
        async def chat(self, *a, **k): raise RuntimeError("x")
    c = fix_mod.FixLLMClient()
    c.set_org_client(_Boom())
    res = asyncio.run(c._chat("s", "u"))
    assert res.text is None     # FixLlmResult(None, 0, 0)
```

- [ ] **Step 2: Run to confirm failure** — FAIL.

- [ ] **Step 3: Implement guard in `fix_llm.py`**

In `__init__` add `self._org_client = None`. Add `set_org_client` (same as Task 7). At the
top of `async def _chat`, before `if not self.enabled`:

```python
        if self._org_client is not None:
            from .llm_providers.base import ChatMessage
            try:
                res = await self._org_client.chat(
                    [ChatMessage("system", system), ChatMessage("user", user)],
                    max_tokens=max_tokens, json=bool(response_format), temperature=temperature)
                return FixLlmResult(res.text or None, res.input_tokens, res.output_tokens)
            except Exception as exc:  # noqa: BLE001 — fail-closed
                log.warning("org LLM provider failed in fix-LLM (fail-closed): %s", exc)
                return FixLlmResult(None, 0, 0)
```

(`FixLlmResult` is the existing return type; confirm its field order — `(text, input, output)` per the anchor.)

- [ ] **Step 4: Inject + bypass quota at the proposer**

In the fix proposer (where `FixLLMClient` is built per finding/scan and `fix_quota` is
checked), resolve the org client and, when present, set it and skip the quota check:

```python
org_client = await resolve_chat_client(org_id, session)
client = FixLLMClient(model=_fix_model_for_plan(org.plan))
if org_client is not None:
    client.set_org_client(org_client)
    # BYO key active → do NOT consume/enforce fix_quota
else:
    ... existing fix_quota.check/consume ...
```

> **Implementer note:** Find the exact quota call (`fix_quota.` something) and wrap it so it's
> only invoked on the env-default path. The plan-routed model (`_fix_model_for_plan`) is
> irrelevant on the BYO path (the org's chosen model wins), so it's fine to still pass it.

- [ ] **Step 5: Run tests to pass** — PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/services/fix_llm.py apps/api/tests/test_llm_provider_wiring.py
git commit -m "feat(llm-providers): route fix proposals through org provider + bypass quota when BYO active"
```

---

## Task 9: Wire `triage_llm.py` (AI Triage 2.0)

**Files:**

- Modify: `apps/api/pencheff_api/services/triage_llm.py` (`__init__` ~93, request method ~115)
- Test: `apps/api/tests/test_llm_provider_wiring.py` (extend)

- [ ] **Step 1: Failing test** (append) — mirror Task 8's two tests against `triage_llm.TriageLLMClient`, asserting the org client is used (JSON mode) and a raised exception yields the existing "no triage" return (`None`).

```python
from pencheff_api.services import triage_llm as triage_mod

def test_triage_routes_through_org_client():
    class _Org:
        provider="google"; model="gemini-2.5-pro"
        async def chat(self, messages, **kw):
            assert kw.get("json") is True
            return ChatResult(text='{"verdict":"exploitable"}')
    c = triage_mod.TriageLLMClient()
    c.set_org_client(_Org())
    # call the public triage method with minimal args; assert it parses the JSON.
    # (Use the real method name from triage_llm.py; it returns TriageResult|None.)
```

> **Implementer note:** Open `triage_llm.py`, find the public async method (the one that
> POSTs with `response_format={"type":"json_object"}`) and its return type. Add the
> `set_org_client` hook + the org-client branch at the top of that method, calling
> `self._org_client.chat(messages, json=True, max_tokens=...)`, then feed `res.text` into the
> SAME JSON parser the env path uses. Fail-closed → return the same `None` the disabled path
> returns. Complete the test against that real method signature.

- [ ] **Step 2-4: Run-fail → implement → run-pass** (same shape as Tasks 7-8).

- [ ] **Step 5: Inject at the triage call site** (per-finding, has `org_id` via the finding/scan); skip the triage quota/gate (`ai_free_tier_enabled`) when an org client is present.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/services/triage_llm.py apps/api/tests/test_llm_provider_wiring.py
git commit -m "feat(llm-providers): route AI-Triage-2.0 through org provider (JSON mode, fail-closed)"
```

---

## Task 10: Wire the agentic fixer (`agentic_fixer/llm_client.py`)

The agentic fixer + scan agent are **tool-calling** loops (OpenAI `tools`/`tool_choice`).
The native Anthropic/Gemini adapters in Tasks 3-4 implement plain chat, NOT tool-calling.
So for these two services the BYO override is **only honored for OpenAI-compatible providers**
(openai / openai_compatible / azure_openai), which speak the same tool-calling shape the loop
already builds. For anthropic/google active providers, the agent/fixer stay on Pencheff's
default (tool-calling-capable) endpoint. This is a deliberate, documented limitation.

**Files:**

- Modify: `apps/api/pencheff_api/services/agentic_fixer/llm_client.py` (`__init__` ~119, `create_message` ~140)
- Test: `apps/api/tests/test_llm_provider_wiring.py` (extend)

- [ ] **Step 1: Failing test** (append)

```python
import asyncio
from pencheff_api.services.agentic_fixer import llm_client as af_mod

def test_agentic_fixer_overrides_only_for_openai_compatible():
    c = af_mod.LLMClient()
    # an org provider row for an openai-compatible kind enables override
    class _Prov: provider="openai"; model="gpt-5"; base_url="https://h/v1"
    assert c.maybe_override_from_provider(_Prov()) is True
    # anthropic/google are NOT honored here (no tool-calling adapter)
    class _Ant: provider="anthropic"; model="claude-opus-4-8"; base_url=None
    assert c.maybe_override_from_provider(_Ant()) is False
```

- [ ] **Step 2: Run to confirm failure** — FAIL.

- [ ] **Step 3: Implement**

Add to `agentic_fixer/llm_client.py` `LLMClient`:

```python
    def maybe_override_from_provider(self, p) -> bool:
        """If the org's active provider is OpenAI-tool-calling-compatible,
        point this client at it (base_url/api_key/model) and return True.
        Anthropic/Gemini are not honored here (the loop needs OpenAI-shaped
        tool calling) — return False so the caller keeps Pencheff defaults."""
        if p is None or p.provider not in ("openai", "openai_compatible", "azure_openai"):
            return False
        from ..credentials import decrypt_credentials
        key = (decrypt_credentials(p.api_key_encrypted) or {}).get("api_key", "") if p.api_key_encrypted else ""
        if not p.base_url and p.provider != "openai":
            return False
        self._base_url = (p.base_url or "https://api.openai.com/v1").rstrip("/")
        self._api_key = key
        self._model = p.model
        self._enabled = bool(key)
        return True
```

> Azure deployment-URL shaping for the agentic loop is out of scope here (the loop builds a
> plain `/chat/completions` URL); for `azure_openai` honor only when `base_url` already points
> at a deployment-style URL — otherwise treat as non-override. Keep it simple: only flip when
> `_enabled` ends true.

- [ ] **Step 4: Inject at the agent-loop construction** (`agentic_fixer/agent_loop.py` ~164,
      where `get_client()` + settings are read; it has `org_id` via the repo/findings). Load the
      org's active provider row and call `client.maybe_override_from_provider(prov)`; when it
      returns True, skip the env-key disabled-check error. Fail-closed already holds: if the org
      endpoint errors mid-loop, the existing `LLMAPIError` handling aborts the run (it does not
      silently switch keys).

- [ ] **Step 5: Run tests to pass** — PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/services/agentic_fixer/llm_client.py apps/api/tests/test_llm_provider_wiring.py
git commit -m "feat(llm-providers): agentic fixer honors org provider (openai-compatible only, documented)"
```

---

## Task 11: Wire the scan agent (`agent_runner` / `scan_runner`)

Same tool-calling constraint as Task 10: honor the org override only for OpenAI-compatible
kinds; anthropic/google active providers leave the scan agent on Pencheff's default.

**Files:**

- Modify: the scan-agent client construction in `services/scan_runner.py` (where `AGENT_LLM_*`
  is read and the agent client is built) — grep `agent_llm_` in `scan_runner.py`.
- Test: covered by the agentic-fixer override test pattern; add one analogous test if the
  scan agent has its own client class, otherwise the shared override helper is reused.

- [ ] **Step 1: Locate the scan-agent client build**

Run: `cd apps/api && grep -rn "agent_llm_\|AGENT_LLM" pencheff_api/services/scan_runner.py | head`
Identify where `agent_llm_base_url`/`agent_llm_api_key`/`agent_llm_model` become the agent's
HTTP client config, and confirm the scan's `org_id` is in scope there.

- [ ] **Step 2: Apply the same OpenAI-compatible-only override**

Before building the agent client, resolve the org's active provider row; if it's an
openai-compatible kind with a usable key, substitute `base_url`/`api_key`/`model` (decrypt via
`decrypt_credentials`). For anthropic/google, log once ("org provider X not tool-calling
compatible; scan agent uses Pencheff default") and proceed on defaults. Fail-closed: if the
substituted endpoint errors, the existing scan-agent error handling already falls back to the
**deterministic** scan (not to Pencheff's agent key) — which satisfies fail-closed (no silent
key swap). Confirm this in `scan_runner` and add a comment.

- [ ] **Step 3: Add/extend a test** asserting the override helper flips only for
      openai-compatible kinds (reuse `maybe_override_from_provider` if you factor it into a shared
      util, or replicate the boolean check). Run it green.

- [ ] **Step 4: Commit**

```bash
git add apps/api/pencheff_api/services/scan_runner.py apps/api/tests/test_llm_provider_wiring.py
git commit -m "feat(llm-providers): scan agent honors org provider (openai-compatible only)"
```

---

## Task 12: Full suite + integration sanity

- [ ] **Step 1: Run the whole AI/provider test set**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_llm_adapters.py tests/test_llm_resolver.py tests/test_llm_provider_wiring.py tests/test_llm_providers_router.py tests/test_llm_providers_schema.py -v`
Expected: all PASS.

- [ ] **Step 2: Import-boot the app**

Run: `cd apps/api && .venv/bin/python -c "from pencheff_api.main import app; print('ok', any(r.path.startswith('/llm-providers') for r in app.routes))"`
Expected: `ok True`.

- [ ] **Step 3: Commit any fixups, then hand off for deploy**

The deploy is the existing flow (push the branch the VM tracks, `pencheff-deploy --pull`, or a
backend-only rebuild of `api`+`worker`) and an Alembic upgrade for migration `0056`. Do NOT
deploy from this plan automatically — surface the migration + rebuild steps to the user.

---

## Self-Review (completed by plan author)

**Spec coverage (data plane):** §3 adapters (openai_compat/anthropic/gemini, JSON-mode
normalization) → Tasks 2-4 ✓. §3 resolver → Task 5 ✓. §2 `/test` → Task 6 ✓. §4 wiring all six
services (llm.py+advisory, fix_llm, triage_llm, agentic fixer, scan agent) → Tasks 7-11 ✓. §4
fail-closed → asserted in each wiring test (org-client raise → existing no-AI return, never env
fallback) ✓. §5/§4 quota bypass when BYO active → Tasks 8 (fix) + 9 (triage) ✓. Sync/async
split → Task 1 `run_sync` bridge, used by the sync `llm.py` only ✓.

**Placeholder scan:** No TBD/TODO. Tasks 9-11 deliberately defer some specifics to
"implementer notes" because the exact method names/quota calls/scan-agent client must be read
from the live files first — each note gives the precise grep + the exact transformation to
apply, not a vague "handle it." Task 6's import line has a typo-with-correction called out
explicitly.

**Type consistency:** `ChatMessage`/`ChatResult` (Task 1) used identically by every adapter
(Tasks 2-4), the factory (Task 5), `/test` (Task 6), and all wiring (Tasks 7-11).
`set_org_client(client)` added with the same signature to `LLMClient` (Task 7) and
`FixLLMClient` (Task 8) and `TriageLLMClient` (Task 9); the agentic fixer/scan agent use
`maybe_override_from_provider(p)` instead (Tasks 10-11) because they mutate base_url/model
rather than wrap a chat client (tool-calling shape). `resolve_chat_client(org_id, session)`
signature identical across all async call sites. `build_client(provider_row)` returns a
`ChatClient`; `_api_key`/`decrypt_credentials({"api_key":...})` round-trips match Plan A's
encryption (`encrypt_credentials({"api_key": ...})`).

**Known limitation (documented in-plan):** the autonomous scan agent + agentic fixer honor the
BYO override only for OpenAI-tool-calling-compatible providers; anthropic/google active
providers leave those two on Pencheff defaults (the native adapters are plain-chat, not
tool-calling). The spec said "all AI features" — this is the one honest caveat where "all"
means "all, with the two tool-calling agents requiring an OpenAI-compatible BYO endpoint." Flag
to the user at execution time.
