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
