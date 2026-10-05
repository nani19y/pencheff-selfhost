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
