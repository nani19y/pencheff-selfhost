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
