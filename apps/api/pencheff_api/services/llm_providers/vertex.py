# apps/api/pencheff_api/services/llm_providers/vertex.py
from __future__ import annotations

import httpx

from .base import ChatResult
from .cloud_auth import vertex_access_token


class VertexClient:
    """Google Vertex AI generateContent (Gemini), ADC-token auth. Same request /
    response shape as the public GeminiClient, different host + bearer auth."""

    def __init__(self, *, model: str, project: str, location: str, service_account_json,
                 extra: dict | None = None, transport: httpx.BaseTransport | None = None) -> None:
        self.provider = "vertex"
        self.model = model
        self._project = project
        self._location = location
        self._sa = service_account_json
        self._extra = extra or {}
        self._transport = transport

    async def chat(self, messages, *, temperature: float = 0.0, max_tokens: int = 1024,
                   json: bool = False, timeout: float = 60.0) -> ChatResult:
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        contents = [{"role": "model" if m.role == "assistant" else "user",
                     "parts": [{"text": m.content}]}
                    for m in messages if m.role != "system"]
        gen_cfg: dict = {"temperature": temperature, "maxOutputTokens": max_tokens}
        if json:
            gen_cfg["responseMimeType"] = "application/json"
        body: dict = {"contents": contents, "generationConfig": gen_cfg}
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        token = vertex_access_token(self._sa)
        # The "global" location uses the prefix-less host; regions use "{region}-aiplatform".
        host = ("aiplatform.googleapis.com" if self._location == "global"
                else f"{self._location}-aiplatform.googleapis.com")
        url = (f"https://{host}/v1/projects/"
               f"{self._project}/locations/{self._location}/publishers/google/models/"
               f"{self.model}:generateContent")
        async with httpx.AsyncClient(timeout=timeout, transport=self._transport) as cli:
            r = await cli.post(url, json=body, headers={"Authorization": f"Bearer {token}",
                                                        "Content-Type": "application/json"})
        r.raise_for_status()
        data = r.json()
        parts = (((data.get("candidates") or [{}])[0].get("content") or {}).get("parts") or [])
        text = "".join(p.get("text", "") for p in parts)
        um = data.get("usageMetadata") or {}
        return ChatResult(text=text, raw=data,
                          input_tokens=int(um.get("promptTokenCount", 0)),
                          output_tokens=int(um.get("candidatesTokenCount", 0)))
