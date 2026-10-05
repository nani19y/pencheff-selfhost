# apps/api/pencheff_api/services/llm_providers/bedrock.py
from __future__ import annotations

import json
from urllib.parse import quote

import httpx

from .base import ChatResult
from .cloud_auth import sigv4_headers


class BedrockClient:
    """AWS Bedrock Converse API, SigV4-signed (no boto3)."""

    def __init__(self, *, model: str, region: str, access_key: str, secret_key: str,
                 session_token: str | None = None, extra: dict | None = None,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.provider = "bedrock"
        self.model = model
        self._region = region
        self._access_key = access_key
        self._secret_key = secret_key
        self._session_token = session_token
        self._extra = extra or {}
        self._transport = transport

    async def chat(self, messages, *, temperature: float = 0.0, max_tokens: int = 1024,
                   json: bool = False, timeout: float = 60.0) -> ChatResult:
        system = [{"text": m.content} for m in messages if m.role == "system"]
        msgs = [{"role": ("assistant" if m.role == "assistant" else "user"),
                 "content": [{"text": m.content}]}
                for m in messages if m.role != "system"]
        body_obj: dict = {"messages": msgs,
                          "inferenceConfig": {"maxTokens": max_tokens, "temperature": temperature}}
        if system:
            body_obj["system"] = system
        body = _dumps(body_obj)
        # Percent-encode the model id once; sign + send the same path.
        path = f"/model/{quote(self.model, safe='')}/converse"
        url = f"https://bedrock-runtime.{self._region}.amazonaws.com{path}"
        headers = sigv4_headers(method="POST", url=url, region=self._region, service="bedrock",
                                body=body, access_key=self._access_key, secret_key=self._secret_key,
                                session_token=self._session_token)
        headers["Content-Type"] = "application/json"
        async with httpx.AsyncClient(timeout=timeout, transport=self._transport) as cli:
            r = await cli.post(url, content=body, headers=headers)
        r.raise_for_status()
        data = r.json()
        content = (((data.get("output") or {}).get("message") or {}).get("content") or [])
        text = "".join(part.get("text", "") for part in content)
        usage = data.get("usage") or {}
        return ChatResult(text=text, raw=data,
                          input_tokens=int(usage.get("inputTokens", 0)),
                          output_tokens=int(usage.get("outputTokens", 0)))


def _dumps(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")
