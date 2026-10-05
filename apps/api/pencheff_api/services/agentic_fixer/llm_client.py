"""OpenAI-compatible chat-completions client for the agentic fixer.

Defaults to Sarvam AI's ``sarvam-105b`` (https://api.sarvam.ai/v1) —
the same provider the scan-agent fallback already targets. Any
OpenAI-compatible endpoint that implements ``/chat/completions`` with
the ``tools`` + ``tool_choice`` parameters works; override via
``AGENTIC_FIX_BASE_URL`` and ``AGENTIC_FIX_MODEL``.

Why OpenAI-compatible and not Anthropic Messages API: Sarvam (the
configured backend) exposes the OpenAI shape. The scan-agent loop in
``services/agent_swarm/agent_loop.py`` already exercises this format
against the same model, so we're on a well-trodden code path.

Tool-call format (OpenAI):
  request.tools[i] = {
    "type": "function",
    "function": {"name": ..., "description": ..., "parameters": {JSON schema}}
  }
  response.choices[0].message.tool_calls[j] = {
    "id": "...",
    "type": "function",
    "function": {"name": "...", "arguments": "JSON-encoded string"}
  }

Compare with Anthropic Messages where ``input`` arrives as a dict
already-decoded. We decode the OpenAI ``arguments`` string ourselves.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from ...config import get_settings
from .cost import Usage

log = logging.getLogger("pencheff.agentic_fixer.llm")


class LLMAPIError(Exception):
    """Raised on non-2xx responses from the chat-completions endpoint."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"agentic fix llm {status}: {body[:500]}")
        self.status = status
        self.body = body


class LLMConfigError(Exception):
    """Raised when the API key is missing or the feature is disabled."""


@dataclass
class ToolUse:
    """One decoded tool_call from a chat-completions response.

    ``call_id`` is the OpenAI tool_call id we have to echo back in
    the subsequent ``tool``-role message so the model can pair its
    own request with the result.
    """

    call_id: str
    name: str
    input: dict[str, Any]


@dataclass
class TextBlock:
    """Assistant text content from a chat-completions response."""

    text: str


@dataclass
class AgentMessage:
    """Decoded shape of one chat-completions response.

    Both Anthropic-shaped and OpenAI-shaped responses normalise into
    this same struct so the agent loop is provider-agnostic. ``raw``
    keeps the original body for debugging / span attributes.

    ``reasoning_content`` is the model's private chain-of-thought
    that some providers expose (DeepSeek's thinking mode). It MUST
    be echoed back on the next request — DeepSeek's API returns
    400 invalid_request_error with message
    "The reasoning_content in the thinking mode must be passed
    back to the API" if it's dropped. Providers that don't use
    thinking mode (Sarvam, OpenAI proper) leave this empty and
    the agent loop simply omits the field from the next request.
    """

    content: list[ToolUse | TextBlock]
    stop_reason: str
    usage: Usage
    raw: dict[str, Any] = field(default_factory=dict)
    reasoning_content: str | None = None

    @property
    def tool_uses(self) -> list[ToolUse]:
        return [b for b in self.content if isinstance(b, ToolUse)]

    @property
    def text(self) -> str:
        return "".join(b.text for b in self.content if isinstance(b, TextBlock))


class LLMClient:
    """Pencheff-keyed OpenAI-compatible chat-completions client.

    Stateless beyond config — safe to reuse across runs in the same
    worker process. Construction validates the settings; if the
    feature is disabled or the key is empty, ``enabled`` returns False
    and every call raises ``LLMConfigError``.
    """

    def __init__(self) -> None:
        s = get_settings()
        self._timeout = s.agentic_fix_request_timeout
        self._max_tokens = s.agentic_fix_max_tokens_per_call
        self.reset_to_defaults()

    def reset_to_defaults(self) -> None:
        """Recompute _enabled/_api_key/_base_url/_model from current settings.

        Called from __init__ and from maybe_override_from_provider when no
        override is applied, so a singleton that was previously pointed at an
        org's BYO key is restored to Pencheff defaults for the next run.
        """
        s = get_settings()
        # Effective values fall back to AGENT_FALLBACK_LLM_* when
        # AGENTIC_FIX_* isn't set — most deployments already have the
        # former configured for the scan-agent fallback, and the
        # agentic fixer rides on the same Sarvam key.
        self._enabled = bool(s.agentic_fix_enabled and s.agentic_fix_effective_api_key)
        self._api_key = s.agentic_fix_effective_api_key
        self._base_url = s.agentic_fix_effective_base_url.rstrip("/")
        self._model = s.agentic_fix_effective_model

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def model(self) -> str:
        return self._model

    def maybe_override_from_provider(self, p) -> bool:
        """If the org's active provider is OpenAI-tool-calling-compatible,
        point this client at it (base_url/api_key/model) and return True.
        Anthropic/Gemini are NOT honored here (the loop needs OpenAI-shaped
        tool calling) — return False so the caller keeps Pencheff defaults.

        When returning False (p is None, incompatible provider, or no usable
        key), reset_to_defaults() is called first so the singleton is never
        left pointing at a previous org's BYO key.
        """
        if p is None or p.provider not in ("openai", "openai_compatible", "azure_openai"):
            self.reset_to_defaults()
            return False
        from ..credentials import decrypt_credentials
        key = (decrypt_credentials(p.api_key_encrypted) or {}).get("api_key", "") if p.api_key_encrypted else ""
        if not p.base_url and p.provider != "openai":
            self.reset_to_defaults()
            return False
        self._base_url = (p.base_url or "https://api.openai.com/v1").rstrip("/")
        self._api_key = key
        self._model = p.model
        self._enabled = bool(key)
        return True

    async def create_message(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        model: str | None = None,
        max_tokens: int | None = None,
    ) -> AgentMessage:
        """One ``POST /chat/completions`` round-trip.

        ``messages`` follow the OpenAI shape: a list of
        ``{role, content}`` (with optional ``tool_calls`` on assistant
        messages and ``tool_call_id`` on tool messages). The system
        prompt is prepended as the first message with ``role=system``.

        ``tools`` use the OpenAI function-calling shape (see module
        docstring). The caller passes the catalog already-formatted —
        the ``tools`` module owns that translation.

        We don't retry inside this function so the calling agent loop
        can be cancelled cleanly between attempts.
        """
        if not self._enabled:
            raise LLMConfigError(
                "agentic fixer disabled: set AGENTIC_FIX_API_KEY"
            )

        prepended = [{"role": "system", "content": system}] + messages
        payload: dict[str, Any] = {
            "model": model or self._model,
            "messages": prepended,
            "max_tokens": max_tokens or self._max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
        except httpx.HTTPError as e:
            raise LLMAPIError(0, f"transport error: {e}") from e

        if resp.status_code != 200:
            raise LLMAPIError(resp.status_code, resp.text)

        return self._decode(resp.json())

    @staticmethod
    def _decode(body: dict[str, Any]) -> AgentMessage:
        """Decode an OpenAI-shaped chat-completions response.

        Tolerates the small differences between providers:
        * ``finish_reason`` may be ``stop`` (text done) or ``tool_calls``
          (model wants to call a tool); we keep the raw value.
        * ``message.content`` may be null when only tool_calls were
          returned — treat as empty string.
        * ``tool_calls[].function.arguments`` is a JSON-encoded
          string; we decode it. Bad JSON → empty dict + log; the
          downstream tool will surface its own validation error.
        """
        choices = body.get("choices") or []
        if not choices:
            return AgentMessage(content=[], stop_reason="empty", usage=Usage(0, 0), raw=body)

        choice = choices[0] or {}
        message = choice.get("message") or {}
        finish_reason = str(choice.get("finish_reason") or "")

        content_blocks: list[ToolUse | TextBlock] = []

        text = message.get("content")
        if text:
            content_blocks.append(TextBlock(text=str(text)))

        # DeepSeek thinking mode (and some Qwen variants) emit a
        # ``reasoning_content`` field that must round-trip back to
        # the API on the next request. We just capture the string;
        # the agent loop owns echoing it.
        reasoning_raw = message.get("reasoning_content")
        reasoning_content = (
            str(reasoning_raw)
            if isinstance(reasoning_raw, str) and reasoning_raw
            else None
        )

        for tc in (message.get("tool_calls") or []):
            fn = (tc.get("function") or {}) if isinstance(tc, dict) else {}
            name = str(fn.get("name") or "")
            args_str = fn.get("arguments") or "{}"
            try:
                args_dict = json.loads(args_str) if isinstance(args_str, str) else dict(args_str)
            except (TypeError, ValueError) as e:
                log.warning(
                    "agentic fix: tool_call '%s' had unparseable JSON arguments: %s",
                    name, e,
                )
                args_dict = {}
            content_blocks.append(ToolUse(
                call_id=str(tc.get("id") or ""),
                name=name,
                input=args_dict if isinstance(args_dict, dict) else {},
            ))

        usage_blob = body.get("usage") or {}
        usage = Usage(
            input_tokens=int(usage_blob.get("prompt_tokens", 0)),
            output_tokens=int(usage_blob.get("completion_tokens", 0)),
            cache_creation_input_tokens=0,
            cache_read_input_tokens=int(usage_blob.get("prompt_tokens_cached", 0) or 0),
        )

        return AgentMessage(
            content=content_blocks,
            stop_reason=finish_reason,
            usage=usage,
            raw=body,
            reasoning_content=reasoning_content,
        )


_client: LLMClient | None = None


def get_client() -> LLMClient:
    """Process-singleton accessor. Lazy so importing this module
    doesn't fail when the agentic fixer is disabled in a deployment.
    """
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
