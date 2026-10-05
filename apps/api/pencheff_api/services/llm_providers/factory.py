from __future__ import annotations

from ..credentials import decrypt_credentials
from .anthropic import AnthropicClient
from .base import ChatClient
from .bedrock import BedrockClient
from .google import GeminiClient
from .openai_compat import OpenAICompatClient
from .vertex import VertexClient


def _creds(p) -> dict:
    return (decrypt_credentials(p.api_key_encrypted) or {}) if p.api_key_encrypted else {}


def build_client(p) -> ChatClient:
    """Construct the adapter for an LlmProvider row. Raises ValueError on an
    unknown provider kind (should never happen — schema validates the kind)."""
    creds = _creds(p)
    extra = p.extra or {}
    if p.provider in ("openai", "openai_compatible", "azure_openai"):
        return OpenAICompatClient(provider=p.provider, model=p.model, base_url=p.base_url,
                                  api_key=creds.get("api_key", ""),
                                  azure_deployment=p.azure_deployment,
                                  azure_api_version=p.azure_api_version, extra=p.extra)
    if p.provider == "anthropic":
        return AnthropicClient(model=p.model, api_key=creds.get("api_key", ""),
                               base_url=p.base_url, extra=p.extra)
    if p.provider == "google":
        return GeminiClient(model=p.model, api_key=creds.get("api_key", ""),
                            base_url=p.base_url, extra=p.extra)
    if p.provider == "bedrock":
        return BedrockClient(model=p.model, region=extra.get("region"),
                             access_key=creds.get("aws_access_key_id"),
                             secret_key=creds.get("aws_secret_access_key"),
                             session_token=creds.get("aws_session_token"), extra=p.extra)
    if p.provider == "vertex":
        return VertexClient(model=p.model, project=extra.get("project"),
                            location=extra.get("location"),
                            service_account_json=creds.get("service_account_json"), extra=p.extra)
    raise ValueError(f"unknown provider kind {p.provider!r}")
