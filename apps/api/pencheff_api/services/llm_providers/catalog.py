"""Provider kinds + curated model suggestions for the BYO-LLM UI.

Free-text models are always allowed (validated as a non-empty string); this
catalog only powers the dropdown suggestions so new model ids don't need a
deploy. Kept deliberately small.
"""
from __future__ import annotations

# The supported provider kinds. Single source of truth — the Pydantic
# Literal in schemas/llm_providers.py and the adapter factory (Plan B) both
# reference this list's members.
PROVIDER_KINDS: tuple[str, ...] = (
    "openai",
    "anthropic",
    "google",
    "azure_openai",
    "openai_compatible",
    "bedrock",
    "vertex",
)

# Curated suggestions per kind. {id: label}. openai_compatible is intentionally
# empty (self-host / arbitrary gateway — free text only).
MODEL_CATALOG: dict[str, list[dict[str, str]]] = {
    "openai": [
        {"id": "gpt-5", "label": "GPT-5"},
        {"id": "gpt-5-mini", "label": "GPT-5 mini"},
        {"id": "gpt-4.1", "label": "GPT-4.1"},
    ],
    "anthropic": [
        {"id": "claude-opus-4-8", "label": "Claude Opus 4.8"},
        {"id": "claude-sonnet-4-6", "label": "Claude Sonnet 4.6"},
        {"id": "claude-haiku-4-5", "label": "Claude Haiku 4.5"},
    ],
    "google": [
        {"id": "gemini-2.5-pro", "label": "Gemini 2.5 Pro"},
        {"id": "gemini-2.5-flash", "label": "Gemini 2.5 Flash"},
    ],
    "azure_openai": [
        {"id": "gpt-5", "label": "GPT-5 (deployment-named)"},
    ],
    "openai_compatible": [],
    "bedrock": [
        {"id": "anthropic.claude-3-5-sonnet-20241022-v2:0", "label": "Claude 3.5 Sonnet (Bedrock)"},
        {"id": "amazon.nova-pro-v1:0", "label": "Amazon Nova Pro"},
        {"id": "meta.llama3-1-70b-instruct-v1:0", "label": "Llama 3.1 70B (Bedrock)"},
    ],
    "vertex": [
        {"id": "gemini-2.5-pro", "label": "Gemini 2.5 Pro (Vertex)"},
        {"id": "gemini-2.5-flash", "label": "Gemini 2.5 Flash (Vertex)"},
    ],
}


def is_valid_kind(kind: str) -> bool:
    return kind in PROVIDER_KINDS
