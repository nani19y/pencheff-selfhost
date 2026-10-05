"""Cost computation for chat-completions calls.

Provider-agnostic. OpenAI-shaped responses ship a ``usage`` block:

  {
    "prompt_tokens": 1234,
    "completion_tokens": 567,
    "total_tokens": 1801,
    "prompt_tokens_cached": 800   # optional, some providers
  }

We normalise both Anthropic-shaped (``input_tokens`` /
``output_tokens`` / ``cache_*``) and OpenAI-shaped responses into
the ``Usage`` dataclass below in ``llm_client._decode``. The cost
calculation here doesn't care which provider produced the counts.

Prices live in ``config.py`` and are dollars-per-million-tokens.
Defaults are Sarvam-105b placeholders — operators on a different
backend override via env. The price table is denormalised into each
``agentic_fix_usage`` row at write time so historical reporting is
stable even if prices change later.
"""
from __future__ import annotations

from dataclasses import dataclass

from ...config import get_settings


@dataclass(frozen=True)
class Usage:
    """Normalised usage record. ``cache_*`` fields default to 0 for
    providers that don't surface caching info (most OpenAI-compatible
    backends including Sarvam don't).
    """

    input_tokens: int
    output_tokens: int
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


def compute_cost_cents(usage: Usage, model: str) -> int:
    """Return cost in USD cents (rounded to nearest cent).

    We only price against the active model's settings. ``model`` is
    accepted for forward-compat with per-model price tables, even
    though today's implementation uses a single price set.
    """
    s = get_settings()
    # Cache-creation tokens (Anthropic-specific) are charged at the
    # plain input rate here for simplicity. Adjust if the workload
    # skews heavy on cached-prefix flows.
    in_cost = (
        (usage.input_tokens + usage.cache_creation_input_tokens)
        * s.agentic_fix_price_input_per_1m_usd / 1_000_000
    )
    out_cost = usage.output_tokens * s.agentic_fix_price_output_per_1m_usd / 1_000_000
    cache_cost = (
        usage.cache_read_input_tokens
        * s.agentic_fix_price_cache_read_per_1m_usd / 1_000_000
    )
    total_usd = in_cost + out_cost + cache_cost
    return int(round(total_usd * 100))
