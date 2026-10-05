# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pencheff Sentry — runtime LLM guardrail.

Two public entry points:

* ``Verdict`` / ``GuardrailDecision`` / ``evaluate`` — the synchronous
  detector chain. Pure Python, no I/O.
* ``serve`` — the HTTP proxy sidecar. Runs a FastAPI app that proxies
  to an OpenAI-compatible upstream with the detector chain inline.

The LiteLLM plugin lives in ``pencheff_sentry.litellm_plugin`` and is
imported lazily so this package is usable without LiteLLM installed.

The MCP middleware lives in ``pencheff_sentry.mcp_middleware`` and
plugs into Pencheff's MCP tool-call path when both are co-installed.
"""
from __future__ import annotations

from .core import GuardrailDecision, Verdict, evaluate

__all__ = ["GuardrailDecision", "Verdict", "evaluate"]
__version__ = "0.1.0"
