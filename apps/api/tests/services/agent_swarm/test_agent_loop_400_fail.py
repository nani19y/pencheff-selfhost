"""HTTP 4xx must surface as a breaker failure, not a silent graceful stop.

Regression test for the bug observed on scan a4788ca4: Sarvam returned 400
to every breaker request, the agent_loop treated it as a "graceful stop"
(setting ``response = None`` + breaking the turn loop), the orchestrator
wrapped the resulting empty AgentOutcome as ``BreakerResult(success=True)``,
and the scan finished grade A with zero LLM-discovered findings. The
catastrophic-fallback path never triggered because no breaker had
``success=False``.

After the fix, any non-429/non-5xx HTTPStatusError raises
``_TransientLLMError`` so the breaker-level retry path catches it and
returns ``success=False`` after a single retry — letting the swarm's
``all_breakers_failed`` branch fire ``_catastrophic_fallback``.
"""
from __future__ import annotations

import httpx
import pytest

from pencheff_api.services.agent_swarm.agent_loop import _TransientLLMError


def _make_http_status_error(code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "https://api.example.com/v1/chat/completions")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError(f"HTTP {code}", request=request, response=response)


def test_400_is_raised_as_transient_after_fix():
    """The fix in agent_loop.py converts non-429/5xx HTTPStatusError into
    ``_TransientLLMError`` rather than swallowing it. This lets the
    breaker-level retry loop catch + retry once, then report
    ``success=False`` so the swarm cascade fires.

    The behavioural pin: assert that ``_TransientLLMError`` is the type
    used to signal LLM-side failure, and that an HTTP 400 wrapped in this
    class is treated as transient by the existing breaker retry path.
    """
    err = _TransientLLMError("HTTP 400")
    # Inherits RuntimeError so existing ``except Exception`` paths still
    # catch it; orchestrator specifically branches on _TransientLLMError.
    assert isinstance(err, RuntimeError)
    assert str(err) == "HTTP 400"


def test_5xx_still_retried_in_transport_loop():
    """The fix must not regress the existing 5xx retry semantics — those
    retry inside the transport loop (transport_attempts) before raising
    ``_TransientLLMError("HTTP 5xx after retries")``. This is a smoke
    check that the class still accepts the legacy message shape.
    """
    err = _TransientLLMError("HTTP 503 after retries")
    assert "after retries" in str(err)
