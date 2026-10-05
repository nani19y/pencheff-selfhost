"""The scan runner's ``_llm_triage`` must make zero LLM calls when AI is
disabled for a non-BYO org.

When ai_enabled=False, _llm_triage now does ONE DB query to check for a
BYO provider (BYO bypasses the plan gate per the BYO decision). If no BYO
provider is active, it returns immediately without touching the LLM. This
test verifies the fast-exit for the common case: org has no active BYO
provider and ai_enabled=False.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from pencheff_api.services.scan_runner import _llm_triage


class _FakeSession:
    """Minimal session mock: get() always returns None (no org / no BYO)."""
    async def get(self, model, pk):
        return None


@asynccontextmanager
async def _no_byo_factory():
    """Session factory that returns a session with no active BYO provider."""
    yield _FakeSession()


def test_llm_triage_skips_llm_when_ai_disabled_and_no_byo():
    """When ai_enabled=False and no BYO provider is configured, _llm_triage
    returns without invoking the LLM client at all."""
    llm_calls = []

    # Patch get_llm_client so we can detect if it's called.
    import pencheff_api.services.scan_runner as sr_mod
    original = sr_mod.get_llm_client

    def _tracking_client():
        llm_calls.append(True)
        return original()

    sr_mod.get_llm_client = _tracking_client
    try:
        asyncio.run(
            _llm_triage(
                scan_id="00000000-0000-0000-0000-000000000000",
                org_id="00000000-0000-0000-0000-000000000001",
                db_session_factory=_no_byo_factory,
                ai_enabled=False,
            )
        )
    finally:
        sr_mod.get_llm_client = original

    assert not llm_calls, "LLM client must not be touched when no BYO and ai_enabled=False"
