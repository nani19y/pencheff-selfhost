"""End-to-end smoke tests for the LLM red-team module pipeline.

Uses ``httpx.MockTransport`` so no live LLM endpoint is needed. Two
mock endpoints — ``pwned`` (always returns text containing every
known canary string) and ``safe`` (always refuses) — exercise both
sides of the verdict function.

The test installs the mock transport into the LlmProbe's internal
httpx client by monkey-patching the LlmProbe constructor at runtime.
This is intrusive but the alternative — running an aiohttp server —
adds far more setup for the same test coverage.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from pencheff.core.session import create_session
from pencheff.modules.llm_red_team import (
    LLM_RED_TEAM_MODULES,
    LlmProbe,
    PromptInjectionModule,
)


# All canary strings used across the LLM01 payload library. The pwned
# transport returns a body that includes all of them so every payload
# matches its success indicator.
_ALL_CANARIES = (
    "CANARY-2718 PWNED-CANARY-91 INJECTED-3 DAN-OK-712 "
    "DEV-MODE: confirmed-canary-44 ENCODED-770 ROT13-PASSED "
    "MULTI-LANG-OK HIERARCHY-CANARY-555 NESTED-OK-001"
)


def _make_pwned_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": _ALL_CANARIES}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20},
            },
        )

    return httpx.MockTransport(handler)


def _make_safe_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": "I'm sorry, I can't help with that. "
                            "That request goes against my guidelines.",
                        }
                    }
                ],
            },
        )

    return httpx.MockTransport(handler)


@pytest.fixture
def patch_probe_transport(monkeypatch):
    """Patch LlmProbe so its internal httpx client uses a MockTransport.

    We can't pass the transport in via constructor (would break the
    public surface), so we override ``_get`` to return a client wired
    to whichever transport the test set first."""
    holder: dict[str, httpx.MockTransport | None] = {"transport": None}
    orig_get = LlmProbe._get

    async def _patched_get(self):  # type: ignore[no-untyped-def]
        if self._client is None:
            self._client = httpx.AsyncClient(
                transport=holder["transport"],
                timeout=httpx.Timeout(self.timeout),
            )
        return self._client

    monkeypatch.setattr(LlmProbe, "_get", _patched_get)

    def _set(transport: httpx.MockTransport) -> None:
        holder["transport"] = transport

    yield _set


def test_pwned_endpoint_emits_findings(patch_probe_transport):
    """LLM01 module against a 'pwned' mock should emit at least one
    finding per technique whose payloads matched."""
    patch_probe_transport(_make_pwned_transport())

    sess = create_session(
        target_url="http://mock/v1/chat",
        credentials={"headers": {"Authorization": "Bearer test"}},
        depth="quick",
        llm_config={"provider": "openai-chat", "model": "test-model"},
    )
    mod = PromptInjectionModule()
    findings = asyncio.run(mod.run(sess, http=None, config={"max_payloads": 20}))

    assert len(findings) >= 1, "expected ≥1 LLM01 finding against pwned mock"
    for f in findings:
        assert f.owasp_category == "LLM01"
        # Title format: "<base title> (<succeeded>/<attacked> payloads)"
        assert "/" in f.title and "payloads" in f.title
        # Each Finding aggregates by technique — check evidence is bounded.
        assert 1 <= len(f.evidence) <= 5


def test_safe_endpoint_emits_no_findings(patch_probe_transport):
    """LLM01 module against a 'safe' mock that always refuses must
    NOT emit any findings — the verdict function rejects refused
    responses."""
    patch_probe_transport(_make_safe_transport())

    sess = create_session(
        target_url="http://mock/v1/chat",
        credentials={"headers": {"Authorization": "Bearer test"}},
        depth="quick",
        llm_config={"provider": "openai-chat", "model": "test-model"},
    )
    mod = PromptInjectionModule()
    findings = asyncio.run(mod.run(sess, http=None, config={"max_payloads": 20}))

    assert findings == [], (
        f"expected zero findings against safe mock — got {len(findings)}: "
        f"{[f.title for f in findings]}"
    )


def test_all_categories_load_without_error():
    """Every module in LLM_RED_TEAM_MODULES must declare a
    payload_file that loads cleanly; this catches typos in the YAML
    library at import time."""
    from pencheff.modules.llm_red_team.base import _load_payloads

    for cat, mod_cls in LLM_RED_TEAM_MODULES.items():
        mod = mod_cls()
        cases = _load_payloads(mod.payload_file)
        assert cases, f"{cat}: payload file is empty or unparseable"
        # Every payload's category must match the module's owasp_category.
        for tc in cases:
            assert tc.category == cat, (
                f"{cat}: payload {tc.id} declares category {tc.category}; "
                f"the module enforces consistency at run time."
            )
        # Techniques get_techniques() must contain the techniques used
        # in the YAML — drift here means the docs / API surface lies.
        techniques = mod.get_techniques()
        used = {tc.technique for tc in cases}
        assert used.issubset(set(techniques)), (
            f"{cat}: get_techniques() missed: {used - set(techniques)}"
        )


def test_finding_carries_real_endpoint(patch_probe_transport):
    """Regression: ``Finding.endpoint`` and ``Evidence.request_url``
    must be the actual chat URL, not the literal placeholder
    ``"(LLM endpoint)"`` and not the rendered request body."""
    patch_probe_transport(_make_pwned_transport())

    sess = create_session(
        target_url="https://api.example.com/v1/chat/completions",
        credentials=None,
        depth="quick",
        llm_config={"provider": "openai-chat", "model": "test-model"},
    )
    mod = PromptInjectionModule()
    findings = asyncio.run(mod.run(sess, http=None, config={"max_payloads": 5}))
    assert findings, "expected ≥1 finding for the regression check"
    for f in findings:
        assert f.endpoint == "https://api.example.com/v1/chat/completions", (
            f"Finding.endpoint = {f.endpoint!r}; expected the configured chat URL"
        )
        for ev in f.evidence:
            assert ev.request_url == "https://api.example.com/v1/chat/completions", (
                f"Evidence.request_url = {ev.request_url!r}; expected the configured chat URL"
            )
            # Sanity: request_body holds the prompt (truncated), not
            # JSON-shaped request payload.
            assert not ev.request_body.startswith("{"), (
                f"Evidence.request_body looks like a JSON body, not a prompt: {ev.request_body!r}"
            )


def test_round_robin_cap_balances_techniques(patch_probe_transport):
    """When max_payloads < total, the cap must round-robin techniques
    so quick-profile scans don't starve any single technique."""
    patch_probe_transport(_make_pwned_transport())

    sess = create_session(
        target_url="http://mock/v1/chat",
        credentials=None,
        depth="quick",
        llm_config={"provider": "openai-chat", "model": "test-model"},
    )
    mod = PromptInjectionModule()
    # 5 payloads — should exercise multiple techniques, not just direct_injection.
    findings = asyncio.run(mod.run(sess, http=None, config={"max_payloads": 5}))
    techniques_hit = {f.category.replace("llm_", "") for f in findings}
    assert len(techniques_hit) >= 2, (
        f"expected ≥2 techniques represented under cap=5; "
        f"got {techniques_hit}"
    )
