from pencheff_api.services.llm_providers.base import ChatResult, ChatMessage
from pencheff_api.services import llm as llm_mod


def test_llm_chat_routes_through_org_client_when_set():
    calls = {}
    class _Org:
        provider="anthropic"; model="claude-opus-4-8"
        async def chat(self, messages, **kw):
            calls["used"] = True
            return ChatResult(text="ORG-ANSWER")
    c = llm_mod.LLMClient()
    c.set_org_client(_Org())
    out = c._chat("sys", "user")
    assert out == "ORG-ANSWER"
    assert calls["used"] is True


def test_llm_chat_failclosed_when_org_client_raises():
    class _Boom:
        provider="openai"; model="m"
        async def chat(self, *a, **k): raise RuntimeError("down")
    c = llm_mod.LLMClient()
    c.set_org_client(_Boom())
    # Fail-closed: returns None (AI unavailable), does NOT fall back to env client.
    assert c._chat("s", "u") is None


import asyncio
from pencheff_api.services import fix_llm as fix_mod


def test_fix_llm_routes_through_org_client():
    class _Org:
        provider="openai"; model="gpt-5"
        async def chat(self, messages, **kw):
            return ChatResult(text="PATCH", input_tokens=1, output_tokens=1)
    c = fix_mod.FixLLMClient()
    c.set_org_client(_Org())
    res = asyncio.run(c._chat("sys", "user"))
    assert res.text == "PATCH"


def test_fix_llm_failclosed():
    class _Boom:
        provider="openai"; model="m"
        async def chat(self, *a, **k): raise RuntimeError("x")
    c = fix_mod.FixLLMClient()
    c.set_org_client(_Boom())
    res = asyncio.run(c._chat("s", "u"))
    assert res.text is None


# ── TriageLLMClient wiring tests ──────────────────────────────────────

import json as _json
from pencheff_api.services.triage_llm import TriageLLMClient, TriageResult

_VALID_TRIAGE_JSON = _json.dumps({
    "walkthrough": "The endpoint reflects user input without sanitisation.",
    "blast_radius": "An attacker can steal session cookies from any victim.",
    "exploit_scenario": "1. Craft payload. 2. Send to victim. 3. Steal cookie.",
    "fix_outline": "Encode all user-controlled output with htmlspecialchars.",
    "confidence": "high",
})

_MINIMAL_KWARGS = dict(
    title="Reflected XSS",
    severity="high",
    category="injection",
    endpoint="/search",
    parameter="q",
    description="The q parameter is reflected unescaped.",
    evidence_excerpt="GET /search?q=<script>alert(1)</script>",
    cvss_score=7.4,
    reachability="internet",
    epss=0.1234,
    kev=False,
    cwe_id="CWE-79",
    owasp_category="A03",
)


def test_triage_llm_routes_through_org_client():
    """org client is used, result reflects its JSON output."""
    calls = {}

    class _Org:
        provider = "anthropic"
        model = "claude-opus-4-8"

        async def chat(self, messages, **kw):
            calls["json_mode"] = kw.get("json")
            calls["used"] = True
            return ChatResult(text=_VALID_TRIAGE_JSON)

    c = TriageLLMClient()
    c.set_org_client(_Org())
    result = asyncio.run(c.triage_finding(**_MINIMAL_KWARGS))

    assert calls.get("used") is True, "org client was not called"
    assert calls.get("json_mode") is True, "org client was not called with json=True"
    assert isinstance(result, TriageResult)
    assert result.walkthrough == "The endpoint reflects user input without sanitisation."
    assert result.confidence == "high"


def test_triage_llm_failclosed_when_org_client_raises():
    """If the org client raises, method returns None — no exception propagates."""
    class _Boom:
        provider = "openai"
        model = "gpt-5"

        async def chat(self, *a, **k):
            raise RuntimeError("provider down")

    c = TriageLLMClient()
    c.set_org_client(_Boom())
    result = asyncio.run(c.triage_finding(**_MINIMAL_KWARGS))
    # Fail-closed: same None the disabled path returns, no exception.
    assert result is None


# ── agentic fixer provider-override wiring tests ─────────────────────

import asyncio
from pencheff_api.services.agentic_fixer import llm_client as af_mod


def test_agentic_fixer_overrides_only_for_openai_compatible():
    c = af_mod.LLMClient()
    from pencheff_api.services.credentials import encrypt_credentials
    class _Prov:
        provider="openai"; model="gpt-5"; base_url="https://h/v1"
        api_key_encrypted=encrypt_credentials({"api_key":"sk-1"}); extra=None
    assert c.maybe_override_from_provider(_Prov()) is True
    class _Ant: provider="anthropic"; model="claude-opus-4-8"; base_url=None; api_key_encrypted=None; extra=None
    assert c.maybe_override_from_provider(_Ant()) is False


# ── scan agent provider-override helper tests ─────────────────────────

from pencheff_api.services.scan_runner import _agent_override_for_provider
from pencheff_api.services.credentials import encrypt_credentials


def _make_prov(provider: str, model: str = "m", base_url: str = "https://h/v1", api_key: str = "sk-x"):
    class _P:
        pass
    p = _P()
    p.provider = provider
    p.model = model
    p.base_url = base_url
    p.api_key_encrypted = encrypt_credentials({"api_key": api_key}) if api_key else None
    return p


def test_scan_agent_override_returned_for_openai_compatible_kinds():
    for kind in ("openai", "openai_compatible", "azure_openai"):
        prov = _make_prov(kind)
        result = _agent_override_for_provider(prov)
        assert result is not None, f"expected override for {kind}"
        base_url, api_key, model = result
        assert base_url == "https://h/v1"
        assert api_key == "sk-x"
        assert model == "m"


def test_scan_agent_override_none_for_non_tool_calling_providers():
    for kind in ("anthropic", "google"):
        prov = _make_prov(kind)
        result = _agent_override_for_provider(prov)
        assert result is None, f"expected None for {kind}"


def test_scan_agent_override_none_when_key_missing():
    prov = _make_prov("openai", api_key="")
    result = _agent_override_for_provider(prov)
    assert result is None


# ── agentic fixer singleton reset tests ───────────────────────────────

def test_agentic_fixer_reset_to_defaults_after_byo_override():
    """After a BYO override sets a custom base_url, calling
    maybe_override_from_provider(None) must restore _base_url to the
    settings default and return False.
    """
    from pencheff_api.config import get_settings
    from pencheff_api.services.agentic_fixer import llm_client as af_mod2

    c = af_mod2.LLMClient()
    # Apply a BYO override.
    class _BYOProv:
        provider = "openai"
        model = "gpt-byo"
        base_url = "https://byo.example.com/v1"
        api_key_encrypted = encrypt_credentials({"api_key": "sk-byo"})
        extra = None

    overridden = c.maybe_override_from_provider(_BYOProv())
    assert overridden is True
    assert c._base_url == "https://byo.example.com/v1"

    # Now call with None (no provider for next org) — must reset.
    result = c.maybe_override_from_provider(None)
    assert result is False

    expected_base_url = get_settings().agentic_fix_effective_base_url.rstrip("/")
    assert c._base_url == expected_base_url, (
        f"_base_url not reset: got {c._base_url!r}, expected {expected_base_url!r}"
    )
