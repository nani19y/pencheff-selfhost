import asyncio
import pytest

from pencheff_api.db.models import LlmProvider, Org
from pencheff_api.services.credentials import encrypt_credentials
from pencheff_api.services.llm_providers.factory import build_client
from pencheff_api.services.llm_providers.resolver import resolve_chat_client
from pencheff_api.services.llm_providers.openai_compat import OpenAICompatClient
from pencheff_api.services.llm_providers.anthropic import AnthropicClient
from pencheff_api.services.llm_providers.google import GeminiClient


def _prov(provider, **kw):
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider=provider,
                    model=kw.get("model", "m"), base_url=kw.get("base_url"))
    p.api_key_encrypted = encrypt_credentials({"api_key": "k"})
    p.azure_deployment = kw.get("azure_deployment")
    p.azure_api_version = kw.get("azure_api_version")
    p.extra = None
    return p


def test_factory_maps_kind_to_adapter():
    assert isinstance(build_client(_prov("openai", base_url="https://h/v1")), OpenAICompatClient)
    assert isinstance(build_client(_prov("openai_compatible", base_url="https://h/v1")), OpenAICompatClient)
    assert isinstance(build_client(_prov("azure_openai", base_url="https://h",
                                         azure_deployment="d", azure_api_version="v")), OpenAICompatClient)
    assert isinstance(build_client(_prov("anthropic")), AnthropicClient)
    assert isinstance(build_client(_prov("google")), GeminiClient)
    assert build_client(_prov("openai")).model == "m"


class _FakeSession:
    def __init__(self, org, provider): self._org, self._p = org, provider
    async def get(self, cls, pk):
        if cls is Org: return self._org
        if cls is LlmProvider: return self._p
        return None


def test_resolver_returns_none_when_no_active_provider():
    org = Org(id="org-1", name="o", plan="pro"); org.active_llm_provider_id = None
    assert asyncio.run(resolve_chat_client("org-1", _FakeSession(org, None))) is None


def test_resolver_builds_client_for_active_provider():
    org = Org(id="org-1", name="o", plan="pro"); org.active_llm_provider_id = "p-1"
    p = _prov("anthropic")
    client = asyncio.run(resolve_chat_client("org-1", _FakeSession(org, p)))
    assert isinstance(client, AnthropicClient)


def test_resolver_none_when_org_missing():
    assert asyncio.run(resolve_chat_client("nope", _FakeSession(None, None))) is None
