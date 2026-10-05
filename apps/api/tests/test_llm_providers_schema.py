from pencheff_api.services.llm_providers.catalog import (
    PROVIDER_KINDS, MODEL_CATALOG, is_valid_kind,
)


def test_catalog_has_all_kinds():
    assert set(MODEL_CATALOG.keys()) == set(PROVIDER_KINDS)
    assert is_valid_kind("anthropic")
    assert is_valid_kind("bedrock") and is_valid_kind("vertex")
    # openai_compatible is free-text only.
    assert MODEL_CATALOG["openai_compatible"] == []


import pytest
from pydantic import ValidationError

from pencheff_api.schemas.llm_providers import (
    LlmProviderCreate, LlmProviderUpdate, LlmProviderOut,
)


def test_openai_compatible_requires_base_url():
    with pytest.raises(ValidationError):
        LlmProviderCreate(label="x", provider="openai_compatible",
                          model="m", api_key="")  # no base_url
    ok = LlmProviderCreate(label="x", provider="openai_compatible",
                           model="m", base_url="https://h/v1", api_key="")
    assert ok.base_url == "https://h/v1"


def test_azure_requires_deployment_and_version():
    with pytest.raises(ValidationError):
        LlmProviderCreate(label="x", provider="azure_openai", model="m",
                          base_url="https://h", api_key="k")  # missing azure fields
    ok = LlmProviderCreate(label="x", provider="azure_openai", model="m",
                           base_url="https://h", api_key="k",
                           azure_deployment="dep", azure_api_version="2024-02-01")
    assert ok.azure_deployment == "dep"


def test_openai_anthropic_google_require_api_key():
    for kind in ("openai", "anthropic", "google"):
        with pytest.raises(ValidationError):
            LlmProviderCreate(label="x", provider=kind, model="m", api_key="")
        ok = LlmProviderCreate(label="x", provider=kind, model="m", api_key="sk-123")
        assert ok.api_key == "sk-123"


def test_unknown_provider_rejected():
    with pytest.raises(ValidationError):
        LlmProviderCreate(label="x", provider="bedrock", model="m", api_key="k")


def test_update_all_optional():
    u = LlmProviderUpdate()
    assert u.label is None and u.api_key is None
    # empty-string api_key is a sentinel meaning "clear", kept distinct from None
    u2 = LlmProviderUpdate(api_key="")
    assert u2.api_key == ""


def test_out_never_has_api_key_field():
    assert "api_key" not in LlmProviderOut.model_fields
    assert "key_set" in LlmProviderOut.model_fields
    assert "key_hint" in LlmProviderOut.model_fields
