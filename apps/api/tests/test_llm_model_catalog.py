from __future__ import annotations

import httpx
import pytest

from pencheff_api.services.llm_model_catalog import (
    LlmModelCatalogRequest,
    azure_deployments_url,
    fetch_llm_model_catalog,
    openai_model_urls_from_endpoint,
    openai_models_url_from_chat_endpoint,
    parse_azure_deployments_payload,
    parse_openai_model_payload,
)


def test_openai_models_url_replaces_chat_completions_path() -> None:
    assert (
        openai_models_url_from_chat_endpoint(
            "https://api.openai.com/v1/chat/completions",
        )
        == "https://api.openai.com/v1/models"
    )


def test_openai_models_url_supports_openai_compatible_base() -> None:
    assert (
        openai_models_url_from_chat_endpoint("https://llm.example.test/v1")
        == "https://llm.example.test/v1/models"
    )


def test_openai_model_urls_tries_deepseek_models_before_v1() -> None:
    assert openai_model_urls_from_endpoint("https://api.deepseek.com") == [
        "https://api.deepseek.com/models",
        "https://api.deepseek.com/v1/models",
    ]


def test_azure_deployments_url_uses_resource_host_and_api_version() -> None:
    assert (
        azure_deployments_url(
            "https://acme.openai.azure.com/openai/deployments/prod/chat/completions?api-version=2024-10-21",
            "2025-01-01-preview",
        )
        == "https://acme.openai.azure.com/openai/deployments?api-version=2025-01-01-preview"
    )


def test_parse_openai_models_dedupes_and_sorts() -> None:
    models = parse_openai_model_payload(
        {
            "data": [
                {"id": "gpt-4o"},
                {"id": "gpt-4o-mini"},
                {"id": "gpt-4o"},
                {"not_id": "ignored"},
            ],
        },
    )
    assert [model.id for model in models] == ["gpt-4o", "gpt-4o-mini"]
    assert all(model.source == "live" for model in models)


def test_parse_azure_deployments_accepts_data_or_value_shapes() -> None:
    models = parse_azure_deployments_payload(
        {
            "value": [
                {"name": "support-prod", "model": {"name": "gpt-4o-mini"}},
                {"id": "support-canary", "model": "gpt-4o"},
            ],
        },
    )
    assert [model.id for model in models] == ["support-canary", "support-prod"]
    assert models[0].description == "Model: gpt-4o"


@pytest.mark.asyncio
async def test_fetch_openai_catalog_uses_models_endpoint() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={"data": [{"id": "gpt-4o-mini"}, {"id": "gpt-4o"}]},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_llm_model_catalog(
            LlmModelCatalogRequest(
                provider="openai-chat",
                endpoint="https://api.openai.com/v1/chat/completions",
                headers={"Authorization": "Bearer sk-test"},
            ),
            client=client,
        )

    assert result.warning is None
    assert [model.id for model in result.models] == ["gpt-4o", "gpt-4o-mini"]
    assert seen[0].url == "https://api.openai.com/v1/models"
    assert seen[0].headers["authorization"] == "Bearer sk-test"


@pytest.mark.asyncio
async def test_fetch_openai_catalog_falls_back_across_candidate_urls() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url) == "https://llm.example.test/v1/models":
            return httpx.Response(404, json={"detail": "not found"})
        return httpx.Response(200, json={"data": [{"id": "local-model"}]})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_llm_model_catalog(
            LlmModelCatalogRequest(
                provider="openai-chat",
                endpoint="https://llm.example.test",
                headers={"Authorization": "Bearer sk-test"},
            ),
            client=client,
        )

    assert result.warning is None
    assert [model.id for model in result.models] == ["local-model"]
    assert seen == [
        "https://llm.example.test/v1/models",
        "https://llm.example.test/models",
    ]


@pytest.mark.asyncio
async def test_fetch_deepseek_catalog_returns_deepseek_presets_on_404() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "not found"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_llm_model_catalog(
            LlmModelCatalogRequest(
                provider="openai-chat",
                endpoint="https://api.deepseek.com",
                headers={"Authorization": "Bearer sk-test"},
            ),
            client=client,
        )

    assert result.warning is not None
    assert [model.id for model in result.models] == [
        "deepseek-v4-flash",
        "deepseek-v4-pro",
        "deepseek-chat",
        "deepseek-reasoner",
    ]


@pytest.mark.asyncio
async def test_custom_catalog_is_manual_only() -> None:
    result = await fetch_llm_model_catalog(
        LlmModelCatalogRequest(provider="custom", endpoint="https://api.example.test/chat"),
    )
    assert result.models == []
    assert result.manual_allowed is True
    assert result.warning is not None
