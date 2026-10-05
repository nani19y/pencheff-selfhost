from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, Field


LlmEndpointProvider = Literal[
    "openai-chat",
    "custom",
    "executable",
    "websocket",
    "bedrock",
    "vertex",
    "azure-openai",
    "browser",
]

ModelSource = Literal["live", "preset"]


class LlmModelInfo(BaseModel):
    id: str
    label: str | None = None
    description: str | None = None
    source: ModelSource = "preset"


class LlmModelCatalogRequest(BaseModel):
    provider: LlmEndpointProvider
    endpoint: str | None = Field(default=None, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    aws_region: str | None = Field(default=None, max_length=80)
    vertex_project: str | None = Field(default=None, max_length=256)
    vertex_location: str | None = Field(default=None, max_length=80)
    azure_deployment: str | None = Field(default=None, max_length=200)
    azure_api_version: str | None = Field(default=None, max_length=80)


class LlmModelCatalogOut(BaseModel):
    provider: LlmEndpointProvider
    models: list[LlmModelInfo]
    warning: str | None = None
    manual_allowed: bool = True


PROVIDER_MODEL_PRESETS: dict[LlmEndpointProvider, tuple[str, ...]] = {
    "openai-chat": (
        "gpt-4o-mini",
        "gpt-4o",
        "gpt-4.1-mini",
        "gpt-4.1",
        "o4-mini",
        "o3-mini",
    ),
    "azure-openai": (
        "gpt-4o-mini",
        "gpt-4o",
        "gpt-4.1-mini",
        "gpt-4.1",
    ),
    "bedrock": (
        "anthropic.claude-3-5-sonnet-20240620-v1:0",
        "anthropic.claude-3-haiku-20240307-v1:0",
        "meta.llama3-70b-instruct-v1:0",
        "mistral.mistral-large-2402-v1:0",
        "amazon.titan-text-express-v1",
    ),
    "vertex": (
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
    ),
    "custom": (),
    "executable": (),
    "websocket": (),
    "browser": (),
}

OPENAI_COMPATIBLE_MODEL_PRESETS_BY_HOST: dict[str, tuple[str, ...]] = {
    "api.deepseek.com": (
        "deepseek-v4-flash",
        "deepseek-v4-pro",
        "deepseek-chat",
        "deepseek-reasoner",
    ),
}


def preset_models(provider: LlmEndpointProvider) -> list[LlmModelInfo]:
    return [
        LlmModelInfo(id=model_id, label=model_id, source="preset")
        for model_id in PROVIDER_MODEL_PRESETS.get(provider, ())
    ]


def preset_models_for_endpoint(
    provider: LlmEndpointProvider,
    endpoint: str | None,
) -> list[LlmModelInfo]:
    if provider == "openai-chat" and endpoint:
        parts = urlsplit(endpoint.strip())
        host_presets = OPENAI_COMPATIBLE_MODEL_PRESETS_BY_HOST.get(
            parts.netloc.lower(),
        )
        if host_presets:
            return [
                LlmModelInfo(id=model_id, label=model_id, source="preset")
                for model_id in host_presets
            ]
    return preset_models(provider)


def openai_model_urls_from_endpoint(endpoint: str | None) -> list[str]:
    if not endpoint:
        return []
    raw = endpoint.strip()
    if not raw:
        return []
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return []
    path = parts.path.rstrip("/")
    candidates: list[str] = []

    def add(candidate_path: str) -> None:
        url = urlunsplit((parts.scheme, parts.netloc, candidate_path, "", ""))
        if url not in candidates:
            candidates.append(url)

    # DeepSeek's OpenAI-compatible base URL is https://api.deepseek.com and
    # its list-models endpoint is GET /models, not /v1/models.
    if parts.netloc.lower() == "api.deepseek.com":
        add("/models")

    if path.endswith("/models"):
        add(path)
    elif path.endswith("/chat/completions"):
        add(path[: -len("/chat/completions")] + "/models")
    elif path.endswith("/v1"):
        add(f"{path}/models")
    elif path in {"", "/"}:
        add("/v1/models")
        add("/models")
    else:
        add(f"{path}/models")
        add("/v1/models")
    return candidates


def openai_models_url_from_chat_endpoint(endpoint: str | None) -> str | None:
    urls = openai_model_urls_from_endpoint(endpoint)
    return urls[0] if urls else None


def azure_deployments_url(endpoint: str | None, api_version: str | None) -> str | None:
    if not endpoint:
        return None
    raw = endpoint.strip()
    if not raw:
        return None
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return None
    path = parts.path.rstrip("/")
    marker = "/openai/deployments/"
    if marker in path:
        path = path.split(marker, 1)[0] + "/openai/deployments"
    elif not path.endswith("/openai/deployments"):
        path = "/openai/deployments"
    version = (api_version or "2024-10-21").strip() or "2024-10-21"
    return urlunsplit((parts.scheme, parts.netloc, path, f"api-version={version}", ""))


def parse_openai_model_payload(payload: object) -> list[LlmModelInfo]:
    if not isinstance(payload, dict):
        return []
    raw_items = payload.get("data")
    if not isinstance(raw_items, list):
        return []
    ids: set[str] = set()
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        model_id = item.get("id")
        if isinstance(model_id, str) and model_id.strip():
            ids.add(model_id.strip())
    return [
        LlmModelInfo(id=model_id, label=model_id, source="live")
        for model_id in sorted(ids)
    ]


def parse_azure_deployments_payload(payload: object) -> list[LlmModelInfo]:
    if not isinstance(payload, dict):
        return []
    raw_items = payload.get("data") or payload.get("value")
    if not isinstance(raw_items, list):
        return []
    out: dict[str, LlmModelInfo] = {}
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        deployment_id = item.get("id") or item.get("name")
        if not isinstance(deployment_id, str) or not deployment_id.strip():
            continue
        model_name = item.get("model")
        if isinstance(model_name, dict):
            model_name = model_name.get("name") or model_name.get("id")
        description = f"Model: {model_name}" if isinstance(model_name, str) and model_name else None
        out[deployment_id.strip()] = LlmModelInfo(
            id=deployment_id.strip(),
            label=deployment_id.strip(),
            description=description,
            source="live",
        )
    return [out[key] for key in sorted(out)]


def _request_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key.strip(): value.strip()
        for key, value in headers.items()
        if key.strip() and value.strip()
    }


async def fetch_llm_model_catalog(
    request: LlmModelCatalogRequest,
    *,
    client: httpx.AsyncClient | None = None,
) -> LlmModelCatalogOut:
    if request.provider in {"custom", "executable", "websocket", "browser"}:
        return LlmModelCatalogOut(
            provider=request.provider,
            models=preset_models(request.provider),
            warning="This provider does not expose a standard model-list API. Type the model or adapter name manually.",
        )

    if request.provider == "openai-chat":
        urls = openai_model_urls_from_endpoint(request.endpoint)
        if not urls:
            return _fallback(request.provider, "Enter a valid HTTP chat-completions URL before loading models.", request.endpoint)
        return await _fetch_first_json_catalog(
            request,
            urls,
            parse_openai_model_payload,
            missing_message="No models were returned by the provider. Type the model ID manually or check the API key scope.",
            client=client,
        )

    if request.provider == "azure-openai":
        url = azure_deployments_url(request.endpoint, request.azure_api_version)
        if not url:
            return _fallback(request.provider, "Enter a valid Azure OpenAI endpoint before loading deployments.", request.endpoint)
        return await _fetch_json_catalog(
            request,
            url,
            parse_azure_deployments_payload,
            missing_message="No Azure deployments were returned. Type the deployment name manually or check the api-key/Entra token.",
            client=client,
        )

    if request.provider == "bedrock":
        return await _fetch_bedrock_catalog(request)

    if request.provider == "vertex":
        return _fallback(
            request.provider,
            "Vertex model catalog discovery varies by project and service account. Pick a preset or type the deployed model ID manually.",
        )

    return _fallback(request.provider, "Pick a preset or type the model ID manually.", request.endpoint)


async def _fetch_first_json_catalog(
    request: LlmModelCatalogRequest,
    urls: list[str],
    parser,
    *,
    missing_message: str,
    client: httpx.AsyncClient | None,
) -> LlmModelCatalogOut:
    last_error: Exception | None = None
    for url in urls:
        result, err = await _try_fetch_json_catalog(
            request,
            url,
            parser,
            missing_message=missing_message,
            client=client,
        )
        if result.warning is None or result.models and err is None:
            return result
        last_error = err
    if last_error is not None:
        return _fallback(
            request.provider,
            f"Could not load live models from this provider: {type(last_error).__name__}. Pick a preset or type the model ID manually.",
            request.endpoint,
        )
    return _fallback(request.provider, missing_message, request.endpoint)


async def _fetch_json_catalog(
    request: LlmModelCatalogRequest,
    url: str,
    parser,
    *,
    missing_message: str,
    client: httpx.AsyncClient | None,
) -> LlmModelCatalogOut:
    result, _err = await _try_fetch_json_catalog(
        request,
        url,
        parser,
        missing_message=missing_message,
        client=client,
    )
    return result


async def _try_fetch_json_catalog(
    request: LlmModelCatalogRequest,
    url: str,
    parser,
    *,
    missing_message: str,
    client: httpx.AsyncClient | None,
) -> tuple[LlmModelCatalogOut, Exception | None]:
    owns_client = client is None
    http_client = client or httpx.AsyncClient(timeout=15.0)
    try:
        response = await http_client.get(url, headers=_request_headers(request.headers))
        response.raise_for_status()
        models = parser(response.json())
        if models:
            return LlmModelCatalogOut(provider=request.provider, models=models), None
        return _fallback(request.provider, missing_message, request.endpoint), None
    except Exception as exc:
        return _fallback(
            request.provider,
            f"Could not load live models from this provider: {type(exc).__name__}. Pick a preset or type the model ID manually.",
            request.endpoint,
        ), exc
    finally:
        if owns_client:
            await http_client.aclose()


async def _fetch_bedrock_catalog(request: LlmModelCatalogRequest) -> LlmModelCatalogOut:
    try:
        import boto3  # type: ignore[import-not-found]
    except Exception:
        return _fallback(
            request.provider,
            "The API worker does not have boto3 installed for live Bedrock model listing. Pick a preset or type the model ID manually.",
        )

    region = (request.aws_region or "us-east-1").strip() or "us-east-1"
    headers = _request_headers(request.headers)
    session_kwargs: dict[str, str] = {}
    if headers.get("X-AWS-Access-Key-Id"):
        session_kwargs["aws_access_key_id"] = headers["X-AWS-Access-Key-Id"]
    if headers.get("X-AWS-Secret-Access-Key"):
        session_kwargs["aws_secret_access_key"] = headers["X-AWS-Secret-Access-Key"]
    if headers.get("X-AWS-Session-Token"):
        session_kwargs["aws_session_token"] = headers["X-AWS-Session-Token"]
    try:
        session = boto3.Session(region_name=region, **session_kwargs)
        client = session.client("bedrock", region_name=region)
        payload = client.list_foundation_models(byOutputModality="TEXT")
    except Exception as exc:
        return _fallback(
            request.provider,
            f"Could not load live Bedrock models: {type(exc).__name__}. Pick a preset or type the model ID manually.",
        )

    models: dict[str, LlmModelInfo] = {}
    for item in payload.get("modelSummaries", []):
        if not isinstance(item, dict):
            continue
        model_id = item.get("modelId")
        if not isinstance(model_id, str) or not model_id.strip():
            continue
        provider_name = item.get("providerName")
        model_name = item.get("modelName")
        desc_parts = [
            part for part in (provider_name, model_name) if isinstance(part, str) and part
        ]
        models[model_id.strip()] = LlmModelInfo(
            id=model_id.strip(),
            label=model_id.strip(),
            description=" / ".join(desc_parts) or None,
            source="live",
        )
    if models:
        return LlmModelCatalogOut(
            provider=request.provider,
            models=[models[key] for key in sorted(models)],
        )
    return _fallback(
        request.provider,
        "Bedrock returned no text foundation models. Pick a preset or type the model ID manually.",
    )


def _fallback(
    provider: LlmEndpointProvider,
    warning: str,
    endpoint: str | None = None,
) -> LlmModelCatalogOut:
    return LlmModelCatalogOut(
        provider=provider,
        models=preset_models_for_endpoint(provider, endpoint),
        warning=warning,
        manual_allowed=True,
    )
