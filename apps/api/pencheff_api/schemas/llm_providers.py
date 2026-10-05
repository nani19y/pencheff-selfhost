from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from ..services.llm_providers.catalog import PROVIDER_KINDS

LlmProviderKind = Literal[
    "openai", "anthropic", "google", "azure_openai", "openai_compatible",
    "bedrock", "vertex",
]


def _validate_kind_fields(provider: str, base_url: str | None,
                          azure_deployment: str | None,
                          azure_api_version: str | None,
                          extra=None, credentials=None) -> None:
    if provider not in PROVIDER_KINDS:
        raise ValueError(f"unknown provider {provider!r}")
    extra = extra or {}
    credentials = credentials or {}
    if provider in ("openai_compatible", "azure_openai") and not base_url:
        raise ValueError(f"{provider} requires base_url")
    if provider == "azure_openai" and not (azure_deployment and azure_api_version):
        raise ValueError("azure_openai requires azure_deployment + azure_api_version")
    if provider == "bedrock":
        if not extra.get("region"):
            raise ValueError("bedrock requires extra.region")
        if not (credentials.get("aws_access_key_id") and credentials.get("aws_secret_access_key")):
            raise ValueError("bedrock requires credentials.aws_access_key_id + aws_secret_access_key")
    if provider == "vertex":
        if not (extra.get("project") and extra.get("location")):
            raise ValueError("vertex requires extra.project + extra.location")
        if not credentials.get("service_account_json"):
            raise ValueError("vertex requires credentials.service_account_json")


class LlmProviderCreate(BaseModel):
    label: str = Field(min_length=1, max_length=120)
    provider: LlmProviderKind
    model: str = Field(min_length=1, max_length=200)
    base_url: str | None = Field(default=None, max_length=1024)
    # Required for hosted providers; openai_compatible may use a keyless
    # self-host, so an empty key is allowed only there.
    api_key: str = ""
    azure_deployment: str | None = Field(default=None, max_length=200)
    azure_api_version: str | None = Field(default=None, max_length=40)
    extra: dict | None = None
    credentials: dict | None = None

    @model_validator(mode="after")
    def _check(self) -> "LlmProviderCreate":
        _validate_kind_fields(self.provider, self.base_url,
                              self.azure_deployment, self.azure_api_version,
                              self.extra, self.credentials)
        if self.provider in ("openai", "anthropic", "google", "azure_openai") and not self.api_key:
            raise ValueError(f"{self.provider} requires a non-empty api_key")
        return self


class LlmProviderUpdate(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=120)
    provider: LlmProviderKind | None = None
    model: str | None = Field(default=None, min_length=1, max_length=200)
    base_url: str | None = Field(default=None, max_length=1024)
    # None = leave unchanged; "" = clear the stored key; non-empty = replace.
    api_key: str | None = None
    azure_deployment: str | None = Field(default=None, max_length=200)
    azure_api_version: str | None = Field(default=None, max_length=40)
    extra: dict | None = None
    credentials: dict | None = None


class LlmProviderOut(BaseModel):
    id: str
    label: str
    provider: str
    model: str
    base_url: str | None = None
    azure_deployment: str | None = None
    azure_api_version: str | None = None
    extra: dict | None = None
    key_set: bool = False
    key_hint: str | None = None  # e.g. "…AB12"
    is_active: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}
