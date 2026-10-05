"""Cloud target schema coverage for Infrastructure & Cloud target kinds."""
from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from pencheff_api.schemas.targets import KindConfig, KindCredentials, TargetCreate


_kind_config = TypeAdapter(KindConfig)
_kind_credentials = TypeAdapter(KindCredentials)


@pytest.mark.parametrize(
    "kind",
    [
        "cloud_account",
        "serverless_function",
        "cloud_storage",
        "load_balancer_cdn",
        "cloud_database",
        "secrets_manager",
    ],
)
def test_cloud_kind_configs_accept_read_only_provider_scope(kind: str) -> None:
    cfg = _kind_config.validate_python({
        "kind": kind,
        "provider": "aws",
        "account_id": "123456789012",
        "regions": ["us-east-1"],
        "resource_tags": {"env": "prod"},
        "inventory": {"sample": []},
    })

    assert cfg.kind == kind
    assert cfg.provider == "aws"
    assert cfg.regions == ["us-east-1"]
    assert cfg.resource_tags == {"env": "prod"}


def test_cloud_credentials_accept_aws_for_any_cloud_kind() -> None:
    creds = _kind_credentials.validate_python({
        "kind": "cloud_storage",
        "provider": "aws",
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "x" * 40,
        "aws_session_token": "session",
    })

    assert creds.kind == "cloud_storage"
    assert creds.provider == "aws"


def test_cloud_credentials_require_provider_specific_fields() -> None:
    with pytest.raises(ValidationError, match="aws_access_key_id"):
        _kind_credentials.validate_python({
            "kind": "cloud_account",
            "provider": "aws",
        })

    with pytest.raises(ValidationError, match="azure_tenant_id"):
        _kind_credentials.validate_python({
            "kind": "cloud_account",
            "provider": "azure",
        })

    with pytest.raises(ValidationError, match="gcp_service_account_json"):
        _kind_credentials.validate_python({
            "kind": "cloud_account",
            "provider": "gcp",
        })


def test_secrets_manager_never_allows_secret_value_reads() -> None:
    with pytest.raises(ValidationError, match="never reads secret values"):
        _kind_config.validate_python({
            "kind": "secrets_manager",
            "provider": "aws",
            "account_id": "123456789012",
            "include_secret_values": True,
        })


def test_cspm_discipline_accepts_cloud_targets() -> None:
    target = TargetCreate(
        name="Prod AWS account",
        base_url="cloud+aws://123456789012",
        kind="cloud_account",
        disciplines=["cspm"],
        kind_config={
            "kind": "cloud_account",
            "provider": "aws",
            "account_id": "123456789012",
        },
        kind_credentials={
            "kind": "cloud_account",
            "provider": "aws",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "x" * 40,
        },
    )

    assert target.kind == "cloud_account"
    assert target.disciplines == ["cspm"]
