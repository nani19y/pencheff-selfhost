"""Schema tests for HostKindConfig + the TargetCreate host-kind branch."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from pencheff_api.schemas.targets import HostKindConfig, TargetCreate


def test_host_kind_config_accepts_minimal_list() -> None:
    cfg = HostKindConfig(hosts=["1.2.3.4"])
    assert cfg.hosts == ["1.2.3.4"]
    assert cfg.is_private_target is False
    assert cfg.kind == "host"


def test_host_kind_config_rejects_empty_list() -> None:
    with pytest.raises(ValidationError):
        HostKindConfig(hosts=[])


def test_host_kind_config_caps_at_50() -> None:
    too_many = [f"box{i}.example.com" for i in range(51)]
    with pytest.raises(ValidationError):
        HostKindConfig(hosts=too_many)


def test_host_kind_config_dedupes_case_insensitive() -> None:
    cfg = HostKindConfig(hosts=["Box.Example.com", "box.example.com"])
    assert cfg.hosts == ["Box.Example.com"]


def test_host_kind_config_rejects_invalid_format() -> None:
    with pytest.raises(ValidationError) as exc:
        HostKindConfig(hosts=["https://no-scheme-please.example"])
    assert "scheme" in str(exc.value).lower()


def test_host_kind_config_ignores_client_supplied_is_private_target() -> None:
    cfg = HostKindConfig(hosts=["1.2.3.4"], is_private_target=True)
    # Schema-level accepts the value (router resets it). Pin documented behavior.
    assert cfg.is_private_target is True


def test_target_create_requires_kind_config_for_host() -> None:
    with pytest.raises(ValidationError) as exc:
        TargetCreate(name="x", base_url="host://list", kind="host", kind_config=None)
    assert "requires kind_config" in str(exc.value)


def test_target_create_rejects_kind_config_kind_mismatch() -> None:
    with pytest.raises(ValidationError):
        TargetCreate(
            name="x",
            base_url="host://list",
            kind="host",
            kind_config=HostKindConfig(hosts=["1.2.3.4"]).model_dump() | {"kind": "web_app"},
        )
