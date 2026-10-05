"""ConsentPayload v2 loader: parses v1 + v2 inputs, emits v2 on save."""
from __future__ import annotations

from pencheff_api.schemas.scans import (
    KIND_REQUIRED_DISCLOSED_ACTIONS,
    ConsentPayload,
    load_consent_payload,
)


def test_host_kind_required_actions_includes_host_os_exploitation() -> None:
    required = KIND_REQUIRED_DISCLOSED_ACTIONS["host"]
    assert "passive_recon" in required
    assert "active_recon" in required
    assert "host_os_exploitation" in required


def test_load_consent_payload_v1_backfills_v2_fields_with_none() -> None:
    raw = {
        "version": 1,
        "acknowledged": True,
        "disclosed_actions": ["passive_recon"],
        "authorization_text": "(legacy — I authorize this legacy scan on the target system.)",
    }
    payload = load_consent_payload(raw)
    assert payload.version == 1
    assert payload.acknowledged is True
    assert payload.disclosed_actions == ["passive_recon"]
    assert payload.authorized_hosts is None
    assert payload.acknowledged_at is None


def test_load_consent_payload_v2_round_trip() -> None:
    raw = {
        "version": 2,
        "acknowledged": True,
        "disclosed_actions": ["passive_recon", "active_recon", "host_os_exploitation"],
        "authorization_text": "I authorize this penetration test on the target system and all listed hosts.",
        "authorized_hosts": ["1.2.3.4"],
        "acknowledged_at": "2026-05-17T10:44:33Z",
        "acknowledged_by_user_id": "user_abc",
        "acknowledged_from_ip": "203.0.113.42",
        "acknowledged_user_agent": "Mozilla/5.0",
    }
    payload = load_consent_payload(raw)
    assert payload.version == 2
    assert payload.authorized_hosts == ["1.2.3.4"]


def test_consent_payload_default_emits_v2() -> None:
    payload = ConsentPayload(
        acknowledged=True,
        disclosed_actions=["passive_recon"],
        authorization_text="I authorize this penetration test on the target system.",
    )
    assert payload.version == 2
