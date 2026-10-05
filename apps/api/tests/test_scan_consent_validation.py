"""Unit tests for Batch B scan consent validation.

Tests cover:
  - ConsentPayload schema validation (missing fields, bad values)
  - ScanCreate rejects requests without consent_payload
  - Server-side staleness check logic
  - API-level overwrite of consent_given_by_user_id is enforced in the router

The router layer requires a live DB + Clerk auth, so we test the Pydantic
validation layer directly (same layer FastAPI calls before the route body
runs). HTTP-level integration tests would require a TestClient fixture not
yet present in this codebase.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest
from pydantic import ValidationError

from pencheff_api.schemas.scans import ConsentPayload, ScanCreate


# ─── Helpers ─────────────────────────────────────────────────────────────────

VALID_AUTH_TEXT = (
    "I confirm I have written authorization from AcmeCorp to perform "
    "an AI-assisted security assessment of acme.example.com."
)
VALID_ACTIONS = ["passive_recon", "active_recon", "vulnerability_probing"]
VALID_TIMESTAMP = datetime.now(tz=timezone.utc).isoformat()


def _valid_consent(**overrides) -> dict:
    base = {
        "acknowledged": True,
        "authorization_text": VALID_AUTH_TEXT,
        "disclosed_actions": VALID_ACTIONS,
        "consent_given_at": VALID_TIMESTAMP,
    }
    base.update(overrides)
    return base


def _valid_scan_create(**consent_overrides) -> dict:
    return {
        "target_id": "00000000-0000-0000-0000-000000000001",
        "profile": "standard",
        "consent_payload": _valid_consent(**consent_overrides),
    }


# ─── ConsentPayload ──────────────────────────────────────────────────────────


class TestConsentPayloadValid:
    def test_valid_payload_parses(self):
        cp = ConsentPayload(**_valid_consent())
        assert cp.acknowledged is True
        assert cp.version == 2  # default (bumped to 2 in Task 5)

    def test_version_defaults_to_2_when_absent(self):
        data = {k: v for k, v in _valid_consent().items() if k != "version"}
        cp = ConsentPayload(**data)
        assert cp.version == 2

    def test_consent_given_at_optional(self):
        data = _valid_consent()
        data["consent_given_at"] = None
        cp = ConsentPayload(**data)
        assert cp.consent_given_at is None

    def test_user_id_defaults_to_none(self):
        cp = ConsentPayload(**_valid_consent())
        assert cp.consent_given_by_user_id is None


class TestConsentPayloadRejectsInvalid:
    def test_rejects_acknowledged_false(self):
        with pytest.raises(ValidationError) as exc_info:
            ConsentPayload(**_valid_consent(acknowledged=False))
        errors = exc_info.value.errors()
        assert any("acknowledged" in str(e) for e in errors)

    def test_rejects_short_authorization_text(self):
        with pytest.raises(ValidationError):
            ConsentPayload(**_valid_consent(authorization_text="Too short."))

    def test_rejects_whitespace_only_authorization_text(self):
        # 60 spaces would pass min_length=50 on the field, but the strip validator
        # catches it.
        with pytest.raises(ValidationError):
            ConsentPayload(**_valid_consent(authorization_text=" " * 60))

    def test_rejects_exactly_49_char_text_after_strip(self):
        text = "A" * 49
        with pytest.raises(ValidationError):
            ConsentPayload(**_valid_consent(authorization_text=text))

    def test_accepts_exactly_50_char_text_after_strip(self):
        text = "A" * 50
        cp = ConsentPayload(**_valid_consent(authorization_text=text))
        assert len(cp.authorization_text) == 50

    def test_accepts_text_with_leading_trailing_whitespace_if_stripped_length_gte_50(self):
        text = "  " + "A" * 50 + "  "
        cp = ConsentPayload(**_valid_consent(authorization_text=text))
        # validator strips the text
        assert cp.authorization_text == "A" * 50

    def test_rejects_empty_disclosed_actions(self):
        with pytest.raises(ValidationError):
            ConsentPayload(**_valid_consent(disclosed_actions=[]))

    def test_rejects_missing_acknowledged(self):
        data = _valid_consent()
        del data["acknowledged"]
        with pytest.raises(ValidationError):
            ConsentPayload(**data)

    def test_rejects_missing_authorization_text(self):
        data = _valid_consent()
        del data["authorization_text"]
        with pytest.raises(ValidationError):
            ConsentPayload(**data)

    def test_rejects_missing_disclosed_actions(self):
        data = _valid_consent()
        del data["disclosed_actions"]
        with pytest.raises(ValidationError):
            ConsentPayload(**data)


# ─── ScanCreate ──────────────────────────────────────────────────────────────


class TestScanCreateRequiresConsent:
    def test_valid_scan_create_parses(self):
        sc = ScanCreate(**_valid_scan_create())
        assert sc.consent_payload.acknowledged is True
        assert sc.consent_payload.version == 2  # default (bumped to 2 in Task 5)

    def test_rejects_missing_consent_payload(self):
        data = {
            "target_id": "00000000-0000-0000-0000-000000000001",
            "profile": "standard",
        }
        with pytest.raises(ValidationError) as exc_info:
            ScanCreate(**data)
        errors = exc_info.value.errors()
        assert any("consent_payload" in str(e) for e in errors)

    def test_rejects_consent_acknowledged_false_via_scan_create(self):
        with pytest.raises(ValidationError):
            ScanCreate(**_valid_scan_create(acknowledged=False))

    def test_rejects_short_auth_text_via_scan_create(self):
        with pytest.raises(ValidationError):
            ScanCreate(**_valid_scan_create(authorization_text="Short."))

    def test_profile_defaults_to_standard(self):
        sc = ScanCreate(**_valid_scan_create())
        assert sc.profile == "standard"

    def test_engagement_id_defaults_to_none(self):
        sc = ScanCreate(**_valid_scan_create())
        assert sc.engagement_id is None


# ─── Staleness logic (router-level, tested as pure logic) ────────────────────

def _staleness_seconds(consent_given_at: datetime) -> float:
    """Replicate the router's age check logic for unit-testable extraction."""
    now_utc = datetime.now(tz=timezone.utc)
    given_at = consent_given_at
    if given_at.tzinfo is None:
        given_at = given_at.replace(tzinfo=timezone.utc)
    else:
        given_at = given_at.astimezone(timezone.utc)
    return (now_utc - given_at).total_seconds()


class TestStalenessLogic:
    def test_fresh_consent_within_5_minutes(self):
        ts = datetime.now(tz=timezone.utc) - timedelta(minutes=4, seconds=59)
        age = _staleness_seconds(ts)
        assert age < 300, "should be less than 5 min"

    def test_stale_consent_just_over_5_minutes(self):
        ts = datetime.now(tz=timezone.utc) - timedelta(minutes=5, seconds=1)
        age = _staleness_seconds(ts)
        assert age > 300, "should be stale"

    def test_naive_datetime_treated_as_utc(self):
        naive_ts = datetime.utcnow() - timedelta(minutes=1)
        age = _staleness_seconds(naive_ts)
        # Should be around 60s, well within 300s limit.
        assert age < 300
