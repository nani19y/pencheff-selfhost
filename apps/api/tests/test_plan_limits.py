import pytest

from pencheff_api.services.quota import PLAN_LIMITS


@pytest.mark.parametrize("plan", ["free", "pro", "team", "self_hosted"])
def test_every_plan_has_unlimited_non_ai_capacity(plan: str) -> None:
    """All non-AI capacity is free for every plan; the only thing Pro adds
    is the LLM-powered features (gated in services.ai_gate, not here)."""
    lim = PLAN_LIMITS[plan]
    assert lim["workspaces"] >= 100
    assert lim["seats"] >= 100
    assert lim["targets_per_ws"] >= 100
    assert lim["scans_per_month_per_ws"] >= 1000


def test_invite_token_hash_is_deterministic_and_length_stable():
    from pencheff_api.services.invites import generate_token, hash_token

    raw, hashed = generate_token()
    assert hash_token(raw) == hashed
    assert len(hashed) == 64  # sha256 hex
    assert raw != hashed
