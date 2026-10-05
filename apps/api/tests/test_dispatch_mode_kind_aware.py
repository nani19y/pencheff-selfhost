"""Unit tests for dispatch_mode kind-aware extensions (feature 001).

Verifies:
* Backwards-compat: legacy 2-arg ``resolve_dispatch_mode(session, org_id)`` keeps
  working (used by call sites that haven't been migrated).
* New 3-arg form ``resolve_dispatch_mode(session, org_id, target_kind)`` adds:
    - Org.force_deterministic_only short-circuit (precedence #1)
    - Unknown kind → deterministic_only (precedence #2)
    - AGENT_FALLBACK_LLM_* OR AGENT_LLM_* preference (precedence #3)
* The new primary preference: AGENT_FALLBACK_LLM_* is enough on its own to
  enable agent mode (no need for AGENT_LLM_*).
* AC-0.2 (fallback path): force_deterministic_only=True always returns
  deterministic_only regardless of plan / quota / beta override.
"""
from __future__ import annotations

import pytest

from pencheff_api.services.dispatch_mode import (
    _KIND_SUPPORTS_AGENT,
    _has_any_agent_key,
    resolve_dispatch_mode,
)


# ----------------------------------------------------------------------------
# Fakes
# ----------------------------------------------------------------------------


class _FakeRow:
    def __init__(self, plan: str | None, used: int, force_deterministic_only: bool) -> None:
        self.plan = plan
        self.option_3_scans_used = used
        self.force_deterministic_only = force_deterministic_only


class _FakeResult:
    def __init__(self, row) -> None:
        self._row = row

    def one_or_none(self):
        return self._row


class _FakeSession:
    """Minimal AsyncSession stand-in: ``.execute`` returns whatever row was set."""
    def __init__(self, row=None) -> None:
        self._row = row

    async def execute(self, stmt):
        return _FakeResult(self._row)


class _FakeSettings:
    def __init__(
        self,
        *,
        agent_llm_api_key: str = "",
        agent_fallback_llm_api_key: str = "",
        agent_dispatch_beta_override: bool = False,
        free_plan_option_3_quota: int = 10,
    ) -> None:
        self.agent_llm_api_key = agent_llm_api_key
        self.agent_fallback_llm_api_key = agent_fallback_llm_api_key
        self.agent_dispatch_beta_override = agent_dispatch_beta_override
        self.free_plan_option_3_quota = free_plan_option_3_quota


# ----------------------------------------------------------------------------
# _has_any_agent_key — pure
# ----------------------------------------------------------------------------


def test_has_any_agent_key_when_neither_set() -> None:
    assert _has_any_agent_key(_FakeSettings()) is False


def test_has_any_agent_key_when_only_legacy_set() -> None:
    assert _has_any_agent_key(_FakeSettings(agent_llm_api_key="x")) is True


def test_has_any_agent_key_when_only_new_primary_set() -> None:
    assert _has_any_agent_key(_FakeSettings(agent_fallback_llm_api_key="x")) is True


def test_has_any_agent_key_when_both_set() -> None:
    assert _has_any_agent_key(
        _FakeSettings(agent_llm_api_key="x", agent_fallback_llm_api_key="y")
    ) is True


# ----------------------------------------------------------------------------
# _KIND_SUPPORTS_AGENT — coverage check
# ----------------------------------------------------------------------------


def test_kind_supports_agent_includes_all_15_kinds() -> None:
    expected = {
        "url", "repo", "llm",
        "web_app", "rest_api", "graphql", "websocket", "grpc",
        "source_code", "cicd_pipeline", "iac",
        "container_image", "k8s_cluster",
        "package_registry", "sbom",
    }
    assert _KIND_SUPPORTS_AGENT == expected


# ----------------------------------------------------------------------------
# resolve_dispatch_mode — backwards-compat (legacy 2-arg signature)
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_legacy_2arg_no_keys_returns_deterministic_only(monkeypatch) -> None:
    monkeypatch.setattr(
        "pencheff_api.services.dispatch_mode.get_settings",
        lambda: _FakeSettings(),
    )
    mode = await resolve_dispatch_mode(_FakeSession(row=("free", 0)), "org-id")
    assert mode == "deterministic_only"


@pytest.mark.asyncio
async def test_legacy_2arg_with_legacy_key_and_paid_plan(monkeypatch) -> None:
    monkeypatch.setattr(
        "pencheff_api.services.dispatch_mode.get_settings",
        lambda: _FakeSettings(agent_llm_api_key="x"),
    )
    mode = await resolve_dispatch_mode(_FakeSession(row=("pro", 0)), "org-id")
    assert mode == "deterministic_then_agent"


# ----------------------------------------------------------------------------
# resolve_dispatch_mode — new 3-arg form
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_force_deterministic_only_short_circuits(monkeypatch) -> None:
    """AC-0.2: Org.force_deterministic_only=True beats every other check."""
    monkeypatch.setattr(
        "pencheff_api.services.dispatch_mode.get_settings",
        lambda: _FakeSettings(
            agent_fallback_llm_api_key="x",
            agent_dispatch_beta_override=True,  # would otherwise win
        ),
    )
    row = _FakeRow(plan="pro", used=0, force_deterministic_only=True)
    mode = await resolve_dispatch_mode(_FakeSession(row=row), "org-id", target_kind="web_app")
    assert mode == "deterministic_only"


@pytest.mark.asyncio
async def test_unknown_kind_returns_deterministic_only(monkeypatch) -> None:
    """Defensive: unknown Target.kind values don't reach the agent path."""
    monkeypatch.setattr(
        "pencheff_api.services.dispatch_mode.get_settings",
        lambda: _FakeSettings(agent_fallback_llm_api_key="x"),
    )
    row = _FakeRow(plan="pro", used=0, force_deterministic_only=False)
    mode = await resolve_dispatch_mode(_FakeSession(row=row), "org-id", target_kind="not_a_kind")
    assert mode == "deterministic_only"


@pytest.mark.asyncio
async def test_new_primary_key_alone_enables_agent(monkeypatch) -> None:
    """AGENT_FALLBACK_LLM_API_KEY is enough — no need for AGENT_LLM_API_KEY."""
    monkeypatch.setattr(
        "pencheff_api.services.dispatch_mode.get_settings",
        lambda: _FakeSettings(
            agent_fallback_llm_api_key="x",
            agent_dispatch_beta_override=True,
        ),
    )
    row = _FakeRow(plan="free", used=0, force_deterministic_only=False)
    mode = await resolve_dispatch_mode(_FakeSession(row=row), "org-id", target_kind="web_app")
    assert mode == "deterministic_then_agent"


@pytest.mark.asyncio
async def test_legacy_key_alone_still_works(monkeypatch) -> None:
    """Pre-feature deployments (only AGENT_LLM_API_KEY set) continue working."""
    monkeypatch.setattr(
        "pencheff_api.services.dispatch_mode.get_settings",
        lambda: _FakeSettings(
            agent_llm_api_key="x",
            agent_dispatch_beta_override=True,
        ),
    )
    row = _FakeRow(plan="free", used=0, force_deterministic_only=False)
    mode = await resolve_dispatch_mode(_FakeSession(row=row), "org-id", target_kind="web_app")
    assert mode == "deterministic_then_agent"


@pytest.mark.asyncio
async def test_no_keys_returns_deterministic_only(monkeypatch) -> None:
    monkeypatch.setattr(
        "pencheff_api.services.dispatch_mode.get_settings",
        lambda: _FakeSettings(),
    )
    row = _FakeRow(plan="pro", used=0, force_deterministic_only=False)
    mode = await resolve_dispatch_mode(_FakeSession(row=row), "org-id", target_kind="web_app")
    assert mode == "deterministic_only"


@pytest.mark.asyncio
async def test_free_plan_post_quota_returns_agent_only(monkeypatch) -> None:
    """Free plan exhausted Option-3 quota with beta override off → agent_only."""
    monkeypatch.setattr(
        "pencheff_api.services.dispatch_mode.get_settings",
        lambda: _FakeSettings(
            agent_fallback_llm_api_key="x",
            agent_dispatch_beta_override=False,
            free_plan_option_3_quota=10,
        ),
    )
    row = _FakeRow(plan="free", used=10, force_deterministic_only=False)
    mode = await resolve_dispatch_mode(_FakeSession(row=row), "org-id", target_kind="web_app")
    assert mode == "agent_only"


@pytest.mark.asyncio
async def test_free_plan_within_quota_returns_deterministic_then_agent(monkeypatch) -> None:
    monkeypatch.setattr(
        "pencheff_api.services.dispatch_mode.get_settings",
        lambda: _FakeSettings(
            agent_fallback_llm_api_key="x",
            agent_dispatch_beta_override=False,
            free_plan_option_3_quota=10,
        ),
    )
    row = _FakeRow(plan="free", used=3, force_deterministic_only=False)
    mode = await resolve_dispatch_mode(_FakeSession(row=row), "org-id", target_kind="web_app")
    assert mode == "deterministic_then_agent"
