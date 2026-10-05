"""Unit tests for the server-side discipline-default applier in
``apps/api/pencheff_api/routers/targets.py::_apply_discipline_defaults``.

The applier runs at POST + PATCH so an FE bypass can't disable a discipline's
safety floor. We cover:
  * KSPM/KIEM force rbac_enum + network_policy_audit on a k8s_cluster config.
  * AI Red Teaming seeds aggressive strategies + the harmbench dataset.
  * AI-SPM seeds the guardrail set (pii / secrets / unsafe-code / tool-authz).
  * Existing user values are preserved (union, not replace).
"""
from __future__ import annotations

from pencheff_api.routers.targets import _apply_discipline_defaults


def test_kspm_forces_rbac_and_netpol_on() -> None:
    kc = {
        "kind": "k8s_cluster",
        "target": "on_prem",
        "rbac_enum": False,            # user tried to turn it off
        "network_policy_audit": False,
        "namespaces": ["default"],
    }
    new_kc, _ = _apply_discipline_defaults(["kspm"], kc, None)
    assert new_kc["rbac_enum"] is True
    assert new_kc["network_policy_audit"] is True
    # Other keys unchanged.
    assert new_kc["namespaces"] == ["default"]


def test_kiem_forces_rbac_and_netpol_on() -> None:
    kc = {"kind": "k8s_cluster", "target": "on_prem", "rbac_enum": False, "network_policy_audit": False}
    new_kc, _ = _apply_discipline_defaults(["kiem"], kc, None)
    assert new_kc["rbac_enum"] is True
    assert new_kc["network_policy_audit"] is True


def test_kspm_ignored_on_non_k8s_config() -> None:
    """If kind_config isn't a k8s_cluster, the applier no-ops gracefully —
    the schema validator already forbids the mismatch at the Pydantic layer,
    but the helper should be defensive too."""
    kc = {"kind": "web_app", "crawl_depth": 3}
    new_kc, _ = _apply_discipline_defaults(["kspm"], kc, None)
    # No new keys added, no existing keys lost.
    assert new_kc == kc


def test_ai_redteam_unions_strategies_and_datasets() -> None:
    """The applier unions defaults into existing values — it must NOT clobber
    a user's pre-existing list."""
    llm = {
        "provider": "openai-chat",
        "redteam": {
            "strategies": ["custom-strategy"],
            "datasets": ["beavertails"],
        },
    }
    _, new_llm = _apply_discipline_defaults(["ai_redteam"], None, llm)
    s = new_llm["redteam"]["strategies"]
    d = new_llm["redteam"]["datasets"]
    # User's value preserved first
    assert s[0] == "custom-strategy"
    assert "beavertails" in d
    # Aggressive defaults appended
    for must in ("jailbreak", "crescendo", "base64", "leetspeak"):
        assert must in s, f"missing {must}"
    assert "harmbench" in d


def test_ai_redteam_seeds_when_no_existing_redteam_block() -> None:
    """When llm_config has no redteam block, the applier creates one."""
    llm = {"provider": "openai-chat"}
    _, new_llm = _apply_discipline_defaults(["ai_redteam"], None, llm)
    assert "redteam" in new_llm
    assert "jailbreak" in new_llm["redteam"]["strategies"]


def test_ai_spm_unions_guardrails() -> None:
    llm = {"provider": "openai-chat", "redteam": {"guardrails": ["bias"]}}
    _, new_llm = _apply_discipline_defaults(["ai_spm"], None, llm)
    g = new_llm["redteam"]["guardrails"]
    assert g[0] == "bias"  # user value preserved first
    for must in ("pii", "secrets", "unsafe-code", "tool-authz"):
        assert must in g


def test_combined_disciplines_compose() -> None:
    """A llm Target tagged with BOTH ai_redteam and ai_spm gets both effects."""
    _, new_llm = _apply_discipline_defaults(
        ["ai_redteam", "ai_spm"], None, {"provider": "openai-chat"},
    )
    rt = new_llm["redteam"]
    assert "jailbreak" in rt["strategies"]
    assert "pii" in rt["guardrails"]
    assert "harmbench" in rt["datasets"]


def test_no_disciplines_is_noop() -> None:
    kc = {"kind": "k8s_cluster", "rbac_enum": False}
    llm = {"provider": "openai-chat"}
    new_kc, new_llm = _apply_discipline_defaults([], kc, llm)
    assert new_kc == kc
    assert new_llm == llm
