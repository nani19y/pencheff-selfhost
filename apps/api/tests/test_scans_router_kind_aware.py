"""Unit tests for the kind-aware helpers added to routers/scans.py
(feature 001-multi-target-scan-pipelines).

Covered:
* ``_required_disclosed_actions(target)`` returns the kind's base disclosed-
  actions set, extended by Phase B disclosures when ``kind_config`` implies
  live-system probing (per spec §10.6 + GATE 2 S-03).
* ``_derive_kind_payload(target, override)`` returns NULL for legacy kinds,
  returns the discriminator + merged override for new kinds.
"""
from __future__ import annotations

import pytest

from pencheff_api.routers.scans import (
    _derive_kind_payload,
    _required_disclosed_actions,
)
from pencheff_api.schemas.scans import KIND_REQUIRED_DISCLOSED_ACTIONS


class _FakeTarget:
    def __init__(self, kind: str, kind_config: dict | None = None) -> None:
        self.kind = kind
        self.kind_config = kind_config


# ----------------------------------------------------------------------------
# _required_disclosed_actions
# ----------------------------------------------------------------------------


def test_required_actions_for_legacy_url_kind() -> None:
    actions = _required_disclosed_actions(_FakeTarget("url"))
    assert actions == frozenset({"passive_recon", "active_recon", "exploitation"})


def test_required_actions_for_web_app() -> None:
    actions = _required_disclosed_actions(_FakeTarget("web_app"))
    assert "passive_recon" in actions
    assert "active_recon" in actions
    assert "exploitation" in actions


def test_required_actions_for_container_image() -> None:
    actions = _required_disclosed_actions(_FakeTarget("container_image"))
    assert "image_pull" in actions
    assert "container_scan" in actions


def test_required_actions_for_source_code() -> None:
    actions = _required_disclosed_actions(_FakeTarget("source_code"))
    assert "clone_repo" in actions
    assert "source_code_scan" in actions


def test_required_actions_for_cicd_pipeline_phase_a_only() -> None:
    """live_api_enabled=False (default) → Phase A only → no live-API action."""
    actions = _required_disclosed_actions(_FakeTarget(
        "cicd_pipeline", kind_config={"kind": "cicd_pipeline", "provider": "github_actions"}
    ))
    assert "ci_config_audit" in actions
    assert "ci_api_read" not in actions


def test_required_actions_for_cicd_pipeline_phase_b() -> None:
    """live_api_enabled=True → Phase A+B → ci_api_read appended."""
    actions = _required_disclosed_actions(_FakeTarget(
        "cicd_pipeline",
        kind_config={"kind": "cicd_pipeline", "provider": "github_actions",
                     "live_api_enabled": True},
    ))
    assert "ci_config_audit" in actions
    assert "ci_api_read" in actions


def test_required_actions_for_k8s_manifests_only() -> None:
    actions = _required_disclosed_actions(_FakeTarget(
        "k8s_cluster", kind_config={"kind": "k8s_cluster", "target": "manifests_only"}
    ))
    assert "k8s_manifest_scan" in actions
    assert "k8s_api_read" not in actions
    assert "rbac_enumeration" not in actions


def test_required_actions_for_k8s_live_cluster_with_rbac() -> None:
    actions = _required_disclosed_actions(_FakeTarget(
        "k8s_cluster",
        kind_config={
            "kind": "k8s_cluster",
            "target": "live_cluster",
            "rbac_enum": True,
        },
    ))
    assert "k8s_manifest_scan" in actions
    assert "k8s_api_read" in actions
    assert "rbac_enumeration" in actions


def test_required_actions_for_k8s_live_cluster_without_rbac() -> None:
    actions = _required_disclosed_actions(_FakeTarget(
        "k8s_cluster",
        kind_config={
            "kind": "k8s_cluster",
            "target": "live_cluster",
            "rbac_enum": False,
        },
    ))
    assert "k8s_api_read" in actions
    assert "rbac_enumeration" not in actions


def test_kind_required_disclosed_actions_covers_every_target_kind() -> None:
    """Every Target.kind value must have a disclosed_actions entry."""
    expected = {
        "url", "repo", "llm",
        "web_app", "rest_api", "graphql", "websocket", "grpc",
        "source_code", "cicd_pipeline", "iac",
        "container_image", "k8s_cluster",
        "package_registry", "sbom",
        "cloud_account", "serverless_function", "cloud_storage",
        "load_balancer_cdn", "cloud_database", "secrets_manager",
        "host",  # sub-project A
        "mcp",   # MCP target (spec 2026-06-16)
        "agent",  # AI agent target (split from mcp, spec 2026-06-16)
        "rag",   # RAG / vector-DB target
        "ml_model",  # ML model artifact target (spec 2026-06-17)
        "voice",  # Voice / Speech-AI target (spec 2026-06-17)
        "android_app", "ios_app",  # Mobile artifacts (spec 002)
        "browser_extension", "desktop_app",  # Client artifacts (spec 002)
        "firmware", "iot_device", "ot_ics_scada",  # OT/IoT firmware (spec 003)
    }
    assert expected == set(KIND_REQUIRED_DISCLOSED_ACTIONS.keys())


# ----------------------------------------------------------------------------
# FE ↔ backend disclosure-vocabulary contract
# ----------------------------------------------------------------------------

# Mirror of REQUIRED_ACTION_IDS_BY_KIND in
# apps/web/lib/consent-disclosures.ts — what the commission modal actually
# sends in ConsentPayload.disclosed_actions. If the backend's
# KIND_REQUIRED_DISCLOSED_ACTIONS expects an ID that's NOT in the FE's
# vocabulary, every modal-submitted scan for that kind 400-errors. This
# test catches the drift.
_FRONTEND_DISCLOSED_ACTION_IDS_BY_KIND: dict[str, set[str]] = {
    "url":              {"passive_recon", "active_recon", "exploitation"},
    "repo":             {"source_code_scan"},
    "llm":              {"llm_red_team_prompts"},
    "web_app":          {"passive_recon", "active_recon", "exploitation"},
    "rest_api":         {"passive_recon", "api_fuzzing", "exploitation"},
    "graphql":          {"introspection_query", "api_fuzzing", "exploitation"},
    "websocket":        {"ws_handshake", "api_fuzzing", "exploitation"},
    "grpc":             {"grpc_reflection", "api_fuzzing", "exploitation"},
    "source_code":      {"source_code_scan", "clone_repo"},
    "iac":              {"iac_scan", "clone_repo"},
    "container_image":  {"image_pull", "container_scan"},
    "package_registry": {"dependency_scan", "registry_query"},
    "sbom":             {"sbom_scan", "vuln_db_query"},
    "cicd_pipeline":    {"ci_config_audit"},
    "k8s_cluster":      {"k8s_manifest_scan"},
    "mcp": {"mcp_enumerate", "mcp_tool_invocation", "mcp_destructive_tool_invocation"},
    "rag": {"rag_enumerate", "rag_query_probe", "rag_poison_injection"},
    "ml_model": {"ml_fetch"},
    "voice": {"voice_enumerate", "voice_audio_probe", "voice_auth_probe"},
}


@pytest.mark.parametrize("kind", sorted(_FRONTEND_DISCLOSED_ACTION_IDS_BY_KIND.keys()))
def test_frontend_disclosure_vocabulary_satisfies_backend(kind: str) -> None:
    """The FE's REQUIRED_ACTION_IDS_BY_KIND (mirrored above) must cover the
    backend's KIND_REQUIRED_DISCLOSED_ACTIONS for every kind — otherwise the
    commission modal sends consent that the router will 400-reject.

    If this test fails after a backend edit, update
    apps/web/lib/consent-disclosures.ts::REQUIRED_ACTION_IDS_BY_KIND to
    match — then update this mirror.
    """
    fe = _FRONTEND_DISCLOSED_ACTION_IDS_BY_KIND[kind]
    be = set(KIND_REQUIRED_DISCLOSED_ACTIONS[kind])
    missing = be - fe
    assert not missing, (
        f"FE consent-disclosures.ts is missing action IDs for kind={kind!r}: "
        f"{sorted(missing)}. The router will 400 every modal-submitted scan "
        f"of this kind. Fix apps/web/lib/consent-disclosures.ts."
    )


# ----------------------------------------------------------------------------
# _derive_kind_payload
# ----------------------------------------------------------------------------


def test_derive_payload_returns_none_for_legacy_url() -> None:
    assert _derive_kind_payload(_FakeTarget("url"), None) is None


def test_derive_payload_returns_none_for_legacy_llm() -> None:
    assert _derive_kind_payload(_FakeTarget("llm"), None) is None


def test_derive_payload_returns_none_for_legacy_repo() -> None:
    assert _derive_kind_payload(_FakeTarget("repo"), None) is None


def test_derive_payload_returns_none_for_source_code() -> None:
    """source_code uses RepoScan, not Scan — no kind_payload row."""
    assert _derive_kind_payload(_FakeTarget("source_code"), None) is None


def test_derive_payload_web_app_no_override() -> None:
    payload = _derive_kind_payload(_FakeTarget("web_app"), None)
    assert payload == {"kind": "web_app"}


def test_derive_payload_container_image_with_digest_override() -> None:
    payload = _derive_kind_payload(
        _FakeTarget("container_image"),
        override={"kind": "container_image", "digest_override": "sha256:deadbeef"},
    )
    assert payload == {"kind": "container_image", "digest_override": "sha256:deadbeef"}


def test_derive_payload_override_kind_field_ignored() -> None:
    """The 'kind' field in override is replaced with target.kind, not honoured
    blindly. (Discriminator-match enforcement happens at the router-level
    before _derive_kind_payload runs.)"""
    payload = _derive_kind_payload(
        _FakeTarget("web_app"),
        override={"kind": "should_be_ignored", "crawl_depth_override": 5},
    )
    assert payload["kind"] == "web_app"
    assert payload["crawl_depth_override"] == 5


def test_mcp_base_required_action_is_enumerate() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions

    class _T:
        kind = "mcp"
        kind_config = {"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"]}

    actions = _required_disclosed_actions(_T())
    assert actions == {"mcp_enumerate"}


def test_mcp_dynamic_invocation_adds_tool_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions

    class _T:
        kind = "mcp"
        kind_config = {"kind": "mcp", "source_type": "mcp_stdio",
                       "command": ["x"], "dynamic_invocation": True}

    actions = _required_disclosed_actions(_T())
    assert "mcp_enumerate" in actions
    assert "mcp_tool_invocation" in actions
    assert "mcp_destructive_tool_invocation" not in actions


def test_mcp_destructive_opt_in_adds_destructive_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions

    class _T:
        kind = "mcp"
        kind_config = {"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"],
                       "dynamic_invocation": True, "destructive_opt_in": True}

    actions = _required_disclosed_actions(_T())
    assert "mcp_destructive_tool_invocation" in actions


def test_mcp_destructive_without_dynamic_does_not_add_destructive() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions

    class _T:
        kind = "mcp"
        kind_config = {"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"],
                       "destructive_opt_in": True}  # dynamic_invocation absent/False

    actions = _required_disclosed_actions(_T())
    assert "mcp_destructive_tool_invocation" not in actions
    assert "mcp_tool_invocation" not in actions


def test_rag_base_required_action_is_enumerate() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "rag"
        kind_config = {"kind": "rag", "source_type": "managed_vdb", "provider": "qdrant", "url": "https://q"}
    assert _required_disclosed_actions(_T()) == {"rag_enumerate"}


def test_rag_query_probes_adds_query_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "rag"
        kind_config = {"kind": "rag", "source_type": "managed_vdb", "provider": "qdrant",
                       "url": "https://q", "query_probes": True}
    a = _required_disclosed_actions(_T())
    assert "rag_query_probe" in a and "rag_poison_injection" not in a


def test_rag_poison_injection_adds_destructive_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "rag"
        kind_config = {"kind": "rag", "source_type": "managed_vdb", "provider": "qdrant", "url": "https://q",
                       "query_probes": True, "poison_injection_opt_in": True}
    a = _required_disclosed_actions(_T())
    assert "rag_poison_injection" in a


def test_ml_model_required_action_is_fetch() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "ml_model"
        kind_config = {"kind": "ml_model", "source_type": "huggingface", "hf_repo": "o/m"}
    assert _required_disclosed_actions(_T()) == {"ml_fetch"}


def test_voice_static_only_requires_enumerate() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "voice"
        kind_config = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/x"}
    assert _required_disclosed_actions(_T()) == {"voice_enumerate"}


def test_voice_audio_probes_adds_audio_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "voice"
        kind_config = {"kind": "voice", "source_type": "voice_bot", "url": "https://h/x", "audio_probes": True}
    assert _required_disclosed_actions(_T()) == {"voice_enumerate", "voice_audio_probe"}


def test_voice_auth_source_with_audio_probes_adds_auth_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "voice"
        kind_config = {"kind": "voice", "source_type": "voice_auth", "url": "https://h/x", "audio_probes": True}
    assert _required_disclosed_actions(_T()) == {"voice_enumerate", "voice_audio_probe", "voice_auth_probe"}
