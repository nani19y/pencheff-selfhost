"""Unit tests for KindConfig + KindCredentials discriminated unions and the
TargetCreate / TargetUpdate cross-kind validators (feature 001).

Verifies:
* Each of the 12 new KindConfig variants validates a happy-path instance.
* ``extra="forbid"`` rejects unknown fields (GATE 2 finding B-003).
* Inter-field validators fire (graphql.schema_sdl when introspection off,
  grpc.proto_files when reflection off, k8s_cluster.manifests_archive_url
  when target="manifests_only", sbom content-XOR-url, source_code.repo_url
  for github_url/tarball_url).
* TargetCreate cross-kind rules: new kinds REQUIRE kind_config; legacy
  kinds reject kind_config; kind_config.kind must match Target.kind.
* TargetCreate kind_credentials rules: only allowed for the 4 supported
  kinds; discriminator must match Target.kind.
* Legacy kind="url"/"repo"/"llm" rows continue working unchanged
  (backward-compat for AC-0.3).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from pencheff_api.schemas.targets import (
    DISCIPLINE_TO_KINDS,
    CicdCreds,
    CicdPipelineConfig,
    CloudAccountConfig,
    CloudDatabaseConfig,
    CloudStorageConfig,
    ContainerImageConfig,
    GraphqlConfig,
    GrpcConfig,
    IacConfig,
    K8sClusterConfig,
    K8sCreds,
    KubeconfigCreds,
    LoadBalancerCdnConfig,
    LlmConfig,
    McpConfig,
    MemoryKindConfig,
    MlModelConfig,
    PackageRegistryConfig,
    RagConfig,
    RegistryCreds,
    RestApiConfig,
    SbomConfig,
    SecretsManagerConfig,
    ServerlessFunctionConfig,
    SourceCodeConfig,
    SourceCodeCreds,
    TargetCreate,
    WebAppConfig,
    WebsocketConfig,
    VoiceConfig,
    GrpcConfig as _GrpcConfig,  # alias for clarity in tests
)


# ============================================================================
# Per-kind happy-path validation
# ============================================================================

def test_web_app_config_happy_path() -> None:
    cfg = WebAppConfig(crawl_depth=5, max_pages=200, browser_render=False)
    assert cfg.kind == "web_app"
    assert cfg.crawl_depth == 5
    assert cfg.max_pages == 200
    assert cfg.api_spec_url is None


def test_rest_api_config_happy_path() -> None:
    cfg = RestApiConfig(api_spec={"openapi": "3.0.0", "paths": {}})
    assert cfg.kind == "rest_api"
    assert cfg.api_spec_format == "auto"


def test_graphql_config_introspection_enabled_default() -> None:
    cfg = GraphqlConfig()
    assert cfg.kind == "graphql"
    assert cfg.introspection_enabled is True
    assert "query" in cfg.operations_to_test
    assert "mutation" in cfg.operations_to_test


def test_graphql_config_introspection_off_requires_sdl() -> None:
    with pytest.raises(ValidationError, match="schema_sdl"):
        GraphqlConfig(introspection_enabled=False)


def test_graphql_config_introspection_off_with_sdl_ok() -> None:
    cfg = GraphqlConfig(introspection_enabled=False, schema_sdl="type Query { ping: String }")
    assert cfg.schema_sdl is not None


def test_websocket_config_happy_path() -> None:
    cfg = WebsocketConfig(subprotocols=["graphql-ws"], origin_header="https://example.com")
    assert cfg.kind == "websocket"


def test_grpc_config_reflection_off_requires_proto() -> None:
    with pytest.raises(ValidationError, match="proto_files"):
        GrpcConfig(reflection_enabled=False)


def test_grpc_config_reflection_off_with_proto_ok() -> None:
    cfg = GrpcConfig(reflection_enabled=False, proto_files=["syntax = 'proto3';"])
    assert cfg.proto_files is not None


def test_source_code_config_github_url_requires_repo_url() -> None:
    with pytest.raises(ValidationError, match="repo_url"):
        SourceCodeConfig(source="github_url")


def test_source_code_config_github_url_with_repo_url_ok() -> None:
    cfg = SourceCodeConfig(source="github_url", repo_url="https://github.com/x/y")
    assert cfg.kind == "source_code"
    assert str(cfg.repo_url).startswith("https://github.com")


def test_source_code_config_github_app_does_not_require_repo_url() -> None:
    # github_app pulls repo via App install; URL not required.
    cfg = SourceCodeConfig(source="github_app")
    assert cfg.repo_url is None


def test_cicd_pipeline_config_happy_path() -> None:
    cfg = CicdPipelineConfig(provider="github_actions", repo_url="https://github.com/x/y")
    assert cfg.kind == "cicd_pipeline"
    assert cfg.live_api_enabled is False


def test_iac_config_happy_path() -> None:
    cfg = IacConfig(frameworks=["terraform", "helm"])
    assert cfg.kind == "iac"
    assert "terraform" in cfg.frameworks


def test_container_image_config_requires_image_ref() -> None:
    with pytest.raises(ValidationError):
        ContainerImageConfig(image_ref="", registry="dockerhub")


def test_container_image_config_happy_path() -> None:
    cfg = ContainerImageConfig(image_ref="alpine:3.10", registry="dockerhub")
    assert cfg.kind == "container_image"


def test_k8s_cluster_manifests_only_requires_archive_url() -> None:
    with pytest.raises(ValidationError, match="manifests_archive_url"):
        K8sClusterConfig(target="manifests_only")


def test_k8s_cluster_live_cluster_does_not_require_archive_url() -> None:
    cfg = K8sClusterConfig(target="live_cluster")
    assert cfg.manifests_archive_url is None


def test_package_registry_requires_non_empty_list() -> None:
    with pytest.raises(ValidationError):
        PackageRegistryConfig(ecosystem="npm", package_list=[])


def test_package_registry_happy_path() -> None:
    cfg = PackageRegistryConfig(
        ecosystem="npm",
        package_list=[{"name": "lodash", "version": "4.17.20"}],
    )
    assert cfg.kind == "package_registry"


def test_sbom_requires_content_or_url() -> None:
    with pytest.raises(ValidationError, match="content.*url|content or url"):
        SbomConfig(format="cyclonedx-json")


def test_sbom_rejects_both_content_and_url() -> None:
    with pytest.raises(ValidationError, match="content.*OR.*url|content OR url"):
        SbomConfig(format="cyclonedx-json", content="{}", url="https://example.com/sbom.json")


def test_sbom_with_content_ok() -> None:
    cfg = SbomConfig(format="cyclonedx-json", content='{"bomFormat":"CycloneDX"}')
    assert cfg.content is not None
    assert cfg.url is None


# ============================================================================
# extra="forbid" enforcement (GATE 2 finding B-003)
# ============================================================================

def test_kind_config_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError, match="extra"):
        WebAppConfig(crawl_depth=3, max_pages=100, browser_render=True, NOT_A_FIELD="x")


def test_kind_credentials_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError, match="extra"):
        KubeconfigCreds(kubeconfig="apiVersion: v1\nkind: Config", NOT_A_FIELD="x")


# ============================================================================
# TargetCreate cross-kind validators
# ============================================================================

def test_target_create_legacy_url_unchanged() -> None:
    """AC-0.3 — legacy url kind continues working with no kind_config."""
    tgt = TargetCreate(name="t", base_url="https://example.com", kind="url")
    assert tgt.kind == "url"
    assert tgt.kind_config is None


def test_target_create_legacy_llm_unchanged() -> None:
    """AC-0.3 — legacy llm kind continues using llm_config, not kind_config."""
    tgt = TargetCreate(
        name="t",
        base_url="https://api.example.com",
        kind="llm",
        llm_config=LlmConfig(provider="openai-chat", model="gpt-4"),
    )
    assert tgt.kind == "llm"
    assert tgt.kind_config is None
    assert tgt.llm_config is not None


def test_target_create_legacy_kind_rejects_kind_config() -> None:
    """kind_config is forbidden on url/repo/llm rows."""
    with pytest.raises(ValidationError, match="kind_config not allowed"):
        TargetCreate(
            name="t",
            base_url="https://example.com",
            kind="url",
            kind_config=WebAppConfig(),
        )


def test_target_create_new_kind_requires_kind_config() -> None:
    """The 11 new non-llm kinds REQUIRE kind_config."""
    with pytest.raises(ValidationError, match="requires kind_config"):
        TargetCreate(name="t", base_url="https://example.com", kind="web_app")


def test_target_create_kind_config_discriminator_must_match_kind() -> None:
    """kind_config.kind must equal Target.kind."""
    with pytest.raises(ValidationError, match="must match Target.kind"):
        TargetCreate(
            name="t",
            base_url="https://example.com",
            kind="web_app",
            kind_config=RestApiConfig(),  # discriminator says rest_api, not web_app
        )


def test_target_create_web_app_happy_path() -> None:
    tgt = TargetCreate(
        name="t",
        base_url="https://example.com",
        kind="web_app",
        kind_config=WebAppConfig(crawl_depth=5),
    )
    assert tgt.kind == "web_app"
    assert tgt.kind_config.kind == "web_app"
    assert tgt.kind_config.crawl_depth == 5


@pytest.mark.parametrize(
    "kind,base_url,cfg_factory",
    [
        ("container_image", "oci://alpine:3.10",
            lambda: ContainerImageConfig(image_ref="alpine:3.10")),
        ("websocket", "wss://realtime.example.com/socket",
            lambda: WebsocketConfig()),
        ("grpc", "grpc://example.com:443",
            lambda: GrpcConfig()),
        ("package_registry", "pkg://npm",
            lambda: PackageRegistryConfig(ecosystem="npm", package_list=[{"name": "express", "version": "4.0.0"}])),
        ("sbom", "sbom://cyclonedx-json",
            lambda: SbomConfig(format="cyclonedx-json", content='{"bomFormat":"CycloneDX","specVersion":"1.5"}')),
        ("iac", "iac://terraform",
            lambda: IacConfig(source="local_path")),
        ("k8s_cluster", "k8s://live/default",
            lambda: K8sClusterConfig(target="live_cluster")),
        ("source_code", "file:///opt/repo",
            lambda: SourceCodeConfig(source="local_path")),
    ],
)
def test_target_create_accepts_synthesised_base_url_schemes(kind, base_url, cfg_factory) -> None:
    """The artifact / hybrid / protocol kinds synthesise non-http schemes for
    base_url (e.g. ``oci://`` for container images, ``wss://`` for websocket,
    ``grpc://`` for gRPC, ``pkg://`` for package registries). Pydantic HttpUrl
    rejected those; base_url is intentionally ``str`` so kind-specific runner
    validation downstream owns the actual semantic check.
    """
    tgt = TargetCreate(
        name="t", base_url=base_url, kind=kind, kind_config=cfg_factory(),
    )
    assert tgt.base_url == base_url
    assert tgt.kind == kind


def test_target_create_k8s_with_kubeconfig_creds() -> None:
    tgt = TargetCreate(
        name="t",
        base_url="https://k8s.example.com",
        kind="k8s_cluster",
        kind_config=K8sClusterConfig(target="live_cluster"),
        kind_credentials=KubeconfigCreds(
            kubeconfig="apiVersion: v1\nkind: Config\nclusters: []\nusers: []\ncontexts: []",
        ),
    )
    assert tgt.kind_credentials is not None
    assert tgt.kind_credentials.kind == "k8s_cluster"


def test_target_create_kind_credentials_discriminator_must_match_kind() -> None:
    with pytest.raises(ValidationError, match="must match Target.kind"):
        TargetCreate(
            name="t",
            base_url="https://k8s.example.com",
            kind="k8s_cluster",
            kind_config=K8sClusterConfig(target="live_cluster"),
            kind_credentials=CicdCreds(provider="github_actions"),  # wrong discriminator
        )


def test_target_create_kind_credentials_unsupported_kind_blocked_by_discriminator() -> None:
    """The KindCredentials union only admits k8s_cluster/container_image/
    cicd_pipeline/source_code as discriminator values, so passing
    kind_credentials with a Target.kind outside that set is already blocked
    at the discriminator-match check (no separate validator needed)."""
    with pytest.raises(ValidationError, match="must match Target.kind"):
        TargetCreate(
            name="t",
            base_url="https://example.com",
            kind="web_app",
            kind_config=WebAppConfig(),
            kind_credentials=KubeconfigCreds(
                kubeconfig="apiVersion: v1\nkind: Config\nclusters: []\nusers: []\ncontexts: []",
            ),
        )


@pytest.mark.parametrize(
    "kind, base_url, cfg, llm_cfg",
    [
        ("url", "https://example.com", None, None),
        ("web_app", "https://example.com", WebAppConfig(), None),
        ("rest_api", "https://api.example.com", RestApiConfig(), None),
        ("graphql", "https://api.example.com/graphql", GraphqlConfig(), None),
        ("websocket", "wss://api.example.com/socket", WebsocketConfig(), None),
        ("grpc", "grpc://api.example.com:443", GrpcConfig(), None),
        (
            "llm",
            "https://api.example.com/v1/chat/completions",
            None,
            LlmConfig(provider="openai-chat", model="gpt-4"),
        ),
        (
            "mcp",
            "https://agents.example.com/mcp",
            McpConfig(
                source_type="mcp_http",
                url="https://agents.example.com/mcp",
                transport="streamable_http",
            ),
            None,
        ),
        (
            "rag",
            "rag://kb/example",
            RagConfig(
                source_type="managed_vdb",
                provider="pinecone",
                url="https://pinecone.example.com",
            ),
            None,
        ),
        (
            "ml_model",
            "https://models.example.com/fraud.pkl",
            MlModelConfig(
                source_type="file_url",
                url="https://models.example.com/fraud.pkl",
            ),
            None,
        ),
        (
            "voice",
            "https://voice.example.com/call",
            VoiceConfig(source_type="voice_bot", url="https://voice.example.com/call"),
            None,
        ),
        ("memory", "memory://mem0/default", MemoryKindConfig(), None),
        (
            "cloud_account",
            "aws://123456789012",
            CloudAccountConfig(provider="aws", account_id="123456789012"),
            None,
        ),
        (
            "serverless_function",
            "aws-lambda://us-east-1/example",
            ServerlessFunctionConfig(provider="aws", account_id="123456789012"),
            None,
        ),
        (
            "cloud_storage",
            "s3://example-bucket",
            CloudStorageConfig(provider="aws", account_id="123456789012"),
            None,
        ),
        (
            "load_balancer_cdn",
            "aws-elb://api-lb",
            LoadBalancerCdnConfig(provider="aws", account_id="123456789012"),
            None,
        ),
        (
            "cloud_database",
            "aws-rds://orders",
            CloudDatabaseConfig(provider="aws", account_id="123456789012"),
            None,
        ),
        (
            "secrets_manager",
            "aws-secrets://prod",
            SecretsManagerConfig(provider="aws", account_id="123456789012"),
            None,
        ),
    ],
)
def test_target_create_allows_attached_repos_for_runtime_security_targets(
    kind, base_url, cfg, llm_cfg,
) -> None:
    tgt = TargetCreate(
        name="t",
        base_url=base_url,
        kind=kind,
        kind_config=cfg,
        llm_config=llm_cfg,
        attached_repository_ids=["00000000-0000-0000-0000-000000000000"],
    )
    assert tgt.attached_repository_ids == ["00000000-0000-0000-0000-000000000000"]


def test_target_create_rejects_attached_repos_for_repository_artifact_targets() -> None:
    with pytest.raises(ValidationError, match="attached_repository_ids only valid"):
        TargetCreate(
            name="t",
            base_url="oci://example/app:latest",
            kind="container_image",
            kind_config=ContainerImageConfig(image_ref="example/app:latest"),
            attached_repository_ids=["00000000-0000-0000-0000-000000000000"],
        )


# ============================================================================
# Smoke: all 12 new kinds round-trip through TargetCreate
# ============================================================================

@pytest.mark.parametrize(
    "kind, cfg_factory",
    [
        ("web_app",          lambda: WebAppConfig()),
        ("rest_api",         lambda: RestApiConfig()),
        ("graphql",          lambda: GraphqlConfig()),
        ("websocket",        lambda: WebsocketConfig()),
        ("grpc",             lambda: GrpcConfig()),
        ("source_code",      lambda: SourceCodeConfig(source="github_app")),
        ("cicd_pipeline",    lambda: CicdPipelineConfig(provider="github_actions")),
        ("iac",              lambda: IacConfig()),
        ("container_image",  lambda: ContainerImageConfig(image_ref="alpine:3.10")),
        ("k8s_cluster",      lambda: K8sClusterConfig(target="live_cluster")),
        ("package_registry", lambda: PackageRegistryConfig(
            ecosystem="npm", package_list=[{"name": "lodash", "version": "4.17.20"}]
        )),
        ("sbom",             lambda: SbomConfig(format="cyclonedx-json", content='{"bomFormat":"CycloneDX"}')),
    ],
)
def test_all_new_kinds_round_trip(kind: str, cfg_factory) -> None:
    cfg = cfg_factory()
    assert cfg.kind == kind
    tgt = TargetCreate(name="t", base_url="https://example.com", kind=kind, kind_config=cfg)
    assert tgt.kind == kind
    assert tgt.kind_config.kind == kind


# ============================================================================
# K8sClusterConfig — multi-provider modes (2026-05-21)
# ============================================================================

def test_k8s_config_live_cluster_normalises_to_on_prem() -> None:
    """live_cluster is the deprecated alias of on_prem and gets rewritten
    server-side so downstream code only has to handle one value."""
    cfg = K8sClusterConfig(target="live_cluster")
    assert cfg.target == "on_prem"


def test_k8s_config_on_prem_does_not_require_archive_url() -> None:
    cfg = K8sClusterConfig(target="on_prem")
    assert cfg.manifests_archive_url is None


def test_k8s_config_aws_eks_requires_region_and_cluster_name() -> None:
    with pytest.raises(ValidationError, match="aws_region.*aws_cluster_name"):
        K8sClusterConfig(target="aws_eks")
    cfg = K8sClusterConfig(
        target="aws_eks", aws_region="us-east-1", aws_cluster_name="prod-eks",
    )
    assert cfg.aws_region == "us-east-1"


def test_k8s_config_azure_aks_requires_full_identifier_tuple() -> None:
    with pytest.raises(ValidationError, match="azure_subscription_id"):
        K8sClusterConfig(target="azure_aks", azure_resource_group="rg")
    cfg = K8sClusterConfig(
        target="azure_aks",
        azure_subscription_id="sub", azure_resource_group="rg", azure_cluster_name="aks",
    )
    assert cfg.azure_cluster_name == "aks"


def test_k8s_config_gcp_gke_requires_project_location_cluster() -> None:
    with pytest.raises(ValidationError, match="gcp_project_id"):
        K8sClusterConfig(target="gcp_gke", gcp_location="us-central1")
    cfg = K8sClusterConfig(
        target="gcp_gke", gcp_project_id="p", gcp_location="us-central1", gcp_cluster_name="c",
    )
    assert cfg.gcp_cluster_name == "c"


# ============================================================================
# K8sCreds — discriminated by provider (2026-05-21)
# ============================================================================

def test_k8s_creds_on_prem_default_provider_back_compat() -> None:
    """Rows persisted as ``{kind: 'k8s_cluster', kubeconfig: '...'}`` before
    the multi-provider rewrite must still parse. ``provider`` defaults to
    on_prem so the flat shape is accepted unchanged."""
    creds = K8sCreds(kubeconfig="apiVersion: v1\nkind: Config")
    assert creds.provider == "on_prem"


def test_k8s_creds_on_prem_requires_kubeconfig() -> None:
    with pytest.raises(ValidationError, match="kubeconfig"):
        K8sCreds(provider="on_prem")


def test_k8s_creds_aws_requires_access_key_and_secret() -> None:
    with pytest.raises(ValidationError, match="aws_access_key_id"):
        K8sCreds(provider="aws")
    creds = K8sCreds(
        provider="aws",
        aws_access_key_id="AKIA…", aws_secret_access_key="sek",
    )
    assert creds.provider == "aws"


def test_k8s_creds_azure_requires_sp_tuple() -> None:
    with pytest.raises(ValidationError, match="azure_tenant_id"):
        K8sCreds(provider="azure", azure_client_id="c", azure_client_secret="s")
    K8sCreds(
        provider="azure",
        azure_tenant_id="t", azure_client_id="c", azure_client_secret="s",
    )


def test_k8s_creds_gcp_requires_service_account_json() -> None:
    with pytest.raises(ValidationError, match="gcp_service_account_json"):
        K8sCreds(provider="gcp")
    K8sCreds(provider="gcp", gcp_service_account_json='{"type":"service_account"}')


def test_kubeconfig_creds_alias_still_imports_and_works() -> None:
    """The legacy name continues working — KubeconfigCreds is a re-export
    alias for K8sCreds so any external callers don't break."""
    assert KubeconfigCreds is K8sCreds
    KubeconfigCreds(kubeconfig="apiVersion: v1\nkind: Config")


# ============================================================================
# RegistryCreds — per-auth-type validation (2026-05-21)
# ============================================================================

def test_registry_creds_basic_requires_password() -> None:
    with pytest.raises(ValidationError, match="password_or_token"):
        RegistryCreds(registry_host="ghcr.io", auth_type="basic", username="u")


def test_registry_creds_ecr_sts_requires_aws_keys() -> None:
    with pytest.raises(ValidationError, match="aws_access_key_id"):
        RegistryCreds(registry_host="123.dkr.ecr.us-east-1.amazonaws.com", auth_type="ecr_sts")
    RegistryCreds(
        registry_host="123.dkr.ecr.us-east-1.amazonaws.com",
        auth_type="ecr_sts",
        aws_access_key_id="AKIA…",
        aws_secret_access_key="sek",
        aws_region="us-east-1",
    )


def test_registry_creds_gcr_service_account_requires_json() -> None:
    with pytest.raises(ValidationError, match="gcr_service_account_json"):
        RegistryCreds(registry_host="gcr.io", auth_type="gcr_service_account")


def test_registry_creds_acr_sp_requires_client_id_and_secret() -> None:
    with pytest.raises(ValidationError, match="acr_client_id"):
        RegistryCreds(registry_host="x.azurecr.io", auth_type="acr_sp")


def test_registry_creds_basic_happy_path() -> None:
    creds = RegistryCreds(
        registry_host="ghcr.io",
        auth_type="basic",
        username="someone",
        password_or_token="ghp_abc",
    )
    assert creds.auth_type == "basic"


# ============================================================================
# Disciplines — security-program tags on Target (2026-05-21)
# ============================================================================

def test_disciplines_default_empty_list() -> None:
    """Existing rows + clients omit disciplines → defaults to []."""
    t = TargetCreate(name="t", base_url="https://example.com", kind="url")
    assert t.disciplines == []


def test_disciplines_kspm_on_k8s_cluster_happy_path() -> None:
    t = TargetCreate(
        name="prod-eks",
        base_url="k8s://aws/us-east-1/prod",
        kind="k8s_cluster",
        kind_config=K8sClusterConfig(
            target="aws_eks",
            aws_region="us-east-1",
            aws_cluster_name="prod",
        ),
        disciplines=["kspm", "kiem"],
    )
    assert "kspm" in t.disciplines
    assert "kiem" in t.disciplines


def test_disciplines_dedup_preserves_order() -> None:
    t = TargetCreate(
        name="t",
        base_url="k8s://live/default",
        kind="k8s_cluster",
        kind_config=K8sClusterConfig(target="on_prem"),
        disciplines=["kspm", "kspm", "kiem", "kspm"],
    )
    assert t.disciplines == ["kspm", "kiem"]


def test_disciplines_reject_incompatible_kind() -> None:
    """KSPM only attaches to k8s_cluster — registering it on web_app should
    fail with a clear message."""
    with pytest.raises(ValidationError, match="discipline='kspm'"):
        TargetCreate(
            name="t",
            base_url="https://example.com",
            kind="web_app",
            kind_config=WebAppConfig(),
            disciplines=["kspm"],
        )


def test_disciplines_reject_unknown() -> None:
    """Pydantic's Literal validator catches the unknown discipline at the
    field level before our cross-validator runs."""
    with pytest.raises(ValidationError):
        TargetCreate(
            name="t",
            base_url="https://example.com",
            kind="url",
            disciplines=["totally-not-real"],
        )


def test_disciplines_aspm_fans_to_three_kinds() -> None:
    """ASPM is compatible with web_app, rest_api, and source_code."""
    for kind, cfg in [
        ("web_app", WebAppConfig()),
        ("rest_api", RestApiConfig()),
        ("source_code", SourceCodeConfig(source="local_path")),
    ]:
        TargetCreate(
            name="t",
            base_url="https://example.com",
            kind=kind,
            kind_config=cfg,
            disciplines=["aspm"],
        )


def test_disciplines_ai_redteam_only_on_llm() -> None:
    """AI Red Teaming attaches only to llm; other kinds reject it."""
    # Happy path
    TargetCreate(
        name="chat",
        base_url="https://api.openai.com/v1/chat/completions",
        kind="llm",
        llm_config=LlmConfig(provider="openai-chat", model="gpt-4"),
        disciplines=["ai_redteam"],
    )
    with pytest.raises(ValidationError, match="discipline='ai_redteam'"):
        TargetCreate(
            name="t",
            base_url="https://example.com",
            kind="url",
            disciplines=["ai_redteam"],
        )


def test_discipline_to_kinds_map_matches_active_kinds() -> None:
    """Every discipline maps to at least one kind that is registrable today
    (catches regressions where a discipline points to a removed kind)."""
    from pencheff_api.schemas.targets import TargetKind
    valid_kinds = set(TargetKind.__args__)
    for d, kinds in DISCIPLINE_TO_KINDS.items():
        assert kinds, f"{d!r} has no allowed kinds"
        for k in kinds:
            assert k in valid_kinds, f"{d!r} → unknown kind {k!r}"
