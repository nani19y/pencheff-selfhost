from datetime import datetime
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator


# Wire-value enum for ``targets.kind``. The 3 legacy values keep working
# unchanged; the 12 new values (feature 001-multi-target-scan-pipelines) each
# get their own JSONB config in ``Target.kind_config`` (or ``Target.llm_config``
# for the legacy ``llm`` kind). See specs/001-multi-target-scan-pipelines/spec.md
# §2 for the FE-typecard-id ↔ wire-kind mapping.
TargetKind = Literal[
    "url", "repo", "llm",
    "web_app", "rest_api", "graphql", "websocket", "grpc",
    "cloud_account", "serverless_function", "cloud_storage",
    "load_balancer_cdn", "cloud_database", "secrets_manager",
    "source_code", "cicd_pipeline", "iac",
    "container_image", "k8s_cluster",
    "package_registry", "sbom",
    "host",  # sub-project A — multi-host list for OS exploitation
    "tls_ssl",  # TLS/SSL config posture (protocols/ciphers/cert) — network group
    "dns",  # DNS records / zone transfer / subdomain enumeration — network group
    "email_security",  # SPF/DKIM/DMARC email-auth posture — network group
    "vpn",  # VPN / remote-access exposure (RDP/SSH/VNC/VPN ports) — network group
    "idp",  # Identity Provider — OIDC/OAuth/SAML config posture — identity group
    "data_store",  # Database / data store exposure + unauth access — identity group
    "memory",  # agent memory / vector-store items, scanned via /v1/memory/scan
    "mcp",  # MCP server / AI agent — source-aware scanner (see spec 2026-06-16)
    "agent",  # AI conversational agent endpoint (split from mcp, spec 2026-06-27)
    "rag",  # RAG / vector-DB target — source-aware scanner (see spec 2026-06-17)
    "ml_model",  # ML model artifact — statically scanned (never loaded) (see spec 2026-06-17)
    "voice",  # Voice / Speech-AI endpoint — source-aware scanner (see spec 2026-06-17)
    "android_app",  # Android APK/AAB — static analysis (never executed) (spec 002)
    "ios_app",  # iOS IPA — static analysis (never executed) (spec 002)
    "browser_extension",  # CRX/XPI — static analysis (spec 002)
    "desktop_app",  # Electron/Java/.NET/Qt — static analysis (spec 002)
    "firmware",  # Firmware/embedded image — static analysis (spec 003)
    "iot_device",  # IoT device firmware (camera/drone/vacuum/router) — static (spec 003)
    "ot_ics_scada",  # OT/ICS/SCADA controller firmware — static (spec 003)
]
# Kinds that REQUIRE ``Target.kind_config`` set on create (the 11 new non-llm
# kinds). The 3 legacy kinds reject ``kind_config``; ``llm`` continues to use
# the existing ``llm_config`` column.
_KINDS_REQUIRING_CONFIG: frozenset[str] = frozenset({
    "web_app", "rest_api", "graphql", "websocket", "grpc",
    "cloud_account", "serverless_function", "cloud_storage",
    "load_balancer_cdn", "cloud_database", "secrets_manager",
    "source_code", "cicd_pipeline", "iac",
    "container_image", "k8s_cluster",
    "package_registry", "sbom",
    "host",
    "memory",
    "mcp",
    "agent",
    "rag",
    "ml_model",
    "voice",
    "android_app",
    "ios_app",
    "browser_extension",
    "desktop_app",
    "firmware",
    "iot_device",
    "ot_ics_scada",
})
_LEGACY_KINDS: frozenset[str] = frozenset({"url", "repo", "llm"})
ATTACHABLE_REPOSITORY_TARGET_KINDS: frozenset[str] = frozenset({
    "url",
    "web_app", "rest_api", "graphql", "websocket", "grpc",
    "cloud_account", "serverless_function", "cloud_storage",
    "load_balancer_cdn", "cloud_database", "secrets_manager",
    "llm", "mcp", "agent", "rag", "ml_model", "voice", "memory",
})
LlmProvider = Literal[
    "openai-chat",
    "custom",
    "executable",
    "websocket",
    "bedrock",
    "vertex",
    "azure-openai",
    "browser",
    "sema4_agent",  # Sema4 conversational worker-agent (create-conversation → post → poll)
]


class Credentials(BaseModel):
    username: str | None = None
    password: str | None = None
    api_key: str | None = None
    token: str | None = None
    cookie: str | None = None
    # Arbitrary header K-V pairs. For LLM targets this carries the
    # provider auth (Authorization, x-api-key, OpenAI-Organization,
    # …); the same Fernet-encrypted blob path stores them.
    headers: dict[str, str] | None = None


class LlmConfig(BaseModel):
    """Non-secret LLM target configuration.

    Stored on Target.llm_config (JSONB). Secrets — API keys, etc. —
    live on Target.credentials_encrypted via Credentials.headers.
    """

    provider: LlmProvider
    # Optional model identifier, passed verbatim into the request
    # body for the openai-chat preset and available as ``{{model}}`` in
    # custom templates.
    model: str | None = None
    # Optional system prompt baseline. The probe engine sends this as
    # the system role on every test so we exercise the *deployed*
    # configuration, not a bare model.
    system_prompt: str | None = None
    # Custom-mode request body template. JSON string; supports the
    # placeholders ``{{prompt}}``, ``{{system}}``, ``{{model}}``.
    request_template: str | None = None
    # Custom-mode response extractor. Lightweight JSONPath, e.g.
    # ``$.choices[0].message.content``.
    response_path: str | None = None
    # Executable-mode command. The command receives JSON on stdin:
    # {"prompt", "system", "model", "metadata"} and returns text or JSON.
    command: list[str] | None = None
    # Optional red-team config — free-form so the runner / CLI / SDK
    # can evolve without an API contract bump. Recognised keys:
    #   datasets:           ["harmbench", "donotanswer", "beavertails", "cyberseceval",
    #                        "toxic-chat", "aegis", "unsafebench", "xstest", "file://..."]
    #   strategies:         ["base64", "leetspeak", "jailbreak", "crescendo", ...]
    #   composite_strategies: ["jailbreak+base64", ...]
    #   guardrails:         ["pii", "secrets", "unsafe-code", "tool-authz"]
    #   plugins:            ["bias", "rag", "mcp", "coding-agent"]   # default = all
    #   languages:          ["Spanish", "Mandarin", ...]
    #   policies, intents, variables, discovery, judge, attacker, embedder
    #   iterative:          "static" | "pair" | "tap" | "goat" | "hydra"
    #   tap:                {depth: 4, branching: 3, width: 10}
    #   goat:               {max_turns: 5}
    #   hydra:              {objectives: [...], max_turns: 3, concurrency: 4}
    #   pair_iterations:    int (PAIR-only)
    #   guardrail_bypass:   bool
    redteam: dict | None = None
    thresholds: dict | None = None
    budget: dict | None = None
    retries: int = Field(default=0, ge=0, le=5)
    backoff_s: float = Field(default=0.25, ge=0, le=10)
    cache: bool = True
    cache_size: int = Field(default=256, ge=0, le=10000)
    timeout_s: int = Field(default=30, ge=1, le=120)
    concurrency: int = Field(default=5, ge=1, le=20)
    # Per-provider rate limit. ``max_rps`` wins; ``max_rpm`` is the
    # convenience fallback (rpm/60). ``rate_burst`` is the bucket
    # capacity in tokens (default = max_rps so a 1-second burst is
    # the steady-state rate). 0 disables.
    max_rps: float | None = Field(default=None, ge=0, le=10000)
    max_rpm: int | None = Field(default=None, ge=0, le=600000)
    rate_burst: float | None = Field(default=None, ge=0, le=100000)

    # AWS Bedrock — region for SigV4 signing. Access keys ride on
    # Credentials.headers as ``X-AWS-Access-Key-Id`` /
    # ``X-AWS-Secret-Access-Key`` (and optional ``X-AWS-Session-Token``).
    aws_region: str | None = None
    # Google Vertex AI — fully-qualified model resource (project + location).
    vertex_project: str | None = None
    vertex_location: str | None = None
    # Azure OpenAI — deployment name + API version. Endpoint URL is the
    # base ``base_url`` already on the target.
    azure_deployment: str | None = None
    azure_api_version: str | None = None

    @model_validator(mode="after")
    def _validate_custom(self) -> "LlmConfig":
        if self.provider == "custom" and not (
            self.request_template and self.response_path
        ):
            raise ValueError(
                "provider='custom' requires both request_template and response_path"
            )
        if self.provider == "executable" and not self.command:
            raise ValueError("provider='executable' requires command")
        if self.provider == "websocket" and self.response_path and not self.request_template:
            raise ValueError("provider='websocket' with response_path requires request_template")
        if self.provider == "bedrock" and not self.model:
            raise ValueError("provider='bedrock' requires model (Bedrock model id)")
        return self


# =============================================================================
# KindConfig — per-kind configuration for the 11 new non-llm target kinds
# (feature 001-multi-target-scan-pipelines). Stored on ``Target.kind_config``
# (JSONB). The legacy ``llm`` kind continues to use ``Target.llm_config``
# above; the legacy ``url``/``repo`` kinds carry no kind_config (NULL).
#
# Every variant uses ``extra="forbid"`` so unknown FE fields fail loudly
# rather than silently dropping (per GATE 2 finding B-003).
# =============================================================================


class _KindConfigBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Egress proxy for scanner traffic — route around IP-based WAF blocks
    # (e.g. ThreatX/Cloudflare returning 403 on the scanner's own IP). An
    # http(s):// URL (optionally with credentials). Applied to the HTTP client
    # and the graphql-cop / inql CLIs.
    proxy: str | None = None
    # Extra request headers merged into every scanner request — a realistic
    # User-Agent / Origin / Referer to blend past signature-based WAF rules.
    headers: dict[str, str] | None = None


class WebAppConfig(_KindConfigBase):
    kind: Literal["web_app"] = "web_app"
    crawl_depth: int = Field(default=3, ge=1, le=10)
    max_pages: int = Field(default=100, ge=1, le=1000)
    browser_render: bool = True
    api_spec_url: HttpUrl | None = None


class RestApiConfig(_KindConfigBase):
    kind: Literal["rest_api"] = "rest_api"
    api_spec: dict | None = None
    api_spec_url: HttpUrl | None = None
    api_spec_format: Literal["openapi3", "swagger2", "postman", "auto"] = "auto"
    auth_in_spec: bool = True


class GraphqlConfig(_KindConfigBase):
    kind: Literal["graphql"] = "graphql"
    introspection_enabled: bool = True
    # Required when ``introspection_enabled=False`` — operator pastes the SDL
    # since we can't fetch it at scan time.
    schema_sdl: str | None = None
    max_query_depth: int = Field(default=10, ge=1, le=50)
    operations_to_test: list[Literal["query", "mutation", "subscription"]] = Field(
        default_factory=lambda: ["query", "mutation"]
    )

    @model_validator(mode="after")
    def _validate_schema(self) -> "GraphqlConfig":
        if not self.introspection_enabled and not self.schema_sdl:
            raise ValueError(
                "graphql.introspection_enabled=False requires schema_sdl"
            )
        return self


class WebsocketConfig(_KindConfigBase):
    kind: Literal["websocket"] = "websocket"
    subprotocols: list[str] = Field(default_factory=list)
    origin_header: str | None = None
    auth_token_in_query: str | None = None


class GrpcConfig(_KindConfigBase):
    kind: Literal["grpc"] = "grpc"
    reflection_enabled: bool = True
    # Required when ``reflection_enabled=False`` — operator uploads .proto file
    # contents (as strings) since we can't introspect the service.
    proto_files: list[str] | None = None
    tls_verify: bool = True
    # Plaintext h2c endpoint (no TLS). Common for internal gRPC; required for
    # grpcurl to connect (otherwise it attempts a TLS handshake and fails).
    plaintext: bool = False

    @model_validator(mode="after")
    def _validate_proto(self) -> "GrpcConfig":
        if not self.reflection_enabled and not self.proto_files:
            raise ValueError(
                "grpc.reflection_enabled=False requires proto_files"
            )
        return self


class SourceCodeConfig(_KindConfigBase):
    kind: Literal["source_code"] = "source_code"
    source: Literal[
        "github_url", "github_app", "gitlab_url", "bitbucket_url",
        "local_path", "tarball_url", "upload",
    ] = "github_url"
    repo_url: HttpUrl | None = None  # required for *_url git sources / tarball
    # source="upload": R2 object key of the operator's uploaded .zip/.tar.gz
    # (from POST /uploads). The scan fetches + extracts it; agent-fix returns a
    # fixed .zip instead of opening a PR (no git remote).
    upload_key: str | None = None
    upload_filename: str | None = None
    upload_sha256: str | None = None
    git_ref: str = "HEAD"
    languages_hint: list[str] | None = None
    scanners_disabled: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_source(self) -> "SourceCodeConfig":
        if (self.source in {"github_url", "gitlab_url", "bitbucket_url", "tarball_url"}
                and not self.repo_url):
            raise ValueError(
                f"source_code.source={self.source!r} requires repo_url"
            )
        if self.source == "upload" and not self.upload_key:
            raise ValueError("source_code.source='upload' requires upload_key")
        return self


class CicdPipelineConfig(_KindConfigBase):
    kind: Literal["cicd_pipeline"] = "cicd_pipeline"
    provider: Literal["github_actions", "gitlab_ci", "jenkins", "azure_pipelines", "circleci"]
    repo_url: HttpUrl | None = None
    config_paths: list[str] = Field(default_factory=list)
    # When True, Target.kind_credentials_encrypted MUST carry CicdCreds for the
    # provider. Without creds, only static config audit (Phase A) runs.
    live_api_enabled: bool = False


class IacConfig(_KindConfigBase):
    kind: Literal["iac"] = "iac"
    frameworks: list[Literal["terraform", "cloudformation", "helm", "kustomize", "arm"]] = Field(
        default_factory=lambda: ["terraform"]
    )
    source: Literal["repo", "tarball_url", "local_path"] = "repo"
    repo_url: HttpUrl | None = None


class ContainerImageConfig(_KindConfigBase):
    kind: Literal["container_image"] = "container_image"
    image_ref: str = Field(min_length=1)
    registry: Literal["dockerhub", "ecr", "gcr", "ghcr", "acr", "custom"] = "dockerhub"
    scan_layers: bool = True
    scan_secrets: bool = True
    scan_misconfigs: bool = True


CloudProvider = Literal["aws", "azure", "gcp"]
CloudKind = Literal[
    "cloud_account",
    "serverless_function",
    "cloud_storage",
    "load_balancer_cdn",
    "cloud_database",
    "secrets_manager",
]


class _CloudConfigBase(_KindConfigBase):
    provider: CloudProvider
    account_id: str | None = None
    subscription_id: str | None = None
    project_id: str | None = None
    regions: list[str] = Field(default_factory=list)
    resource_tags: dict[str, str] = Field(default_factory=dict)
    inventory: dict | None = None
    read_only: bool = True

    @model_validator(mode="after")
    def _validate_read_only(self) -> "_CloudConfigBase":
        if not self.read_only:
            raise ValueError("cloud target scans are read-only")
        if self.provider == "aws" and not self.account_id:
            raise ValueError("provider='aws' requires account_id")
        if self.provider == "azure" and not self.subscription_id:
            raise ValueError("provider='azure' requires subscription_id")
        if self.provider == "gcp" and not self.project_id:
            raise ValueError("provider='gcp' requires project_id")
        return self


class CloudAccountConfig(_CloudConfigBase):
    kind: Literal["cloud_account"] = "cloud_account"
    services: list[str] = Field(default_factory=list)
    include_iam: bool = True
    include_network: bool = True
    include_audit_logging: bool = True


class ServerlessFunctionConfig(_CloudConfigBase):
    kind: Literal["serverless_function"] = "serverless_function"
    function_names: list[str] = Field(default_factory=list)
    include_env_metadata: bool = True
    check_public_invocation: bool = True
    check_runtime: bool = True


class CloudStorageConfig(_CloudConfigBase):
    kind: Literal["cloud_storage"] = "cloud_storage"
    resource_names: list[str] = Field(default_factory=list)
    check_public_access: bool = True
    check_encryption: bool = True
    check_logging: bool = True


class LoadBalancerCdnConfig(_CloudConfigBase):
    kind: Literal["load_balancer_cdn"] = "load_balancer_cdn"
    resource_names: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    check_tls: bool = True
    check_origin_exposure: bool = True
    check_waf: bool = True
    check_cache_policy: bool = True


class CloudDatabaseConfig(_CloudConfigBase):
    kind: Literal["cloud_database"] = "cloud_database"
    resource_names: list[str] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=list)
    check_public_access: bool = True
    check_encryption: bool = True
    check_backups: bool = True


class SecretsManagerConfig(_CloudConfigBase):
    kind: Literal["secrets_manager"] = "secrets_manager"
    resource_names: list[str] = Field(default_factory=list)
    check_rotation: bool = True
    check_policy: bool = True
    check_encryption: bool = True
    include_secret_values: bool = False

    @model_validator(mode="after")
    def _validate_no_secret_values(self) -> "SecretsManagerConfig":
        super()._validate_read_only()
        if self.include_secret_values:
            raise ValueError("Pencheff never reads secret values")
        return self


class K8sClusterConfig(_KindConfigBase):
    kind: Literal["k8s_cluster"] = "k8s_cluster"
    # ``live_cluster`` is the legacy alias for ``on_prem`` (paste-kubeconfig).
    # The validator normalises it on read so back-compat rows just work.
    target: Literal[
        "manifests_only",
        "on_prem",
        "live_cluster",  # deprecated alias of on_prem
        "aws_eks",
        "azure_aks",
        "gcp_gke",
    ] = "manifests_only"
    # Required when target=="manifests_only".
    manifests_archive_url: HttpUrl | None = None
    namespaces: list[str] = Field(default_factory=lambda: ["default"])
    rbac_enum: bool = True
    network_policy_audit: bool = True

    # Cluster identifiers for cloud-managed K8s. Set only for the matching
    # target mode; the kubeconfig itself is derived at scan time from
    # ``kind_credentials`` (K8sCreds) using each cloud's Python SDK.
    aws_region: str | None = None
    aws_cluster_name: str | None = None
    azure_subscription_id: str | None = None
    azure_resource_group: str | None = None
    azure_cluster_name: str | None = None
    gcp_project_id: str | None = None
    gcp_location: str | None = None
    gcp_cluster_name: str | None = None

    @model_validator(mode="after")
    def _validate_k8s(self) -> "K8sClusterConfig":
        # Normalise legacy alias.
        if self.target == "live_cluster":
            self.target = "on_prem"
        if self.target == "manifests_only" and not self.manifests_archive_url:
            raise ValueError(
                "k8s_cluster.target='manifests_only' requires manifests_archive_url"
            )
        if self.target == "aws_eks" and not (self.aws_region and self.aws_cluster_name):
            raise ValueError(
                "k8s_cluster.target='aws_eks' requires aws_region and aws_cluster_name"
            )
        if self.target == "azure_aks" and not (
            self.azure_subscription_id
            and self.azure_resource_group
            and self.azure_cluster_name
        ):
            raise ValueError(
                "k8s_cluster.target='azure_aks' requires azure_subscription_id, "
                "azure_resource_group, and azure_cluster_name"
            )
        if self.target == "gcp_gke" and not (
            self.gcp_project_id and self.gcp_location and self.gcp_cluster_name
        ):
            raise ValueError(
                "k8s_cluster.target='gcp_gke' requires gcp_project_id, "
                "gcp_location, and gcp_cluster_name"
            )
        return self


class PackageRegistryConfig(_KindConfigBase):
    kind: Literal["package_registry"] = "package_registry"
    ecosystem: Literal["npm", "pypi", "maven", "cargo", "gem", "composer", "go", "nuget"]
    # List of {name, version} dicts. Non-empty (Pydantic min_length).
    package_list: list[dict] = Field(min_length=1)
    include_dev: bool = False


class SbomConfig(_KindConfigBase):
    kind: Literal["sbom"] = "sbom"
    format: Literal["cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag-value"]
    # Either ``content`` (inline, ≤ 16 MiB once decoded) OR ``url`` (remote SBOM).
    content: str | None = Field(default=None, max_length=16 * 1024 * 1024)
    url: HttpUrl | None = None
    check_licenses: bool = True
    check_suppliers: bool = True

    @model_validator(mode="after")
    def _validate_content_or_url(self) -> "SbomConfig":
        if not self.content and not self.url:
            raise ValueError("sbom requires either content (inline) or url (remote)")
        if self.content and self.url:
            raise ValueError("sbom: provide either content OR url, not both")
        return self


class _ClientArtifactConfigBase(_KindConfigBase):
    """Shared base for the Mobile & Client Security artifact kinds (spec 002).

    MVP ingestion = ``file_url`` (operator-hosted URL to the artifact). The
    worker downloads it (sha256-verified, integrity gate) into the scan's
    working dir and runs the existing static mobile modules — the artifact is
    NEVER executed (no device/emulator). ``sha256`` is required because the
    underlying ``artifact_download`` verb mandates it and it pins the exact
    binary the operator intended. A later milestone adds signed object-storage
    upload as an alternative source.
    """

    file_url: HttpUrl
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


class AndroidAppConfig(_ClientArtifactConfigBase):
    kind: Literal["android_app"] = "android_app"
    # Optional MobSF REST enrichment pass on top of the first-party static
    # sweep (requires a MobSF server + MOBSF_API_KEY on the worker).
    use_mobsf: bool = False


class IosAppConfig(_ClientArtifactConfigBase):
    kind: Literal["ios_app"] = "ios_app"
    # App-Store IPAs are FairPlay-encrypted (cryptid=1), which caps code-level
    # static depth; the report surfaces this. No extra knobs for MVP.


class BrowserExtensionConfig(_ClientArtifactConfigBase):
    kind: Literal["browser_extension"] = "browser_extension"
    # CRX (Chrome/Edge), XPI (Firefox), or a zipped unpacked extension.


class DesktopAppConfig(_ClientArtifactConfigBase):
    kind: Literal["desktop_app"] = "desktop_app"
    # Electron/Java(JAR)/.NET/Qt bundle (zip/jar) or a raw native binary.


class FirmwareConfig(_ClientArtifactConfigBase):
    kind: Literal["firmware"] = "firmware"
    # Raw firmware/embedded image (.bin/.img/.hex) or a packed archive.


class IotDeviceConfig(_ClientArtifactConfigBase):
    kind: Literal["iot_device"] = "iot_device"
    # IoT device firmware (camera, drone, robot vacuum, router, …). Optional
    # free-form device context used only for report labelling.
    vendor: str | None = Field(default=None, max_length=120)
    model: str | None = Field(default=None, max_length=120)
    device_class: str | None = Field(default=None, max_length=120)


class OtIcsScadaConfig(_ClientArtifactConfigBase):
    kind: Literal["ot_ics_scada"] = "ot_ics_scada"
    # OT/ICS/SCADA controller firmware or config export. Static-only — no
    # active industrial-protocol probing (which can disrupt physical processes).
    system_type: str | None = Field(default=None, max_length=120)


class HostKindConfig(_KindConfigBase):
    """Host-kind target config — multi-host list for OS-level scanning.

    Sub-project A of the Mythos OS-exploit ladder. The agent that consumes
    this list ships in sub-project B; until then, routers/scans.py returns
    HTTP 409 for any scan against a host-kind Target. See
    docs/superpowers/specs/2026-05-17-host-target-kind-design.md.
    """

    kind: Literal["host"] = "host"
    # 50 hosts per Target — abuse-signal + UX limit. See spec §"Data model".
    hosts: list[str] = Field(min_length=1, max_length=50)
    # SERVER-SET: routers/targets.py classifies the resolved IPs at create/PATCH
    # time and rewrites this field. Client-supplied values are ignored during
    # persistence (the router strips and re-computes). Field stays in the schema
    # so it round-trips through reads.
    is_private_target: bool = False

    @field_validator("hosts")
    @classmethod
    def _validate_hosts(cls, raw: list[str]) -> list[str]:
        from pencheff_api.services.host_validation import (
            HostValidationError,
            validate_host_format,
        )

        deduped: list[str] = []
        seen: set[str] = set()
        for entry in raw:
            if not isinstance(entry, str):
                raise ValueError(f"host entries must be strings, got {type(entry)!r}")
            key = entry.lower()
            if key in seen:
                continue
            try:
                validate_host_format(entry)
            except HostValidationError as exc:
                raise ValueError(f"invalid host {entry!r}: {exc}") from exc
            seen.add(key)
            deduped.append(entry)
        if not deduped:
            raise ValueError("hosts must contain at least one valid entry after dedup")
        return deduped


class MemoryItemIn(BaseModel):
    """A single structured memory item for ``POST /v1/memory/scan``.

    Accepted alongside bare strings in ``MemoryKindConfig.items`` and the
    ``items`` body field of the scan endpoint.  The sentry ``_coerce_items``
    helper (Plan M2 Task 1) already handles both forms.
    """

    model_config = ConfigDict(extra="forbid")

    id: str | None = None
    text: str
    namespace: str | None = None
    source: str | None = None


MemorySourceType = Literal[
    "manual_items",
    "file_upload",
    "mem0",
    "zep",
    "langgraph_store",
    "redis",
    "pinecone",
    "chroma",
    "qdrant",
    "weaviate",
    "custom_http",
]
MemoryFileFormat = Literal["auto", "txt", "json", "jsonl", "csv", "md"]
_MEMORY_PROVIDER_SOURCES: frozenset[str] = frozenset({
    "mem0",
    "zep",
    "langgraph_store",
    "redis",
    "pinecone",
    "chroma",
    "qdrant",
    "weaviate",
    "custom_http",
})


class MemoryKindConfig(_KindConfigBase):
    """Agent memory / vector-store target — a batch of stored memory items
    (long-term memory rows, RAG chunks, retrieved docs) audited for secrets
    at rest + memory poisoning. Scanned on-demand from the target page via
    ``POST /v1/memory/scan`` (the memory scanner), NOT the Celery scan
    pipeline — so this kind has no scan-consent / discipline coupling."""

    kind: Literal["memory"] = "memory"
    source_type: MemorySourceType = "manual_items"
    url: str | None = None
    org_id: str | None = None
    project_id: str | None = None
    user_id: str | None = None
    session_id: str | None = None
    collection: str | None = None
    namespace: str | None = None
    index_name: str | None = None
    file_name: str | None = None
    file_format: MemoryFileFormat = "auto"
    request_template: str | None = None
    response_path: str | None = None
    # Each item is either a bare string (legacy) or a structured object with
    # at minimum a ``text`` field (Plan M2 Task 3).  May be empty at
    # registration (add later).  Capped to match the scanner's batch limit.
    items: list[str | MemoryItemIn] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def _validate_source(self) -> "MemoryKindConfig":
        if self.source_type in _MEMORY_PROVIDER_SOURCES and not self.url:
            raise ValueError(f"source_type={self.source_type!r} requires url")
        if (
            self.source_type == "custom_http"
            and not (self.request_template and self.response_path)
        ):
            raise ValueError(
                "source_type='custom_http' requires request_template and response_path",
            )
        if self.source_type == "file_upload" and not self.items:
            raise ValueError(
                "source_type='file_upload' requires at least one parsed item",
            )
        return self


class McpConfig(_KindConfigBase):
    """MCP server target config (source-aware). mcp_http and mcp_stdio only.

    Agent sources (agent_http/agent_browser) are now handled by AgentConfig.
    Auth secrets ride on Target.kind_credentials_encrypted. See spec 2026-06-16.
    """

    kind: Literal["mcp"] = "mcp"
    source_type: Literal["mcp_http", "mcp_stdio"]

    # mcp_http
    url: HttpUrl | None = None
    transport: Literal["sse", "streamable_http"] | None = None

    # mcp_stdio
    command: list[str] | None = None
    env: dict[str, str] | None = None  # non-secret only; secrets via kind_credentials
    cwd: str | None = None

    # dynamic-testing controls
    tool_allowlist: list[str] = Field(default_factory=list)
    tool_denylist: list[str] = Field(default_factory=list)
    dynamic_invocation: bool = False
    destructive_opt_in: bool = False

    @model_validator(mode="after")
    def _validate_source(self) -> "McpConfig":
        st = self.source_type
        if st == "mcp_http" and not (self.url and self.transport):
            raise ValueError("source_type='mcp_http' requires url and transport")
        if st == "mcp_stdio" and not self.command:
            raise ValueError("source_type='mcp_stdio' requires command")
        overlap = set(self.tool_allowlist) & set(self.tool_denylist)
        if overlap:
            raise ValueError(
                f"tool_allowlist and tool_denylist overlap: {sorted(overlap)}"
            )
        if self.destructive_opt_in and not self.dynamic_invocation:
            raise ValueError("destructive_opt_in requires dynamic_invocation")
        return self


# agent_http providers whose transport POSTs/connects to Target.base_url — they
# require a url. Mirrors the provider dropdown in the agent registration form.
_AGENT_HTTP_URL_REQUIRED = frozenset({
    "openai-chat", "custom", "websocket", "bedrock", "vertex", "azure-openai",
})


class AgentConfig(_KindConfigBase):
    """AI agent target config (conversational endpoint). Split out of McpConfig
    (spec 2026-06-27): agent_http reuses the LlmProbe engine; agent_browser drives
    Playwright. Auth secrets ride on Target.credentials_encrypted."""

    kind: Literal["agent"] = "agent"
    source_type: Literal["agent_http", "agent_browser"]

    # agent_http (LLM-style; reuses LlmProbe engine)
    url: HttpUrl | None = None
    provider: LlmProvider | None = None
    model: str | None = None
    request_template: str | None = None
    response_path: str | None = None

    # agent_browser (Playwright)
    prompt_selector: str | None = None
    send_selector: str | None = None
    response_selector: str | None = None

    # dynamic-testing controls
    tool_allowlist: list[str] = Field(default_factory=list)
    tool_denylist: list[str] = Field(default_factory=list)
    dynamic_invocation: bool = False
    destructive_opt_in: bool = False
    # Optional per-target red-team override. Present keys replace the curated
    # agent default (categories/strategies/datasets/plugins). Free-form, like
    # LlmConfig.redteam. See spec 2026-06-27-agent-attack-suite.
    redteam: dict | None = None

    @model_validator(mode="after")
    def _validate_source(self) -> "AgentConfig":
        st = self.source_type
        if st == "agent_http" and not self.provider:
            raise ValueError("source_type='agent_http' requires provider")
        # agent_http reuses the LlmProbe engine. The HTTP/WS/cloud-invoke
        # providers below POST/connect to the target's endpoint (Target.base_url);
        # without a url the scan falls back to the ``agent://…`` placeholder and
        # every request returns HTTP 0. ``executable`` (local subprocess) and
        # ``sema4_agent`` (endpoint derived from its own flow) need no url.
        if st == "agent_http" and self.provider in _AGENT_HTTP_URL_REQUIRED and not self.url:
            raise ValueError(
                "source_type='agent_http' requires url (the agent's chat/invoke "
                f"endpoint) for provider '{self.provider}'"
            )
        if st == "agent_browser" and not (
            self.url and self.prompt_selector and self.send_selector
            and self.response_selector
        ):
            raise ValueError(
                "source_type='agent_browser' requires url, prompt_selector, "
                "send_selector, response_selector"
            )
        if st == "agent_http" and self.provider == "custom" and not (
            self.request_template and self.response_path
        ):
            raise ValueError(
                "source_type='agent_http' with provider='custom' requires "
                "request_template and response_path"
            )
        overlap = set(self.tool_allowlist) & set(self.tool_denylist)
        if overlap:
            raise ValueError(f"tool_allowlist and tool_denylist overlap: {sorted(overlap)}")
        if self.destructive_opt_in and not self.dynamic_invocation:
            raise ValueError("destructive_opt_in requires dynamic_invocation")
        return self


RagProvider = Literal["pinecone", "weaviate", "qdrant", "chroma", "milvus", "pgvector", "redis"]


class RagConfig(_KindConfigBase):
    """RAG / vector-DB target config (source-aware). See spec 2026-06-17.
    Distinct from MemoryKindConfig (a batch of stored items) — this is the live
    retrieval system. Auth secrets ride on Target.kind_credentials_encrypted."""

    kind: Literal["rag"] = "rag"
    source_type: Literal["managed_vdb", "self_hosted_vdb", "rag_endpoint", "embedding_artifact"]

    provider: RagProvider | None = None
    url: str | None = None
    index_name: str | None = None
    namespace: str | None = None

    provider_llm: LlmProvider | None = None
    request_template: str | None = None
    response_path: str | None = None

    items: list[str] | None = None

    query_probes: bool = False
    poison_injection_opt_in: bool = False
    canary_text: str | None = None
    redteam: dict | None = None

    @model_validator(mode="after")
    def _validate_source(self) -> "RagConfig":
        st = self.source_type
        if st in ("managed_vdb", "self_hosted_vdb") and not (self.provider and self.url):
            raise ValueError(f"source_type={st!r} requires provider and url")
        if st == "rag_endpoint" and not self.provider_llm:
            raise ValueError("source_type='rag_endpoint' requires provider_llm")
        if st == "embedding_artifact" and not self.items:
            raise ValueError("source_type='embedding_artifact' requires items")
        if self.poison_injection_opt_in and not self.query_probes:
            raise ValueError("poison_injection_opt_in requires query_probes")
        return self


class MlModelConfig(_KindConfigBase):
    """ML model artifact target — STATICALLY scanned (never loaded). See spec 2026-06-17."""
    kind: Literal["ml_model"] = "ml_model"
    source_type: Literal["file_url", "huggingface", "local_path"]
    url: str | None = None
    hf_repo: str | None = None
    hf_revision: str | None = None
    local_path: str | None = None
    format_hint: Literal["auto", "pickle", "pytorch", "safetensors", "keras", "h5", "savedmodel", "gguf", "joblib"] = "auto"
    max_bytes: int = Field(default=524_288_000, ge=1, le=5_368_709_120)

    @model_validator(mode="after")
    def _validate_source(self) -> "MlModelConfig":
        st = self.source_type
        if st == "file_url" and not self.url:
            raise ValueError("source_type='file_url' requires url")
        if st == "huggingface" and not self.hf_repo:
            raise ValueError("source_type='huggingface' requires hf_repo")
        if st == "local_path" and not self.local_path:
            raise ValueError("source_type='local_path' requires local_path")
        return self


class VoiceConfig(_KindConfigBase):
    """Voice / Speech-AI endpoint target. Static transport probes always; crafted
    audio submission is consent-gated (audio_probes). See spec 2026-06-17."""
    kind: Literal["voice"] = "voice"
    source_type: Literal["stt_endpoint", "voice_bot", "tts_endpoint", "voice_auth"]
    url: str
    audio_format: Literal["wav", "mp3", "flac", "ogg"] = "wav"
    request_template: str | None = None
    response_path: str | None = None
    injection_phrase: str | None = None
    audio_probes: bool = False


TlsCertSource = Literal["endpoint", "upload", "acm", "azure_keyvault", "gcp", "cloudflare"]
DnsProvider = Literal["generic", "route53", "cloudflare", "azure_dns", "gcp"]
EmailProvider = Literal["generic", "ses", "resend", "google_workspace", "azure_acs"]
VpnType = Literal["auto", "openvpn", "wireguard", "ipsec", "ssl_vpn", "pptp", "remote_access"]
IdpProvider = Literal["generic_oidc", "okta", "azure_ad", "auth0", "workos", "casdoor", "saml", "custom"]
DataStoreEngine = Literal["auto", "redis", "memcached", "mongodb", "postgresql", "mysql",
                          "elasticsearch", "mssql", "couchdb", "cassandra"]


class TlsSslConfig(_KindConfigBase):
    """TLS/SSL configuration posture. Cert can come from a live endpoint probe, an
    uploaded/pasted PEM, or a cloud provider (ACM / Key Vault / GCP / Cloudflare)."""
    kind: Literal["tls_ssl"] = "tls_ssl"
    source: TlsCertSource = "endpoint"
    hosts: list[str] = Field(default_factory=list, max_length=50)  # "host" (→:443) or "host:port"
    certificate_pem: str | None = Field(default=None, max_length=256 * 1024)  # upload/paste
    # provider references (used per source)
    acm_certificate_arn: str | None = None
    keyvault_url: str | None = None
    keyvault_cert_name: str | None = None
    gcp_certificate: str | None = None  # projects/…/certificates/… or map entry
    cloudflare_zone_id: str | None = None
    # checks
    check_protocols: bool = True
    check_ciphers: bool = True
    check_certificate: bool = True
    check_hardening: bool = True
    run_ssl_labs: bool = False  # opt-in; sends the hostname to Qualys (third party)

    @model_validator(mode="after")
    def _validate_source(self) -> "TlsSslConfig":
        if self.source == "endpoint" and not self.hosts:
            raise ValueError("tls_ssl source='endpoint' requires at least one host")
        if self.source == "upload" and not self.certificate_pem:
            raise ValueError("tls_ssl source='upload' requires certificate_pem")
        if self.source == "acm" and not self.acm_certificate_arn:
            raise ValueError("tls_ssl source='acm' requires acm_certificate_arn")
        return self


class DnsConfig(_KindConfigBase):
    kind: Literal["dns"] = "dns"
    provider: DnsProvider = "generic"
    domain: str = Field(min_length=1, max_length=253)
    hosted_zone_id: str | None = None  # route53
    cloudflare_zone_id: str | None = None
    gcp_managed_zone: str | None = None  # gcp
    azure_resource_group: str | None = None  # azure_dns
    subdomain_enum: bool = True
    zone_transfer: bool = True
    check_dnssec: bool = True
    check_caa: bool = True
    check_takeover: bool = True


class EmailSecurityConfig(_KindConfigBase):
    kind: Literal["email_security"] = "email_security"
    provider: EmailProvider = "generic"
    domain: str = Field(min_length=1, max_length=253)
    dkim_selectors: list[str] = Field(
        default_factory=lambda: ["default", "google", "selector1", "selector2", "k1", "mail"])
    check_mta_sts: bool = True
    check_tls_rpt: bool = True
    check_bimi: bool = True


class VpnConfig(_KindConfigBase):
    """VPN / remote-access exposure — fingerprint + port-scan host(s) for VPN/remote services."""
    kind: Literal["vpn"] = "vpn"
    hosts: list[str] = Field(min_length=1, max_length=50)
    vpn_type: VpnType = "auto"


class IdpConfig(_KindConfigBase):
    """Identity Provider — OIDC discovery + SAML metadata + (with creds) admin-API policy checks."""
    kind: Literal["idp"] = "idp"
    provider: IdpProvider = "generic_oidc"
    issuer_url: str = Field(min_length=1, max_length=2048)  # OIDC issuer / IdP base URL
    saml_metadata_url: str | None = Field(default=None, max_length=2048)
    org_domain: str | None = None  # e.g. your-org.okta.com / tenant.auth0.com


class DataStoreConfig(_KindConfigBase):
    """Database / data store — connection exposure + unauthenticated-access probe."""
    kind: Literal["data_store"] = "data_store"
    hosts: list[str] = Field(min_length=1, max_length=50)  # "host" or "host:port"
    engine: DataStoreEngine = "auto"


KindConfig = Annotated[
    Union[
        WebAppConfig, RestApiConfig, GraphqlConfig, WebsocketConfig, GrpcConfig,
        CloudAccountConfig, ServerlessFunctionConfig, CloudStorageConfig,
        LoadBalancerCdnConfig, CloudDatabaseConfig, SecretsManagerConfig,
        SourceCodeConfig, CicdPipelineConfig, IacConfig, ContainerImageConfig,
        K8sClusterConfig, PackageRegistryConfig, SbomConfig,
        HostKindConfig, MemoryKindConfig, McpConfig, AgentConfig, RagConfig, MlModelConfig,
        VoiceConfig,
        AndroidAppConfig, IosAppConfig, BrowserExtensionConfig, DesktopAppConfig,
        FirmwareConfig, IotDeviceConfig, OtIcsScadaConfig,
        TlsSslConfig, DnsConfig, EmailSecurityConfig, VpnConfig,
        IdpConfig, DataStoreConfig,
    ],
    Field(discriminator="kind"),
]


# =============================================================================
# KindCredentials — per-kind credential shapes for kinds whose secrets don't
# fit the flat ``Credentials`` model (kubeconfig YAML, registry auth tuples,
# CI provider tokens, GitHub App private keys). Decrypted from
# ``Target.kind_credentials_encrypted`` (Fernet) at scan time.
# =============================================================================


class _KindCredsBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


class K8sCreds(_KindCredsBase):
    """Credentials for a Kubernetes cluster target.

    Discriminated by ``provider``:
      * ``on_prem`` — operator-pasted kubeconfig YAML (legacy + on-prem path)
      * ``aws``    — IAM access keys; scan worker derives a fresh kubeconfig
                     via boto3 + EKS DescribeCluster + an inline SigV4 token
      * ``azure``  — Service Principal (tenant + client id + secret); scan
                     worker pulls admin kubeconfig via the AKS SDK
      * ``gcp``    — Service Account JSON; scan worker derives a kubeconfig
                     via the GKE SDK and SA-backed access token

    Back-compat: rows persisted before this change stored the flat shape
    ``{kind: 'k8s_cluster', kubeconfig: '...'}``. ``provider`` defaults to
    ``on_prem`` so those rows parse unchanged.
    """

    kind: Literal["k8s_cluster"] = "k8s_cluster"
    provider: Literal["on_prem", "aws", "azure", "gcp"] = "on_prem"
    # on_prem — multi-line YAML with embedded base64 cert-data; capped at 64 KiB.
    kubeconfig: str | None = Field(default=None, max_length=65536)
    context: str | None = None
    # AWS
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    # Azure (Service Principal)
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    # GCP (Service Account JSON)
    gcp_service_account_json: str | None = Field(default=None, max_length=16 * 1024)

    @model_validator(mode="after")
    def _validate(self) -> "K8sCreds":
        if self.provider == "on_prem":
            if not self.kubeconfig or len(self.kubeconfig) < 10:
                raise ValueError(
                    "k8s_cluster creds with provider='on_prem' require a kubeconfig"
                )
        elif self.provider == "aws":
            if not (self.aws_access_key_id and self.aws_secret_access_key):
                raise ValueError(
                    "k8s_cluster creds with provider='aws' require "
                    "aws_access_key_id and aws_secret_access_key"
                )
        elif self.provider == "azure":
            if not (
                self.azure_tenant_id
                and self.azure_client_id
                and self.azure_client_secret
            ):
                raise ValueError(
                    "k8s_cluster creds with provider='azure' require "
                    "azure_tenant_id, azure_client_id, and azure_client_secret"
                )
        elif self.provider == "gcp":
            if not self.gcp_service_account_json:
                raise ValueError(
                    "k8s_cluster creds with provider='gcp' require "
                    "gcp_service_account_json"
                )
        return self


# Back-compat alias for callers that imported the old name.
KubeconfigCreds = K8sCreds


class RegistryCreds(_KindCredsBase):
    kind: Literal["container_image"] = "container_image"
    registry_host: str
    auth_type: Literal["basic", "token", "docker_config", "ecr_sts", "gcr_service_account", "acr_sp"]
    username: str | None = None
    password_or_token: str | None = None
    docker_config_json: str | None = Field(default=None, max_length=64 * 1024)
    gcr_service_account_json: str | None = Field(default=None, max_length=16 * 1024)
    # ECR — operator supplies static IAM creds; scan worker calls
    # ``ecr.get_authorization_token`` at pull time to swap them for a
    # short-lived (12 h) registry password.
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    aws_region: str | None = None
    ecr_sts_role_arn: str | None = None
    # ACR — Service Principal (or basic).
    acr_client_id: str | None = None
    acr_client_secret: str | None = None
    acr_tenant_id: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> "RegistryCreds":
        if self.auth_type == "basic" or self.auth_type == "token":
            if not self.password_or_token:
                raise ValueError(
                    f"container_image creds with auth_type={self.auth_type!r} "
                    "require password_or_token"
                )
        elif self.auth_type == "docker_config":
            if not self.docker_config_json:
                raise ValueError(
                    "container_image creds with auth_type='docker_config' "
                    "require docker_config_json"
                )
        elif self.auth_type == "ecr_sts":
            if not (self.aws_access_key_id and self.aws_secret_access_key):
                raise ValueError(
                    "container_image creds with auth_type='ecr_sts' require "
                    "aws_access_key_id and aws_secret_access_key"
                )
        elif self.auth_type == "gcr_service_account":
            if not self.gcr_service_account_json:
                raise ValueError(
                    "container_image creds with auth_type='gcr_service_account' "
                    "require gcr_service_account_json"
                )
        elif self.auth_type == "acr_sp":
            if not (self.acr_client_id and self.acr_client_secret):
                raise ValueError(
                    "container_image creds with auth_type='acr_sp' require "
                    "acr_client_id and acr_client_secret"
                )
        return self


class CicdCreds(_KindCredsBase):
    kind: Literal["cicd_pipeline"] = "cicd_pipeline"
    provider: Literal["github_actions", "gitlab_ci", "jenkins", "azure_pipelines", "circleci"]
    token: str | None = None
    github_app_id: str | None = None
    github_app_private_key: str | None = Field(default=None, max_length=8192)
    jenkins_user: str | None = None


class IacCreds(_KindCredsBase):
    # Token to clone a private IaC repo and open agentic-fix PRs against it
    # (GitHub PAT). Only needed for private repos / agent-fix; public IaC audit
    # needs no credentials.
    kind: Literal["iac"] = "iac"
    token: str | None = None


class SourceCodeCreds(_KindCredsBase):
    kind: Literal["source_code"] = "source_code"
    auth_type: Literal["pat", "github_app", "ssh_key"]
    pat: str | None = None
    github_app_id: str | None = None
    github_app_private_key: str | None = Field(default=None, max_length=8192)
    github_app_installation_id: str | None = None
    ssh_private_key: str | None = Field(default=None, max_length=8192)


class CloudProviderCreds(_KindCredsBase):
    kind: CloudKind
    provider: CloudProvider
    # AWS
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    aws_role_arn: str | None = None
    # Azure
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    # GCP
    gcp_service_account_json: str | None = Field(default=None, max_length=16 * 1024)

    @model_validator(mode="after")
    def _validate_provider_fields(self) -> "CloudProviderCreds":
        if self.provider == "aws":
            if not (self.aws_access_key_id and self.aws_secret_access_key):
                raise ValueError(
                    "cloud provider creds with provider='aws' require "
                    "aws_access_key_id and aws_secret_access_key"
                )
        elif self.provider == "azure":
            if not (
                self.azure_tenant_id
                and self.azure_client_id
                and self.azure_client_secret
            ):
                raise ValueError(
                    "cloud provider creds with provider='azure' require "
                    "azure_tenant_id, azure_client_id, and azure_client_secret"
                )
        elif self.provider == "gcp":
            if not self.gcp_service_account_json:
                raise ValueError(
                    "cloud provider creds with provider='gcp' require "
                    "gcp_service_account_json"
                )
        return self


# ── Provider credentials for the network/identity scan kinds (all optional —
# credentials only enable provider-API *enrichment* on top of universal checks) ──
class TlsSslCreds(_KindCredsBase):
    kind: Literal["tls_ssl"] = "tls_ssl"
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    aws_region: str | None = None
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    gcp_service_account_json: str | None = Field(default=None, max_length=16 * 1024)
    cloudflare_api_token: str | None = None


class DnsCreds(_KindCredsBase):
    kind: Literal["dns"] = "dns"
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    cloudflare_api_token: str | None = None
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    azure_subscription_id: str | None = None
    gcp_service_account_json: str | None = Field(default=None, max_length=16 * 1024)


class EmailSecurityCreds(_KindCredsBase):
    kind: Literal["email_security"] = "email_security"
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    aws_region: str | None = None
    resend_api_key: str | None = None
    google_workspace_sa_json: str | None = Field(default=None, max_length=16 * 1024)
    google_workspace_admin: str | None = None
    azure_acs_connection_string: str | None = None


class VpnCreds(_KindCredsBase):
    kind: Literal["vpn"] = "vpn"
    username: str | None = None
    password: str | None = None
    client_cert_pem: str | None = Field(default=None, max_length=64 * 1024)


class IdpCreds(_KindCredsBase):
    kind: Literal["idp"] = "idp"
    api_token: str | None = None  # Okta SSWS / Auth0 mgmt token / WorkOS / Casdoor
    client_id: str | None = None
    client_secret: str | None = None
    org_domain: str | None = None


class DataStoreCreds(_KindCredsBase):
    kind: Literal["data_store"] = "data_store"
    username: str | None = None
    password: str | None = None


KindCredentials = Annotated[
    Union[K8sCreds, RegistryCreds, CicdCreds, IacCreds, SourceCodeCreds, CloudProviderCreds,
          TlsSslCreds, DnsCreds, EmailSecurityCreds, VpnCreds, IdpCreds, DataStoreCreds],
    Field(discriminator="kind"),
]


# =============================================================================
# Discipline — security-program shorthands that fan out to one or more target
# kinds and (for some disciplines) apply registration-time scan-profile
# defaults. See docs/superpowers/specs/2026-05-21-discipline-target-picker-design.md
# =============================================================================

Discipline = Literal[
    "cspm",          # Cloud Security Posture Management     → cloud_* kinds
    "ciem",          # Cloud Infrastructure Entitlement Mgmt → cloud IAM-capable kinds
    "dspm",          # Data Security Posture Management      → storage/db/secrets
    "serverless_security", # Serverless Security             → serverless_function
    "edge_security", # Edge / CDN Security                   → load_balancer_cdn
    "kspm",          # Kubernetes Security Posture Management → k8s_cluster
    "kiem",          # Kubernetes Identity & Entitlement      → k8s_cluster (RBAC focus)
    "cwpp",          # Cloud Workload Protection              → container_image + k8s_cluster + host
    "aspm",          # Application Security Posture           → web_app + rest_api + source_code
    "api_security",  # API Security                           → rest_api + graphql
    "ai_redteam",    # AI Red Teaming                         → llm (aggressive strategies)
    "ai_spm",        # AI Security Posture Management         → llm (guardrails focus)
    "sbom_analysis", # SBOM / Dependencies                    → sbom
]

# Each discipline's compatible target kinds. A Target may carry any combination
# of disciplines whose allowed-kinds set contains its own ``kind``.
DISCIPLINE_TO_KINDS: dict[str, frozenset[str]] = {
    "cspm":          frozenset({
        "cloud_account", "serverless_function", "cloud_storage",
        "load_balancer_cdn", "cloud_database", "secrets_manager",
    }),
    "ciem":          frozenset({
        "cloud_account", "serverless_function", "cloud_storage",
        "cloud_database", "secrets_manager",
    }),
    "dspm":          frozenset({"cloud_storage", "cloud_database", "secrets_manager"}),
    "serverless_security": frozenset({"serverless_function"}),
    "edge_security": frozenset({"load_balancer_cdn"}),
    "kspm":          frozenset({"k8s_cluster"}),
    "kiem":          frozenset({"k8s_cluster"}),
    "cwpp":          frozenset({"container_image", "k8s_cluster", "host", "serverless_function"}),
    "aspm":          frozenset({"web_app", "rest_api", "source_code"}),
    "api_security":  frozenset({"rest_api", "graphql"}),
    "ai_redteam":    frozenset({"llm", "agent"}),
    "ai_spm":        frozenset({"llm", "agent"}),
    "sbom_analysis": frozenset({"sbom"}),
}


def _validate_disciplines_for_kind(disciplines: list[str], kind: str) -> None:
    """Raise ValueError if any discipline can't attach to this kind."""
    for d in disciplines:
        allowed = DISCIPLINE_TO_KINDS.get(d)
        if allowed is None:
            raise ValueError(f"unknown discipline: {d!r}")
        if kind not in allowed:
            raise ValueError(
                f"discipline={d!r} not compatible with kind={kind!r}; "
                f"allowed kinds: {sorted(allowed)}"
            )


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    # ``base_url`` is the primary identifier for the Target. It is HTTP(S) for
    # DAST + LLM kinds (url/web_app/rest_api/graphql/llm), but for the artifact,
    # hybrid, and protocol kinds it is a synthesised tag — ``oci://alpine:3.10``
    # / ``wss://...`` / ``grpc://...`` / ``pkg://npm`` / ``sbom://cyclonedx-json``
    # / ``iac://terraform`` / ``k8s://live/default`` / ``file:///path``. Pydantic
    # HttpUrl + AnyUrl both reject one or more of those, so we accept any string
    # here and let the kind-specific runner / allowlist enforcement validate
    # downstream. The DB column is already ``String(2048)`` — this matches.
    base_url: str = Field(min_length=1, max_length=2048)
    kind: TargetKind = "url"
    scope: list[str] | None = None
    exclude_paths: list[str] | None = None
    credentials: Credentials | None = None
    llm_config: LlmConfig | None = None
    # Per-kind config for the 11 new non-llm kinds. Required when kind is one
    # of those; rejected for legacy url/repo/llm kinds.
    kind_config: KindConfig | None = None
    # Per-kind credentials (kubeconfig / registry / CI tokens / GitHub App key)
    # for kinds whose secrets don't fit the flat ``Credentials`` shape.
    kind_credentials: KindCredentials | None = None
    # Repositories (already registered in the same workspace) that contain
    # source code for this runtime target. Used by scan detail pages and the
    # agentic fixer to map runtime/cloud/AI findings back to code.
    attached_repository_ids: list[str] | None = None
    # Security-program disciplines this Target serves (KSPM, ASPM, AI-SPM, …).
    # Validated against ``DISCIPLINE_TO_KINDS`` — each entry's compatible-kinds
    # set must contain Target.kind. Empty list means "no discipline tag".
    disciplines: list[Discipline] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_disciplines(self) -> "TargetCreate":
        if self.disciplines:
            _validate_disciplines_for_kind(list(self.disciplines), self.kind)
            # Dedup while preserving first occurrence order.
            seen: set[str] = set()
            deduped: list = []
            for d in self.disciplines:
                if d in seen:
                    continue
                seen.add(d)
                deduped.append(d)
            self.disciplines = deduped
        return self

    @model_validator(mode="after")
    def _validate_llm(self) -> "TargetCreate":
        if self.kind == "llm" and self.llm_config is None:
            raise ValueError("kind='llm' requires llm_config")
        if self.kind != "llm" and self.llm_config is not None:
            raise ValueError("llm_config only valid when kind='llm'")
        if (
            self.attached_repository_ids
            and self.kind not in ATTACHABLE_REPOSITORY_TARGET_KINDS
        ):
            raise ValueError(
                "attached_repository_ids only valid for runtime, cloud, or AI target kinds",
            )
        return self

    @model_validator(mode="after")
    def _validate_kind_config(self) -> "TargetCreate":
        # The 11 new non-llm kinds REQUIRE kind_config.
        if self.kind in _KINDS_REQUIRING_CONFIG and self.kind_config is None:
            raise ValueError(f"kind={self.kind!r} requires kind_config")
        # Legacy kinds (url/repo/llm) MUST NOT carry kind_config.
        if self.kind in _LEGACY_KINDS and self.kind_config is not None:
            raise ValueError(
                f"kind_config not allowed for legacy kind={self.kind!r}; "
                f"use llm_config for kind='llm'"
            )
        # Discriminator on kind_config must match Target.kind.
        if self.kind_config is not None and self.kind_config.kind != self.kind:
            raise ValueError(
                f"kind_config.kind ({self.kind_config.kind!r}) must match "
                f"Target.kind ({self.kind!r})"
            )
        return self

    @model_validator(mode="after")
    def _validate_kind_credentials(self) -> "TargetCreate":
        # The KindCredentials discriminated union only admits 4 ``kind`` values
        # (k8s_cluster, container_image, cicd_pipeline, source_code), so the
        # "unsupported kind" case is unreachable here; only the discriminator-
        # match check is meaningful.
        if self.kind_credentials is not None and self.kind_credentials.kind != self.kind:
            raise ValueError(
                f"kind_credentials.kind ({self.kind_credentials.kind!r}) must "
                f"match Target.kind ({self.kind!r})"
            )
        return self


class TargetUpdate(BaseModel):
    """Partial update: omit fields to leave them unchanged.

    Credentials behaviour:
      * ``credentials = None`` leaves the stored credentials untouched.
      * ``credentials = {}`` clears them.
      * ``credentials = {...}`` replaces them.

    attached_repository_ids behaviour:
      * ``None`` (omitted) leaves the existing set untouched.
      * ``[]`` clears all attachments.
      * ``[...]`` replaces the set with the provided IDs.
    """

    name: str | None = Field(default=None, min_length=1, max_length=200)
    # See TargetCreate.base_url for why this is ``str`` rather than HttpUrl.
    base_url: str | None = Field(default=None, min_length=1, max_length=2048)
    scope: list[str] | None = None
    exclude_paths: list[str] | None = None
    credentials: Credentials | None = None
    clear_credentials: bool = False
    llm_config: LlmConfig | None = None
    # kind_config / kind_credentials follow the same omit-vs-clear pattern as
    # credentials: ``None`` leaves the stored value unchanged; pass the matching
    # clear_* flag to nullify.
    kind_config: KindConfig | None = None
    clear_kind_config: bool = False
    kind_credentials: KindCredentials | None = None
    clear_kind_credentials: bool = False
    attached_repository_ids: list[str] | None = None
    # Disciplines follow the same omit/clear/replace pattern as repos:
    # ``None`` (omitted) leaves the existing list untouched, ``[]`` clears,
    # a non-empty list replaces.
    disciplines: list[Discipline] | None = None
    # Recipient list for the per-target weekly digest. Pass an empty
    # list to disable. Omit (None) to leave unchanged.
    weekly_digest_emails: list[str] | None = None


class TargetOut(BaseModel):
    id: str
    name: str
    base_url: str
    scope: list[str] | None = None
    exclude_paths: list[str] | None = None
    has_credentials: bool
    # Set when this Target is a passive mirror of a Repository. The UI
    # uses ``kind`` to render a badge ("URL" / "REPO" / "LLM") and to
    # route commission-scan to ``POST /repos/{id}/scan`` instead of
    # ``POST /scans`` for repo-mirror entries.
    repository_id: str | None = None
    kind: TargetKind = "url"
    # Returned only for kind == "llm". The provider/model/system are
    # safe to expose; secrets live on credentials_encrypted and never
    # leave the API.
    llm_config: LlmConfig | None = None
    # Returned for the 11 new non-llm kinds. Safe to expose (no secrets).
    kind_config: KindConfig | None = None
    # Presence-only flag for per-kind credentials. NEVER expose the encrypted
    # blob or its decrypted contents (kubeconfig, registry tokens, etc.).
    has_kind_credentials: bool = False
    # IDs of repositories attached to this runtime/cloud/AI target.
    attached_repository_ids: list[str] = Field(default_factory=list)
    # Security-program disciplines this Target carries. Empty list when
    # untagged (the legacy default).
    disciplines: list[Discipline] = Field(default_factory=list)
    # Per-target weekly digest recipient list. NULL/empty = disabled.
    weekly_digest_emails: list[str] | None = None
    created_at: datetime
