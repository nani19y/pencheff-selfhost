"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { Button, Input, Label } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import {
  GuardrailsEditor,
  type Guardrails as GuardrailsConfig,
} from "@/components/guardrails-editor";
import { FirewallEditor } from "@/components/firewall-editor";
import { EmailRecipientsInput } from "@/components/email-recipients-input";
import { api } from "@/lib/api";
import { useWorkspace } from "@/lib/workspace-context";
// Feature 001 — reuse the same form section components the new-target page uses,
// hydrated from the loaded Target.kind_config and submitted via PATCH.
import {
  ContainerImageFormSection,
  DEFAULT_CONTAINER_IMAGE_CONFIG,
  EMPTY_CONTAINER_IMAGE_CREDS,
  buildContainerImageKindCredentials,
  type ContainerImageConfig,
  type ContainerImageCredsDraft,
} from "@/components/register-target/container-image-form-section";
import {
  IacFormSection,
  DEFAULT_IAC_CONFIG,
  EMPTY_IAC_CREDS,
  type IacConfig,
  type IacCreds,
} from "@/components/register-target/iac-form-section";
import {
  PackageRegistryFormSection,
  DEFAULT_PACKAGE_REGISTRY_CONFIG,
  type PackageRegistryConfig,
} from "@/components/register-target/package-registry-form-section";
import {
  SbomFormSection,
  DEFAULT_SBOM_CONFIG,
  type SbomConfig,
} from "@/components/register-target/sbom-form-section";
import {
  CicdPipelineFormSection,
  DEFAULT_CICD_PIPELINE_CONFIG,
  EMPTY_CICD_PIPELINE_CREDS,
  type CicdPipelineConfig,
  type CicdPipelineCreds,
} from "@/components/register-target/cicd-pipeline-form-section";
import {
  K8sClusterFormSection,
  DEFAULT_K8S_CLUSTER_CONFIG,
  EMPTY_K8S_CREDS,
  buildK8sKindCredentials,
  validateK8sFormBeforeSubmit,
  type K8sClusterConfig,
  type K8sCredsDraft,
} from "@/components/register-target/k8s-cluster-form-section";
import {
  CloudFormSection,
  CLOUD_KINDS as CLOUD_KIND_LIST,
  buildCloudBaseUrl,
  buildCloudKindCredentials,
  cloudDisplayName,
  defaultCloudDraft,
  finalizeCloudDraft,
  validateCloudDraft,
  type CloudConfig,
  type CloudKind,
  type CloudTargetDraft,
} from "@/components/register-target/cloud-form-section";
import {
  WebAppFormSection,
  DEFAULT_WEB_APP_CONFIG,
  EMPTY_WEB_APP_CREDS,
  type WebAppConfig,
  type WebAppCredentials,
} from "@/components/register-target/web-app-form-section";
import {
  RestApiFormSection,
  DEFAULT_REST_API_CONFIG,
  EMPTY_REST_API_CREDS,
  type RestApiConfig,
  type RestApiCredentials,
} from "@/components/register-target/rest-api-form-section";
import {
  GraphqlFormSection,
  DEFAULT_GRAPHQL_CONFIG,
  EMPTY_GRAPHQL_CREDS,
  type GraphqlConfig,
  type GraphqlCredentials,
} from "@/components/register-target/graphql-form-section";
import {
  WebsocketFormSection,
  DEFAULT_WEBSOCKET_CONFIG,
  EMPTY_WEBSOCKET_CREDS,
  type WebsocketConfig,
  type WebsocketCredentials,
} from "@/components/register-target/websocket-form-section";
import {
  GrpcFormSection,
  DEFAULT_GRPC_CONFIG,
  DEFAULT_GRPC_METADATA,
  type GrpcConfig,
  type GrpcMetadataRow,
} from "@/components/register-target/grpc-form-section";
import {
  SourceCodeFormSection,
  DEFAULT_SOURCE_CODE_CONFIG,
  EMPTY_SOURCE_CODE_CREDS,
  type SourceCodeConfig,
  type SourceCodeCreds,
} from "@/components/register-target/source-code-form-section";
import {
  MemoryFormSection,
  type MemoryFileFormat,
  type MemorySourceType,
} from "@/components/register-target/memory-form-section";
import { McpFormSection } from "@/components/register-target/mcp-form-section";
import { AgentFormSection } from "@/components/register-target/agent-form-section";
import { RagFormSection } from "@/components/register-target/rag-form-section";
import {
  MlModelFormSection,
  type MlSourceType,
  type MlFormatHint,
} from "@/components/register-target/ml-model-form-section";
import {
  VoiceFormSection,
  type VoiceSourceType,
  type VoiceAudioFormat,
} from "@/components/register-target/voice-form-section";
import {
  LlmFormSection,
  type LlmJudgeProvider,
  type LlmProvider,
} from "@/components/register-target/llm-form-section";

// Kinds whose edit UI is dedicated form sections (not the legacy url/repo/llm
// form). When ``kind`` is in this set we render the section + PATCH the typed
// kind_config / kind_credentials payload.
const NEW_KIND_FORM_SECTIONS: ReadonlySet<Kind> = new Set([
  // Artifact + hybrid
  "container_image",
  "iac",
  "package_registry",
  "sbom",
  "cicd_pipeline",
  "k8s_cluster",
  // Infrastructure & Cloud Security
  ...CLOUD_KIND_LIST,
  // DAST cluster + source_code (feature 001 — second phase)
  "web_app",
  "rest_api",
  "graphql",
  "websocket",
  "grpc",
  "source_code",
  // MCP / AI-agent target kind
  "memory",
  "mcp",
  "agent",
  // RAG / vector-DB target kind
  "rag",
  // ML model artifact target kind
  "ml_model",
  // Voice / Speech-AI target kind
  "voice",
]);

// Feature 001 — widened from the legacy 3-value union to all 15 SupportedKind
// values. The new kinds (web_app / source_code / container_image / etc.) load
// in this page so detail-page → edit-page navigation doesn't 404, but the
// existing rich edit UI only covers the legacy url/repo/llm kinds. New kinds
// see an advisory directing them to PATCH /targets/{id} or delete + re-register.
type Kind =
  | "url"
  | "repo"
  | "llm"
  | "web_app"
  | "rest_api"
  | "graphql"
  | "websocket"
  | "grpc"
  | "source_code"
  | "cicd_pipeline"
  | "iac"
  | "container_image"
  | "k8s_cluster"
  | "package_registry"
  | "sbom"
  | "cloud_account"
  | "serverless_function"
  | "cloud_storage"
  | "load_balancer_cdn"
  | "cloud_database"
  | "secrets_manager"
  | "memory"
  | "mcp"
  | "agent"
  | "rag"
  | "ml_model"
  | "voice";

const REPO_ATTACHABLE_KINDS: ReadonlySet<Kind> = new Set([
  "url",
  "web_app",
  "rest_api",
  "graphql",
  "websocket",
  "grpc",
  "llm",
  "mcp",
  "rag",
  "ml_model",
  "voice",
  "memory",
  "cloud_account",
  "serverless_function",
  "cloud_storage",
  "load_balancer_cdn",
  "cloud_database",
  "secrets_manager",
]);

function canAttachRepos(kind: Kind): boolean {
  return REPO_ATTACHABLE_KINDS.has(kind);
}

type AttachableRepo = {
  id: string;
  full_name: string;
  provider: string;
  language: string | null;
  html_url: string;
  local_path: string | null;
};

type LlmConfigOut = {
  provider: LlmProvider;
  model?: string | null;
  system_prompt?: string | null;
  request_template?: string | null;
  response_path?: string | null;
  command?: string[] | null;
  redteam?: Record<string, unknown> | null;
  thresholds?: Record<string, unknown> | null;
  budget?: Record<string, unknown> | null;
  retries?: number;
  backoff_s?: number;
  cache?: boolean;
  cache_size?: number;
  timeout_s?: number;
  concurrency?: number;
  max_rps?: number | null;
  max_rpm?: number | null;
  rate_burst?: number | null;
  aws_region?: string | null;
  vertex_project?: string | null;
  vertex_location?: string | null;
  azure_deployment?: string | null;
  azure_api_version?: string | null;
  guardrails?: GuardrailsConfig | null;
};

type Target = {
  id: string;
  name: string;
  base_url: string;
  scope: string[] | null;
  exclude_paths: string[] | null;
  has_credentials: boolean;
  has_kind_credentials?: boolean;
  kind?: Kind;
  llm_config?: LlmConfigOut | null;
  // Feature 001 — typed JSONB payload returned by the API for the 11 new
  // non-llm kinds. Discriminated union; the kind field matches Target.kind.
  kind_config?: Record<string, unknown> | null;
  attached_repository_ids?: string[];
  weekly_digest_emails?: string[] | null;
  created_at: string;
};

type HeaderRow = { key: string; value: string };
type Profile = "quick" | "standard" | "deep";

const CLOUD_EDIT_KINDS: ReadonlySet<Kind> = new Set(CLOUD_KIND_LIST);

function isCloudKind(kind: Kind): kind is CloudKind {
  return CLOUD_EDIT_KINDS.has(kind);
}

const MEMORY_PROVIDER_SOURCES = new Set<MemorySourceType>([
  "mem0",
  "zep",
  "langgraph_store",
  "redis",
  "pinecone",
  "chroma",
  "qdrant",
  "weaviate",
  "custom_http",
]);

function buildHeaderCreds(rows: HeaderRow[]) {
  const headers: Record<string, string> = {};
  for (const row of rows) {
    const key = row.key.trim();
    const value = row.value.trim();
    if (key && value) headers[key] = value;
  }
  return Object.keys(headers).length > 0 ? { headers } : null;
}

function parseMemoryItemLine(line: string): string | Record<string, unknown> {
  const trimmed = line.trim();
  if (!trimmed) return "";
  try {
    const parsed = JSON.parse(trimmed);
    if (
      parsed &&
      !Array.isArray(parsed) &&
      typeof parsed === "object" &&
      typeof parsed.text === "string"
    ) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // Plain text memory rows are valid.
  }
  return trimmed;
}

function memoryItemsFromText(
  value: string,
): (string | Record<string, unknown>)[] {
  return value
    .split("\n")
    .map(parseMemoryItemLine)
    .filter((item) => {
      if (typeof item === "string") return Boolean(item);
      return Boolean(item.text);
    });
}

function compactObject<T extends Record<string, unknown>>(value: T): T {
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => entry !== "" && entry !== null),
  ) as T;
}

function memoryBaseUrl(
  sourceType: MemorySourceType,
  providerUrl: string,
  label: string,
) {
  if (sourceType === "manual_items") return `memory://${label || "items"}`;
  if (sourceType === "file_upload") return `memory+file://${label || "upload"}`;
  const trimmed = providerUrl.trim();
  if (!trimmed) return `memory+${sourceType}://source`;
  try {
    return `memory+${sourceType}://${new URL(trimmed).host}`;
  } catch {
    return `memory+${sourceType}://${trimmed}`;
  }
}

function csvList(value: string): string[] | null {
  const rows = value
    .split(/[,\n]/)
    .map((v) => v.trim())
    .filter(Boolean);
  return rows.length ? rows : null;
}

function parseJsonObject(
  value: string,
  label: string,
): Record<string, unknown> | null {
  if (!value.trim()) return null;
  const parsed = JSON.parse(value);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error(`${label} must be a JSON object.`);
  }
  return parsed as Record<string, unknown>;
}

function parseJsonValue(value: string, label: string): unknown {
  if (!value.trim()) return null;
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

function stringifyJsonValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

export default function EditTargetPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const id = mounted ? pathSegment(pathname, 2) : "";
  const router = useRouter();

  const { activeWorkspace } = useWorkspace();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [weeklyDigestEmails, setWeeklyDigestEmails] = useState<string[]>([]);

  // Common
  const [kind, setKind] = useState<Kind>("url");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [hadCreds, setHadCreds] = useState(false);
  const [clearCreds, setClearCreds] = useState(false);

  // URL-target credentials (write-only). Blank = leave alone.
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [token, setToken] = useState("");
  const [cookie, setCookie] = useState("");

  // LLM-target fields
  const [llmProvider, setLlmProvider] = useState<LlmProvider>("openai-chat");
  const [llmModel, setLlmModel] = useState("");
  const [llmSystemPrompt, setLlmSystemPrompt] = useState("");
  const [llmRequestTemplate, setLlmRequestTemplate] = useState("");
  const [llmResponsePath, setLlmResponsePath] = useState("");
  const [llmCommand, setLlmCommand] = useState("");
  const [awsRegion, setAwsRegion] = useState("us-east-1");
  const [vertexProject, setVertexProject] = useState("");
  const [vertexLocation, setVertexLocation] = useState("us-central1");
  const [azureDeployment, setAzureDeployment] = useState("");
  const [azureApiVersion, setAzureApiVersion] = useState("2024-10-21");
  // Auth header rows (LLM kind). Existing values are write-only so the
  // form starts empty + a hint that headers are on file.
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>([
    { key: "Authorization", value: "" },
  ]);
  // Red-team JSON-shaped fields
  const [llmStrategies, setLlmStrategies] = useState("");
  const [llmCompositeStrategies, setLlmCompositeStrategies] = useState("");
  const [llmDatasets, setLlmDatasets] = useState("");
  const [llmGuardrails, setLlmGuardrails] = useState("");
  const [llmLanguages, setLlmLanguages] = useState("");
  const [llmPoliciesJson, setLlmPoliciesJson] = useState("");
  const [llmIntentsJson, setLlmIntentsJson] = useState("");
  const [llmVariablesJson, setLlmVariablesJson] = useState("");
  const [llmDiscoveryJson, setLlmDiscoveryJson] = useState("");
  const [llmJudgeJson, setLlmJudgeJson] = useState("");
  const [llmAttackerJson, setLlmAttackerJson] = useState("");
  const [llmEmbedderJson, setLlmEmbedderJson] = useState("");
  const [llmJudgeEnabled, setLlmJudgeEnabled] = useState(false);
  const [llmJudgeProvider, setLlmJudgeProvider] =
    useState<LlmJudgeProvider>("openai-chat");
  const [llmJudgeEndpoint, setLlmJudgeEndpoint] = useState(
    "https://api.openai.com/v1/chat/completions",
  );
  const [llmJudgeModel, setLlmJudgeModel] = useState("");
  const [llmJudgeCommand, setLlmJudgeCommand] = useState("");
  const [llmJudgeHeaderRows, setLlmJudgeHeaderRows] = useState<HeaderRow[]>([
    { key: "Authorization", value: "" },
  ]);
  const [llmIterative, setLlmIterative] = useState<
    "" | "static" | "pair" | "tap" | "goat" | "hydra"
  >("");
  const [llmGuardrailBypass, setLlmGuardrailBypass] = useState(false);
  // Limits + rate
  const [llmMaxLatencyMs, setLlmMaxLatencyMs] = useState("");
  const [llmMaxTokensPerCall, setLlmMaxTokensPerCall] = useState("");
  const [llmMaxCalls, setLlmMaxCalls] = useState("");
  const [llmMaxCostUsd, setLlmMaxCostUsd] = useState("");
  const [llmRetries, setLlmRetries] = useState("");
  const [llmTimeoutS, setLlmTimeoutS] = useState("");
  const [llmConcurrency, setLlmConcurrency] = useState("");
  const [llmMaxRps, setLlmMaxRps] = useState("");
  const [llmMaxRpm, setLlmMaxRpm] = useState("");
  const [llmRateBurst, setLlmRateBurst] = useState("");
  const [llmGuardrailsConfig, setLlmGuardrailsConfig] =
    useState<GuardrailsConfig | null>(null);
  const [llmProfile, setLlmProfile] = useState<Profile>("standard");

  // ── Feature 001 — DAST cluster + source_code kind state ─────────────────
  // (web_app / rest_api / graphql / websocket / grpc / source_code each own
  // their own typed config + credentials.)
  const [webAppCfg, setWebAppCfg] = useState<WebAppConfig>(
    DEFAULT_WEB_APP_CONFIG,
  );
  const [webAppCreds, setWebAppCreds] =
    useState<WebAppCredentials>(EMPTY_WEB_APP_CREDS);

  const [restApiCfg, setRestApiCfg] = useState<RestApiConfig>(
    DEFAULT_REST_API_CONFIG,
  );
  const [restApiRawSpec, setRestApiRawSpec] = useState<string>("");
  const [restApiCreds, setRestApiCreds] =
    useState<RestApiCredentials>(EMPTY_REST_API_CREDS);

  const [graphqlCfg, setGraphqlCfg] = useState<GraphqlConfig>(
    DEFAULT_GRAPHQL_CONFIG,
  );
  const [graphqlCreds, setGraphqlCreds] =
    useState<GraphqlCredentials>(EMPTY_GRAPHQL_CREDS);

  const [wsCfg, setWsCfg] = useState<WebsocketConfig>(DEFAULT_WEBSOCKET_CONFIG);
  const [wsRawSubprotocols, setWsRawSubprotocols] = useState<string>("");
  const [wsCreds, setWsCreds] = useState<WebsocketCredentials>(
    EMPTY_WEBSOCKET_CREDS,
  );

  const [grpcCfg, setGrpcCfg] = useState<GrpcConfig>(DEFAULT_GRPC_CONFIG);
  const [grpcRawProto, setGrpcRawProto] = useState<string>("");
  const [grpcMetadata, setGrpcMetadata] = useState<GrpcMetadataRow[]>(
    DEFAULT_GRPC_METADATA,
  );

  const [sourceCodeCfg, setSourceCodeCfg] = useState<SourceCodeConfig>(
    DEFAULT_SOURCE_CODE_CONFIG,
  );
  const [sourceCodeCreds, setSourceCodeCreds] = useState<SourceCodeCreds>(
    EMPTY_SOURCE_CODE_CREDS,
  );
  const [sourceCodeRawLangs, setSourceCodeRawLangs] = useState<string>("");

  // ── Feature 001 per-kind form state (artifact + hybrid kinds) ───────────
  // Each state slot defaults to the kind's default config; on hydrate, the
  // loaded Target.kind_config replaces it when present + discriminator matches.
  const [containerImageCfg, setContainerImageCfg] =
    useState<ContainerImageConfig>(DEFAULT_CONTAINER_IMAGE_CONFIG);
  const [containerImageCreds, setContainerImageCreds] =
    useState<ContainerImageCredsDraft>(EMPTY_CONTAINER_IMAGE_CREDS);
  const [iacCfg, setIacCfg] = useState<IacConfig>(DEFAULT_IAC_CONFIG);
  const [iacCreds, setIacCreds] = useState<IacCreds>(EMPTY_IAC_CREDS);
  const [packageRegistryCfg, setPackageRegistryCfg] =
    useState<PackageRegistryConfig>(DEFAULT_PACKAGE_REGISTRY_CONFIG);
  const [rawPackages, setRawPackages] = useState<string>("");
  const [sbomCfg, setSbomCfg] = useState<SbomConfig>(DEFAULT_SBOM_CONFIG);
  const [cicdCfg, setCicdCfg] = useState<CicdPipelineConfig>(
    DEFAULT_CICD_PIPELINE_CONFIG,
  );
  const [cicdCreds, setCicdCreds] = useState<CicdPipelineCreds>(
    EMPTY_CICD_PIPELINE_CREDS,
  );
  const [rawCicdPaths, setRawCicdPaths] = useState<string>("");
  const [k8sCfg, setK8sCfg] = useState<K8sClusterConfig>(
    DEFAULT_K8S_CLUSTER_CONFIG,
  );
  const [k8sCreds, setK8sCreds] = useState<K8sCredsDraft>(EMPTY_K8S_CREDS);
  const [clearKindCredentials, setClearKindCredentials] =
    useState<boolean>(false);
  const [rawNamespaces, setRawNamespaces] = useState<string>("default");

  // ── Infrastructure & Cloud Security kind state ──────────────────────────
  const [cloudDraft, setCloudDraft] = useState<CloudTargetDraft>(() =>
    defaultCloudDraft("cloud_account"),
  );

  // ── MCP kind state ───────────────────────────────────────────────────────
  const [mcpSourceType, setMcpSourceType] = useState<
    "mcp_http" | "mcp_stdio" | "agent_http" | "agent_browser"
  >("mcp_http");
  const [mcpUrl, setMcpUrl] = useState("");
  const [mcpTransport, setMcpTransport] = useState<"sse" | "streamable_http">(
    "sse",
  );
  const [mcpCommand, setMcpCommand] = useState("");
  const [mcpCwd, setMcpCwd] = useState("");
  const [mcpEnvRows, setMcpEnvRows] = useState<
    { key: string; value: string }[]
  >([]);
  const [mcpProvider, setMcpProvider] = useState("openai-chat");
  const [mcpModel, setMcpModel] = useState("");
  const [mcpRequestTemplate, setMcpRequestTemplate] = useState("");
  const [mcpResponsePath, setMcpResponsePath] = useState("");
  const [mcpPromptSelector, setMcpPromptSelector] = useState("");
  const [mcpSendSelector, setMcpSendSelector] = useState("");
  const [mcpResponseSelector, setMcpResponseSelector] = useState("");
  const [mcpToolAllowlist, setMcpToolAllowlist] = useState("");
  const [mcpToolDenylist, setMcpToolDenylist] = useState("");
  const [mcpDynamicInvocation, setMcpDynamicInvocation] = useState(false);
  const [mcpDestructiveOptIn, setMcpDestructiveOptIn] = useState(false);
  const [mcpHeaderRows, setMcpHeaderRows] = useState<
    { key: string; value: string }[]
  >([]);

  // ── RAG kind state ───────────────────────────────────────────────────────
  const [ragSourceType, setRagSourceType] = useState<
    "managed_vdb" | "self_hosted_vdb" | "rag_endpoint" | "embedding_artifact"
  >("managed_vdb");
  const [ragProvider, setRagProvider] = useState("pinecone");
  const [ragUrl, setRagUrl] = useState("");
  const [ragIndexName, setRagIndexName] = useState("");
  const [ragNamespace, setRagNamespace] = useState("");
  const [ragProviderLlm, setRagProviderLlm] = useState("openai-chat");
  const [ragRequestTemplate, setRagRequestTemplate] = useState("");
  const [ragResponsePath, setRagResponsePath] = useState("");
  const [ragItems, setRagItems] = useState("");
  const [ragCanaryText, setRagCanaryText] = useState("");
  const [ragQueryProbes, setRagQueryProbes] = useState(false);
  const [ragPoisonInjectionOptIn, setRagPoisonInjectionOptIn] = useState(false);
  const [ragHeaderRows, setRagHeaderRows] = useState<
    { key: string; value: string }[]
  >([]);

  // ── ML model kind state ──────────────────────────────────────────────────
  const [mlSourceType, setMlSourceType] = useState<MlSourceType>("file_url");
  const [mlUrl, setMlUrl] = useState("");
  const [mlHfRepo, setMlHfRepo] = useState("");
  const [mlHfRevision, setMlHfRevision] = useState("");
  const [mlLocalPath, setMlLocalPath] = useState("");
  const [mlFormatHint, setMlFormatHint] = useState<MlFormatHint>("auto");
  const [mlMaxBytes, setMlMaxBytes] = useState(524288000);

  // ── Voice / Speech-AI kind state ─────────────────────────────────────────
  const [voiceSourceType, setVoiceSourceType] =
    useState<VoiceSourceType>("stt_endpoint");
  const [voiceUrl, setVoiceUrl] = useState("");
  const [voiceAudioFormat, setVoiceAudioFormat] =
    useState<VoiceAudioFormat>("wav");
  const [voiceRequestTemplate, setVoiceRequestTemplate] = useState("");
  const [voiceResponsePath, setVoiceResponsePath] = useState("");
  const [voiceInjectionPhrase, setVoiceInjectionPhrase] = useState("");
  const [voiceAudioProbes, setVoiceAudioProbes] = useState(false);
  const [voiceHeaderRows, setVoiceHeaderRows] = useState<
    { key: string; value: string }[]
  >([{ key: "Authorization", value: "" }]);

  // ── Agent memory / vector-store kind state ──────────────────────────────
  const [memoryItemsText, setMemoryItemsText] = useState("");
  const [memorySourceType, setMemorySourceType] =
    useState<MemorySourceType>("manual_items");
  const [memoryUrl, setMemoryUrl] = useState("");
  const [memoryOrgId, setMemoryOrgId] = useState("");
  const [memoryProjectId, setMemoryProjectId] = useState("");
  const [memoryUserId, setMemoryUserId] = useState("");
  const [memorySessionId, setMemorySessionId] = useState("");
  const [memoryCollection, setMemoryCollection] = useState("");
  const [memoryNamespace, setMemoryNamespace] = useState("");
  const [memoryIndexName, setMemoryIndexName] = useState("");
  const [memoryFileName, setMemoryFileName] = useState("");
  const [memoryFileFormat, setMemoryFileFormat] =
    useState<MemoryFileFormat>("auto");
  const [memoryRequestTemplate, setMemoryRequestTemplate] = useState(
    '{"user_id":"{{user_id}}","namespace":"{{namespace}}","limit":500}',
  );
  const [memoryResponsePath, setMemoryResponsePath] =
    useState("$.memories[*].text");
  const [memoryHeaderRows, setMemoryHeaderRows] = useState<HeaderRow[]>([]);

  // True when the loaded Target.has_kind_credentials is set; renders a "creds
  // on file" notice and a "clear" toggle.
  const [hadKindCreds, setHadKindCreds] = useState<boolean>(false);

  // URL-target → attached repos. Hydrated from the target on mount;
  // available repos are fetched separately from /repos.
  const [availableRepos, setAvailableRepos] = useState<AttachableRepo[]>([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [reposError, setReposError] = useState<string | null>(null);
  const [attachedRepoIds, setAttachedRepoIds] = useState<string[]>([]);
  const [repoFilter, setRepoFilter] = useState("");

  function toggleAttachedRepo(rid: string) {
    setAttachedRepoIds((prev) =>
      prev.includes(rid) ? prev.filter((x) => x !== rid) : [...prev, rid],
    );
  }

  // Hydrate from the API.
  useEffect(() => {
    if (!id) return;
    let alive = true;
    api<Target>(`/targets/${id}`)
      .then((t) => {
        if (!alive) return;
        setKind((t.kind ?? "url") as Kind);
        setName(t.name);
        setUrl(t.base_url);
        setHadCreds(t.has_credentials);
        setHadKindCreds(Boolean(t.has_kind_credentials));
        if (Array.isArray(t.attached_repository_ids)) {
          setAttachedRepoIds(t.attached_repository_ids);
        }
        if (Array.isArray(t.weekly_digest_emails)) {
          setWeeklyDigestEmails(t.weekly_digest_emails);
        }
        // Feature 001 — hydrate the typed kind-specific form state when the
        // API returns kind_config matching one of the 6 new artifact/hybrid
        // kinds. The discriminator (cfg.kind) is checked so a server-side
        // drift never poisons a different kind's state.
        const kc = t.kind_config as Record<string, unknown> | null | undefined;
        if (kc && typeof kc === "object" && typeof kc.kind === "string") {
          switch (kc.kind) {
            case "web_app":
              setWebAppCfg(kc as unknown as WebAppConfig);
              break;
            case "rest_api": {
              const cfg = kc as unknown as RestApiConfig;
              setRestApiCfg(cfg);
              setRestApiRawSpec(
                cfg.api_spec ? JSON.stringify(cfg.api_spec, null, 2) : "",
              );
              break;
            }
            case "graphql":
              setGraphqlCfg(kc as unknown as GraphqlConfig);
              break;
            case "websocket": {
              const cfg = kc as unknown as WebsocketConfig;
              setWsCfg(cfg);
              setWsRawSubprotocols((cfg.subprotocols || []).join("\n"));
              break;
            }
            case "grpc": {
              const cfg = kc as unknown as GrpcConfig;
              setGrpcCfg(cfg);
              setGrpcRawProto(
                (cfg.proto_files || []).join("\n\n// --- FILE BREAK ---\n\n"),
              );
              break;
            }
            case "source_code": {
              const cfg = kc as unknown as SourceCodeConfig;
              setSourceCodeCfg(cfg);
              setSourceCodeRawLangs((cfg.languages_hint || []).join(", "));
              break;
            }
            case "container_image":
              setContainerImageCfg(kc as unknown as ContainerImageConfig);
              break;
            case "iac":
              setIacCfg(kc as unknown as IacConfig);
              break;
            case "package_registry": {
              const cfg = kc as unknown as PackageRegistryConfig;
              setPackageRegistryCfg(cfg);
              // Render the package_list back into the textarea as JSON.
              const obj: Record<string, string> = {};
              for (const p of cfg.package_list || []) {
                if (p && typeof p.name === "string")
                  obj[p.name] = p.version || "*";
              }
              setRawPackages(JSON.stringify(obj, null, 2));
              break;
            }
            case "sbom":
              setSbomCfg(kc as unknown as SbomConfig);
              break;
            case "cicd_pipeline": {
              const cfg = kc as unknown as CicdPipelineConfig;
              setCicdCfg(cfg);
              setRawCicdPaths((cfg.config_paths || []).join("\n"));
              break;
            }
            case "k8s_cluster": {
              const cfg = kc as unknown as K8sClusterConfig;
              // Normalise legacy "live_cluster" alias for back-compat with rows
              // written before the multi-provider rewrite.
              if ((cfg.target as string) === "live_cluster") {
                cfg.target = "on_prem";
              }
              setK8sCfg(cfg);
              setRawNamespaces((cfg.namespaces || ["default"]).join("\n"));
              const provider: K8sCredsDraft["provider"] =
                cfg.target === "aws_eks"
                  ? "aws"
                  : cfg.target === "azure_aks"
                    ? "azure"
                    : cfg.target === "gcp_gke"
                      ? "gcp"
                      : "on_prem";
              setK8sCreds((prev) => ({ ...prev, provider }));
              break;
            }
            case "cloud_account":
            case "serverless_function":
            case "cloud_storage":
            case "load_balancer_cdn":
            case "cloud_database":
            case "secrets_manager": {
              const cfg = kc as unknown as CloudConfig;
              setCloudDraft({
                ...defaultCloudDraft(cfg.kind),
                name: t.name,
                config: cfg,
                rawRegions: (cfg.regions || []).join(", "),
                rawResourceNames: (
                  cfg.function_names ||
                  cfg.resource_names ||
                  []
                ).join("\n"),
                rawResourceTagsJson: JSON.stringify(
                  cfg.resource_tags || {},
                  null,
                  2,
                ),
                rawInventoryJson: cfg.inventory
                  ? JSON.stringify(cfg.inventory, null, 2)
                  : "",
              });
              break;
            }
            case "memory": {
              const c = kc as Record<string, unknown>;
              setMemorySourceType(
                (c.source_type as MemorySourceType) ?? "manual_items",
              );
              setMemoryUrl((c.url as string) ?? "");
              setMemoryOrgId((c.org_id as string) ?? "");
              setMemoryProjectId((c.project_id as string) ?? "");
              setMemoryUserId((c.user_id as string) ?? "");
              setMemorySessionId((c.session_id as string) ?? "");
              setMemoryCollection((c.collection as string) ?? "");
              setMemoryNamespace((c.namespace as string) ?? "");
              setMemoryIndexName((c.index_name as string) ?? "");
              setMemoryFileName((c.file_name as string) ?? "");
              setMemoryFileFormat(
                (c.file_format as MemoryFileFormat) ?? "auto",
              );
              setMemoryRequestTemplate(
                (c.request_template as string) ??
                  '{"user_id":"{{user_id}}","namespace":"{{namespace}}","limit":500}',
              );
              setMemoryResponsePath(
                (c.response_path as string) ?? "$.memories[*].text",
              );
              setMemoryItemsText(
                Array.isArray(c.items)
                  ? (c.items as Array<string | Record<string, unknown>>)
                      .map((item) =>
                        typeof item === "string" ? item : JSON.stringify(item),
                      )
                      .join("\n")
                  : "",
              );
              break;
            }
            case "mcp": {
              const c = kc as Record<string, unknown>;
              setMcpSourceType(
                (c.source_type as
                  "mcp_http" | "mcp_stdio" | "agent_http" | "agent_browser") ??
                  "mcp_http",
              );
              setMcpUrl((c.url as string) ?? "");
              setMcpTransport(
                (c.transport as "sse" | "streamable_http") ?? "sse",
              );
              setMcpCommand(
                Array.isArray(c.command)
                  ? (c.command as string[]).join(" ")
                  : "",
              );
              setMcpCwd((c.cwd as string) ?? "");
              if (c.env && typeof c.env === "object") {
                setMcpEnvRows(
                  Object.entries(c.env as Record<string, string>).map(
                    ([key, value]) => ({ key, value }),
                  ),
                );
              }
              setMcpProvider((c.provider as string) ?? "openai-chat");
              setMcpModel((c.model as string) ?? "");
              setMcpRequestTemplate((c.request_template as string) ?? "");
              setMcpResponsePath((c.response_path as string) ?? "");
              setMcpPromptSelector((c.prompt_selector as string) ?? "");
              setMcpSendSelector((c.send_selector as string) ?? "");
              setMcpResponseSelector((c.response_selector as string) ?? "");
              setMcpToolAllowlist(
                Array.isArray(c.tool_allowlist)
                  ? (c.tool_allowlist as string[]).join("\n")
                  : "",
              );
              setMcpToolDenylist(
                Array.isArray(c.tool_denylist)
                  ? (c.tool_denylist as string[]).join("\n")
                  : "",
              );
              setMcpDynamicInvocation(Boolean(c.dynamic_invocation));
              setMcpDestructiveOptIn(Boolean(c.destructive_opt_in));
              // credentials.headers are write-only on the API side; we start
              // with an empty row set and let the user re-enter if needed.
              break;
            }
            case "agent": {
              const c = kc as Record<string, unknown>;
              setMcpSourceType(
                (c.source_type as
                  "mcp_http" | "mcp_stdio" | "agent_http" | "agent_browser") ??
                  "agent_http",
              );
              setMcpUrl((c.url as string) ?? "");
              setMcpProvider((c.provider as string) ?? "openai-chat");
              setMcpModel((c.model as string) ?? "");
              setMcpRequestTemplate((c.request_template as string) ?? "");
              setMcpResponsePath((c.response_path as string) ?? "");
              setMcpPromptSelector((c.prompt_selector as string) ?? "");
              setMcpSendSelector((c.send_selector as string) ?? "");
              setMcpResponseSelector((c.response_selector as string) ?? "");
              setMcpToolAllowlist(
                Array.isArray(c.tool_allowlist)
                  ? (c.tool_allowlist as string[]).join("\n")
                  : "",
              );
              setMcpToolDenylist(
                Array.isArray(c.tool_denylist)
                  ? (c.tool_denylist as string[]).join("\n")
                  : "",
              );
              setMcpDynamicInvocation(Boolean(c.dynamic_invocation));
              setMcpDestructiveOptIn(Boolean(c.destructive_opt_in));
              break;
            }
            case "rag": {
              const c = kc as Record<string, unknown>;
              setRagSourceType(
                (c.source_type as
                  | "managed_vdb"
                  | "self_hosted_vdb"
                  | "rag_endpoint"
                  | "embedding_artifact") ?? "managed_vdb",
              );
              setRagProvider((c.provider as string) ?? "pinecone");
              setRagUrl((c.url as string) ?? "");
              setRagIndexName((c.index_name as string) ?? "");
              setRagNamespace((c.namespace as string) ?? "");
              setRagProviderLlm((c.provider_llm as string) ?? "openai-chat");
              setRagRequestTemplate((c.request_template as string) ?? "");
              setRagResponsePath((c.response_path as string) ?? "");
              setRagItems(
                Array.isArray(c.items) ? (c.items as string[]).join("\n") : "",
              );
              setRagCanaryText((c.canary_text as string) ?? "");
              setRagQueryProbes(Boolean(c.query_probes));
              setRagPoisonInjectionOptIn(Boolean(c.poison_injection_opt_in));
              // credentials.headers are write-only on the API side; we start
              // with an empty row set and let the user re-enter if needed.
              break;
            }
            case "ml_model": {
              const c = kc as Record<string, unknown>;
              setMlSourceType((c.source_type as MlSourceType) ?? "file_url");
              setMlUrl((c.url as string) ?? "");
              setMlHfRepo((c.hf_repo as string) ?? "");
              setMlHfRevision((c.hf_revision as string) ?? "");
              setMlLocalPath((c.local_path as string) ?? "");
              setMlFormatHint((c.format_hint as MlFormatHint) ?? "auto");
              if (typeof c.max_bytes === "number") setMlMaxBytes(c.max_bytes);
              break;
            }
            case "voice": {
              const c = kc as Record<string, unknown>;
              setVoiceSourceType(
                (c.source_type as VoiceSourceType) ?? "stt_endpoint",
              );
              setVoiceUrl((c.url as string) ?? "");
              setVoiceAudioFormat(
                (c.audio_format as VoiceAudioFormat) ?? "wav",
              );
              setVoiceRequestTemplate((c.request_template as string) ?? "");
              setVoiceResponsePath((c.response_path as string) ?? "");
              setVoiceInjectionPhrase((c.injection_phrase as string) ?? "");
              setVoiceAudioProbes(Boolean(c.audio_probes));
              break;
            }
          }
        }
        const cfg = t.llm_config || null;
        if (cfg) {
          setLlmProvider(cfg.provider ?? "openai-chat");
          setLlmModel(cfg.model ?? "");
          setLlmSystemPrompt(cfg.system_prompt ?? "");
          setLlmRequestTemplate(cfg.request_template ?? "");
          setLlmResponsePath(cfg.response_path ?? "");
          setLlmCommand(cfg.command ? cfg.command.join(" ") : "");
          setAwsRegion(cfg.aws_region ?? "us-east-1");
          setVertexProject(cfg.vertex_project ?? "");
          setVertexLocation(cfg.vertex_location ?? "us-central1");
          setAzureDeployment(cfg.azure_deployment ?? "");
          setAzureApiVersion(cfg.azure_api_version ?? "2024-10-21");
          setLlmGuardrailsConfig(cfg.guardrails ?? null);
          if (typeof cfg.retries === "number")
            setLlmRetries(String(cfg.retries));
          if (typeof cfg.timeout_s === "number")
            setLlmTimeoutS(String(cfg.timeout_s));
          if (typeof cfg.concurrency === "number")
            setLlmConcurrency(String(cfg.concurrency));
          if (cfg.max_rps != null) setLlmMaxRps(String(cfg.max_rps));
          if (cfg.max_rpm != null) setLlmMaxRpm(String(cfg.max_rpm));
          if (cfg.rate_burst != null) setLlmRateBurst(String(cfg.rate_burst));
          const th = cfg.thresholds || {};
          if (typeof th["max_latency_ms"] === "number")
            setLlmMaxLatencyMs(String(th["max_latency_ms"]));
          if (typeof th["max_tokens_per_call"] === "number")
            setLlmMaxTokensPerCall(String(th["max_tokens_per_call"]));
          const bg = cfg.budget || {};
          if (typeof bg["max_calls"] === "number")
            setLlmMaxCalls(String(bg["max_calls"]));
          if (typeof bg["max_cost_usd"] === "number")
            setLlmMaxCostUsd(String(bg["max_cost_usd"]));
          const rt = cfg.redteam || {};
          if (Array.isArray(rt["strategies"]))
            setLlmStrategies((rt["strategies"] as string[]).join(", "));
          const cs = rt["composite_strategies"];
          if (Array.isArray(cs))
            setLlmCompositeStrategies(
              cs
                .map((row) =>
                  Array.isArray(row) ? row.join("+") : String(row),
                )
                .join(", "),
            );
          if (Array.isArray(rt["datasets"]))
            setLlmDatasets((rt["datasets"] as string[]).join(", "));
          if (Array.isArray(rt["guardrails"]))
            setLlmGuardrails(
              (rt["guardrails"] as Array<string | Record<string, unknown>>)
                .map((g) => (typeof g === "string" ? g : JSON.stringify(g)))
                .join(", "),
            );
          if (Array.isArray(rt["languages"]))
            setLlmLanguages((rt["languages"] as string[]).join(", "));
          if (rt["policies"])
            setLlmPoliciesJson(stringifyJsonValue(rt["policies"]));
          if (rt["intents"])
            setLlmIntentsJson(stringifyJsonValue(rt["intents"]));
          if (rt["variables"])
            setLlmVariablesJson(stringifyJsonValue(rt["variables"]));
          if (rt["discovery"])
            setLlmDiscoveryJson(stringifyJsonValue(rt["discovery"]));
          if (rt["judge"]) {
            setLlmJudgeJson(stringifyJsonValue(rt["judge"]));
            const judge = rt["judge"] as Record<string, unknown>;
            setLlmJudgeEnabled(Boolean(judge.enabled ?? true));
            setLlmJudgeProvider(
              (judge.provider as LlmJudgeProvider) ?? "openai-chat",
            );
            setLlmJudgeEndpoint((judge.endpoint as string) ?? "");
            setLlmJudgeModel((judge.model as string) ?? "");
            setLlmJudgeCommand(
              Array.isArray(judge.command)
                ? (judge.command as string[]).join(" ")
                : "",
            );
            if (judge.headers && typeof judge.headers === "object") {
              setLlmJudgeHeaderRows(
                Object.entries(judge.headers as Record<string, string>).map(
                  ([key, value]) => ({ key, value }),
                ),
              );
            }
          }
          if (rt["attacker"])
            setLlmAttackerJson(stringifyJsonValue(rt["attacker"]));
          if (rt["embedder"])
            setLlmEmbedderJson(stringifyJsonValue(rt["embedder"]));
          const iter = rt["iterative"];
          if (iter === "pair" || iter === "static") setLlmIterative(iter);
          else if (iter === true) setLlmIterative("static");
          if (typeof rt["guardrail_bypass"] === "boolean")
            setLlmGuardrailBypass(rt["guardrail_bypass"] as boolean);
        }
      })
      .catch((e: { message?: string } | unknown) => {
        const msg = (e as { message?: string })?.message ?? "Target not found.";
        setError(msg);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [id]);

  // Load the list of attachable repos once we know the target kind supports it.
  useEffect(() => {
    if (!canAttachRepos(kind)) return;
    let cancelled = false;
    setReposLoading(true);
    setReposError(null);
    api<AttachableRepo[]>("/repos")
      .then((rs) => {
        if (!cancelled) setAvailableRepos(rs);
      })
      .catch((err) => {
        if (!cancelled) setReposError(err?.message || "Failed to load repos.");
      })
      .finally(() => {
        if (!cancelled) setReposLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [kind]);

  const llmKind = kind === "llm";

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      // ── Feature 001 — artifact + hybrid kind PATCH branch ────────────────
      // The 6 new kinds use their own form sections and submit a focused
      // payload via PATCH /targets/{id}. We branch early so the rest of this
      // function (LLM red-team JSON gather, URL-target credential write-only,
      // attached_repository_ids reconciliation) keeps driving url/repo/llm
      // unchanged for non-attachable kinds.
      if (NEW_KIND_FORM_SECTIONS.has(kind)) {
        let cfgPayload: Record<string, unknown> | null = null;
        let credsPayload: Record<string, unknown> | null = null;
        let flatCreds: Record<string, unknown> | null = null;
        let baseUrl = url;
        if (isCloudKind(kind)) {
          const validationError = validateCloudDraft(cloudDraft, {
            allowStoredCredentials: hadKindCreds && !clearKindCredentials,
          });
          if (validationError) throw new Error(validationError);
          const cfg = finalizeCloudDraft(cloudDraft);
          cfgPayload = cfg;
          baseUrl = buildCloudBaseUrl(kind, cfg);
          const built = buildCloudKindCredentials(kind, cfg, cloudDraft.creds);
          if (built) credsPayload = built;
        } else if (kind === "memory") {
          const memItems = memoryItemsFromText(memoryItemsText);
          if (
            MEMORY_PROVIDER_SOURCES.has(memorySourceType) &&
            !memoryUrl.trim()
          ) {
            throw new Error("Memory provider endpoint URL is required.");
          }
          if (memorySourceType === "file_upload" && memItems.length === 0) {
            throw new Error("Upload or paste at least one parsed memory item.");
          }
          if (
            memorySourceType === "custom_http" &&
            (!memoryRequestTemplate.trim() || !memoryResponsePath.trim())
          ) {
            throw new Error(
              "Custom HTTP memory source requires a request template and response path.",
            );
          }
          cfgPayload = compactObject({
            kind: "memory",
            source_type: memorySourceType,
            url: memoryUrl.trim(),
            org_id: memoryOrgId.trim(),
            project_id: memoryProjectId.trim(),
            user_id: memoryUserId.trim(),
            session_id: memorySessionId.trim(),
            collection: memoryCollection.trim(),
            namespace: memoryNamespace.trim(),
            index_name: memoryIndexName.trim(),
            file_name: memoryFileName.trim(),
            file_format:
              memorySourceType === "file_upload" ? memoryFileFormat : "",
            request_template:
              memorySourceType === "custom_http"
                ? memoryRequestTemplate.trim()
                : "",
            response_path:
              memorySourceType === "custom_http"
                ? memoryResponsePath.trim()
                : "",
            items: memItems,
          });
          const memoryCreds = MEMORY_PROVIDER_SOURCES.has(memorySourceType)
            ? buildHeaderCreds(memoryHeaderRows)
            : null;
          if (memoryCreds) flatCreds = memoryCreds;
          baseUrl = memoryBaseUrl(
            memorySourceType,
            memoryUrl,
            name || memoryFileName || "items",
          );
        } else if (kind === "web_app") {
          if (!url.trim()) throw new Error("Application URL is required.");
          cfgPayload = {
            ...webAppCfg,
            api_spec_url: webAppCfg.api_spec_url?.trim() || undefined,
          };
          const c = webAppCreds;
          if (c.username || c.password || c.api_key || c.token || c.cookie) {
            flatCreds = {
              username: c.username || null,
              password: c.password || null,
              api_key: c.api_key || null,
              token: c.token || null,
              cookie: c.cookie || null,
            };
          }
        } else if (kind === "rest_api") {
          if (!url.trim()) throw new Error("API base URL is required.");
          cfgPayload = {
            ...restApiCfg,
            api_spec_url: restApiCfg.api_spec_url?.trim() || undefined,
            api_spec: restApiCfg.api_spec ?? null,
          };
          const c = restApiCreds;
          if (c.username || c.password || c.api_key || c.token || c.cookie) {
            flatCreds = {
              username: c.username || null,
              password: c.password || null,
              api_key: c.api_key || null,
              token: c.token || null,
              cookie: c.cookie || null,
            };
          }
        } else if (kind === "graphql") {
          if (!url.trim()) throw new Error("GraphQL endpoint is required.");
          if (
            !graphqlCfg.introspection_enabled &&
            !graphqlCfg.schema_sdl?.trim()
          ) {
            throw new Error(
              "Paste the schema SDL when introspection is disabled.",
            );
          }
          if (graphqlCfg.operations_to_test.length === 0) {
            throw new Error("Select at least one GraphQL operation type.");
          }
          cfgPayload = {
            ...graphqlCfg,
            schema_sdl: graphqlCfg.schema_sdl?.trim() || undefined,
            proxy: graphqlCfg.proxy?.trim() || undefined,
            headers:
              graphqlCfg.headers && Object.keys(graphqlCfg.headers).length
                ? graphqlCfg.headers
                : undefined,
          };
          const c = graphqlCreds;
          if (c.username || c.password || c.api_key || c.token || c.cookie) {
            flatCreds = {
              username: c.username || null,
              password: c.password || null,
              api_key: c.api_key || null,
              token: c.token || null,
              cookie: c.cookie || null,
            };
          }
        } else if (kind === "websocket") {
          if (!url.trim()) throw new Error("WebSocket endpoint is required.");
          cfgPayload = {
            ...wsCfg,
            origin_header: wsCfg.origin_header?.trim() || undefined,
            auth_token_in_query: wsCfg.auth_token_in_query?.trim() || undefined,
          };
          if (wsCreds.token || wsCreds.cookie) {
            flatCreds = {
              token: wsCreds.token || null,
              cookie: wsCreds.cookie || null,
            };
          }
        } else if (kind === "grpc") {
          if (!url.trim()) throw new Error("gRPC authority is required.");
          if (
            !grpcCfg.reflection_enabled &&
            (!grpcCfg.proto_files || grpcCfg.proto_files.length === 0)
          ) {
            throw new Error(
              "Paste or upload .proto file contents when reflection is disabled.",
            );
          }
          cfgPayload = grpcCfg;
          const headers: Record<string, string> = {};
          for (const row of grpcMetadata) {
            const k = row.key.trim();
            const v = row.value.trim();
            if (k && v) headers[k] = v;
          }
          if (Object.keys(headers).length > 0) flatCreds = { headers };
        } else if (kind === "source_code") {
          const needsRepoUrl =
            sourceCodeCfg.source === "github_url" ||
            sourceCodeCfg.source === "tarball_url";
          if (needsRepoUrl && !sourceCodeCfg.repo_url?.trim()) {
            throw new Error(
              "Repository / tarball URL is required for this source type.",
            );
          }
          cfgPayload = sourceCodeCfg;
          baseUrl =
            sourceCodeCfg.repo_url?.trim() ||
            (sourceCodeCfg.source === "local_path"
              ? "file:///"
              : "github-app://installation");
          if (sourceCodeCfg.source !== "local_path") {
            const sc = sourceCodeCreds;
            if (sc.auth_type === "pat" && sc.pat?.trim()) {
              credsPayload = {
                kind: "source_code",
                auth_type: "pat",
                pat: sc.pat,
              };
            } else if (
              sc.auth_type === "github_app" &&
              sc.github_app_id?.trim() &&
              sc.github_app_private_key?.trim()
            ) {
              credsPayload = {
                kind: "source_code",
                auth_type: "github_app",
                github_app_id: sc.github_app_id,
                github_app_private_key: sc.github_app_private_key,
                github_app_installation_id:
                  sc.github_app_installation_id?.trim() || undefined,
              };
            } else if (
              sc.auth_type === "ssh_key" &&
              sc.ssh_private_key?.trim()
            ) {
              credsPayload = {
                kind: "source_code",
                auth_type: "ssh_key",
                ssh_private_key: sc.ssh_private_key,
              };
            }
          }
        } else if (kind === "container_image") {
          if (!containerImageCfg.image_ref.trim())
            throw new Error("Container image reference is required.");
          cfgPayload = containerImageCfg;
          baseUrl = `oci://${containerImageCfg.image_ref}`;
          const ciCreds = buildContainerImageKindCredentials(
            containerImageCfg,
            containerImageCreds,
          );
          if (ciCreds) credsPayload = ciCreds;
        } else if (kind === "iac") {
          if (
            (iacCfg.source === "repo" || iacCfg.source === "tarball_url") &&
            !iacCfg.repo_url?.trim()
          ) {
            throw new Error("IaC source URL is required.");
          }
          if (iacCfg.frameworks.length === 0)
            throw new Error("Select at least one IaC framework.");
          cfgPayload = iacCfg;
          baseUrl = iacCfg.repo_url || `iac://${iacCfg.frameworks.join("+")}`;
          // Blank token on edit → keep whatever is already stored.
          if (iacCfg.source === "repo" && iacCreds.token?.trim()) {
            credsPayload = { kind: "iac", token: iacCreds.token.trim() };
          }
        } else if (kind === "package_registry") {
          if (packageRegistryCfg.package_list.length === 0)
            throw new Error("Package list cannot be empty.");
          cfgPayload = packageRegistryCfg;
          baseUrl = `pkg://${packageRegistryCfg.ecosystem}`;
        } else if (kind === "sbom") {
          if (!sbomCfg.content && !sbomCfg.url)
            throw new Error("SBOM requires either content or url.");
          cfgPayload = sbomCfg;
          baseUrl = sbomCfg.url || `sbom://${sbomCfg.format}`;
        } else if (kind === "cicd_pipeline") {
          if (!cicdCfg.repo_url?.trim())
            throw new Error("CI/CD pipeline repo URL is required.");
          cfgPayload = cicdCfg;
          baseUrl = cicdCfg.repo_url;
          // Blank token on edit → keep whatever is already stored.
          if (cicdCreds.token?.trim() || cicdCreds.jenkins_user?.trim()) {
            credsPayload = {
              kind: "cicd_pipeline",
              provider: cicdCfg.provider,
              ...(cicdCreds.token?.trim()
                ? { token: cicdCreds.token.trim() }
                : {}),
              ...(cicdCreds.jenkins_user?.trim()
                ? { jenkins_user: cicdCreds.jenkins_user.trim() }
                : {}),
            };
          }
        } else if (kind === "k8s_cluster") {
          // Edit-flow tolerance: when creds are already on file, skip the
          // creds-required check so the user can edit just the config side.
          const credsAlreadySent =
            buildK8sKindCredentials(k8sCfg, k8sCreds) !== null;
          if (
            !credsAlreadySent &&
            hadKindCreds &&
            k8sCfg.target !== "manifests_only"
          ) {
            // OK — leave previously-stored creds in place.
          } else {
            const k8sErr = validateK8sFormBeforeSubmit(k8sCfg, k8sCreds);
            if (k8sErr) throw new Error(k8sErr);
          }
          cfgPayload = k8sCfg;
          if (k8sCfg.target === "manifests_only") {
            baseUrl = k8sCfg.manifests_archive_url || `k8s://manifests`;
          } else if (k8sCfg.target === "aws_eks") {
            baseUrl = `k8s://aws/${k8sCfg.aws_region}/${k8sCfg.aws_cluster_name}`;
          } else if (k8sCfg.target === "azure_aks") {
            baseUrl = `k8s://azure/${k8sCfg.azure_resource_group}/${k8sCfg.azure_cluster_name}`;
          } else if (k8sCfg.target === "gcp_gke") {
            baseUrl = `k8s://gcp/${k8sCfg.gcp_project_id}/${k8sCfg.gcp_location}/${k8sCfg.gcp_cluster_name}`;
          } else {
            baseUrl = `k8s://live/${k8sCfg.namespaces.join(",")}`;
          }
          const built = buildK8sKindCredentials(k8sCfg, k8sCreds);
          if (built) credsPayload = built;
        } else if (kind === "mcp") {
          const st = mcpSourceType;
          if (st === "mcp_http" && !mcpUrl.trim())
            throw new Error("MCP server URL is required.");
          if (st === "mcp_stdio" && !mcpCommand.trim())
            throw new Error("stdio command is required.");
          if (st === "agent_http" && !mcpProvider)
            throw new Error("Agent provider is required.");
          if (
            st === "agent_browser" &&
            !(
              mcpUrl.trim() &&
              mcpPromptSelector.trim() &&
              mcpSendSelector.trim() &&
              mcpResponseSelector.trim()
            )
          )
            throw new Error(
              "Browser agent requires URL and all three selectors.",
            );
          if (mcpDestructiveOptIn && !mcpDynamicInvocation)
            throw new Error(
              "Destructive invocation requires dynamic invocation.",
            );

          const allow = mcpToolAllowlist
            .split(/[\n,]/)
            .map((s) => s.trim())
            .filter(Boolean);
          const deny = mcpToolDenylist
            .split(/[\n,]/)
            .map((s) => s.trim())
            .filter(Boolean);
          const overlap = allow.filter((a) => deny.includes(a));
          if (overlap.length)
            throw new Error(`Tool allow/deny overlap: ${overlap.join(", ")}`);

          const env: Record<string, string> = {};
          for (const row of mcpEnvRows) {
            const k = row.key.trim();
            const v = row.value.trim();
            if (k && v) env[k] = v;
          }

          const cfg: Record<string, unknown> = {
            kind: "mcp",
            source_type: st,
          };
          if (st === "mcp_http") {
            cfg.url = mcpUrl;
            cfg.transport = mcpTransport;
          }
          if (st === "mcp_stdio") {
            cfg.command = mcpCommand
              .split(/[\n ]+/)
              .map((s) => s.trim())
              .filter(Boolean);
            if (mcpCwd.trim()) cfg.cwd = mcpCwd.trim();
            if (Object.keys(env).length) cfg.env = env;
          }
          if (st === "agent_http") {
            cfg.provider = mcpProvider;
            if (mcpModel.trim()) cfg.model = mcpModel.trim();
            if (mcpProvider === "custom") {
              cfg.request_template = mcpRequestTemplate;
              cfg.response_path = mcpResponsePath;
            }
          }
          if (st === "agent_browser") {
            cfg.url = mcpUrl;
            cfg.prompt_selector = mcpPromptSelector;
            cfg.send_selector = mcpSendSelector;
            cfg.response_selector = mcpResponseSelector;
          }
          if (allow.length) cfg.tool_allowlist = allow;
          if (deny.length) cfg.tool_denylist = deny;
          cfg.dynamic_invocation = mcpDynamicInvocation;
          cfg.destructive_opt_in = mcpDestructiveOptIn;

          cfgPayload = cfg;
          baseUrl =
            st === "mcp_http" || st === "agent_browser"
              ? mcpUrl
              : `mcp://${name || st}`;

          const mcpHeaders: Record<string, string> = {};
          for (const row of mcpHeaderRows) {
            const k = row.key.trim();
            const v = row.value.trim();
            if (k && v) mcpHeaders[k] = v;
          }
          if (Object.keys(mcpHeaders).length) {
            flatCreds = { headers: mcpHeaders };
          }
        } else if (kind === "agent") {
          const st = mcpSourceType;
          if (st === "agent_http" && !mcpProvider)
            throw new Error("Agent provider is required.");
          if (
            st === "agent_browser" &&
            !(
              mcpUrl.trim() &&
              mcpPromptSelector.trim() &&
              mcpSendSelector.trim() &&
              mcpResponseSelector.trim()
            )
          )
            throw new Error(
              "Browser agent requires URL and all three selectors.",
            );
          if (mcpDestructiveOptIn && !mcpDynamicInvocation)
            throw new Error(
              "Destructive invocation requires dynamic invocation.",
            );

          const allow = mcpToolAllowlist
            .split(/[\n,]/)
            .map((s) => s.trim())
            .filter(Boolean);
          const deny = mcpToolDenylist
            .split(/[\n,]/)
            .map((s) => s.trim())
            .filter(Boolean);
          const overlap = allow.filter((a) => deny.includes(a));
          if (overlap.length)
            throw new Error(`Tool allow/deny overlap: ${overlap.join(", ")}`);

          const agentCfg: Record<string, unknown> = {
            kind: "agent",
            source_type: st,
          };
          if (st === "agent_http") {
            agentCfg.provider = mcpProvider;
            if (mcpModel.trim()) agentCfg.model = mcpModel.trim();
            // Every agent_http provider except "executable" POSTs to this
            // endpoint; without it base_url stays agent://… and requests HTTP 0.
            if (mcpProvider !== "executable") {
              if (!mcpUrl.trim())
                throw new Error(
                  "Agent adapter requires a chat-completions URL.",
                );
              agentCfg.url = mcpUrl.trim();
            }
            if (mcpProvider === "custom") {
              agentCfg.request_template = mcpRequestTemplate;
              agentCfg.response_path = mcpResponsePath;
            }
          }
          if (st === "agent_browser") {
            agentCfg.url = mcpUrl;
            agentCfg.prompt_selector = mcpPromptSelector;
            agentCfg.send_selector = mcpSendSelector;
            agentCfg.response_selector = mcpResponseSelector;
          }
          if (allow.length) agentCfg.tool_allowlist = allow;
          if (deny.length) agentCfg.tool_denylist = deny;
          agentCfg.dynamic_invocation = mcpDynamicInvocation;
          agentCfg.destructive_opt_in = mcpDestructiveOptIn;

          cfgPayload = agentCfg;
          baseUrl = mcpUrl.trim() ? mcpUrl.trim() : `agent://${name || st}`;

          const agentHeaders: Record<string, string> = {};
          for (const row of mcpHeaderRows) {
            const k = row.key.trim();
            const v = row.value.trim();
            if (k && v) agentHeaders[k] = v;
          }
          if (Object.keys(agentHeaders).length) {
            flatCreds = { headers: agentHeaders };
          }
        } else if (kind === "rag") {
          const st = ragSourceType;
          if (
            (st === "managed_vdb" || st === "self_hosted_vdb") &&
            !(ragProvider && ragUrl.trim())
          )
            throw new Error("Vector DB requires provider and URL.");
          if (st === "rag_endpoint" && !(ragProviderLlm && ragUrl.trim()))
            throw new Error("RAG endpoint requires a provider and URL.");
          if (
            st === "rag_endpoint" &&
            ragProviderLlm === "custom" &&
            !(ragRequestTemplate.trim() && ragResponsePath.trim())
          )
            throw new Error(
              "Custom provider requires request template and response path.",
            );
          if (st === "embedding_artifact" && !ragItems.trim())
            throw new Error("Embedding artifact requires items.");
          if (ragPoisonInjectionOptIn && !ragQueryProbes)
            throw new Error("Poison injection requires query probes.");

          const cfg: Record<string, unknown> = { kind: "rag", source_type: st };
          if (st === "managed_vdb" || st === "self_hosted_vdb") {
            cfg.provider = ragProvider;
            cfg.url = ragUrl;
            if (ragIndexName.trim()) cfg.index_name = ragIndexName.trim();
            if (ragNamespace.trim()) cfg.namespace = ragNamespace.trim();
          }
          if (st === "rag_endpoint") {
            cfg.provider_llm = ragProviderLlm;
            cfg.url = ragUrl;
            if (ragProviderLlm === "custom") {
              cfg.request_template = ragRequestTemplate;
              cfg.response_path = ragResponsePath;
            }
          }
          if (st === "embedding_artifact")
            cfg.items = ragItems
              .split("\n")
              .map((s) => s.trim())
              .filter(Boolean);
          cfg.query_probes = ragQueryProbes;
          cfg.poison_injection_opt_in = ragPoisonInjectionOptIn;
          if (ragCanaryText.trim()) cfg.canary_text = ragCanaryText.trim();

          cfgPayload = cfg;
          baseUrl =
            st === "managed_vdb" ||
            st === "self_hosted_vdb" ||
            st === "rag_endpoint"
              ? ragUrl
              : `rag://${name || st}`;

          const ragHeaders: Record<string, string> = {};
          for (const row of ragHeaderRows) {
            const k = row.key.trim();
            const v = row.value.trim();
            if (k && v) ragHeaders[k] = v;
          }
          if (Object.keys(ragHeaders).length) {
            flatCreds = { headers: ragHeaders };
          }
        } else if (kind === "ml_model") {
          const st = mlSourceType;
          if (st === "file_url" && !mlUrl.trim())
            throw new Error("File URL source requires a model URL.");
          if (st === "huggingface" && !mlHfRepo.trim())
            throw new Error(
              "Hugging Face source requires a repo (owner/model).",
            );
          if (st === "local_path" && !mlLocalPath.trim())
            throw new Error("Local path source requires a model path.");

          const cfg: Record<string, unknown> = {
            kind: "ml_model",
            source_type: st,
            format_hint: mlFormatHint,
            max_bytes: mlMaxBytes,
          };
          if (st === "file_url") cfg.url = mlUrl.trim();
          if (st === "huggingface") {
            cfg.hf_repo = mlHfRepo.trim();
            if (mlHfRevision.trim()) cfg.hf_revision = mlHfRevision.trim();
          }
          if (st === "local_path") cfg.local_path = mlLocalPath.trim();

          cfgPayload = cfg;
          baseUrl =
            st === "file_url"
              ? mlUrl.trim()
              : st === "huggingface"
                ? `hf://${mlHfRepo.trim()}`
                : `file://${mlLocalPath.trim()}`;
        } else if (kind === "voice") {
          if (!voiceUrl.trim())
            throw new Error("Voice target requires an endpoint URL.");

          const cfg: Record<string, unknown> = {
            kind: "voice",
            source_type: voiceSourceType,
            url: voiceUrl.trim(),
            audio_format: voiceAudioFormat,
            audio_probes: voiceAudioProbes,
          };
          if (voiceRequestTemplate.trim())
            cfg.request_template = voiceRequestTemplate.trim();
          if (voiceResponsePath.trim())
            cfg.response_path = voiceResponsePath.trim();
          if (voiceInjectionPhrase.trim())
            cfg.injection_phrase = voiceInjectionPhrase.trim();

          cfgPayload = cfg;
          baseUrl = voiceUrl.trim();

          const voiceHeaders: Record<string, string> = {};
          for (const row of voiceHeaderRows) {
            const k = row.key.trim();
            const v = row.value.trim();
            if (k && v) voiceHeaders[k] = v;
          }
          // Only replace creds when the operator typed a header; leaving the
          // fields blank preserves any existing stored credential.
          if (Object.keys(voiceHeaders).length) {
            flatCreds = { headers: voiceHeaders };
          }
        }

        const patch: Record<string, unknown> = {
          name: isCloudKind(kind)
            ? cloudDraft.name ||
              cloudDisplayName(kind, finalizeCloudDraft(cloudDraft))
            : name,
          base_url: baseUrl,
          kind_config: cfgPayload,
        };
        if (credsPayload) {
          patch.kind_credentials = credsPayload;
        } else if (clearKindCredentials) {
          patch.clear_kind_credentials = true;
        }
        // DAST cluster + source_code kinds carry their write-only credentials
        // in the flat Credentials shape (the same path as kind=url + kind=llm).
        if (flatCreds) {
          patch.credentials = flatCreds;
        } else if (clearCreds) {
          patch.clear_credentials = true;
        }
        if (canAttachRepos(kind)) {
          patch.attached_repository_ids = attachedRepoIds;
        }
        // Digest emails follow the existing pattern (empty list clears).
        patch.weekly_digest_emails = weeklyDigestEmails;
        await api(`/targets/${id}`, { method: "PATCH", json: patch });
        router.push(`/targets/${id}`);
        return;
      }

      const payload: Record<string, unknown> = {
        name,
        base_url: url,
      };

      if (clearCreds) {
        payload.clear_credentials = true;
      } else if (llmKind) {
        // LLM headers — only POST credentials when at least one row has
        // both key + value, otherwise leave the existing blob intact.
        const headers: Record<string, string> = {};
        for (const row of headerRows) {
          const k = row.key.trim();
          const v = row.value.trim();
          if (k && v) headers[k] = v;
        }
        if (Object.keys(headers).length > 0) {
          payload.credentials = { headers };
        }
      } else {
        // URL-target write-only credentials.
        const hasCredInput = !!(
          username ||
          password ||
          apiKey ||
          token ||
          cookie
        );
        if (hasCredInput) {
          payload.credentials = {
            username: username || null,
            password: password || null,
            api_key: apiKey || null,
            token: token || null,
            cookie: cookie || null,
          };
        }
      }

      if (llmKind) {
        // Build llm_config from the form. We send a full object so the
        // backend replaces the previous one cleanly (semantics: edit
        // = full overwrite of the non-secret config). Empty fields
        // become null so the backend can drop them.
        const redteam: Record<string, unknown> = {};
        const strategies = csvList(llmStrategies);
        if (strategies) redteam.strategies = strategies;
        const composite = csvList(llmCompositeStrategies)?.map((s) =>
          s.includes("+")
            ? s
                .split("+")
                .map((p) => p.trim())
                .filter(Boolean)
            : s,
        );
        if (composite && composite.length)
          redteam.composite_strategies = composite;
        const datasets = csvList(llmDatasets);
        if (datasets) redteam.datasets = datasets;
        const guardrails = csvList(llmGuardrails);
        if (guardrails) redteam.guardrails = guardrails;
        const languages = csvList(llmLanguages);
        if (languages) redteam.languages = languages;
        const policies = parseJsonValue(llmPoliciesJson, "Policies");
        if (policies) redteam.policies = policies;
        const intents = parseJsonValue(llmIntentsJson, "Intents");
        if (intents) redteam.intents = intents;
        const variables = parseJsonObject(llmVariablesJson, "Variables");
        if (variables) redteam.variables = variables;
        const discovery = parseJsonObject(llmDiscoveryJson, "Discovery");
        if (discovery) redteam.discovery = discovery;
        const judgeHeaders: Record<string, string> = {};
        for (const row of llmJudgeHeaderRows) {
          const k = row.key.trim();
          const v = row.value.trim();
          if (k && v) judgeHeaders[k] = v;
        }
        if (llmJudgeEnabled) {
          redteam.judge = {
            enabled: true,
            provider: llmJudgeProvider,
            endpoint:
              llmJudgeProvider === "executable"
                ? null
                : llmJudgeEndpoint || null,
            model: llmJudgeModel || null,
            headers: Object.keys(judgeHeaders).length > 0 ? judgeHeaders : null,
            command:
              llmJudgeProvider === "executable"
                ? csvList(llmJudgeCommand)
                : null,
          };
        }
        const attacker = parseJsonObject(llmAttackerJson, "Attacker");
        if (attacker) redteam.attacker = attacker;
        const embedder = parseJsonObject(llmEmbedderJson, "Embedder");
        if (embedder) redteam.embedder = embedder;
        if (llmIterative) redteam.iterative = llmIterative;
        if (llmGuardrailBypass) redteam.guardrail_bypass = true;

        const thresholds: Record<string, unknown> = {};
        if (llmMaxLatencyMs)
          thresholds.max_latency_ms = Number(llmMaxLatencyMs);
        if (llmMaxTokensPerCall)
          thresholds.max_tokens_per_call = Number(llmMaxTokensPerCall);

        const budget: Record<string, unknown> = {};
        if (llmMaxCalls) budget.max_calls = Number(llmMaxCalls);
        if (llmMaxCostUsd) budget.max_cost_usd = Number(llmMaxCostUsd);

        if (llmProvider === "custom") {
          if (!llmRequestTemplate.trim() || !llmResponsePath.trim()) {
            throw new Error(
              "Custom provider requires both a request body template and a response path.",
            );
          }
        }
        if (llmProvider === "executable" && !llmCommand.trim()) {
          throw new Error("Executable provider requires a command.");
        }
        if (
          llmJudgeEnabled &&
          llmJudgeProvider !== "executable" &&
          llmJudgeProvider !== "openai-moderation" &&
          !llmJudgeEndpoint.trim()
        ) {
          throw new Error("Judge mode requires a judge endpoint.");
        }
        if (
          llmJudgeEnabled &&
          llmJudgeProvider === "executable" &&
          !llmJudgeCommand.trim()
        ) {
          throw new Error("Executable judge requires a command.");
        }

        payload.llm_config = {
          provider: llmProvider,
          model: llmModel || null,
          system_prompt: llmSystemPrompt || null,
          request_template:
            llmProvider === "custom" || llmProvider === "websocket"
              ? llmRequestTemplate
              : null,
          response_path:
            llmProvider === "custom" || llmProvider === "websocket"
              ? llmResponsePath
              : null,
          command:
            llmProvider === "executable"
              ? llmCommand.trim().split(/\s+/).filter(Boolean)
              : null,
          aws_region:
            llmProvider === "bedrock" ? awsRegion.trim() || "us-east-1" : null,
          vertex_project:
            llmProvider === "vertex" ? vertexProject.trim() || null : null,
          vertex_location:
            llmProvider === "vertex"
              ? vertexLocation.trim() || "us-central1"
              : null,
          azure_deployment:
            llmProvider === "azure-openai"
              ? azureDeployment.trim() || null
              : null,
          azure_api_version:
            llmProvider === "azure-openai"
              ? azureApiVersion.trim() || "2024-10-21"
              : null,
          redteam: Object.keys(redteam).length ? redteam : null,
          thresholds: Object.keys(thresholds).length ? thresholds : null,
          budget: Object.keys(budget).length ? budget : null,
          retries: llmRetries ? Number(llmRetries) : null,
          timeout_s: llmTimeoutS ? Number(llmTimeoutS) : null,
          concurrency: llmConcurrency ? Number(llmConcurrency) : null,
          max_rps: llmMaxRps ? Number(llmMaxRps) : null,
          max_rpm: llmMaxRpm ? Number(llmMaxRpm) : null,
          rate_burst: llmRateBurst ? Number(llmRateBurst) : null,
          guardrails: llmGuardrailsConfig,
        };
      }

      // Send the current selection on every save for attachable targets so the
      // backend reconciles add/remove against the join table. For non-attachable
      // targets, omit the field so the API leaves it untouched.
      if (canAttachRepos(kind)) {
        payload.attached_repository_ids = attachedRepoIds;
      }

      // Always send the digest emails so an empty list clears the
      // subscription. The backend sanitises + caps; client-side we
      // only forward what the picker captured.
      payload.weekly_digest_emails = weeklyDigestEmails;

      await api(`/targets/${id}`, { method: "PATCH", json: payload });
      router.push(`/targets/${id}`);
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Unable to save changes.";
      setError(msg);
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="py-6">
        <InlineLoading label="Loading target…" />
      </div>
    );
  }

  return (
    <div>
      <header className="mb-6">
        <p className="eyebrow-gilt">Amendment</p>
        <h1 className="mt-4 font-display text-[36px] md:text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
          Edit target.
        </h1>
        <p className="mt-3 text-[14px] text-slate max-w-[60ch]">
          Update identification, rotate credentials, or tune red-team
          configuration. Credential fields left blank retain what's already on
          file.
        </p>
      </header>

      <div className="formal-surface-elev p-6 md:p-8">
        {error && (
          <div className="mb-6 advisory-warn font-body text-[13px]">
            {error}
          </div>
        )}

        {/* Feature 001 — artifact + hybrid kind edit sections. When kind is
            one of the 6 new artifact/hybrid kinds, render its dedicated form
            section + save controls. The legacy url/repo/llm form below is
            skipped via the early-return in onSubmit. */}
        {NEW_KIND_FORM_SECTIONS.has(kind) ? (
          <form onSubmit={onSubmit} className="space-y-10">
            {isCloudKind(kind) && (
              <CloudFormSection draft={cloudDraft} onChange={setCloudDraft} />
            )}
            {kind === "web_app" && (
              <WebAppFormSection
                value={webAppCfg}
                onChange={setWebAppCfg}
                name={name}
                setName={setName}
                appUrl={url}
                setAppUrl={setUrl}
                creds={webAppCreds}
                setCreds={setWebAppCreds}
              />
            )}
            {kind === "rest_api" && (
              <RestApiFormSection
                value={restApiCfg}
                onChange={setRestApiCfg}
                name={name}
                setName={setName}
                baseUrl={url}
                setBaseUrl={setUrl}
                rawSpec={restApiRawSpec}
                setRawSpec={setRestApiRawSpec}
                creds={restApiCreds}
                setCreds={setRestApiCreds}
              />
            )}
            {kind === "graphql" && (
              <GraphqlFormSection
                value={graphqlCfg}
                onChange={setGraphqlCfg}
                name={name}
                setName={setName}
                endpoint={url}
                setEndpoint={setUrl}
                creds={graphqlCreds}
                setCreds={setGraphqlCreds}
              />
            )}
            {kind === "websocket" && (
              <WebsocketFormSection
                value={wsCfg}
                onChange={setWsCfg}
                name={name}
                setName={setName}
                wsEndpoint={url}
                setWsEndpoint={setUrl}
                rawSubprotocols={wsRawSubprotocols}
                setRawSubprotocols={setWsRawSubprotocols}
                creds={wsCreds}
                setCreds={setWsCreds}
              />
            )}
            {kind === "grpc" && (
              <GrpcFormSection
                value={grpcCfg}
                onChange={setGrpcCfg}
                name={name}
                setName={setName}
                authority={url}
                setAuthority={setUrl}
                rawProto={grpcRawProto}
                setRawProto={setGrpcRawProto}
                metadata={grpcMetadata}
                setMetadata={setGrpcMetadata}
              />
            )}
            {kind === "source_code" && (
              <SourceCodeFormSection
                value={sourceCodeCfg}
                onChange={setSourceCodeCfg}
                name={name}
                setName={setName}
                creds={sourceCodeCreds}
                setCreds={setSourceCodeCreds}
                rawLangsHint={sourceCodeRawLangs}
                setRawLangsHint={setSourceCodeRawLangs}
              />
            )}
            {kind === "container_image" && (
              <ContainerImageFormSection
                value={containerImageCfg}
                onChange={setContainerImageCfg}
                name={name}
                setName={setName}
                creds={containerImageCreds}
                setCreds={setContainerImageCreds}
              />
            )}
            {kind === "iac" && (
              <IacFormSection
                value={iacCfg}
                onChange={setIacCfg}
                name={name}
                setName={setName}
                creds={iacCreds}
                setCreds={setIacCreds}
              />
            )}
            {kind === "package_registry" && (
              <PackageRegistryFormSection
                value={packageRegistryCfg}
                onChange={setPackageRegistryCfg}
                name={name}
                setName={setName}
                rawPackages={rawPackages}
                setRawPackages={setRawPackages}
              />
            )}
            {kind === "sbom" && (
              <SbomFormSection
                value={sbomCfg}
                onChange={setSbomCfg}
                name={name}
                setName={setName}
              />
            )}
            {kind === "cicd_pipeline" && (
              <CicdPipelineFormSection
                value={cicdCfg}
                onChange={setCicdCfg}
                name={name}
                setName={setName}
                rawConfigPaths={rawCicdPaths}
                setRawConfigPaths={setRawCicdPaths}
                creds={cicdCreds}
                setCreds={setCicdCreds}
              />
            )}
            {kind === "k8s_cluster" && (
              <K8sClusterFormSection
                value={k8sCfg}
                onChange={setK8sCfg}
                name={name}
                setName={setName}
                creds={k8sCreds}
                setCreds={setK8sCreds}
                rawNamespaces={rawNamespaces}
                setRawNamespaces={setRawNamespaces}
              />
            )}
            {kind === "memory" && (
              <MemoryFormSection
                name={name}
                setName={setName}
                sourceType={memorySourceType}
                setSourceType={setMemorySourceType}
                url={memoryUrl}
                setUrl={setMemoryUrl}
                orgId={memoryOrgId}
                setOrgId={setMemoryOrgId}
                projectId={memoryProjectId}
                setProjectId={setMemoryProjectId}
                userId={memoryUserId}
                setUserId={setMemoryUserId}
                sessionId={memorySessionId}
                setSessionId={setMemorySessionId}
                collection={memoryCollection}
                setCollection={setMemoryCollection}
                namespace={memoryNamespace}
                setNamespace={setMemoryNamespace}
                indexName={memoryIndexName}
                setIndexName={setMemoryIndexName}
                fileName={memoryFileName}
                setFileName={setMemoryFileName}
                fileFormat={memoryFileFormat}
                setFileFormat={setMemoryFileFormat}
                requestTemplate={memoryRequestTemplate}
                setRequestTemplate={setMemoryRequestTemplate}
                responsePath={memoryResponsePath}
                setResponsePath={setMemoryResponsePath}
                headerRows={memoryHeaderRows}
                setHeaderRows={setMemoryHeaderRows}
                rawItems={memoryItemsText}
                setRawItems={setMemoryItemsText}
              />
            )}
            {kind === "mcp" &&
              (mcpSourceType === "mcp_http" ||
                mcpSourceType === "mcp_stdio") && (
                <McpFormSection
                  name={name}
                  setName={setName}
                  sourceType={mcpSourceType}
                  setSourceType={(v) =>
                    setMcpSourceType(
                      v as
                        | "mcp_http"
                        | "mcp_stdio"
                        | "agent_http"
                        | "agent_browser",
                    )
                  }
                  url={mcpUrl}
                  setUrl={setMcpUrl}
                  transport={mcpTransport}
                  setTransport={setMcpTransport}
                  command={mcpCommand}
                  setCommand={setMcpCommand}
                  cwd={mcpCwd}
                  setCwd={setMcpCwd}
                  envRows={mcpEnvRows}
                  setEnvRows={setMcpEnvRows}
                  toolAllowlist={mcpToolAllowlist}
                  setToolAllowlist={setMcpToolAllowlist}
                  toolDenylist={mcpToolDenylist}
                  setToolDenylist={setMcpToolDenylist}
                  dynamicInvocation={mcpDynamicInvocation}
                  setDynamicInvocation={setMcpDynamicInvocation}
                  destructiveOptIn={mcpDestructiveOptIn}
                  setDestructiveOptIn={setMcpDestructiveOptIn}
                  headerRows={mcpHeaderRows}
                  setHeaderRows={setMcpHeaderRows}
                />
              )}
            {/* ponytail: legacy mcp targets with agent source_type render via AgentFormSection */}
            {(kind === "mcp" || kind === "agent") &&
              (mcpSourceType === "agent_http" ||
                mcpSourceType === "agent_browser") && (
                <AgentFormSection
                  name={name}
                  setName={setName}
                  sourceType={mcpSourceType as "agent_http" | "agent_browser"}
                  setSourceType={(v) =>
                    setMcpSourceType(
                      v as
                        | "mcp_http"
                        | "mcp_stdio"
                        | "agent_http"
                        | "agent_browser",
                    )
                  }
                  url={mcpUrl}
                  setUrl={setMcpUrl}
                  provider={mcpProvider}
                  setProvider={setMcpProvider}
                  model={mcpModel}
                  setModel={setMcpModel}
                  requestTemplate={mcpRequestTemplate}
                  setRequestTemplate={setMcpRequestTemplate}
                  responsePath={mcpResponsePath}
                  setResponsePath={setMcpResponsePath}
                  promptSelector={mcpPromptSelector}
                  setPromptSelector={setMcpPromptSelector}
                  sendSelector={mcpSendSelector}
                  setSendSelector={setMcpSendSelector}
                  responseSelector={mcpResponseSelector}
                  setResponseSelector={setMcpResponseSelector}
                  toolAllowlist={mcpToolAllowlist}
                  setToolAllowlist={setMcpToolAllowlist}
                  toolDenylist={mcpToolDenylist}
                  setToolDenylist={setMcpToolDenylist}
                  dynamicInvocation={mcpDynamicInvocation}
                  setDynamicInvocation={setMcpDynamicInvocation}
                  destructiveOptIn={mcpDestructiveOptIn}
                  setDestructiveOptIn={setMcpDestructiveOptIn}
                  headerRows={mcpHeaderRows}
                  setHeaderRows={setMcpHeaderRows}
                />
              )}
            {kind === "rag" && (
              <RagFormSection
                name={name}
                setName={setName}
                sourceType={ragSourceType}
                setSourceType={setRagSourceType}
                provider={ragProvider}
                setProvider={setRagProvider}
                url={ragUrl}
                setUrl={setRagUrl}
                indexName={ragIndexName}
                setIndexName={setRagIndexName}
                namespace={ragNamespace}
                setNamespace={setRagNamespace}
                providerLlm={ragProviderLlm}
                setProviderLlm={setRagProviderLlm}
                requestTemplate={ragRequestTemplate}
                setRequestTemplate={setRagRequestTemplate}
                responsePath={ragResponsePath}
                setResponsePath={setRagResponsePath}
                items={ragItems}
                setItems={setRagItems}
                canaryText={ragCanaryText}
                setCanaryText={setRagCanaryText}
                queryProbes={ragQueryProbes}
                setQueryProbes={setRagQueryProbes}
                poisonInjectionOptIn={ragPoisonInjectionOptIn}
                setPoisonInjectionOptIn={setRagPoisonInjectionOptIn}
                headerRows={ragHeaderRows}
                setHeaderRows={setRagHeaderRows}
              />
            )}
            {kind === "ml_model" && (
              <MlModelFormSection
                name={name}
                setName={setName}
                sourceType={mlSourceType}
                setSourceType={setMlSourceType}
                url={mlUrl}
                setUrl={setMlUrl}
                hfRepo={mlHfRepo}
                setHfRepo={setMlHfRepo}
                hfRevision={mlHfRevision}
                setHfRevision={setMlHfRevision}
                localPath={mlLocalPath}
                setLocalPath={setMlLocalPath}
                formatHint={mlFormatHint}
                setFormatHint={setMlFormatHint}
                maxBytes={mlMaxBytes}
                setMaxBytes={setMlMaxBytes}
              />
            )}
            {kind === "voice" && (
              <VoiceFormSection
                name={name}
                setName={setName}
                sourceType={voiceSourceType}
                setSourceType={setVoiceSourceType}
                url={voiceUrl}
                setUrl={setVoiceUrl}
                audioFormat={voiceAudioFormat}
                setAudioFormat={setVoiceAudioFormat}
                requestTemplate={voiceRequestTemplate}
                setRequestTemplate={setVoiceRequestTemplate}
                responsePath={voiceResponsePath}
                setResponsePath={setVoiceResponsePath}
                injectionPhrase={voiceInjectionPhrase}
                setInjectionPhrase={setVoiceInjectionPhrase}
                audioProbes={voiceAudioProbes}
                setAudioProbes={setVoiceAudioProbes}
                headerRows={voiceHeaderRows}
                setHeaderRows={setVoiceHeaderRows}
              />
            )}

            {hadKindCreds && (
              <section>
                <p className="font-body text-[13px] text-slate italic">
                  Kind credentials are on file (encrypted blob in{" "}
                  <code>kind_credentials_encrypted</code>). Re-enter the
                  credentials above to overwrite, or check the box below to
                  delete.
                </p>
                <label className="mt-2 flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={clearKindCredentials}
                    onChange={(e) => setClearKindCredentials(e.target.checked)}
                    className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
                  />
                  <span className="font-body text-[13px] text-rust">
                    Clear stored kind credentials (Phase B scans will fall back
                    to manifests-only / Phase A only)
                  </span>
                </label>
              </section>
            )}

            <hr className="rule" />

            <div className="flex items-center justify-between">
              <Link href={`/targets/${id}`}>
                <Button variant="cyan">Cancel</Button>
              </Link>
              <Button variant="pink" type="submit" disabled={saving}>
                {saving ? "Saving…" : "Save changes"}
              </Button>
            </div>
          </form>
        ) : (
          <form onSubmit={onSubmit} className="space-y-10">
            {llmKind && (
              <LlmFormSection
                url={url}
                setUrl={setUrl}
                name={name}
                setName={setName}
                llmProvider={llmProvider}
                setLlmProvider={setLlmProvider}
                llmModel={llmModel}
                setLlmModel={setLlmModel}
                llmSystemPrompt={llmSystemPrompt}
                setLlmSystemPrompt={setLlmSystemPrompt}
                llmRequestTemplate={llmRequestTemplate}
                setLlmRequestTemplate={setLlmRequestTemplate}
                llmResponsePath={llmResponsePath}
                setLlmResponsePath={setLlmResponsePath}
                llmCommand={llmCommand}
                setLlmCommand={setLlmCommand}
                awsRegion={awsRegion}
                setAwsRegion={setAwsRegion}
                vertexProject={vertexProject}
                setVertexProject={setVertexProject}
                vertexLocation={vertexLocation}
                setVertexLocation={setVertexLocation}
                azureDeployment={azureDeployment}
                setAzureDeployment={setAzureDeployment}
                azureApiVersion={azureApiVersion}
                setAzureApiVersion={setAzureApiVersion}
                llmStrategies={llmStrategies}
                setLlmStrategies={setLlmStrategies}
                llmCompositeStrategies={llmCompositeStrategies}
                setLlmCompositeStrategies={setLlmCompositeStrategies}
                llmDatasets={llmDatasets}
                setLlmDatasets={setLlmDatasets}
                llmGuardrails={llmGuardrails}
                setLlmGuardrails={setLlmGuardrails}
                llmLanguages={llmLanguages}
                setLlmLanguages={setLlmLanguages}
                llmPoliciesJson={llmPoliciesJson}
                setLlmPoliciesJson={setLlmPoliciesJson}
                llmIntentsJson={llmIntentsJson}
                setLlmIntentsJson={setLlmIntentsJson}
                llmVariablesJson={llmVariablesJson}
                setLlmVariablesJson={setLlmVariablesJson}
                llmDiscoveryJson={llmDiscoveryJson}
                setLlmDiscoveryJson={setLlmDiscoveryJson}
                llmIterative={llmIterative}
                setLlmIterative={setLlmIterative}
                llmGuardrailBypass={llmGuardrailBypass}
                setLlmGuardrailBypass={setLlmGuardrailBypass}
                llmJudgeEnabled={llmJudgeEnabled}
                setLlmJudgeEnabled={setLlmJudgeEnabled}
                llmJudgeProvider={llmJudgeProvider}
                setLlmJudgeProvider={setLlmJudgeProvider}
                llmJudgeEndpoint={llmJudgeEndpoint}
                setLlmJudgeEndpoint={setLlmJudgeEndpoint}
                llmJudgeModel={llmJudgeModel}
                setLlmJudgeModel={setLlmJudgeModel}
                llmJudgeCommand={llmJudgeCommand}
                setLlmJudgeCommand={setLlmJudgeCommand}
                llmJudgeHeaderRows={llmJudgeHeaderRows}
                setLlmJudgeHeaderRows={setLlmJudgeHeaderRows}
                llmMaxLatencyMs={llmMaxLatencyMs}
                setLlmMaxLatencyMs={setLlmMaxLatencyMs}
                llmMaxTokensPerCall={llmMaxTokensPerCall}
                setLlmMaxTokensPerCall={setLlmMaxTokensPerCall}
                llmMaxCalls={llmMaxCalls}
                setLlmMaxCalls={setLlmMaxCalls}
                llmMaxCostUsd={llmMaxCostUsd}
                setLlmMaxCostUsd={setLlmMaxCostUsd}
                llmRetries={llmRetries}
                setLlmRetries={setLlmRetries}
                llmTimeoutS={llmTimeoutS}
                setLlmTimeoutS={setLlmTimeoutS}
                llmConcurrency={llmConcurrency}
                setLlmConcurrency={setLlmConcurrency}
                llmMaxRps={llmMaxRps}
                setLlmMaxRps={setLlmMaxRps}
                llmMaxRpm={llmMaxRpm}
                setLlmMaxRpm={setLlmMaxRpm}
                llmRateBurst={llmRateBurst}
                setLlmRateBurst={setLlmRateBurst}
                headerRows={headerRows}
                setHeaderRows={setHeaderRows}
                llmGuardrailsConfig={llmGuardrailsConfig}
                setLlmGuardrailsConfig={setLlmGuardrailsConfig}
                profile={llmProfile}
                setProfile={setLlmProfile}
              />
            )}

            {/* Identification */}
            {!llmKind && (
              <section>
                <div className="flex items-baseline gap-3 mb-5">
                  <span className="eyebrow-gilt">01</span>
                  <h2 className="font-display text-[18px] text-ink">
                    Identification
                  </h2>
                </div>
                <div className="grid md:grid-cols-2 gap-5">
                  <div className="md:col-span-2">
                    <Label>
                      {llmKind ? "Chat completions URL" : "Application URL"}
                    </Label>
                    <Input
                      type="url"
                      required
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      className={llmKind ? "font-mono text-[13px]" : undefined}
                    />
                  </div>
                  <div className="md:col-span-2">
                    <Label>Name</Label>
                    <Input
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </div>
                </div>
              </section>
            )}

            <hr className="rule" />

            {/* LLM-target form */}
            {false && llmKind && (
              <>
                <section>
                  <div className="flex items-baseline gap-3 mb-5">
                    <span className="eyebrow-gilt">02</span>
                    <h2 className="font-display text-[18px] text-ink">
                      Provider & model
                    </h2>
                  </div>
                  <div className="grid md:grid-cols-2 gap-5">
                    <div>
                      <Label>Provider</Label>
                      <select
                        value={llmProvider}
                        onChange={(e) =>
                          setLlmProvider(e.target.value as LlmProvider)
                        }
                        className="block w-full border border-hairline bg-paper px-3 py-2 text-[13px] text-graphite focus:outline-none focus:border-ink"
                      >
                        <option value="openai-chat">OpenAI-compatible</option>
                        <option value="custom">Custom (template)</option>
                        <option value="executable">
                          Executable (local command)
                        </option>
                        <option value="websocket">WebSocket</option>
                        <option value="bedrock">AWS Bedrock</option>
                        <option value="vertex">Google Vertex AI</option>
                        <option value="azure-openai">Azure OpenAI</option>
                        <option value="browser">Browser (Playwright)</option>
                      </select>
                    </div>
                    <div>
                      <Label>Model</Label>
                      <Input
                        value={llmModel}
                        onChange={(e) => setLlmModel(e.target.value)}
                        placeholder="nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free"
                        className="font-mono text-[12px]"
                      />
                    </div>
                    <div className="md:col-span-2">
                      <Label>System prompt baseline (optional)</Label>
                      <textarea
                        value={llmSystemPrompt}
                        onChange={(e) => setLlmSystemPrompt(e.target.value)}
                        rows={3}
                        className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
                      />
                    </div>
                    {llmProvider === "custom" && (
                      <>
                        <div className="md:col-span-2">
                          <Label>
                            Request body template (JSON, with {"{{prompt}}"} /{" "}
                            {"{{system}}"} / {"{{model}}"})
                          </Label>
                          <textarea
                            value={llmRequestTemplate}
                            onChange={(e) =>
                              setLlmRequestTemplate(e.target.value)
                            }
                            rows={3}
                            className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
                          />
                        </div>
                        <div className="md:col-span-2">
                          <Label>Response JSONPath</Label>
                          <Input
                            value={llmResponsePath}
                            onChange={(e) => setLlmResponsePath(e.target.value)}
                            placeholder="$.choices[0].message.content"
                            className="font-mono text-[12px]"
                          />
                        </div>
                      </>
                    )}
                    {llmProvider === "executable" && (
                      <div className="md:col-span-2">
                        <Label>Command (space-separated)</Label>
                        <Input
                          value={llmCommand}
                          onChange={(e) => setLlmCommand(e.target.value)}
                          placeholder="/usr/local/bin/llm-adapter"
                          className="font-mono text-[12px]"
                        />
                      </div>
                    )}
                  </div>
                </section>

                <hr className="rule" />

                <section>
                  <div className="flex items-baseline gap-3 mb-1">
                    <span className="eyebrow-gilt">03</span>
                    <h2 className="font-display text-[18px] text-ink">
                      Auth headers
                    </h2>
                  </div>
                  <p className="text-[13px] text-slate italic mb-5">
                    {hadCreds
                      ? "Credentials are on file. Add new rows to replace them, or check 'clear' below to wipe them."
                      : "No credentials on file. Add Authorization + any provider-specific headers below."}
                  </p>
                  <fieldset
                    disabled={clearCreds}
                    className={
                      clearCreds ? "opacity-40 pointer-events-none" : undefined
                    }
                  >
                    <div className="space-y-3">
                      {headerRows.map((row, idx) => (
                        <div
                          key={idx}
                          className="grid grid-cols-[1fr_2fr_auto] gap-3 items-end"
                        >
                          <div>
                            {idx === 0 && <Label>Header name</Label>}
                            <Input
                              value={row.key}
                              placeholder="Authorization"
                              onChange={(e) => {
                                const next = [...headerRows];
                                next[idx] = {
                                  ...next[idx],
                                  key: e.target.value,
                                };
                                setHeaderRows(next);
                              }}
                              className="font-mono text-[12px]"
                              autoComplete="off"
                            />
                          </div>
                          <div>
                            {idx === 0 && <Label>Value</Label>}
                            <Input
                              type="password"
                              value={row.value}
                              placeholder="Bearer sk-or-v1-…"
                              onChange={(e) => {
                                const next = [...headerRows];
                                next[idx] = {
                                  ...next[idx],
                                  value: e.target.value,
                                };
                                setHeaderRows(next);
                              }}
                              className="font-mono text-[12px]"
                              autoComplete="off"
                            />
                          </div>
                          <button
                            type="button"
                            onClick={() =>
                              setHeaderRows(
                                headerRows.filter((_, i) => i !== idx),
                              )
                            }
                            className="border border-hairline rounded-sm px-3 py-2 font-mono text-[11px] text-slate hover:border-ink hover:text-ink"
                            aria-label={`Remove header ${idx + 1}`}
                          >
                            ✕
                          </button>
                        </div>
                      ))}
                      <button
                        type="button"
                        onClick={() =>
                          setHeaderRows([...headerRows, { key: "", value: "" }])
                        }
                        className="border border-dashed border-hairline rounded-sm px-4 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-slate hover:border-ink hover:text-ink"
                      >
                        + Add header
                      </button>
                    </div>
                  </fieldset>
                  {hadCreds && (
                    <label className="mt-5 flex items-center gap-3 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={clearCreds}
                        onChange={(e) => setClearCreds(e.target.checked)}
                        className="w-[18px] h-[18px] border border-hairline rounded-sm accent-oxblood"
                      />
                      <span className="font-body text-[13px] text-graphite">
                        Clear stored credentials.
                      </span>
                    </label>
                  )}
                </section>

                <hr className="rule" />

                <section>
                  <div className="flex items-baseline gap-3 mb-5">
                    <span className="eyebrow-gilt">04</span>
                    <h2 className="font-display text-[18px] text-ink">
                      Red-team configuration
                    </h2>
                  </div>
                  <div className="grid gap-5">
                    <div>
                      <Label>Strategies (comma-separated)</Label>
                      <Input
                        value={llmStrategies}
                        onChange={(e) => setLlmStrategies(e.target.value)}
                        placeholder="base64, jailbreak, crescendo, …"
                      />
                    </div>
                    <div>
                      <Label>
                        Composite strategies (comma-separated; use + to chain)
                      </Label>
                      <Input
                        value={llmCompositeStrategies}
                        onChange={(e) =>
                          setLlmCompositeStrategies(e.target.value)
                        }
                        placeholder="leetspeak+base64, jailbreak+leetspeak, …"
                      />
                    </div>
                    <div className="grid sm:grid-cols-2 gap-5">
                      <div>
                        <Label>Datasets</Label>
                        <Input
                          value={llmDatasets}
                          onChange={(e) => setLlmDatasets(e.target.value)}
                          placeholder="donotanswer, harmbench, …"
                        />
                      </div>
                      <div>
                        <Label>Guardrails</Label>
                        <Input
                          value={llmGuardrails}
                          onChange={(e) => setLlmGuardrails(e.target.value)}
                          placeholder="pii, secrets, unsafe-code, tool-authz"
                        />
                      </div>
                      <div>
                        <Label>Languages</Label>
                        <Input
                          value={llmLanguages}
                          onChange={(e) => setLlmLanguages(e.target.value)}
                          placeholder="Spanish, Mandarin, …"
                        />
                      </div>
                      <div>
                        <Label>Iterative search</Label>
                        <select
                          value={llmIterative}
                          onChange={(e) =>
                            setLlmIterative(
                              e.target.value as
                                | ""
                                | "static"
                                | "pair"
                                | "tap"
                                | "goat"
                                | "hydra",
                            )
                          }
                          className="block w-full border border-hairline bg-paper px-3 py-2 text-[13px] text-graphite focus:outline-none focus:border-ink"
                        >
                          <option value="">off</option>
                          <option value="static">static (no attacker)</option>
                          <option value="pair">PAIR (requires attacker)</option>
                          <option value="tap">
                            TAP — tree-of-attacks-with-pruning (requires
                            attacker)
                          </option>
                          <option value="goat">
                            GOAT — multi-turn technique-switching (requires
                            attacker)
                          </option>
                          <option value="hydra">
                            Hydra — parallel multi-objective fan-out (requires
                            attacker)
                          </option>
                        </select>
                      </div>
                    </div>
                    <label className="flex items-center gap-3 text-[13px] text-graphite">
                      <input
                        type="checkbox"
                        checked={llmGuardrailBypass}
                        onChange={(e) =>
                          setLlmGuardrailBypass(e.target.checked)
                        }
                      />
                      Active guardrail-bypass probes
                    </label>
                    {[
                      [
                        "Policies (JSON)",
                        llmPoliciesJson,
                        setLlmPoliciesJson,
                        '[{"id":"...", "policy":"...", "prompts":[]}]',
                      ],
                      [
                        "Intents (JSON)",
                        llmIntentsJson,
                        setLlmIntentsJson,
                        '["intent string", ["multi","turn"]]',
                      ],
                      [
                        "Variables (JSON object)",
                        llmVariablesJson,
                        setLlmVariablesJson,
                        '{"customer":"ACME","tier":"pro"}',
                      ],
                      [
                        "Discovery (JSON object)",
                        llmDiscoveryJson,
                        setLlmDiscoveryJson,
                        '{"purpose":"...","limitations":"...","tools":[]}',
                      ],
                      [
                        "Judge (JSON object)",
                        llmJudgeJson,
                        setLlmJudgeJson,
                        '{"enabled":true,"provider":"openai-moderation","endpoint":"https://api.openai.com/v1/moderations","headers":{"Authorization":"Bearer sk-..."}}',
                      ],
                      [
                        "Attacker (JSON object)",
                        llmAttackerJson,
                        setLlmAttackerJson,
                        '{"enabled":true,"provider":"openai-chat","endpoint":"…","model":"…","headers":{"Authorization":"Bearer …"}}',
                      ],
                      [
                        "Embedder (JSON object)",
                        llmEmbedderJson,
                        setLlmEmbedderJson,
                        '{"enabled":true,"endpoint":"https://api.openai.com/v1/embeddings","model":"text-embedding-3-small","headers":{"Authorization":"Bearer sk-..."},"threshold":0.85}',
                      ],
                    ].map(([label, value, setter, ph]) => (
                      <div key={String(label)}>
                        <Label>{label as string}</Label>
                        <textarea
                          value={value as string}
                          onChange={(e) =>
                            (setter as (v: string) => void)(e.target.value)
                          }
                          rows={3}
                          placeholder={ph as string}
                          className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
                        />
                      </div>
                    ))}
                  </div>
                </section>

                <hr className="rule" />

                <section>
                  <div className="flex items-baseline gap-3 mb-5">
                    <span className="eyebrow-gilt">05</span>
                    <h2 className="font-display text-[18px] text-ink">
                      Limits, rate, retries
                    </h2>
                  </div>
                  <div className="grid md:grid-cols-3 gap-5">
                    <div>
                      <Label>Max latency ms</Label>
                      <Input
                        type="number"
                        value={llmMaxLatencyMs}
                        onChange={(e) => setLlmMaxLatencyMs(e.target.value)}
                        placeholder="30000"
                      />
                    </div>
                    <div>
                      <Label>Max tokens per call</Label>
                      <Input
                        type="number"
                        value={llmMaxTokensPerCall}
                        onChange={(e) => setLlmMaxTokensPerCall(e.target.value)}
                        placeholder="4000"
                      />
                    </div>
                    <div>
                      <Label>Max calls (kill switch)</Label>
                      <Input
                        type="number"
                        value={llmMaxCalls}
                        onChange={(e) => setLlmMaxCalls(e.target.value)}
                        placeholder="2000"
                      />
                    </div>
                    <div>
                      <Label>Max cost USD (kill switch)</Label>
                      <Input
                        type="number"
                        step="0.01"
                        value={llmMaxCostUsd}
                        onChange={(e) => setLlmMaxCostUsd(e.target.value)}
                        placeholder="5.00"
                      />
                    </div>
                    <div>
                      <Label>Retries</Label>
                      <Input
                        type="number"
                        value={llmRetries}
                        onChange={(e) => setLlmRetries(e.target.value)}
                        placeholder="3"
                      />
                    </div>
                    <div>
                      <Label>Timeout seconds</Label>
                      <Input
                        type="number"
                        value={llmTimeoutS}
                        onChange={(e) => setLlmTimeoutS(e.target.value)}
                        placeholder="30"
                      />
                    </div>
                    <div>
                      <Label>Concurrency</Label>
                      <Input
                        type="number"
                        value={llmConcurrency}
                        onChange={(e) => setLlmConcurrency(e.target.value)}
                        placeholder="3"
                      />
                    </div>
                    <div>
                      <Label>Max RPM</Label>
                      <Input
                        type="number"
                        value={llmMaxRpm}
                        onChange={(e) => setLlmMaxRpm(e.target.value)}
                        placeholder="18"
                      />
                      <p className="mt-1 font-mono text-[10px] text-mist">
                        OpenRouter free ≈ 20 RPM
                      </p>
                    </div>
                    <div>
                      <Label>Max RPS (overrides RPM)</Label>
                      <Input
                        type="number"
                        step="0.05"
                        value={llmMaxRps}
                        onChange={(e) => setLlmMaxRps(e.target.value)}
                        placeholder="0.3"
                      />
                    </div>
                    <div>
                      <Label>Rate burst (tokens)</Label>
                      <Input
                        type="number"
                        step="0.5"
                        value={llmRateBurst}
                        onChange={(e) => setLlmRateBurst(e.target.value)}
                        placeholder="defaults to RPS"
                      />
                    </div>
                  </div>
                  <p className="mt-3 text-[12px] text-slate italic">
                    The rate bucket is shared per (endpoint, RPS) so all OWASP
                    modules in a scan respect a single per-key cap. 429
                    responses honour the upstream <code>Retry-After</code>{" "}
                    header automatically.
                  </p>
                </section>

                <hr className="rule" />

                <section>
                  <div className="flex items-baseline gap-3 mb-1">
                    <span className="eyebrow-gilt">Sentry</span>
                    <h2 className="font-display text-[18px] text-ink">
                      Guardrails
                    </h2>
                  </div>
                  <p className="text-[13px] text-slate italic mb-6">
                    Toggle which OWASP-LLM-Top-10 categories the hosted Sentry
                    proxy enforces on this target. Saves independently of the
                    rest of this form.
                  </p>
                  <GuardrailsEditor targetId={id} />
                </section>

                <hr className="rule" />

                <section>
                  <div className="flex items-baseline gap-3 mb-1">
                    <span className="eyebrow-gilt">Sentry</span>
                    <h2 className="font-display text-[18px] text-ink">
                      Agent firewall
                    </h2>
                  </div>
                  <p className="text-[13px] text-slate italic mb-6">
                    Gate the tool calls the model makes through the proxy. Saves
                    independently of the rest of this form.
                  </p>
                  <FirewallEditor targetId={id} />
                </section>
              </>
            )}

            {/* URL-target credentials */}
            {!llmKind && kind !== "repo" && (
              <section>
                <div className="flex items-baseline gap-3 mb-1">
                  <span className="eyebrow-gilt">02</span>
                  <h2 className="font-display text-[18px] text-ink">
                    Credentials
                  </h2>
                </div>
                <p className="text-[13px] text-slate italic mb-6">
                  {hadCreds
                    ? "Credentials are on file. Enter new values to replace them, or check the box below to clear them entirely."
                    : "No credentials are currently on file."}
                </p>
                <fieldset
                  disabled={clearCreds}
                  className={
                    clearCreds ? "opacity-40 pointer-events-none" : undefined
                  }
                >
                  <div className="grid sm:grid-cols-2 gap-5">
                    <div>
                      <Label>Username</Label>
                      <Input
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        autoComplete="off"
                      />
                    </div>
                    <div>
                      <Label>Password</Label>
                      <Input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        autoComplete="off"
                      />
                    </div>
                    <div>
                      <Label>API key</Label>
                      <Input
                        value={apiKey}
                        onChange={(e) => setApiKey(e.target.value)}
                        autoComplete="off"
                      />
                    </div>
                    <div>
                      <Label>Bearer token</Label>
                      <Input
                        value={token}
                        onChange={(e) => setToken(e.target.value)}
                        autoComplete="off"
                      />
                    </div>
                    <div className="sm:col-span-2">
                      <Label>Cookie header</Label>
                      <Input
                        value={cookie}
                        onChange={(e) => setCookie(e.target.value)}
                        autoComplete="off"
                      />
                    </div>
                  </div>
                </fieldset>
                {hadCreds && (
                  <label className="mt-5 flex items-center gap-3 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={clearCreds}
                      onChange={(e) => setClearCreds(e.target.checked)}
                      className="w-[18px] h-[18px] border border-hairline rounded-sm accent-oxblood"
                    />
                    <span className="font-body text-[13px] text-graphite">
                      Clear stored credentials.
                    </span>
                  </label>
                )}
              </section>
            )}

            {canAttachRepos(kind) && (
              <>
                <hr className="rule" />

                <section>
                  <div className="flex items-baseline gap-3 mb-1">
                    <span className="eyebrow-gilt">03</span>
                    <h2 className="font-display text-[18px] text-ink">
                      Source repositories
                    </h2>
                  </div>
                  <p className="text-[13px] text-slate italic mb-4">
                    Multi-select registered repos. The scan detail page links
                    them for source context, and Agent fix uses the selected
                    source repo to open remediation PRs for this target's
                    findings.
                  </p>

                  {reposLoading && <InlineLoading label="Loading repos…" />}
                  {reposError && (
                    <p className="font-mono text-[12px] text-rust">
                      {reposError}
                    </p>
                  )}
                  {!reposLoading &&
                    !reposError &&
                    availableRepos.length === 0 && (
                      <p className="font-body text-[13px] text-slate">
                        No repositories registered yet.{" "}
                        <Link
                          href="/repos"
                          className="underline underline-offset-[4px] decoration-gilt decoration-1 hover:text-ink"
                        >
                          Register a repository
                        </Link>{" "}
                        to attach it to this URL target.
                      </p>
                    )}
                  {!reposLoading &&
                    !reposError &&
                    availableRepos.length > 0 && (
                      <>
                        <div className="mb-4 flex items-center gap-3">
                          <Input
                            type="search"
                            placeholder="Filter by name or language…"
                            value={repoFilter}
                            onChange={(e) => setRepoFilter(e.target.value)}
                            className="max-w-md"
                          />
                          <span className="font-mono text-[11px] text-mist whitespace-nowrap">
                            {attachedRepoIds.length} of {availableRepos.length}{" "}
                            selected
                          </span>
                        </div>
                        <ul
                          className="divide-y divide-hairline border border-hairline rounded-sm bg-paper max-h-[320px] overflow-y-auto"
                          role="listbox"
                          aria-label="Attached repositories"
                          aria-multiselectable="true"
                        >
                          {availableRepos
                            .filter((r) => {
                              const q = repoFilter.trim().toLowerCase();
                              if (!q) return true;
                              return (
                                r.full_name.toLowerCase().includes(q) ||
                                (r.language || "").toLowerCase().includes(q)
                              );
                            })
                            .map((r) => {
                              const checked = attachedRepoIds.includes(r.id);
                              return (
                                <li key={r.id}>
                                  <label
                                    className={
                                      "flex items-start gap-3 px-4 py-3 cursor-pointer transition-colors " +
                                      (checked
                                        ? "bg-vellum"
                                        : "hover:bg-vellum/40")
                                    }
                                  >
                                    <input
                                      type="checkbox"
                                      checked={checked}
                                      onChange={() => toggleAttachedRepo(r.id)}
                                      aria-label={`Attach ${r.full_name}`}
                                      className="mt-1 w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
                                    />
                                    <span className="flex-1 min-w-0">
                                      <span className="block font-mono text-[13px] text-ink truncate">
                                        {r.full_name}
                                      </span>
                                      <span className="block font-mono text-[11px] text-mist truncate">
                                        {r.provider}
                                        {r.language ? ` · ${r.language}` : ""}
                                        {r.local_path
                                          ? ` · ${r.local_path}`
                                          : ""}
                                      </span>
                                    </span>
                                  </label>
                                </li>
                              );
                            })}
                        </ul>
                      </>
                    )}
                </section>
              </>
            )}

            <hr className="rule" />

            <section>
              <p className="eyebrow-gilt mb-3">Weekly digest</p>
              <p className="text-[13px] text-graphite mb-4 max-w-[60ch]">
                Send a weekly summary of this target&rsquo;s recent assessments
                every Monday at 9:00 UTC. Recipients receive grade trajectory,
                severity counts, and a link to the target dashboard. Leave empty
                to disable.
              </p>
              <EmailRecipientsInput
                value={weeklyDigestEmails}
                onChange={setWeeklyDigestEmails}
                workspaceId={activeWorkspace?.id ?? null}
                label="Digest recipients"
                hint="Pick a workspace member or type any email."
                max={20}
              />
            </section>

            <hr className="rule" />

            <section className="flex flex-wrap items-center justify-between gap-4">
              <Link href={`/targets/${id}`}>
                <Button variant="lime" type="button">
                  Cancel
                </Button>
              </Link>
              <Button
                type="submit"
                variant="pink"
                disabled={saving}
                className="min-w-[200px]"
              >
                {saving ? "Saving…" : "Save changes"}
              </Button>
            </section>
          </form>
        )}
      </div>
    </div>
  );
}
