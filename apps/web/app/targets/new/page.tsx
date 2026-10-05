"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Button, Input } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { api } from "@/lib/api";
import {
  GuardrailsEditor,
  type Guardrails as GuardrailsConfig,
} from "@/components/guardrails-editor";
import {
  CATEGORIES,
  TYPES_BY_ID,
  type SupportedKind,
} from "@/components/register-target/target-types";
import {
  NetworkIdentityFormSection,
  defaultNIDraft,
  type NIDraft,
} from "@/components/register-target/network-identity-form-section";

// Kinds whose step-2 config UI + submit handler exist. Derived from the ACTIVE
// cards in CATEGORIES so a new active target type is never a dead-end form again
// (previously a hand-written list that silently drifted from `status:"active"`).
const RENDERABLE_KINDS: SupportedKind[] = CATEGORIES.flatMap((c) =>
  c.types
    .filter((t) => t.status === "active" && t.kind !== null)
    .map((t) => t.kind as SupportedKind),
);
import { Step1TypeSelector } from "@/components/register-target/step-1-type-selector";
import {
  DISCIPLINE_TO_KINDS,
  type DisciplineId,
} from "@/components/register-target/disciplines";
import {
  LlmFormSection,
  type LlmJudgeProvider,
} from "@/components/register-target/llm-form-section";
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
import { MobileAppFormSection } from "@/components/register-target/mobile-app-form-section";
import { ClientArtifactFormSection } from "@/components/register-target/client-artifact-form-section";
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
  type CloudKind,
  type CloudTargetDraft,
} from "@/components/register-target/cloud-form-section";
import {
  HostFormSection,
  type HostKindConfigDraft,
} from "@/components/register-target/host-form-section";
import { useWorkspace } from "@/lib/workspace-context";

type Profile = "quick" | "standard" | "deep";
type LlmProvider =
  | "openai-chat"
  | "custom"
  | "executable"
  | "websocket"
  | "bedrock"
  | "vertex"
  | "azure-openai"
  | "browser";
type HeaderRow = { key: string; value: string };

type AttachableRepo = {
  id: string;
  full_name: string;
  provider: string;
  language: string | null;
  html_url: string;
  local_path: string | null;
};

const REPO_ATTACHABLE_KINDS = new Set<SupportedKind>([
  "web_app",
  "rest_api",
  "graphql",
  "websocket",
  "grpc",
  "llm",
  "mcp",
  "agent",
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

function canAttachReposForKind(kind: SupportedKind): boolean {
  return REPO_ATTACHABLE_KINDS.has(kind);
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
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object")
    throw new Error(`${label} must be a JSON object.`);
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

// Flat creds → backend ``Credentials`` shape. Returns null when every field is empty.
function buildFlatCreds(c: {
  username: string;
  password: string;
  api_key: string;
  token: string;
  cookie: string;
}) {
  if (!c.username && !c.password && !c.api_key && !c.token && !c.cookie)
    return null;
  return {
    username: c.username || null,
    password: c.password || null,
    api_key: c.api_key || null,
    token: c.token || null,
    cookie: c.cookie || null,
  };
}

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
    // Plain memory rows are the common case.
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

// The 5 DAST-cluster kinds + source_code each have their own form section now.
// Artifact + hybrid kinds also have their own. LLM keeps its dedicated section.
// Legacy url/repo kinds are no longer surfaced in Step 1 (no card maps to them),
// so the registration path does not render their forms anymore.
const ARTIFACT_HYBRID_KINDS: ReadonlySet<SupportedKind> = new Set([
  "container_image",
  "iac",
  "package_registry",
  "sbom",
  "cicd_pipeline",
  "k8s_cluster",
  "memory",
]);

const CLOUD_TARGET_KINDS: ReadonlySet<SupportedKind> = new Set<SupportedKind>(
  CLOUD_KIND_LIST,
);

function isCloudKind(kind: SupportedKind): kind is CloudKind {
  return CLOUD_TARGET_KINDS.has(kind);
}

function RegisterTargetContent() {
  const router = useRouter();
  const { activeOrg } = useWorkspace();

  // ── Step state ────────────────────────────────────────────────────────────
  // Wizard state is client-only, so a cold load / reload of ?step=2 has no
  // selections behind it. Always start at step 1; the only path to step 2 is
  // goToStep2(), which is gated behind a non-empty selection in step 1. This
  // avoids the dead-end "nothing to configure" screen on a direct deep-link.
  const [step, setStep] = useState<1 | 2>(1);
  const [selectedTypeIds, setSelectedTypeIds] = useState<Set<string>>(
    new Set(),
  );
  const [selectedDisciplines, setSelectedDisciplines] = useState<
    Set<DisciplineId>
  >(new Set());

  const selectedKinds = useMemo(() => {
    const kinds = new Set<SupportedKind>();
    for (const id of selectedTypeIds) {
      const k = TYPES_BY_ID[id]?.kind;
      if (k) kinds.add(k);
    }
    return [...kinds] as SupportedKind[];
  }, [selectedTypeIds]);

  // ── Per-section state (each kind owns its own name + primary identifier
  //     + typed config + write-only credentials) ─────────────────────────────

  // web_app
  const [webAppName, setWebAppName] = useState("");
  const [webAppUrl, setWebAppUrl] = useState("");
  const [webAppCfg, setWebAppCfg] = useState<WebAppConfig>(
    DEFAULT_WEB_APP_CONFIG,
  );
  const [webAppCreds, setWebAppCreds] =
    useState<WebAppCredentials>(EMPTY_WEB_APP_CREDS);

  // rest_api
  const [restApiName, setRestApiName] = useState("");
  const [restApiBaseUrl, setRestApiBaseUrl] = useState("");
  const [restApiCfg, setRestApiCfg] = useState<RestApiConfig>(
    DEFAULT_REST_API_CONFIG,
  );
  const [restApiRawSpec, setRestApiRawSpec] = useState<string>("");
  const [restApiCreds, setRestApiCreds] =
    useState<RestApiCredentials>(EMPTY_REST_API_CREDS);

  // graphql
  const [graphqlName, setGraphqlName] = useState("");
  const [graphqlEndpoint, setGraphqlEndpoint] = useState("");
  const [graphqlCfg, setGraphqlCfg] = useState<GraphqlConfig>(
    DEFAULT_GRAPHQL_CONFIG,
  );
  const [graphqlCreds, setGraphqlCreds] =
    useState<GraphqlCredentials>(EMPTY_GRAPHQL_CREDS);

  // websocket
  const [wsName, setWsName] = useState("");
  const [wsEndpoint, setWsEndpoint] = useState("");
  const [wsCfg, setWsCfg] = useState<WebsocketConfig>(DEFAULT_WEBSOCKET_CONFIG);
  const [wsRawSubprotocols, setWsRawSubprotocols] = useState<string>("");
  const [wsCreds, setWsCreds] = useState<WebsocketCredentials>(
    EMPTY_WEBSOCKET_CREDS,
  );

  // grpc
  const [grpcName, setGrpcName] = useState("");
  const [grpcAuthority, setGrpcAuthority] = useState("");
  const [grpcCfg, setGrpcCfg] = useState<GrpcConfig>(DEFAULT_GRPC_CONFIG);
  const [grpcRawProto, setGrpcRawProto] = useState<string>("");
  const [grpcMetadata, setGrpcMetadata] = useState<GrpcMetadataRow[]>(
    DEFAULT_GRPC_METADATA,
  );

  // source_code
  const [sourceCodeName, setSourceCodeName] = useState("");
  const [sourceCodeCfg, setSourceCodeCfg] = useState<SourceCodeConfig>(
    DEFAULT_SOURCE_CODE_CONFIG,
  );
  const [sourceCodeCreds, setSourceCodeCreds] = useState<SourceCodeCreds>(
    EMPTY_SOURCE_CODE_CREDS,
  );
  const [sourceCodeRawLangs, setSourceCodeRawLangs] = useState<string>("");

  // ── Artifact + hybrid state (feature 001) ─────────────────────────────────
  const [artifactName, setArtifactName] = useState("");
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
  const [memoryHeaderRows, setMemoryHeaderRows] = useState<HeaderRow[]>([
    { key: "Authorization", value: "" },
  ]);
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
  const [rawNamespaces, setRawNamespaces] = useState<string>("default");

  // cloud_account / serverless_function / cloud_storage / edge / db / secrets
  const [cloudDrafts, setCloudDrafts] = useState<
    Record<CloudKind, CloudTargetDraft>
  >(
    () =>
      Object.fromEntries(
        CLOUD_KIND_LIST.map((kind) => [kind, defaultCloudDraft(kind)]),
      ) as Record<CloudKind, CloudTargetDraft>,
  );

  // ── Host state ────────────────────────────────────────────────────────────
  const [hostKindConfig, setHostKindConfig] = useState<HostKindConfigDraft>({
    kind: "host",
    hosts: [],
  });
  // Provider-aware network/identity kinds (tls_ssl/dns/email_security/vpn/idp/
  // data_store) — one NIDraft ({config, creds}) per selected kind.
  const [niDrafts, setNiDrafts] = useState<Record<string, NIDraft>>({});
  const niDraft = (k: SupportedKind): NIDraft =>
    niDrafts[k] ?? defaultNIDraft(k);
  const setNiDraft = (k: SupportedKind, d: NIDraft) =>
    setNiDrafts((cur) => ({ ...cur, [k]: d }));

  // ── LLM form state ────────────────────────────────────────────────────────
  const [llmName, setLlmName] = useState("");
  const [llmUrl, setLlmUrl] = useState(
    "https://api.openai.com/v1/chat/completions",
  );
  const [llmProvider, setLlmProvider] = useState<LlmProvider>("openai-chat");
  const [llmModel, setLlmModel] = useState("");
  const [llmSystemPrompt, setLlmSystemPrompt] = useState("");
  const [llmRequestTemplate, setLlmRequestTemplate] = useState(
    '{"model":"{{model}}","messages":[{"role":"user","content":"{{prompt}}"}]}',
  );
  const [llmResponsePath, setLlmResponsePath] = useState(
    "$.choices[0].message.content",
  );
  const [llmCommand, setLlmCommand] = useState("");
  const [awsRegion, setAwsRegion] = useState("us-east-1");
  const [vertexProject, setVertexProject] = useState("");
  const [vertexLocation, setVertexLocation] = useState("us-central1");
  const [azureDeployment, setAzureDeployment] = useState("");
  const [azureApiVersion, setAzureApiVersion] = useState("2024-10-21");
  const [llmStrategies, setLlmStrategies] = useState(
    "base64, rot13, leetspeak, jailbreak, crescendo",
  );
  const [llmCompositeStrategies, setLlmCompositeStrategies] = useState("");
  const [llmDatasets, setLlmDatasets] = useState("harmbench, donotanswer");
  const [llmGuardrails, setLlmGuardrails] = useState(
    "pii, secrets, unsafe-code, tool-authz",
  );
  const [llmLanguages, setLlmLanguages] = useState("");
  const [llmPoliciesJson, setLlmPoliciesJson] = useState("");
  const [llmIntentsJson, setLlmIntentsJson] = useState("");
  const [llmVariablesJson, setLlmVariablesJson] = useState("");
  const [llmDiscoveryJson, setLlmDiscoveryJson] = useState("");
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
  const [llmMaxLatencyMs, setLlmMaxLatencyMs] = useState("");
  const [llmMaxTokensPerCall, setLlmMaxTokensPerCall] = useState("");
  const [llmMaxCalls, setLlmMaxCalls] = useState("");
  const [llmMaxCostUsd, setLlmMaxCostUsd] = useState("");
  const [llmRetries, setLlmRetries] = useState("3");
  const [llmTimeoutS, setLlmTimeoutS] = useState("30");
  const [llmConcurrency, setLlmConcurrency] = useState("3");
  const [llmMaxRps, setLlmMaxRps] = useState("");
  const [llmMaxRpm, setLlmMaxRpm] = useState("18");
  const [llmRateBurst, setLlmRateBurst] = useState("");
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>([
    { key: "Authorization", value: "" },
  ]);
  const [llmGuardrailsConfig, setLlmGuardrailsConfig] =
    useState<GuardrailsConfig | null>(null);
  const [llmProfile, setLlmProfile] = useState<Profile>("standard");

  // ── MCP form state ────────────────────────────────────────────────────────
  const [mcpName, setMcpName] = useState("");
  const [mcpSourceType, setMcpSourceType] = useState<"mcp_http" | "mcp_stdio">(
    "mcp_http",
  );
  const [mcpUrl, setMcpUrl] = useState("");
  const [mcpTransport, setMcpTransport] = useState<"sse" | "streamable_http">(
    "sse",
  );
  const [mcpCommand, setMcpCommand] = useState("");
  const [mcpCwd, setMcpCwd] = useState("");
  const [mcpEnvRows, setMcpEnvRows] = useState<
    { key: string; value: string }[]
  >([]);
  const [mcpToolAllowlist, setMcpToolAllowlist] = useState("");
  const [mcpToolDenylist, setMcpToolDenylist] = useState("");
  const [mcpDynamicInvocation, setMcpDynamicInvocation] = useState(false);
  const [mcpDestructiveOptIn, setMcpDestructiveOptIn] = useState(false);
  const [mcpHeaderRows, setMcpHeaderRows] = useState<
    { key: string; value: string }[]
  >([{ key: "Authorization", value: "" }]);

  // ── Agent form state ──────────────────────────────────────────────────────
  const [agentName, setAgentName] = useState("");
  const [agentSourceType, setAgentSourceType] = useState<
    "agent_http" | "agent_browser"
  >("agent_http");
  const [agentUrl, setAgentUrl] = useState("");
  const [agentProvider, setAgentProvider] = useState("openai-chat");
  const [agentModel, setAgentModel] = useState("");
  const [agentRequestTemplate, setAgentRequestTemplate] = useState(
    '{"model":"{{model}}","messages":[{"role":"user","content":"{{prompt}}"}]}',
  );
  const [agentResponsePath, setAgentResponsePath] = useState(
    "$.choices[0].message.content",
  );
  const [agentPromptSelector, setAgentPromptSelector] = useState("");
  const [agentSendSelector, setAgentSendSelector] = useState("");
  const [agentResponseSelector, setAgentResponseSelector] = useState("");
  const [agentToolAllowlist, setAgentToolAllowlist] = useState("");
  const [agentToolDenylist, setAgentToolDenylist] = useState("");
  const [agentDynamicInvocation, setAgentDynamicInvocation] = useState(false);
  const [agentDestructiveOptIn, setAgentDestructiveOptIn] = useState(false);
  const [agentHeaderRows, setAgentHeaderRows] = useState<
    { key: string; value: string }[]
  >([{ key: "Authorization", value: "" }]);

  // ── RAG form state ────────────────────────────────────────────────────────
  const [ragName, setRagName] = useState("");
  const [ragSourceType, setRagSourceType] = useState<
    "managed_vdb" | "self_hosted_vdb" | "rag_endpoint" | "embedding_artifact"
  >("managed_vdb");
  const [ragProvider, setRagProvider] = useState("pinecone");
  const [ragUrl, setRagUrl] = useState("");
  const [ragIndexName, setRagIndexName] = useState("");
  const [ragNamespace, setRagNamespace] = useState("");
  const [ragProviderLlm, setRagProviderLlm] = useState("openai-chat");
  const [ragRequestTemplate, setRagRequestTemplate] = useState(
    '{"messages":[{"role":"user","content":"{{prompt}}"}]}',
  );
  const [ragResponsePath, setRagResponsePath] = useState(
    "$.choices[0].message.content",
  );
  const [ragItems, setRagItems] = useState("");
  const [ragCanaryText, setRagCanaryText] = useState("");
  const [ragQueryProbes, setRagQueryProbes] = useState(false);
  const [ragPoisonInjectionOptIn, setRagPoisonInjectionOptIn] = useState(false);
  const [ragHeaderRows, setRagHeaderRows] = useState<
    { key: string; value: string }[]
  >([{ key: "Authorization", value: "" }]);

  // ── ML model form state ───────────────────────────────────────────────────
  const [mlName, setMlName] = useState("");
  const [mlSourceType, setMlSourceType] = useState<MlSourceType>("file_url");
  const [mlUrl, setMlUrl] = useState("");
  const [mlHfRepo, setMlHfRepo] = useState("");
  const [mlHfRevision, setMlHfRevision] = useState("");
  const [mlLocalPath, setMlLocalPath] = useState("");
  const [mlFormatHint, setMlFormatHint] = useState<MlFormatHint>("auto");
  const [mlMaxBytes, setMlMaxBytes] = useState(524288000);

  const [voiceName, setVoiceName] = useState("");
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

  // ── Mobile app form state (spec 002 — separate per platform) ───────────────
  const [androidName, setAndroidName] = useState("");
  const [androidFileUrl, setAndroidFileUrl] = useState("");
  const [androidSha256, setAndroidSha256] = useState("");
  const [androidUseMobsf, setAndroidUseMobsf] = useState(false);
  const [iosName, setIosName] = useState("");
  const [iosFileUrl, setIosFileUrl] = useState("");
  const [iosSha256, setIosSha256] = useState("");
  const [extName, setExtName] = useState("");
  const [extFileUrl, setExtFileUrl] = useState("");
  const [extSha256, setExtSha256] = useState("");
  const [deskName, setDeskName] = useState("");
  const [deskFileUrl, setDeskFileUrl] = useState("");
  const [deskSha256, setDeskSha256] = useState("");
  const [fwName, setFwName] = useState("");
  const [fwFileUrl, setFwFileUrl] = useState("");
  const [fwSha256, setFwSha256] = useState("");
  const [iotName, setIotName] = useState("");
  const [iotFileUrl, setIotFileUrl] = useState("");
  const [iotSha256, setIotSha256] = useState("");
  const [otName, setOtName] = useState("");
  const [otFileUrl, setOtFileUrl] = useState("");
  const [otSha256, setOtSha256] = useState("");

  // ── Shared state ──────────────────────────────────────────────────────────
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [startAfter, setStartAfter] = useState(true);
  const [availableRepos, setAvailableRepos] = useState<AttachableRepo[]>([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [reposError, setReposError] = useState<string | null>(null);
  const [attachedRepoIds, setAttachedRepoIds] = useState<string[]>([]);
  const [repoFilter, setRepoFilter] = useState("");

  const selectedAttachableKinds = useMemo(
    () => selectedKinds.filter(canAttachReposForKind),
    [selectedKinds],
  );
  const canAttachReposForSelection = selectedAttachableKinds.length > 0;

  useEffect(() => {
    if (step !== 2 || !canAttachReposForSelection) return;
    let cancelled = false;
    setReposLoading(true);
    setReposError(null);
    api<AttachableRepo[]>("/repos")
      .then((repos) => {
        if (!cancelled) setAvailableRepos(repos);
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
  }, [step, canAttachReposForSelection]);

  function toggleAttachedRepo(id: string) {
    setAttachedRepoIds((current) =>
      current.includes(id)
        ? current.filter((existing) => existing !== id)
        : [...current, id],
    );
  }

  const attachedRepoPayload = { attached_repository_ids: attachedRepoIds };

  // Step is driven by local state only — NOT the URL. Pushing "?step=N" here
  // caused a query-param navigation that remounted the page in the static
  // export, resetting all useState (step + selections) on the first Continue
  // (the second "worked" only because the URL was already ?step=2, making the
  // push a no-op). Nothing reads ?step on mount, so there's nothing to sync.
  function goToStep2() {
    window.scrollTo(0, 0);
    setStep(2);
  }

  function goToStep1() {
    window.scrollTo(0, 0);
    setStep(1);
    setError(null);
  }

  // Disciplines that fan out to a given kind. Each Target only gets the
  // disciplines whose compatibility map includes its own kind.
  function disciplinesFor(kind: string): DisciplineId[] {
    return [...selectedDisciplines].filter((d) =>
      DISCIPLINE_TO_KINDS[d]?.includes(kind),
    );
  }

  function setCloudDraft(kind: CloudKind, draft: CloudTargetDraft) {
    setCloudDrafts((current) => ({ ...current, [kind]: draft }));
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    let redirectTargetId: string | null = null;

    try {
      // ── web_app ──────────────────────────────────────────────────────────
      if (selectedKinds.includes("web_app")) {
        if (!webAppUrl.trim())
          throw new Error("Web application URL is required.");
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: webAppName || new URL(webAppUrl).hostname,
            base_url: webAppUrl,
            kind: "web_app",
            kind_config: {
              ...webAppCfg,
              api_spec_url: webAppCfg.api_spec_url?.trim() || undefined,
            },
            credentials: buildFlatCreds(webAppCreds),
            disciplines: disciplinesFor("web_app"),
            ...attachedRepoPayload,
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── rest_api ─────────────────────────────────────────────────────────
      if (selectedKinds.includes("rest_api")) {
        if (!restApiBaseUrl.trim())
          throw new Error("REST API base URL is required.");
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: restApiName || new URL(restApiBaseUrl).hostname,
            base_url: restApiBaseUrl,
            kind: "rest_api",
            kind_config: {
              ...restApiCfg,
              api_spec_url: restApiCfg.api_spec_url?.trim() || undefined,
              api_spec: restApiCfg.api_spec ?? null,
            },
            credentials: buildFlatCreds(restApiCreds),
            disciplines: disciplinesFor("rest_api"),
            ...attachedRepoPayload,
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── graphql ──────────────────────────────────────────────────────────
      if (selectedKinds.includes("graphql")) {
        if (!graphqlEndpoint.trim())
          throw new Error("GraphQL endpoint is required.");
        if (
          !graphqlCfg.introspection_enabled &&
          !graphqlCfg.schema_sdl?.trim()
        ) {
          throw new Error(
            "Paste the schema SDL when introspection is disabled.",
          );
        }
        if (graphqlCfg.operations_to_test.length === 0) {
          throw new Error(
            "Select at least one GraphQL operation type to test.",
          );
        }
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: graphqlName || new URL(graphqlEndpoint).hostname,
            base_url: graphqlEndpoint,
            kind: "graphql",
            kind_config: {
              ...graphqlCfg,
              schema_sdl: graphqlCfg.schema_sdl?.trim() || undefined,
              proxy: graphqlCfg.proxy?.trim() || undefined,
              headers:
                graphqlCfg.headers && Object.keys(graphqlCfg.headers).length
                  ? graphqlCfg.headers
                  : undefined,
            },
            credentials: buildFlatCreds({
              username: graphqlCreds.username,
              password: graphqlCreds.password,
              api_key: graphqlCreds.api_key,
              token: graphqlCreds.token,
              cookie: graphqlCreds.cookie,
            }),
            disciplines: disciplinesFor("graphql"),
            ...attachedRepoPayload,
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── websocket ────────────────────────────────────────────────────────
      if (selectedKinds.includes("websocket")) {
        if (!wsEndpoint.trim())
          throw new Error("WebSocket endpoint is required.");
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name:
              wsName ||
              new URL(wsEndpoint.replace(/^wss?:\/\//, "https://")).hostname,
            base_url: wsEndpoint,
            kind: "websocket",
            kind_config: {
              ...wsCfg,
              origin_header: wsCfg.origin_header?.trim() || undefined,
              auth_token_in_query:
                wsCfg.auth_token_in_query?.trim() || undefined,
            },
            credentials:
              wsCreds.token || wsCreds.cookie
                ? {
                    token: wsCreds.token || null,
                    cookie: wsCreds.cookie || null,
                    username: null,
                    password: null,
                    api_key: null,
                  }
                : null,
            disciplines: disciplinesFor("websocket"),
            ...attachedRepoPayload,
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── grpc ─────────────────────────────────────────────────────────────
      if (selectedKinds.includes("grpc")) {
        if (!grpcAuthority.trim())
          throw new Error("gRPC authority is required.");
        if (
          !grpcCfg.reflection_enabled &&
          (!grpcCfg.proto_files || grpcCfg.proto_files.length === 0)
        ) {
          throw new Error(
            "Paste or upload .proto file contents when reflection is disabled.",
          );
        }
        const grpcHeaders: Record<string, string> = {};
        for (const row of grpcMetadata) {
          const k = row.key.trim();
          const v = row.value.trim();
          if (k && v) grpcHeaders[k] = v;
        }
        const grpcBase = grpcAuthority.includes("://")
          ? grpcAuthority
          : `grpc://${grpcAuthority}`;
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: grpcName || grpcAuthority.replace(/:\d+$/, ""),
            base_url: grpcBase,
            kind: "grpc",
            kind_config: grpcCfg,
            disciplines: disciplinesFor("grpc"),
            ...attachedRepoPayload,
            credentials: Object.keys(grpcHeaders).length
              ? {
                  token: null,
                  cookie: null,
                  username: null,
                  password: null,
                  api_key: null,
                  // gRPC auth is per-call metadata; we tunnel it through the headers field.
                  // The scan-runner reads creds.headers as gRPC metadata when kind="grpc".
                  // (Mirrors how the LLM kind packs auth headers.)
                  headers: grpcHeaders,
                }
              : null,
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── source_code ──────────────────────────────────────────────────────
      if (selectedKinds.includes("source_code")) {
        const needsRepoUrl =
          sourceCodeCfg.source === "github_url" ||
          sourceCodeCfg.source === "tarball_url";
        if (needsRepoUrl && !sourceCodeCfg.repo_url?.trim()) {
          throw new Error(
            "Repository / tarball URL is required for this source type.",
          );
        }
        if (sourceCodeCfg.source === "upload" && !sourceCodeCfg.upload_key) {
          throw new Error("Upload a folder or archive before continuing.");
        }
        const baseUrl =
          sourceCodeCfg.source === "upload"
            ? `upload://${sourceCodeCfg.upload_filename || "archive"}`
            : sourceCodeCfg.repo_url?.trim() ||
              (sourceCodeCfg.source === "local_path"
                ? "file:///"
                : "github-app://installation");

        let kindCreds: SourceCodeCreds | null = null;
        if (sourceCodeCfg.source !== "local_path") {
          if (
            sourceCodeCreds.auth_type === "pat" &&
            sourceCodeCreds.pat?.trim()
          ) {
            kindCreds = {
              kind: "source_code",
              auth_type: "pat",
              pat: sourceCodeCreds.pat,
            };
          } else if (
            sourceCodeCreds.auth_type === "github_app" &&
            sourceCodeCreds.github_app_id?.trim() &&
            sourceCodeCreds.github_app_private_key?.trim()
          ) {
            kindCreds = {
              kind: "source_code",
              auth_type: "github_app",
              github_app_id: sourceCodeCreds.github_app_id,
              github_app_private_key: sourceCodeCreds.github_app_private_key,
              github_app_installation_id:
                sourceCodeCreds.github_app_installation_id?.trim() || undefined,
            };
          } else if (
            sourceCodeCreds.auth_type === "ssh_key" &&
            sourceCodeCreds.ssh_private_key?.trim()
          ) {
            kindCreds = {
              kind: "source_code",
              auth_type: "ssh_key",
              ssh_private_key: sourceCodeCreds.ssh_private_key,
            };
          }
        }

        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name:
              sourceCodeName ||
              (sourceCodeCfg.repo_url
                ? new URL(sourceCodeCfg.repo_url).pathname
                    .replace(/^\//, "")
                    .replace(/\.git$/, "")
                : "source-code"),
            base_url: baseUrl,
            kind: "source_code",
            kind_config: sourceCodeCfg,
            disciplines: disciplinesFor("source_code"),
            ...(kindCreds ? { kind_credentials: kindCreds } : {}),
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── Infrastructure & Cloud Security ─────────────────────────────────
      for (const kind of selectedKinds.filter(isCloudKind)) {
        const draft = cloudDrafts[kind];
        const validationError = validateCloudDraft(draft);
        if (validationError) throw new Error(validationError);
        const cfg = finalizeCloudDraft(draft);
        const kindCreds = buildCloudKindCredentials(kind, cfg, draft.creds);
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: draft.name || cloudDisplayName(kind, cfg),
            base_url: buildCloudBaseUrl(kind, cfg),
            kind,
            kind_config: cfg,
            disciplines: disciplinesFor(kind),
            ...attachedRepoPayload,
            ...(kindCreds ? { kind_credentials: kindCreds } : {}),
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── Artifact + hybrid kinds (existing 6 sections) ────────────────────
      for (const kind of selectedKinds.filter((k) =>
        ARTIFACT_HYBRID_KINDS.has(k),
      )) {
        let cfg: Record<string, unknown> | null = null;
        let kindCreds: Record<string, unknown> | null = null;
        let baseUrl: string;
        let displayName = artifactName;

        if (kind === "container_image") {
          if (!containerImageCfg.image_ref.trim())
            throw new Error("Container image reference is required.");
          cfg = containerImageCfg;
          baseUrl = `oci://${containerImageCfg.image_ref}`;
          if (!displayName) displayName = containerImageCfg.image_ref;
          kindCreds = buildContainerImageKindCredentials(
            containerImageCfg,
            containerImageCreds,
          );
        } else if (kind === "iac") {
          if (
            (iacCfg.source === "repo" || iacCfg.source === "tarball_url") &&
            !iacCfg.repo_url?.trim()
          ) {
            throw new Error("IaC source URL is required.");
          }
          if (iacCfg.frameworks.length === 0)
            throw new Error("Select at least one IaC framework.");
          cfg = iacCfg;
          baseUrl = iacCfg.repo_url || `iac://${iacCfg.frameworks.join("+")}`;
          if (iacCfg.source === "repo" && iacCreds.token?.trim()) {
            kindCreds = { kind: "iac", token: iacCreds.token.trim() };
          }
        } else if (kind === "package_registry") {
          if (packageRegistryCfg.package_list.length === 0) {
            throw new Error("Paste or upload a non-empty package list.");
          }
          cfg = packageRegistryCfg;
          baseUrl = `pkg://${packageRegistryCfg.ecosystem}`;
        } else if (kind === "sbom") {
          if (!sbomCfg.content && !sbomCfg.url) {
            throw new Error(
              "SBOM requires either inline content or a remote URL.",
            );
          }
          cfg = sbomCfg;
          baseUrl = sbomCfg.url || `sbom://${sbomCfg.format}`;
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
          cfg = compactObject({
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
          kindCreds = MEMORY_PROVIDER_SOURCES.has(memorySourceType)
            ? buildHeaderCreds(memoryHeaderRows)
            : null;
          baseUrl = memoryBaseUrl(
            memorySourceType,
            memoryUrl,
            displayName || memoryFileName || "items",
          );
        } else if (kind === "cicd_pipeline") {
          if (!cicdCfg.repo_url?.trim())
            throw new Error("CI/CD pipeline repo URL is required.");
          cfg = cicdCfg;
          baseUrl = cicdCfg.repo_url;
          if (cicdCreds.token?.trim() || cicdCreds.jenkins_user?.trim()) {
            kindCreds = {
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
          const k8sErr = validateK8sFormBeforeSubmit(k8sCfg, k8sCreds);
          if (k8sErr) throw new Error(k8sErr);
          cfg = k8sCfg;
          kindCreds = buildK8sKindCredentials(k8sCfg, k8sCreds);
          if (k8sCfg.target === "manifests_only") {
            baseUrl = k8sCfg.manifests_archive_url!;
          } else if (k8sCfg.target === "aws_eks") {
            baseUrl = `k8s://aws/${k8sCfg.aws_region}/${k8sCfg.aws_cluster_name}`;
          } else if (k8sCfg.target === "azure_aks") {
            baseUrl = `k8s://azure/${k8sCfg.azure_resource_group}/${k8sCfg.azure_cluster_name}`;
          } else if (k8sCfg.target === "gcp_gke") {
            baseUrl = `k8s://gcp/${k8sCfg.gcp_project_id}/${k8sCfg.gcp_location}/${k8sCfg.gcp_cluster_name}`;
          } else {
            baseUrl = `k8s://live/${k8sCfg.namespaces.join(",")}`;
          }
        } else {
          continue;
        }

        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: displayName || (kind as string),
            base_url: baseUrl,
            kind,
            kind_config: cfg,
            disciplines: disciplinesFor(kind),
            ...(kind === "memory" ? attachedRepoPayload : {}),
            ...(kindCreds ? { kind_credentials: kindCreds } : {}),
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── llm ──────────────────────────────────────────────────────────────
      if (selectedKinds.includes("llm")) {
        if (!llmUrl.trim())
          throw new Error("Paste the chat-completions endpoint URL.");
        if (
          llmProvider === "custom" &&
          (!llmRequestTemplate.trim() || !llmResponsePath.trim())
        ) {
          throw new Error(
            "Custom provider requires both a request body template and a response path.",
          );
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

        const headers: Record<string, string> = {};
        for (const row of headerRows) {
          const k = row.key.trim();
          const v = row.value.trim();
          if (k && v) headers[k] = v;
        }
        const credsLlm = Object.keys(headers).length > 0 ? { headers } : null;
        const judgeHeaders: Record<string, string> = {};
        for (const row of llmJudgeHeaderRows) {
          const k = row.key.trim();
          const v = row.value.trim();
          if (k && v) judgeHeaders[k] = v;
        }

        let redteam: Record<string, unknown> | null = null;
        let thresholds: Record<string, unknown> | null = null;
        let budget: Record<string, unknown> | null = null;
        try {
          redteam = {
            strategies: csvList(llmStrategies),
            composite_strategies: csvList(llmCompositeStrategies),
            datasets: csvList(llmDatasets),
            guardrails: csvList(llmGuardrails),
            languages: csvList(llmLanguages),
            policies: parseJsonValue(llmPoliciesJson, "Policies JSON"),
            intents: parseJsonValue(llmIntentsJson, "Intents JSON"),
            variables: parseJsonObject(llmVariablesJson, "Variables JSON"),
            discovery: parseJsonObject(llmDiscoveryJson, "Discovery JSON"),
            iterative: llmIterative || null,
            guardrail_bypass: llmGuardrailBypass || null,
            judge: llmJudgeEnabled
              ? {
                  enabled: true,
                  provider: llmJudgeProvider,
                  endpoint:
                    llmJudgeProvider === "executable"
                      ? null
                      : llmJudgeEndpoint || null,
                  model: llmJudgeModel || null,
                  headers:
                    Object.keys(judgeHeaders).length > 0 ? judgeHeaders : null,
                  command:
                    llmJudgeProvider === "executable"
                      ? csvList(llmJudgeCommand)
                      : null,
                }
              : null,
          };
          redteam = Object.fromEntries(
            Object.entries(redteam).filter(([, v]) => v !== null),
          );
          thresholds = Object.fromEntries(
            Object.entries({
              max_latency_ms: llmMaxLatencyMs ? Number(llmMaxLatencyMs) : null,
              max_tokens_per_call: llmMaxTokensPerCall
                ? Number(llmMaxTokensPerCall)
                : null,
            }).filter(([, v]) => v !== null),
          );
          budget = Object.fromEntries(
            Object.entries({
              max_calls: llmMaxCalls ? Number(llmMaxCalls) : null,
              max_cost_usd: llmMaxCostUsd ? Number(llmMaxCostUsd) : null,
            }).filter(([, v]) => v !== null),
          );
        } catch (err) {
          throw err instanceof Error
            ? err
            : new Error("Invalid LLM red-team JSON.");
        }

        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: llmName || new URL(llmUrl).hostname,
            base_url: llmUrl,
            kind: "llm",
            disciplines: disciplinesFor("llm"),
            credentials: credsLlm,
            ...attachedRepoPayload,
            llm_config: {
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
                llmProvider === "executable" ? csvList(llmCommand) : null,
              aws_region:
                llmProvider === "bedrock"
                  ? awsRegion.trim() || "us-east-1"
                  : null,
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
              redteam:
                redteam && Object.keys(redteam).length > 0 ? redteam : null,
              thresholds:
                thresholds && Object.keys(thresholds).length > 0
                  ? thresholds
                  : null,
              budget: budget && Object.keys(budget).length > 0 ? budget : null,
              retries: Number(llmRetries || 0),
              timeout_s: Number(llmTimeoutS || 30),
              concurrency: Number(llmConcurrency || 5),
              max_rps: llmMaxRps ? Number(llmMaxRps) : null,
              max_rpm: llmMaxRpm ? Number(llmMaxRpm) : null,
              rate_burst: llmRateBurst ? Number(llmRateBurst) : null,
              guardrails: llmGuardrailsConfig,
            },
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── host ─────────────────────────────────────────────────────────────
      if (selectedKinds.includes("host")) {
        if (hostKindConfig.hosts.length === 0) {
          throw new Error("At least one host is required.");
        }
        const primaryHost = hostKindConfig.hosts[0];
        const baseUrl = `host://${primaryHost}${hostKindConfig.hosts.length > 1 ? "-list" : ""}`;
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: primaryHost,
            base_url: baseUrl,
            kind: "host",
            kind_config: hostKindConfig,
            disciplines: disciplinesFor("host"),
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── provider-aware network / identity kinds ──────────────────────────
      for (const nk of [
        "tls_ssl",
        "dns",
        "email_security",
        "vpn",
        "idp",
        "data_store",
      ] as const) {
        if (!selectedKinds.includes(nk)) continue;
        const { config, creds } = niDraft(nk);
        const kindConfig: Record<string, unknown> = { ...config, kind: nk };
        delete kindConfig.hosts_text; // UI-only helper
        let ident: string;
        if (nk === "dns" || nk === "email_security") {
          const domain = String(config.domain ?? "").trim();
          if (!domain) throw new Error(`${nk}: a domain is required.`);
          ident = domain;
        } else if (nk === "idp") {
          const issuer = String(config.issuer_url ?? "").trim();
          if (!issuer) throw new Error("IdP: an issuer URL is required.");
          ident = issuer.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
        } else if (
          nk === "tls_ssl" &&
          config.source &&
          config.source !== "endpoint"
        ) {
          ident = String(config.source);
        } else {
          const hosts = (config.hosts as string[] | undefined) ?? [];
          if (hosts.length === 0)
            throw new Error(`${nk}: at least one host is required.`);
          ident = `${hosts[0]}${hosts.length > 1 ? "-list" : ""}`;
        }
        const cleanCreds = Object.fromEntries(
          Object.entries(creds).filter(
            ([, v]) => v != null && String(v).trim() !== "",
          ),
        );
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: `${nk} — ${ident}`.slice(0, 200),
            base_url: `${nk}://${ident}`,
            kind: nk,
            kind_config: kindConfig,
            disciplines: disciplinesFor(nk),
            ...(Object.keys(cleanCreds).length
              ? { kind_credentials: { kind: nk, ...cleanCreds } }
              : {}),
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── mcp ──────────────────────────────────────────────────────────────
      if (selectedKinds.includes("mcp")) {
        const st = mcpSourceType;
        if (st === "mcp_http" && !mcpUrl.trim())
          throw new Error("MCP server URL is required.");
        if (st === "mcp_stdio" && !mcpCommand.trim())
          throw new Error("stdio command is required.");
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

        const mcpHeaders: Record<string, string> = {};
        for (const row of mcpHeaderRows) {
          const k = row.key.trim();
          const v = row.value.trim();
          if (k && v) mcpHeaders[k] = v;
        }
        const env: Record<string, string> = {};
        for (const row of mcpEnvRows) {
          const k = row.key.trim();
          const v = row.value.trim();
          if (k && v) env[k] = v;
        }

        const cfg: Record<string, unknown> = { kind: "mcp", source_type: st };
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
        if (allow.length) cfg.tool_allowlist = allow;
        if (deny.length) cfg.tool_denylist = deny;
        cfg.dynamic_invocation = mcpDynamicInvocation;
        cfg.destructive_opt_in = mcpDestructiveOptIn;

        const baseUrl = st === "mcp_http" ? mcpUrl : `mcp://${mcpName || st}`;
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: mcpName || baseUrl,
            base_url: baseUrl,
            kind: "mcp",
            kind_config: cfg,
            disciplines: disciplinesFor("mcp"),
            ...attachedRepoPayload,
            ...(Object.keys(mcpHeaders).length
              ? { credentials: { headers: mcpHeaders } }
              : {}),
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── agent ─────────────────────────────────────────────────────────────
      if (selectedKinds.includes("agent")) {
        const st = agentSourceType;
        if (st === "agent_http" && !agentProvider)
          throw new Error("Agent provider is required.");
        if (
          st === "agent_http" &&
          agentProvider === "custom" &&
          !(agentRequestTemplate.trim() && agentResponsePath.trim())
        )
          throw new Error(
            "Custom provider requires request template and response path.",
          );
        if (
          st === "agent_browser" &&
          !(
            agentUrl.trim() &&
            agentPromptSelector.trim() &&
            agentSendSelector.trim() &&
            agentResponseSelector.trim()
          )
        )
          throw new Error(
            "Browser agent requires URL and all three selectors.",
          );
        if (agentDestructiveOptIn && !agentDynamicInvocation)
          throw new Error(
            "Destructive invocation requires dynamic invocation.",
          );

        const allow = agentToolAllowlist
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean);
        const deny = agentToolDenylist
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean);
        const overlap = allow.filter((a) => deny.includes(a));
        if (overlap.length)
          throw new Error(`Tool allow/deny overlap: ${overlap.join(", ")}`);

        const agentHeaders: Record<string, string> = {};
        for (const row of agentHeaderRows) {
          const k = row.key.trim();
          const v = row.value.trim();
          if (k && v) agentHeaders[k] = v;
        }

        const cfg: Record<string, unknown> = {
          kind: "agent",
          source_type: st,
        };
        if (st === "agent_http") {
          cfg.provider = agentProvider;
          if (agentModel.trim()) cfg.model = agentModel.trim();
          // Every agent_http provider except the local "executable" one POSTs
          // to this endpoint. Without it the target's base_url stays
          // agent://… and every request returns HTTP 0.
          if (agentProvider !== "executable") {
            if (!agentUrl.trim())
              throw new Error("Agent adapter requires a chat-completions URL.");
            cfg.url = agentUrl.trim();
          }
          if (agentProvider === "custom") {
            cfg.request_template = agentRequestTemplate;
            cfg.response_path = agentResponsePath;
          }
        }
        if (st === "agent_browser") {
          cfg.url = agentUrl;
          cfg.prompt_selector = agentPromptSelector;
          cfg.send_selector = agentSendSelector;
          cfg.response_selector = agentResponseSelector;
        }
        if (allow.length) cfg.tool_allowlist = allow;
        if (deny.length) cfg.tool_denylist = deny;
        cfg.dynamic_invocation = agentDynamicInvocation;
        cfg.destructive_opt_in = agentDestructiveOptIn;

        // base_url IS the agent endpoint (agent_http adapter URL or
        // agent_browser page URL). Only the executable provider has none —
        // then fall back to the agent://… placeholder.
        const baseUrl = agentUrl.trim()
          ? agentUrl.trim()
          : `agent://${agentName || st}`;
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: agentName || baseUrl,
            base_url: baseUrl,
            kind: "agent",
            kind_config: cfg,
            disciplines: disciplinesFor("agent"),
            ...attachedRepoPayload,
            ...(Object.keys(agentHeaders).length
              ? { credentials: { headers: agentHeaders } }
              : {}),
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── rag ──────────────────────────────────────────────────────────────
      if (selectedKinds.includes("rag")) {
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

        const headers: Record<string, string> = {};
        for (const r of ragHeaderRows) {
          const k = r.key.trim();
          const v = r.value.trim();
          if (k && v) headers[k] = v;
        }

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

        const baseUrl =
          st === "managed_vdb" ||
          st === "self_hosted_vdb" ||
          st === "rag_endpoint"
            ? ragUrl
            : `rag://${ragName || st}`;
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: ragName || baseUrl,
            base_url: baseUrl,
            kind: "rag",
            kind_config: cfg,
            disciplines: disciplinesFor("rag"),
            ...attachedRepoPayload,
            ...(Object.keys(headers).length
              ? { credentials: { headers } }
              : {}),
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── ml_model ───────────────────────────────────────────────────────────
      if (selectedKinds.includes("ml_model")) {
        const st = mlSourceType;
        if (st === "file_url" && !mlUrl.trim())
          throw new Error("File URL source requires a model URL.");
        if (st === "huggingface" && !mlHfRepo.trim())
          throw new Error("Hugging Face source requires a repo (owner/model).");
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

        const baseUrl =
          st === "file_url"
            ? mlUrl.trim()
            : st === "huggingface"
              ? `hf://${mlHfRepo.trim()}`
              : `file://${mlLocalPath.trim()}`;
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: mlName || baseUrl,
            base_url: baseUrl,
            kind: "ml_model",
            kind_config: cfg,
            disciplines: disciplinesFor("ml_model"),
            ...attachedRepoPayload,
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── voice ────────────────────────────────────────────────────────────
      if (selectedKinds.includes("voice")) {
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

        const voiceHeaders: Record<string, string> = {};
        for (const row of voiceHeaderRows) {
          const k = row.key.trim();
          const v = row.value.trim();
          if (k && v) voiceHeaders[k] = v;
        }

        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: voiceName || voiceUrl.trim(),
            base_url: voiceUrl.trim(),
            kind: "voice",
            kind_config: cfg,
            disciplines: disciplinesFor("voice"),
            ...attachedRepoPayload,
            ...(Object.keys(voiceHeaders).length
              ? { credentials: { headers: voiceHeaders } }
              : {}),
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── android_app ──────────────────────────────────────────────────────
      if (selectedKinds.includes("android_app")) {
        if (!androidFileUrl.trim())
          throw new Error(
            "Android target requires an artifact URL (.apk / .aab).",
          );
        if (!/^[0-9a-fA-F]{64}$/.test(androidSha256.trim()))
          throw new Error(
            "Android target requires a 64-char hex SHA-256 of the artifact.",
          );
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: androidName || androidFileUrl.trim(),
            base_url: `apk://${androidName || androidFileUrl.trim()}`,
            kind: "android_app",
            kind_config: {
              kind: "android_app",
              file_url: androidFileUrl.trim(),
              sha256: androidSha256.trim(),
              use_mobsf: androidUseMobsf,
            },
            disciplines: disciplinesFor("android_app"),
            ...attachedRepoPayload,
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── ios_app ──────────────────────────────────────────────────────────
      if (selectedKinds.includes("ios_app")) {
        if (!iosFileUrl.trim())
          throw new Error("iOS target requires an artifact URL (.ipa).");
        if (!/^[0-9a-fA-F]{64}$/.test(iosSha256.trim()))
          throw new Error(
            "iOS target requires a 64-char hex SHA-256 of the artifact.",
          );
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: iosName || iosFileUrl.trim(),
            base_url: `ipa://${iosName || iosFileUrl.trim()}`,
            kind: "ios_app",
            kind_config: {
              kind: "ios_app",
              file_url: iosFileUrl.trim(),
              sha256: iosSha256.trim(),
            },
            disciplines: disciplinesFor("ios_app"),
            ...attachedRepoPayload,
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── browser_extension ────────────────────────────────────────────────
      if (selectedKinds.includes("browser_extension")) {
        if (!extFileUrl.trim())
          throw new Error(
            "Browser extension requires an artifact URL (.crx / .xpi / .zip).",
          );
        if (!/^[0-9a-fA-F]{64}$/.test(extSha256.trim()))
          throw new Error(
            "Browser extension requires a 64-char hex SHA-256 of the artifact.",
          );
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: extName || extFileUrl.trim(),
            base_url: `crx://${extName || extFileUrl.trim()}`,
            kind: "browser_extension",
            kind_config: {
              kind: "browser_extension",
              file_url: extFileUrl.trim(),
              sha256: extSha256.trim(),
            },
            disciplines: disciplinesFor("browser_extension"),
            ...attachedRepoPayload,
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── desktop_app ──────────────────────────────────────────────────────
      if (selectedKinds.includes("desktop_app")) {
        if (!deskFileUrl.trim())
          throw new Error(
            "Desktop application requires an artifact URL (.zip / .jar / binary).",
          );
        if (!/^[0-9a-fA-F]{64}$/.test(deskSha256.trim()))
          throw new Error(
            "Desktop application requires a 64-char hex SHA-256 of the artifact.",
          );
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: deskName || deskFileUrl.trim(),
            base_url: `app://${deskName || deskFileUrl.trim()}`,
            kind: "desktop_app",
            kind_config: {
              kind: "desktop_app",
              file_url: deskFileUrl.trim(),
              sha256: deskSha256.trim(),
            },
            disciplines: disciplinesFor("desktop_app"),
            ...attachedRepoPayload,
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      // ── firmware / IoT / OT (spec 003) — static firmware analysis ──────────
      for (const fw of [
        {
          kind: "firmware" as const,
          name: fwName,
          url: fwFileUrl,
          sha: fwSha256,
          prefix: "fw",
          label: "Firmware",
        },
        {
          kind: "iot_device" as const,
          name: iotName,
          url: iotFileUrl,
          sha: iotSha256,
          prefix: "iot",
          label: "IoT device",
        },
        {
          kind: "ot_ics_scada" as const,
          name: otName,
          url: otFileUrl,
          sha: otSha256,
          prefix: "ot",
          label: "OT/ICS/SCADA",
        },
      ]) {
        if (!selectedKinds.includes(fw.kind)) continue;
        if (!fw.url.trim())
          throw new Error(
            `${fw.label} requires a firmware artifact URL (.bin / .img / archive).`,
          );
        if (!/^[0-9a-fA-F]{64}$/.test(fw.sha.trim()))
          throw new Error(
            `${fw.label} requires a 64-char hex SHA-256 of the artifact.`,
          );
        const t = await api<{ id: string }>("/targets", {
          method: "POST",
          json: {
            name: fw.name || fw.url.trim(),
            base_url: `${fw.prefix}://${fw.name || fw.url.trim()}`,
            kind: fw.kind,
            kind_config: {
              kind: fw.kind,
              file_url: fw.url.trim(),
              sha256: fw.sha.trim(),
            },
            disciplines: disciplinesFor(fw.kind),
            ...attachedRepoPayload,
          },
        });
        if (!redirectTargetId) redirectTargetId = t.id;
      }

      if (redirectTargetId && startAfter) {
        router.push(`/targets/${redirectTargetId}?commission=1`);
      } else {
        router.push("/dashboard");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Registration failed.");
    } finally {
      setLoading(false);
    }
  }

  // ── Step 1 ────────────────────────────────────────────────────────────────
  if (step === 1) {
    return (
      <Step1TypeSelector
        selectedIds={selectedTypeIds}
        onChange={setSelectedTypeIds}
        selectedDisciplines={selectedDisciplines}
        onDisciplineChange={setSelectedDisciplines}
        onContinue={goToStep2}
        onCancel={() => router.push("/targets")}
      />
    );
  }

  // ── Step 2 ────────────────────────────────────────────────────────────────
  const hasAnySupported = selectedKinds.some((k) =>
    RENDERABLE_KINDS.includes(k),
  );

  return (
    <div>
      {/* Back + header */}
      <div className="mb-8">
        <button
          type="button"
          onClick={goToStep1}
          className="flex items-center gap-2 font-body text-[13px] text-slate hover:text-ink transition-colors mb-5"
        >
          <span>←</span>
          <span>Back to type selection</span>
        </button>
        <p className="eyebrow-gilt">Configuration</p>
        <h1 className="mt-3 font-display text-[36px] md:text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
          Configure Targets.
        </h1>
        <p className="mt-2 text-[14px] text-slate">
          {selectedTypeIds.size} target type
          {selectedTypeIds.size !== 1 ? "s" : ""} selected
          {selectedKinds.length > 0 && (
            <>
              {" "}
              · {selectedKinds.join(", ")} scan
              {selectedKinds.length !== 1 ? "s" : ""}
            </>
          )}
        </p>
      </div>

      {!hasAnySupported && (
        <div className="advisory-warn font-body text-[13px] mb-6">
          The selected target types are not yet configurable. Please go back and
          select at least one active target type.
        </div>
      )}

      <div className="formal-surface-elev p-8 md:p-10">
        {error && (
          <div className="mb-6 advisory-warn font-body text-[13px]">
            {error}
          </div>
        )}

        <form onSubmit={onSubmit} className="space-y-10">
          {selectedKinds.includes("web_app") && (
            <WebAppFormSection
              value={webAppCfg}
              onChange={setWebAppCfg}
              name={webAppName}
              setName={setWebAppName}
              appUrl={webAppUrl}
              setAppUrl={setWebAppUrl}
              creds={webAppCreds}
              setCreds={setWebAppCreds}
            />
          )}

          {selectedKinds.includes("rest_api") && (
            <RestApiFormSection
              value={restApiCfg}
              onChange={setRestApiCfg}
              name={restApiName}
              setName={setRestApiName}
              baseUrl={restApiBaseUrl}
              setBaseUrl={setRestApiBaseUrl}
              rawSpec={restApiRawSpec}
              setRawSpec={setRestApiRawSpec}
              creds={restApiCreds}
              setCreds={setRestApiCreds}
            />
          )}

          {selectedKinds.includes("graphql") && (
            <GraphqlFormSection
              value={graphqlCfg}
              onChange={setGraphqlCfg}
              name={graphqlName}
              setName={setGraphqlName}
              endpoint={graphqlEndpoint}
              setEndpoint={setGraphqlEndpoint}
              creds={graphqlCreds}
              setCreds={setGraphqlCreds}
            />
          )}

          {selectedKinds.includes("websocket") && (
            <WebsocketFormSection
              value={wsCfg}
              onChange={setWsCfg}
              name={wsName}
              setName={setWsName}
              wsEndpoint={wsEndpoint}
              setWsEndpoint={setWsEndpoint}
              rawSubprotocols={wsRawSubprotocols}
              setRawSubprotocols={setWsRawSubprotocols}
              creds={wsCreds}
              setCreds={setWsCreds}
            />
          )}

          {selectedKinds.includes("grpc") && (
            <GrpcFormSection
              value={grpcCfg}
              onChange={setGrpcCfg}
              name={grpcName}
              setName={setGrpcName}
              authority={grpcAuthority}
              setAuthority={setGrpcAuthority}
              rawProto={grpcRawProto}
              setRawProto={setGrpcRawProto}
              metadata={grpcMetadata}
              setMetadata={setGrpcMetadata}
            />
          )}

          {selectedKinds.includes("source_code") && (
            <SourceCodeFormSection
              value={sourceCodeCfg}
              onChange={setSourceCodeCfg}
              name={sourceCodeName}
              setName={setSourceCodeName}
              creds={sourceCodeCreds}
              setCreds={setSourceCodeCreds}
              rawLangsHint={sourceCodeRawLangs}
              setRawLangsHint={setSourceCodeRawLangs}
            />
          )}

          {CLOUD_KIND_LIST.filter((kind) => selectedKinds.includes(kind)).map(
            (kind) => (
              <CloudFormSection
                key={kind}
                draft={cloudDrafts[kind]}
                onChange={(draft) => setCloudDraft(kind, draft)}
              />
            ),
          )}

          {/* Artifact + hybrid kinds */}
          {selectedKinds.includes("container_image") && (
            <ContainerImageFormSection
              value={containerImageCfg}
              onChange={setContainerImageCfg}
              name={artifactName}
              setName={setArtifactName}
              creds={containerImageCreds}
              setCreds={setContainerImageCreds}
            />
          )}
          {selectedKinds.includes("iac") && (
            <IacFormSection
              value={iacCfg}
              onChange={setIacCfg}
              name={artifactName}
              setName={setArtifactName}
              creds={iacCreds}
              setCreds={setIacCreds}
            />
          )}
          {selectedKinds.includes("package_registry") && (
            <PackageRegistryFormSection
              value={packageRegistryCfg}
              onChange={setPackageRegistryCfg}
              name={artifactName}
              setName={setArtifactName}
              rawPackages={rawPackages}
              setRawPackages={setRawPackages}
            />
          )}
          {selectedKinds.includes("sbom") && (
            <SbomFormSection
              value={sbomCfg}
              onChange={setSbomCfg}
              name={artifactName}
              setName={setArtifactName}
            />
          )}
          {selectedKinds.includes("cicd_pipeline") && (
            <CicdPipelineFormSection
              value={cicdCfg}
              onChange={setCicdCfg}
              name={artifactName}
              setName={setArtifactName}
              rawConfigPaths={rawCicdPaths}
              setRawConfigPaths={setRawCicdPaths}
              creds={cicdCreds}
              setCreds={setCicdCreds}
            />
          )}
          {selectedKinds.includes("k8s_cluster") && (
            <K8sClusterFormSection
              value={k8sCfg}
              onChange={setK8sCfg}
              name={artifactName}
              setName={setArtifactName}
              creds={k8sCreds}
              setCreds={setK8sCreds}
              rawNamespaces={rawNamespaces}
              setRawNamespaces={setRawNamespaces}
            />
          )}

          {selectedKinds.includes("host") && (
            <HostFormSection
              value={hostKindConfig}
              onChange={setHostKindConfig}
              allowPrivateTargets={activeOrg?.allow_private_targets ?? false}
            />
          )}

          {(
            [
              "tls_ssl",
              "dns",
              "email_security",
              "vpn",
              "idp",
              "data_store",
            ] as const
          ).map((nk) =>
            selectedKinds.includes(nk) ? (
              <NetworkIdentityFormSection
                key={nk}
                kind={nk}
                value={niDraft(nk)}
                onChange={(d) => setNiDraft(nk, d)}
              />
            ) : null,
          )}

          {selectedKinds.includes("memory") && (
            <MemoryFormSection
              name={artifactName}
              setName={setArtifactName}
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

          {selectedKinds.includes("llm") && (
            <LlmFormSection
              url={llmUrl}
              setUrl={setLlmUrl}
              name={llmName}
              setName={setLlmName}
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

          {selectedKinds.includes("mcp") && (
            <McpFormSection
              name={mcpName}
              setName={setMcpName}
              sourceType={mcpSourceType}
              setSourceType={setMcpSourceType}
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

          {selectedKinds.includes("agent") && (
            <AgentFormSection
              name={agentName}
              setName={setAgentName}
              sourceType={agentSourceType}
              setSourceType={setAgentSourceType}
              url={agentUrl}
              setUrl={setAgentUrl}
              provider={agentProvider}
              setProvider={setAgentProvider}
              model={agentModel}
              setModel={setAgentModel}
              requestTemplate={agentRequestTemplate}
              setRequestTemplate={setAgentRequestTemplate}
              responsePath={agentResponsePath}
              setResponsePath={setAgentResponsePath}
              promptSelector={agentPromptSelector}
              setPromptSelector={setAgentPromptSelector}
              sendSelector={agentSendSelector}
              setSendSelector={setAgentSendSelector}
              responseSelector={agentResponseSelector}
              setResponseSelector={setAgentResponseSelector}
              toolAllowlist={agentToolAllowlist}
              setToolAllowlist={setAgentToolAllowlist}
              toolDenylist={agentToolDenylist}
              setToolDenylist={setAgentToolDenylist}
              dynamicInvocation={agentDynamicInvocation}
              setDynamicInvocation={setAgentDynamicInvocation}
              destructiveOptIn={agentDestructiveOptIn}
              setDestructiveOptIn={setAgentDestructiveOptIn}
              headerRows={agentHeaderRows}
              setHeaderRows={setAgentHeaderRows}
            />
          )}

          {selectedKinds.includes("rag") && (
            <RagFormSection
              name={ragName}
              setName={setRagName}
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

          {selectedKinds.includes("ml_model") && (
            <MlModelFormSection
              name={mlName}
              setName={setMlName}
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

          {selectedKinds.includes("voice") && (
            <VoiceFormSection
              name={voiceName}
              setName={setVoiceName}
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

          {selectedKinds.includes("android_app") && (
            <MobileAppFormSection
              platform="android"
              name={androidName}
              setName={setAndroidName}
              fileUrl={androidFileUrl}
              setFileUrl={setAndroidFileUrl}
              sha256={androidSha256}
              setSha256={setAndroidSha256}
              useMobsf={androidUseMobsf}
              setUseMobsf={setAndroidUseMobsf}
            />
          )}

          {selectedKinds.includes("ios_app") && (
            <MobileAppFormSection
              platform="ios"
              name={iosName}
              setName={setIosName}
              fileUrl={iosFileUrl}
              setFileUrl={setIosFileUrl}
              sha256={iosSha256}
              setSha256={setIosSha256}
            />
          )}

          {selectedKinds.includes("browser_extension") && (
            <ClientArtifactFormSection
              variant="browser_extension"
              name={extName}
              setName={setExtName}
              fileUrl={extFileUrl}
              setFileUrl={setExtFileUrl}
              sha256={extSha256}
              setSha256={setExtSha256}
            />
          )}

          {selectedKinds.includes("desktop_app") && (
            <ClientArtifactFormSection
              variant="desktop_app"
              name={deskName}
              setName={setDeskName}
              fileUrl={deskFileUrl}
              setFileUrl={setDeskFileUrl}
              sha256={deskSha256}
              setSha256={setDeskSha256}
            />
          )}

          {selectedKinds.includes("firmware") && (
            <ClientArtifactFormSection
              variant="firmware"
              name={fwName}
              setName={setFwName}
              fileUrl={fwFileUrl}
              setFileUrl={setFwFileUrl}
              sha256={fwSha256}
              setSha256={setFwSha256}
            />
          )}

          {selectedKinds.includes("iot_device") && (
            <ClientArtifactFormSection
              variant="iot_device"
              name={iotName}
              setName={setIotName}
              fileUrl={iotFileUrl}
              setFileUrl={setIotFileUrl}
              sha256={iotSha256}
              setSha256={setIotSha256}
            />
          )}

          {selectedKinds.includes("ot_ics_scada") && (
            <ClientArtifactFormSection
              variant="ot_ics_scada"
              name={otName}
              setName={setOtName}
              fileUrl={otFileUrl}
              setFileUrl={setOtFileUrl}
              sha256={otSha256}
              setSha256={setOtSha256}
            />
          )}

          {canAttachReposForSelection && (
            <>
              <hr className="rule" />
              <section>
                <div className="flex items-baseline gap-3 mb-1">
                  <span className="eyebrow-gilt">SOURCE</span>
                  <h2 className="font-display text-[18px] text-ink">
                    Source repositories
                  </h2>
                </div>
                <p className="text-[13px] text-slate italic mb-4">
                  Optional. Attach registered repos that contain the code for{" "}
                  {selectedAttachableKinds.join(", ")} targets. The Agent fix
                  flow uses these repos to open remediation PRs for scan
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
                      No repositories registered yet. Register one from the
                      Repositories page, then return here to attach it.
                    </p>
                  )}
                {!reposLoading && !reposError && availableRepos.length > 0 && (
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
                      aria-label="Repositories to attach"
                      aria-multiselectable="true"
                    >
                      {availableRepos
                        .filter((repo) => {
                          const q = repoFilter.trim().toLowerCase();
                          if (!q) return true;
                          return (
                            repo.full_name.toLowerCase().includes(q) ||
                            (repo.language || "").toLowerCase().includes(q)
                          );
                        })
                        .map((repo) => {
                          const checked = attachedRepoIds.includes(repo.id);
                          return (
                            <li key={repo.id}>
                              <label
                                className={
                                  "flex items-start gap-3 px-4 py-3 cursor-pointer transition-colors " +
                                  (checked ? "bg-vellum" : "hover:bg-vellum/40")
                                }
                              >
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={() => toggleAttachedRepo(repo.id)}
                                  aria-label={`Attach ${repo.full_name}`}
                                  className="mt-1 w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
                                />
                                <span className="flex-1 min-w-0">
                                  <span className="block font-mono text-[13px] text-ink truncate">
                                    {repo.full_name}
                                  </span>
                                  <span className="block font-mono text-[11px] text-mist truncate">
                                    {repo.provider}
                                    {repo.language ? ` · ${repo.language}` : ""}
                                    {repo.local_path
                                      ? ` · ${repo.local_path}`
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

          {/* Footer */}
          <section className="flex flex-wrap items-center justify-between gap-6">
            {hasAnySupported && (
              <label className="flex items-center gap-3 cursor-pointer select-none">
                <input
                  id="startAfter"
                  type="checkbox"
                  checked={startAfter}
                  onChange={(e) => setStartAfter(e.target.checked)}
                  className="w-[18px] h-[18px] border border-hairline rounded-sm accent-ink"
                />
                <span className="font-body text-[13px] text-graphite">
                  Commission the assessment immediately upon registration.
                </span>
              </label>
            )}

            <div className="flex items-center gap-3">
              <Button variant="yellow" type="button" onClick={goToStep1}>
                ← Back
              </Button>
              {hasAnySupported && (
                <Button
                  type="submit"
                  variant="pink"
                  disabled={loading}
                  className="min-w-[200px]"
                >
                  {loading
                    ? "Submitting…"
                    : startAfter
                      ? "Register & commission"
                      : "Register target"}
                </Button>
              )}
            </div>
          </section>
        </form>
      </div>
    </div>
  );
}

export default function RegisterTargetPage() {
  return (
    <Suspense fallback={<InlineLoading label="Loading…" />}>
      <RegisterTargetContent />
    </Suspense>
  );
}
