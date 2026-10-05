/**
 * Canonical catalogue of AI-driven actions Pencheff discloses to the operator
 * at scan-creation time. Every active and upcoming agent class is listed
 * here so the consent UI is forward-compatible with future agents.
 *
 * The ``id`` values map 1:1 to the ``disclosed_actions`` array persisted in
 * ``Scan.consent_payload`` AND to the keys in the backend's
 * ``KIND_REQUIRED_DISCLOSED_ACTIONS`` map at
 * ``apps/api/pencheff_api/schemas/scans.py``.
 *
 * Feature 001 introduced kind-aware enforcement — the router rejects scans
 * whose ``disclosed_actions`` doesn't cover the required set for the target's
 * kind. The modal calls ``getKindDisclosures(kind, kindConfig)`` to compute
 * the right action catalogue to surface (and the IDs to send).
 */

import type { SupportedKind } from "@/components/register-target/target-types";

export interface DisclosedAction {
  id: string;
  displayName: string;
  description: string;
  /** When true, the agent lands in a future batch and is pre-disclosed now. */
  upcoming?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────
// Action catalogue — keyed by ID for sharing across kinds.
// ─────────────────────────────────────────────────────────────────────────

const ACTIONS: Record<string, DisclosedAction> = {
  passive_recon: {
    id: "passive_recon",
    displayName: "Passive recon",
    description:
      "Read public DNS / cert transparency / robots.txt / sitemap. Zero traffic to your application.",
  },
  active_recon: {
    id: "active_recon",
    displayName: "Active recon",
    description:
      "Crawl your application; enumerate endpoints, parameters, forms.",
  },
  vulnerability_probing: {
    id: "vulnerability_probing",
    displayName: "Vulnerability probing",
    description:
      "Targeted probes against discovered endpoints (SQLi, XSS, IDOR, etc.) using non-destructive payloads.",
  },
  exploit_chaining: {
    id: "exploit_chaining",
    displayName: "Exploit chain validation",
    description:
      "Multi-step attack-chain verification: e.g., SSRF → cloud metadata → IAM. No data is extracted; only step-by-step reachability is verified.",
  },
  compliance_mapping: {
    id: "compliance_mapping",
    displayName: "Compliance mapping",
    description:
      "Read-only categorisation of findings against PCI/HIPAA/SOC2/GDPR controls.",
  },
  schema_impact_introspection: {
    id: "schema_impact_introspection",
    displayName: "Schema-impact introspection",
    description:
      "For verified injection findings, query database schema (table names, column types, estimated row counts). No row data extracted.",
  },
  payload_synthesis: {
    id: "payload_synthesis",
    displayName: "Reproducible PoC synthesis",
    description:
      "Generate curl and Python PoCs from finding metadata. Read-only.",
  },
  evidence_capture: {
    id: "evidence_capture",
    displayName: "Evidence screenshots (Batch C)",
    description:
      "Drive a headless browser to verified findings; capture screenshots; redact obvious PII regions.",
    upcoming: true,
  },
  admin_panel_enumeration: {
    id: "admin_panel_enumeration",
    displayName: "Admin panel enumeration (Batch C)",
    description:
      "When admin access is verified, drive a headless browser into the admin panel read-only: capture front-page screenshot, enumerate ≤ 5 menu links, immediately log out.",
    upcoming: true,
  },
  // ── Feature 001 — new actions for the 12 new kinds ──
  api_fuzzing: {
    id: "api_fuzzing",
    displayName: "API parameter fuzzing",
    description:
      "Fuzz REST / GraphQL / WebSocket / gRPC parameters with safe non-destructive payloads. Mass-assignment, BOLA, broken-auth, rate-limit probes.",
  },
  introspection_query: {
    id: "introspection_query",
    displayName: "GraphQL introspection",
    description:
      "Issue a single introspection query against the GraphQL endpoint to discover schema for downstream BOLA / IDOR probing.",
  },
  ws_handshake: {
    id: "ws_handshake",
    displayName: "WebSocket handshake probing",
    description:
      "Negotiate the WS handshake, test origin-pin / auth-on-handshake / CSWSH vectors.",
  },
  grpc_reflection: {
    id: "grpc_reflection",
    displayName: "gRPC reflection enumeration",
    description:
      "Enumerate gRPC services + methods via reflection. Methods are then probed with primitive fuzz payloads.",
  },
  exploitation: {
    id: "exploitation",
    displayName: "Exploit-chain validation",
    description:
      "Multi-step attack-chain verification: e.g., SSRF → cloud metadata → IAM. Includes vulnerability_probing + exploit_chaining. No data extraction.",
  },
  clone_repo: {
    id: "clone_repo",
    displayName: "Clone source repository",
    description:
      "Clone the registered repository to a sandboxed temp directory (--depth=1, --no-hardlinks, core.hooksPath=/dev/null — repo-side hooks neutralized).",
  },
  source_code_scan: {
    id: "source_code_scan",
    displayName: "Source-code SAST",
    description:
      "Run semgrep / bandit / gosec / brakeman / eslint / gitleaks / yara / osv-scanner against the cloned source. Read-only.",
  },
  iac_scan: {
    id: "iac_scan",
    displayName: "Infrastructure-as-Code audit",
    description:
      "Run checkov + tfsec against Terraform / CloudFormation / Helm / Kustomize / ARM templates. Read-only.",
  },
  image_pull: {
    id: "image_pull",
    displayName: "Container image acquisition",
    description:
      "Pull the registered container image into a sandboxed OCI layout via skopeo (never docker pull — no exec during pull).",
  },
  container_scan: {
    id: "container_scan",
    displayName: "Container vulnerability + secret scan",
    description:
      "Run trivy + syft + grype against the image layers. Detects CVEs, embedded secrets, OS-package misconfigurations.",
  },
  dependency_scan: {
    id: "dependency_scan",
    displayName: "Package-registry dependency audit",
    description:
      "Audit the supplied package list against ecosystem vulnerability databases (osv-scanner, npm-audit, pip-audit).",
  },
  registry_query: {
    id: "registry_query",
    displayName: "Package-registry metadata query",
    description:
      "Query the package registry (npmjs.org / pypi.org / etc.) for package metadata to enrich findings.",
  },
  sbom_scan: {
    id: "sbom_scan",
    displayName: "SBOM analysis",
    description:
      "Parse the supplied CycloneDX / SPDX SBOM and check components against vulnerability databases.",
  },
  vuln_db_query: {
    id: "vuln_db_query",
    displayName: "Vulnerability database lookup",
    description:
      "Query OSV / NVD / GHSA for SBOM components to surface known CVEs + license issues.",
  },
  ci_config_audit: {
    id: "ci_config_audit",
    displayName: "CI/CD configuration audit",
    description:
      "Read CI workflow files (GitHub Actions, GitLab CI, Jenkinsfile, etc.) and audit for untrusted-PR triggers, secret leakage, missing approvals.",
  },
  ci_api_read: {
    id: "ci_api_read",
    displayName: "CI provider API enumeration",
    description:
      "Hit the CI provider's REST API (read-only) to enumerate workflows, secret names (NOT values), deploy keys, runner pools.",
  },
  k8s_manifest_scan: {
    id: "k8s_manifest_scan",
    displayName: "Kubernetes manifest audit",
    description:
      "Run checkov + trivy against the supplied K8s manifests (Helm chart, Kustomize overlay, raw YAML). Read-only.",
  },
  k8s_api_read: {
    id: "k8s_api_read",
    displayName: "Kubernetes API enumeration",
    description:
      "Use the supplied kubeconfig to list resources (rolebindings, networkpolicies, etc.) via kubectl get. Read-only.",
  },
  cloud_metadata_read: {
    id: "cloud_metadata_read",
    displayName: "Cloud metadata posture checks",
    description:
      "Use read-only cloud credentials or operator-supplied inventory JSON to inspect IAM, storage, serverless, load balancer/CDN, database, secret-manager, and audit-log metadata. Secret values are never requested, read, logged, or stored.",
  },
  rbac_enumeration: {
    id: "rbac_enumeration",
    displayName: "RBAC effective-permissions enumeration",
    description:
      "Use rakkess to enumerate effective RBAC permissions across namespaces. Flags wildcard verbs, escalate, impersonate.",
  },
  llm_red_team_prompts: {
    id: "llm_red_team_prompts",
    displayName: "LLM red-team prompts",
    description:
      "Probe the LLM endpoint with prompt-injection / jailbreak / system-prompt-extraction / training-data-leakage payloads from configured datasets.",
  },
  mcp_enumerate: {
    id: "mcp_enumerate",
    displayName: "MCP enumeration & static analysis",
    description:
      "Connect to the MCP server / agent and enumerate its tools, resources, and prompts, then statically analyze the manifest (tool descriptions, schemas) for poisoning, hidden instructions, and excessive agency. No tools are invoked; no side effects.",
  },
  agent_probe: {
    id: "agent_probe",
    displayName: "Send adversarial probe prompts to the agent",
    description:
      "Send adversarial prompt sequences to the AI agent (via HTTP adapter or browser UI) to detect prompt injection, goal hijacking, system-prompt extraction, and unsafe tool-call patterns. No data is modified on the target; only agent responses are captured.",
  },
  mcp_tool_invocation: {
    id: "mcp_tool_invocation",
    displayName: "MCP tool invocation (safe)",
    description:
      "Dynamically invoke the server's read-only / non-destructive tools with adversarial inputs to detect injection-via-tool-output, SSRF, and parameter-injection. May cause read-side effects on the target.",
  },
  mcp_destructive_tool_invocation: {
    id: "mcp_destructive_tool_invocation",
    displayName: "MCP destructive tool invocation",
    description:
      "Invoke tools classed as destructive (exec / file-write / delete / payment / network-egress) with adversarial inputs to prove impact. This can modify or destroy data on the target — only authorize against a sandbox / throwaway target you own.",
  },
  host_os_exploitation: {
    id: "host_os_exploitation",
    displayName: "Host operating-system exploitation",
    description:
      "Run remote and local exploits against the operating systems and exposed services of the listed hosts. " +
      "On a successful compromise, Pencheff will execute read-only reconnaissance commands (hostname, current user, " +
      "directory listings, kernel/version banners), capture one screenshot of the active session, and exfiltrate up to " +
      "256 KB of evidence per host to demonstrate impact. Pencheff will NOT modify, delete, or persist anything on the " +
      "target; sessions are torn down immediately after evidence capture. By authorizing this action you attest that " +
      "you own these hosts or hold written authorization from the owner.",
  },
  rag_enumerate: {
    id: "rag_enumerate",
    displayName: "RAG / vector-DB enumeration & static analysis",
    description:
      "Connect to the RAG system / vector DB and enumerate its indexes/collections, audit configuration (auth, multi-tenancy/isolation), and sample stored chunks for secrets/PII at rest. No queries that mutate data; no writes.",
  },
  rag_query_probe: {
    id: "rag_query_probe",
    displayName: "RAG query probing (read-only)",
    description:
      "Issue read-only retrieval and extraction queries to detect membership inference, verbatim datastore extraction, cross-tenant retrieval leakage, and poisoning susceptibility. May surface stored content in responses.",
  },
  rag_poison_injection: {
    id: "rag_poison_injection",
    displayName: "RAG poisoning injection (destructive)",
    description:
      "Write poisoned documents into the index to prove PoisonedRAG-style retrieval+generation control. This MODIFIES the target index — only authorize against a sandbox/throwaway index you own; the probe removes the injected documents after testing.",
  },
  ml_fetch: {
    id: "ml_fetch",
    displayName: "ML model fetch & static inspection",
    description:
      "Download (or read) the model artifact and statically inspect its bytes/opcodes/structure for unsafe-deserialization RCE, unsafe formats, and Keras code-execution. The model is NEVER loaded, deserialized, or executed.",
  },
  voice_enumerate: {
    id: "voice_enumerate",
    displayName: "Voice endpoint enumeration & transport posture",
    description:
      "Probe the voice endpoint's transport posture: reachability without auth, audio-URL SSRF surface, and oversized/malformed-audio handling. No crafted-speech submission.",
  },
  voice_audio_probe: {
    id: "voice_audio_probe",
    displayName:
      "Crafted-audio submission (cross-modal injection / ultrasonic)",
    description:
      "Submit synthesized audio to the endpoint to test cross-modal prompt injection and ultrasonic hidden commands. Only authorize against endpoints you own or are authorized to test.",
  },
  voice_auth_probe: {
    id: "voice_auth_probe",
    displayName: "Voice-auth spoofing (synthetic speaker audio)",
    description:
      "Submit synthetic/altered speaker audio to a voice-authentication endpoint to test anti-spoofing. Requires crafted-audio submission; only against authorized targets.",
  },
  memory_enumerate: {
    id: "memory_enumerate",
    displayName: "Agent-memory / vector-store enumeration & static analysis",
    description:
      "Read the provided agent-memory / vector-store items (pasted, uploaded, or fetched from the registered provider) and statically scan them for secrets, PII, and memory-poisoning / prompt-injection content at rest. No items are written or modified.",
  },
  mobile_fetch: {
    id: "mobile_fetch",
    displayName: "Mobile artifact fetch & integrity check",
    description:
      "Download the registered app artifact (APK/AAB/IPA) and verify its SHA-256. The artifact is stored only for the duration of the scan.",
  },
  mobile_static_scan: {
    id: "mobile_static_scan",
    displayName: "Mobile static analysis",
    description:
      "Statically analyse the app's bytes — manifest/Info.plist, exported components, hardcoded secrets, weak crypto, cleartext traffic, Mach-O protections. The app is NEVER installed or executed (no device/emulator).",
  },
  client_fetch: {
    id: "client_fetch",
    displayName: "Client artifact fetch & integrity check",
    description:
      "Download the registered extension/desktop artifact and verify its SHA-256. Stored only for the duration of the scan.",
  },
  client_static_scan: {
    id: "client_static_scan",
    displayName: "Client artifact static analysis",
    description:
      "Statically analyse the artifact's bytes — extension manifest/permissions/CSP/DOM-sinks or desktop Electron config/dependencies — plus hardcoded secrets. The artifact is NEVER executed.",
  },
  firmware_fetch: {
    id: "firmware_fetch",
    displayName: "Firmware image fetch & integrity check",
    description:
      "Download the registered firmware image and verify its SHA-256. Stored only for the duration of the scan.",
  },
  firmware_static_scan: {
    id: "firmware_static_scan",
    displayName: "Firmware static analysis",
    description:
      "Statically analyse the firmware image — embedded keys/certificates, default/hardcoded credentials, insecure services, cleartext endpoints, secrets, and component versions. The firmware is NEVER flashed or executed, and no live device or industrial network is probed.",
  },
};

/**
 * Backward-compatible export — the legacy 9-item catalogue. Still used by
 * the few call sites that need the "everything Pencheff might do" picker;
 * the kind-aware modal uses ``getKindDisclosures`` instead.
 */
export const DISCLOSED_ACTIONS: DisclosedAction[] = [
  ACTIONS.passive_recon,
  ACTIONS.active_recon,
  ACTIONS.vulnerability_probing,
  ACTIONS.exploit_chaining,
  ACTIONS.compliance_mapping,
  ACTIONS.schema_impact_introspection,
  ACTIONS.payload_synthesis,
  ACTIONS.evidence_capture,
  ACTIONS.admin_panel_enumeration,
];

/**
 * Per-kind required disclosed-actions set. Mirrors the backend's
 * ``KIND_REQUIRED_DISCLOSED_ACTIONS`` at apps/api/pencheff_api/schemas/scans.py
 * exactly — the router rejects scans whose disclosed_actions doesn't cover
 * this set for the target's kind.
 */
const REQUIRED_ACTION_IDS_BY_KIND: Record<SupportedKind, string[]> = {
  url: ["passive_recon", "active_recon", "exploitation"],
  repo: ["source_code_scan"],
  llm: ["llm_red_team_prompts"],
  web_app: ["passive_recon", "active_recon", "exploitation"],
  rest_api: ["passive_recon", "api_fuzzing", "exploitation"],
  graphql: ["introspection_query", "api_fuzzing", "exploitation"],
  websocket: ["ws_handshake", "api_fuzzing", "exploitation"],
  grpc: ["grpc_reflection", "api_fuzzing", "exploitation"],
  source_code: ["source_code_scan", "clone_repo"],
  iac: ["iac_scan", "clone_repo"],
  container_image: ["image_pull", "container_scan"],
  package_registry: ["dependency_scan", "registry_query"],
  sbom: ["sbom_scan", "vuln_db_query"],
  cicd_pipeline: ["ci_config_audit"],
  k8s_cluster: ["k8s_manifest_scan"],
  cloud_account: ["cloud_metadata_read"],
  serverless_function: ["cloud_metadata_read"],
  cloud_storage: ["cloud_metadata_read"],
  load_balancer_cdn: ["cloud_metadata_read"],
  cloud_database: ["cloud_metadata_read"],
  secrets_manager: ["cloud_metadata_read"],
  host: ["passive_recon", "active_recon", "host_os_exploitation"],
  tls_ssl: ["active_recon"],
  dns: ["passive_recon"],
  email_security: ["passive_recon"],
  vpn: ["active_recon"],
  idp: ["passive_recon"],
  data_store: ["active_recon"],
  // Memory targets (card #30) are commissioned through the consent-gated
  // /scans pipeline like the other AI kinds, so they MUST disclose at least one
  // action or ConsentPayload (min_length=1) rejects the scan.
  memory: ["memory_enumerate"],
  // MCP targets always disclose enumeration; dynamic/destructive are conditional.
  mcp: ["mcp_enumerate"],
  // Agent targets: adversarial probe prompts (matches backend agent_probe requirement).
  agent: ["agent_probe"],
  // RAG / vector-DB targets — stopgap until Task 2 lands the full 3-action vocab.
  rag: ["rag_enumerate"],
  // ML model targets always disclose the single static fetch+inspect action.
  ml_model: ["ml_fetch"],
  // Voice targets always disclose enumeration; audio/auth probes are conditional.
  voice: ["voice_enumerate"],
  // Mobile artifacts (spec 002): static-only — fetch the artifact + scan it.
  // Never executed (no device/emulator).
  android_app: ["mobile_fetch", "mobile_static_scan"],
  ios_app: ["mobile_fetch", "mobile_static_scan"],
  browser_extension: ["client_fetch", "client_static_scan"],
  desktop_app: ["client_fetch", "client_static_scan"],
  firmware: ["firmware_fetch", "firmware_static_scan"],
  iot_device: ["firmware_fetch", "firmware_static_scan"],
  ot_ics_scada: ["firmware_fetch", "firmware_static_scan"],
};

/**
 * Additional actions worth surfacing to the operator alongside the required
 * set — these are NOT enforced by the router but tell the user what the
 * scan will additionally do. The modal renders the union.
 */
const ADDITIONAL_ACTIONS_BY_KIND: Record<SupportedKind, string[]> = {
  url: [
    "vulnerability_probing",
    "compliance_mapping",
    "schema_impact_introspection",
    "payload_synthesis",
    "evidence_capture",
    "admin_panel_enumeration",
  ],
  repo: [],
  llm: [],
  web_app: [
    "vulnerability_probing",
    "compliance_mapping",
    "schema_impact_introspection",
    "payload_synthesis",
    "evidence_capture",
    "admin_panel_enumeration",
  ],
  rest_api: [
    "vulnerability_probing",
    "compliance_mapping",
    "payload_synthesis",
  ],
  graphql: ["vulnerability_probing", "compliance_mapping", "payload_synthesis"],
  websocket: [
    "vulnerability_probing",
    "compliance_mapping",
    "payload_synthesis",
  ],
  grpc: ["vulnerability_probing", "compliance_mapping", "payload_synthesis"],
  source_code: ["compliance_mapping"],
  iac: ["compliance_mapping"],
  container_image: ["compliance_mapping"],
  package_registry: ["compliance_mapping"],
  sbom: ["compliance_mapping"],
  cicd_pipeline: ["compliance_mapping"],
  k8s_cluster: ["compliance_mapping"],
  cloud_account: ["compliance_mapping"],
  serverless_function: ["compliance_mapping"],
  cloud_storage: ["compliance_mapping"],
  load_balancer_cdn: ["compliance_mapping"],
  cloud_database: ["compliance_mapping"],
  secrets_manager: ["compliance_mapping"],
  // No additional optional actions for host kind in sub-project A.
  // Future sub-projects (D/E/F) may add compliance_mapping, chain extras, etc.
  host: [],
  tls_ssl: [],
  dns: [],
  email_security: [],
  vpn: [],
  idp: [],
  data_store: [],
  memory: [],
  // mcp_tool_invocation and mcp_destructive_tool_invocation are in ACTIONS but
  // added conditionally in getKindDisclosures — NOT here — to preserve the
  // invariant that dynamic_invocation=false → only mcp_enumerate is disclosed.
  mcp: [],
  agent: [],
  // RAG stopgap — no additional optional actions until Task 2 lands.
  rag: [],
  // ML model targets disclose only the single ml_fetch action.
  ml_model: [],
  // voice_audio_probe and voice_auth_probe are in ACTIONS but added
  // conditionally in getKindDisclosures — NOT here — to preserve the invariant
  // that audio_probes=false → only voice_enumerate is disclosed.
  voice: [],
  // Mobile artifacts: static-only, no additional optional actions.
  android_app: [],
  ios_app: [],
  browser_extension: [],
  desktop_app: [],
  firmware: [],
  iot_device: [],
  ot_ics_scada: [],
};

export interface KindConfigForDisclosures {
  /** When set, augments hybrid Phase A disclosures with Phase B actions. */
  kind?: SupportedKind;
  live_api_enabled?: boolean;
  target?: "manifests_only" | "live_cluster";
  rbac_enum?: boolean;
  /** Host-kind targets: the list of hosts the operator is authorizing. */
  hosts?: string[];
  /** MCP targets: dynamic-testing opt-ins that add tool-invocation disclosures. */
  dynamic_invocation?: boolean;
  destructive_opt_in?: boolean;
  /** RAG targets: query-probe opt-in adds read-only retrieval attack disclosures. */
  query_probes?: boolean;
  /** RAG targets: poison-injection opt-in (requires query_probes). */
  poison_injection_opt_in?: boolean;
  /** Voice targets: crafted-audio submission opt-in adds cross-modal probes. */
  audio_probes?: boolean;
  /** Voice targets: source_type drives the nested voice_auth_probe disclosure. */
  source_type?: string;
}

/**
 * Compute the action set to surface in the commission modal for a given kind.
 *
 * Returns both the renderable list (with display names + descriptions for the
 * UI) AND the flat ID array to send in ``ConsentPayload.disclosed_actions``.
 * The two are kept aligned so the router never rejects a modal-submitted scan.
 *
 * The optional ``kind_config`` widens the disclosure set when hybrid kinds
 * enable Phase B (live CI API enumeration or live K8s cluster probing).
 */
export function getKindDisclosures(
  kind: SupportedKind | undefined,
  // Accept the raw Target.kind_config too: callers pass it straight through so
  // every conditional flag (dynamic_invocation, destructive_opt_in, query_probes,
  // audio_probes, …) is present. Hand-mapping a typed subset per call site is
  // what dropped the MCP tool-invocation disclosures and 400'd the scan.
  kindConfig?: KindConfigForDisclosures | Record<string, unknown> | null,
): { actions: DisclosedAction[]; ids: string[] } {
  const k = (kind ?? "url") as SupportedKind;
  const required =
    REQUIRED_ACTION_IDS_BY_KIND[k] ?? REQUIRED_ACTION_IDS_BY_KIND.url;
  const additional = ADDITIONAL_ACTIONS_BY_KIND[k] ?? [];
  const ids = new Set<string>([...required, ...additional]);
  // Phase B extensions per spec 10.6: cicd_pipeline live_api_enabled adds
  // ci_api_read; k8s_cluster live_cluster adds k8s_api_read (+ rbac_enumeration
  // if rbac_enum is on). The router auto-enforces these when kind_config implies
  // them; surfacing them in the modal keeps the consent honest.
  if (k === "cicd_pipeline" && kindConfig?.live_api_enabled) {
    ids.add("ci_api_read");
  }
  if (k === "k8s_cluster" && kindConfig?.target === "live_cluster") {
    ids.add("k8s_api_read");
    if (kindConfig?.rbac_enum !== false) {
      ids.add("rbac_enumeration");
    }
  }
  if ((k === "mcp" || k === "agent") && kindConfig?.dynamic_invocation) {
    ids.add("mcp_tool_invocation");
    if (kindConfig?.destructive_opt_in) {
      ids.add("mcp_destructive_tool_invocation");
    }
  }
  if (k === "rag" && kindConfig?.query_probes) {
    ids.add("rag_query_probe");
    if (kindConfig?.poison_injection_opt_in) {
      ids.add("rag_poison_injection");
    }
  }
  if (k === "voice" && kindConfig?.audio_probes) {
    ids.add("voice_audio_probe");
    if (kindConfig?.source_type === "voice_auth") {
      ids.add("voice_auth_probe");
    }
  }
  const orderedIds = [...ids];
  const actions = orderedIds
    .map((id) => ACTIONS[id])
    .filter((a): a is DisclosedAction => Boolean(a));
  return { actions, ids: orderedIds };
}
