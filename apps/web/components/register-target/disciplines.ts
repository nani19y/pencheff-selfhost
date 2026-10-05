// Security-program disciplines exposed in the "By Discipline" tab on Step 1
// of /targets/new. Each entry fans out to one or more target-type-card IDs
// from target-types.ts; selecting a discipline auto-checks those cards.
//
// Backend mirror: apps/api/pencheff_api/schemas/targets.py::DISCIPLINE_TO_KINDS
// — keep the two lists in sync. The kind-compatibility map there is the
// authority; the typeIds here are the FE shortcut that maps each discipline
// to the matching target-type-CARD ids (kebab-case slugs) rather than the
// wire kinds.

export type DisciplineId =
  | "cspm"
  | "ciem"
  | "dspm"
  | "serverless_security"
  | "edge_security"
  | "kspm"
  | "kiem"
  | "cwpp"
  | "aspm"
  | "api_security"
  | "ai_redteam"
  | "ai_spm"
  | "sbom_analysis";

export type DisciplineCategory =
  | "cloud" // CSPM, CIEM, DSPM, serverless, edge/CDN
  | "cnapp" // KSPM, KIEM, CWPP
  | "appsec" // ASPM, API Security
  | "ai" // AI Red Teaming, AI-SPM
  | "supply_chain"; // SBOM Analysis

export type Discipline = {
  id: DisciplineId;
  label: string; // short label rendered on the card
  longLabel: string; // hover/expanded label
  description: string; // 1-2 sentence hint
  // Target-type CARD ids from target-types.ts (kebab-case slugs).
  typeIds: string[];
  category: DisciplineCategory;
};

export const DISCIPLINES: Discipline[] = [
  // ── Cloud ───────────────────────────────────────────────────────────────
  {
    id: "cspm",
    label: "CSPM",
    longLabel: "Cloud Security Posture Management",
    description:
      "Audit AWS, Azure, or GCP account metadata for public exposure, encryption gaps, logging gaps, and risky defaults.",
    typeIds: [
      "cloud-account",
      "serverless",
      "cloud-storage",
      "load-balancer-cdn",
      "database-cloud",
      "secrets-manager",
    ],
    category: "cloud",
  },
  {
    id: "ciem",
    label: "CIEM",
    longLabel: "Cloud Infrastructure Entitlement Management",
    description:
      "Review cloud IAM principals, policies, service identities, and broad entitlements across account, serverless, storage, database, and secret targets.",
    typeIds: [
      "cloud-account",
      "serverless",
      "cloud-storage",
      "database-cloud",
      "secrets-manager",
    ],
    category: "cloud",
  },
  {
    id: "dspm",
    label: "DSPM",
    longLabel: "Data Security Posture Management",
    description:
      "Focus on cloud data stores: storage buckets, managed databases, and secret-manager metadata without reading secret values.",
    typeIds: ["cloud-storage", "database-cloud", "secrets-manager"],
    category: "cloud",
  },
  {
    id: "serverless_security",
    label: "Serverless Security",
    longLabel: "Serverless Security",
    description:
      "Check functions for public invocation, deprecated runtimes, secret-like environment metadata, and overbroad execution roles.",
    typeIds: ["serverless"],
    category: "cloud",
  },
  {
    id: "edge_security",
    label: "Edge Security",
    longLabel: "Load Balancer / CDN Security",
    description:
      "Assess edge endpoints for legacy TLS, missing WAF policies, exposed origins, and risky cache behavior.",
    typeIds: ["load-balancer-cdn"],
    category: "cloud",
  },

  // ── CNAPP ──────────────────────────────────────────────────────────────
  {
    id: "kspm",
    label: "KSPM",
    longLabel: "Kubernetes Security Posture Management",
    description:
      "Audit a Kubernetes cluster for misconfigurations, RBAC drift, and missing network policies.",
    typeIds: ["kubernetes"],
    category: "cnapp",
  },
  {
    id: "kiem",
    label: "KIEM",
    longLabel: "Kubernetes Identity & Entitlement Management",
    description:
      "Enumerate cluster RBAC and surface over-broad bindings (cluster-admin to default SA, wildcard verbs, escalation paths).",
    typeIds: ["kubernetes"],
    category: "cnapp",
  },
  {
    id: "cwpp",
    label: "CWPP",
    longLabel: "Cloud Workload Protection Platform",
    description:
      "Scan container images, Kubernetes workloads, and hosts together for vulns + misconfigurations.",
    typeIds: ["container-image", "kubernetes", "network-host", "serverless"],
    category: "cnapp",
  },

  // ── AppSec & API ───────────────────────────────────────────────────────
  {
    id: "aspm",
    label: "ASPM",
    longLabel: "Application Security Posture Management",
    description:
      "End-to-end app coverage: DAST against the running web app, REST API fuzzing, and SAST/SCA against the source repo.",
    typeIds: ["web-app", "rest-api", "source-code-repo"],
    category: "appsec",
  },
  {
    id: "api_security",
    label: "API Security",
    longLabel: "API Security",
    description:
      "REST + GraphQL endpoint testing: auth, BOLA/IDOR, injection, schema drift.",
    typeIds: ["rest-api", "graphql-api"],
    category: "appsec",
  },

  // ── AI ─────────────────────────────────────────────────────────────────
  {
    id: "ai_redteam",
    label: "AI Red Teaming",
    longLabel: "AI Red Teaming",
    description:
      "Aggressive jailbreak / crescendo / PAIR / TAP probes against an LLM endpoint, seeded with HarmBench prompts.",
    typeIds: ["llm-endpoint"],
    category: "ai",
  },
  {
    id: "ai_spm",
    label: "AI-SPM",
    longLabel: "AI Security Posture Management",
    description:
      "LLM guardrail audit: PII leakage, secret exfiltration, unsafe code generation, tool-use authorisation.",
    typeIds: ["llm-endpoint"],
    category: "ai",
  },

  // ── Supply chain ───────────────────────────────────────────────────────
  {
    id: "sbom_analysis",
    label: "SBOM Analysis",
    longLabel: "SBOM / Dependencies",
    description:
      "Ingest a CycloneDX or SPDX SBOM and flag known-vulnerable / license-risky / supplier-anomalous components.",
    typeIds: ["sbom-deps"],
    category: "supply_chain",
  },
];

export const DISCIPLINES_BY_ID: Record<DisciplineId, Discipline> =
  Object.fromEntries(DISCIPLINES.map((d) => [d.id, d])) as Record<
    DisciplineId,
    Discipline
  >;

export const DISCIPLINE_CATEGORY_LABEL: Record<DisciplineCategory, string> = {
  cloud: "Cloud Security",
  cnapp: "CNAPP — Cloud Native",
  appsec: "AppSec & API",
  ai: "AI Security",
  supply_chain: "Supply Chain",
};

// Reverse lookup: target-type-card id → disciplines that fan to it.
export const TYPE_ID_TO_DISCIPLINES: Record<string, DisciplineId[]> = (() => {
  const map: Record<string, DisciplineId[]> = {};
  for (const d of DISCIPLINES) {
    for (const tid of d.typeIds) {
      (map[tid] ||= []).push(d.id);
    }
  }
  return map;
})();

// Maps a target-type-card id (e.g. "kubernetes") to the wire kind
// (e.g. "k8s_cluster") so the FE can filter disciplines per outgoing
// POST /targets payload (each Target only carries the disciplines whose
// kind-allowlist matches its own kind). Mirrors target-types.ts::TYPES_BY_ID
// but only for the type-IDs that any discipline references — keeps this
// module self-contained.
export const DISCIPLINE_KIND_FOR_TYPE_ID: Record<string, string> = {
  "cloud-account": "cloud_account",
  serverless: "serverless_function",
  "cloud-storage": "cloud_storage",
  "load-balancer-cdn": "load_balancer_cdn",
  "database-cloud": "cloud_database",
  "secrets-manager": "secrets_manager",
  kubernetes: "k8s_cluster",
  "container-image": "container_image",
  "network-host": "host",
  "web-app": "web_app",
  "rest-api": "rest_api",
  "graphql-api": "graphql",
  "source-code-repo": "source_code",
  "llm-endpoint": "llm",
  "sbom-deps": "sbom",
};

// Server-side: each discipline's compatible wire kinds. Mirrors
// DISCIPLINE_TO_KINDS in apps/api/pencheff_api/schemas/targets.py — keep
// in sync.
export const DISCIPLINE_TO_KINDS: Record<
  DisciplineId,
  ReadonlyArray<string>
> = {
  cspm: [
    "cloud_account",
    "serverless_function",
    "cloud_storage",
    "load_balancer_cdn",
    "cloud_database",
    "secrets_manager",
  ],
  ciem: [
    "cloud_account",
    "serverless_function",
    "cloud_storage",
    "cloud_database",
    "secrets_manager",
  ],
  dspm: ["cloud_storage", "cloud_database", "secrets_manager"],
  serverless_security: ["serverless_function"],
  edge_security: ["load_balancer_cdn"],
  kspm: ["k8s_cluster"],
  kiem: ["k8s_cluster"],
  cwpp: ["container_image", "k8s_cluster", "host", "serverless_function"],
  aspm: ["web_app", "rest_api", "source_code"],
  api_security: ["rest_api", "graphql"],
  ai_redteam: ["llm", "agent"],
  ai_spm: ["llm", "agent"],
  sbom_analysis: ["sbom"],
};

export function disciplinesForKind(kind: string): DisciplineId[] {
  const out: DisciplineId[] = [];
  for (const [d, kinds] of Object.entries(DISCIPLINE_TO_KINDS) as [
    DisciplineId,
    ReadonlyArray<string>,
  ][]) {
    if (kinds.includes(kind)) out.push(d);
  }
  return out;
}
