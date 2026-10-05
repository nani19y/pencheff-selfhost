import type { Metadata } from "next";
import Link from "next/link";
import { notFound, permanentRedirect } from "next/navigation";
import { JsonLd } from "@/components/json-ld";
import { LandingNav } from "@/components/landing-nav";
import { MarketingDocBody } from "@/components/marketing-doc-body";
import {
  aliasTarget,
  getMarketingTopic,
  getMenuOverviewHref,
  getMenuSlug,
  getTopicsForMenu,
  isAliasTopic,
  NAV_MENUS,
  type MarketingTopic,
} from "@/lib/marketing-nav";
import {
  hasDocMapping,
  loadDocSections,
  type DocSection,
} from "@/lib/marketing-docs";
import { MARKETING_FAQS, type FaqItem } from "@/lib/marketing-faqs";
import {
  MARKETING_REFERENCES,
  type ExternalRef,
} from "@/lib/marketing-references";
import { createMetadata } from "@/lib/seo";
import {
  breadcrumbJsonLd,
  faqJsonLd,
  techArticleJsonLd,
  webPageJsonLd,
} from "@/lib/structured-data";

type DetailProfile = {
  badge: string;
  summary: string;
  capabilities: string[];
  workflow: string[];
  evidence: string[];
  controls: string[];
  docs: string[];
};

const DEFAULT_PROFILE: DetailProfile = {
  badge: "Platform detail",
  summary:
    "This capability is part of the Pencheff operating model: define scope, run deterministic and agentic checks, normalize the evidence, prioritize the risk, and produce an actionable deliverable.",
  capabilities: [
    "Workspace-aware target registration, scan ownership, and reusable scope settings.",
    "Unified finding records across runtime, source, dependency, infrastructure, AI, and manual evidence.",
    "Severity, reachability, exploitability, confidence, affected asset, and remediation metadata.",
    "Dashboards for status, risk, open work, rechecks, and audit-ready reporting.",
    "Exports for executive readers, engineers, compliance teams, and downstream systems.",
  ],
  workflow: [
    "Register the target or choose an existing workspace asset.",
    "Select a profile that controls depth, safety, time budget, and evidence requirements.",
    "Run deterministic checks first, then enrich high-signal leads with agentic analysis where useful.",
    "Deduplicate findings, preserve raw evidence, and attach remediation guidance.",
    "Route the output into dashboards, reports, integrations, schedules, and retest loops.",
  ],
  evidence: [
    "Finding title, severity, affected component, CWE or category, confidence, and status.",
    "Reproduction notes, scanner provenance, request or trace evidence where applicable.",
    "Remediation guidance written for the observed behavior rather than a generic checklist.",
    "Compliance mappings, owner state, comments, and re-examination history.",
  ],
  controls: [
    "Authorized testing boundaries remain explicit at target creation.",
    "Credentials and secrets are handled as scoped assessment inputs.",
    "Operator-facing output separates confirmed issues from informational context.",
    "Every item is designed to be traceable from summary to source evidence.",
  ],
  docs: [
    "apps/docs/pages/reference/overview.mdx",
    "apps/docs/pages/reference/findings.mdx",
    "apps/docs/pages/features/findings-stream.mdx",
  ],
};

const PROFILES: Record<string, DetailProfile> = {
  client: {
    badge: "Mobile & client security",
    summary:
      "Pencheff statically analyzes uploaded client artifacts — Android APK/AAB, iOS IPA, browser extensions (CRX/XPI), and desktop bundles (Electron, Java, .NET, Qt). Each artifact is unpacked and inspected as data, never installed or executed, with findings mapped to OWASP MASVS, CWE, and CVSS.",
    capabilities: [
      "Android APK/AAB: AndroidManifest, exported components, debuggable/allowBackup flags, hardcoded secrets, weak crypto, and cleartext traffic — mapped to OWASP MASVS.",
      "iOS IPA: Info.plist / App Transport Security, custom URL schemes, Mach-O protections, embedded secrets, and third-party SDK CVEs — with FairPlay encryption limits surfaced.",
      "Browser extensions: permission and CSP scoring, broad host access, remote-code loading, DOM injection sinks, broad externally_connectable, and hardcoded secrets.",
      "Desktop apps: insecure Electron webPreferences, dangerous calls (eval, child_process, shell.openExternal), outdated Electron versions, and embedded secrets.",
      "Integrity-checked ingestion (SHA-256) and isolated, no-execute analysis so untrusted binaries are safe to scan.",
    ],
    workflow: [
      "Register a Mobile & Client target with a direct artifact URL and its SHA-256 digest.",
      "Pencheff downloads and SHA-256-verifies the artifact, then unpacks it (APK/IPA/CRX/asar/archive) inside an isolated container.",
      "Run the kind-specific static analyzer — the artifact is never installed or executed.",
      "Normalize results into the unified findings stream with severity, CWE, CVSS, and OWASP/MASVS mappings.",
      "Route output into dashboards, reports, integrations, and retest loops alongside web, API, and cloud findings.",
    ],
    evidence: [
      "Finding title, severity, category (mobile/extension/desktop), CWE, and CVSS.",
      "Static evidence — the file, manifest key, or code location that triggered the rule.",
      "OWASP MASVS and Mobile Top 10 mappings for mobile; Electron Security Checklist alignment for desktop.",
      "Remediation written for the observed misconfiguration or exposure, not a generic checklist.",
    ],
    controls: [
      "Artifacts are fetched only from the operator-registered URL and SHA-256-verified before analysis.",
      "Analysis is fully static — no device, emulator, or execution — so untrusted binaries carry no detonation risk.",
      "Archive unpacking is guarded against zip-slip path traversal and zip-bomb inputs.",
      "Artifacts are scoped to the scan and not retained beyond it.",
    ],
    docs: [
      "apps/docs/pages/features/mobile-security.mdx",
      "apps/docs/pages/features/browser-extension.mdx",
      "apps/docs/pages/features/desktop-app.mdx",
      "apps/docs/pages/tutorials/android-apk-scanning.mdx",
    ],
  },
  dast: {
    badge: "Runtime DAST",
    summary:
      "Live application testing combines reconnaissance, crawling, authenticated coverage, active probes, OAST callbacks, and proof-oriented verification so web and API issues are not just listed, but demonstrated.",
    capabilities: [
      "Passive and active reconnaissance, technology fingerprinting, endpoint inventory, and crawl expansion.",
      "Authenticated crawling for SPAs, role-aware flows, cookies, headers, JWTs, OAuth/OIDC, and MFA-sensitive areas.",
      "Injection coverage for SQL, NoSQL, command, SSTI, XXE, SSRF, LDAP, deserialization, path traversal, and file upload abuse.",
      "Client-side and protocol checks for XSS, DOM XSS, CSRF, CORS, clickjacking, cache poisoning, redirects, headers, WebSockets, and GraphQL.",
      "Verification probes that promote high-confidence results into replayable findings with request and response context.",
    ],
    workflow: [
      "Create a URL or API target with scope, auth material, allowed hosts, and rate limits.",
      "Map the surface with recon, crawl, endpoint discovery, and optional OpenAPI or traffic-derived routes.",
      "Run profile-controlled checks from quick validation through deep exploit-chain analysis.",
      "Re-test candidate issues with focused probes before they become confirmed findings.",
      "Attach evidence, severity, remediation, and compliance mappings to the unified findings stream.",
    ],
    evidence: [
      "HTTP request and response excerpts, affected URL, parameter, method, status code, and payload family.",
      "OAST callbacks, browser screenshots, chain notes, and exact reproduction steps where applicable.",
      "Authentication context, role assumptions, session notes, and guardrails used during assessment.",
      "OWASP, CWE, PCI DSS, SOC 2, ISO 27001, NIST, and HIPAA mappings for audit readers.",
    ],
    controls: [
      "Scope allow-lists, profile depth, time budgets, and evidence requirements bound active testing.",
      "State-changing and destructive behavior can be constrained by target policy and profile selection.",
      "Findings are deduplicated against existing scan history and can be re-examined on demand.",
      "Authenticated material is scoped to the target and treated as assessment-only input.",
    ],
    docs: [
      "apps/docs/pages/features/dast.mdx",
      "apps/docs/pages/quickstart/url-scan.mdx",
      "apps/docs/pages/features/api-discovery.mdx",
      "apps/docs/pages/features/authentication.mdx",
      "apps/docs/pages/features/proxy.mdx",
      "apps/docs/pages/features/fuzzer.mdx",
    ],
  },
  code: {
    badge: "Code security",
    summary:
      "Repository scanning gives source findings the same operational treatment as runtime findings: scanner provenance, line-level evidence, remediation guidance, SARIF, GitHub annotations, and fix state.",
    capabilities: [
      "Semgrep OSS packs, Bandit, gosec, Brakeman, ESLint security, tree-sitter rules, and niche-language scaffolds.",
      "Secret detection with gitleaks and suspicious-code indicators with YARA-style patterns.",
      "GitHub repository connection, webhook-triggered scans, hardlink staging, gitignore-aware filtering, and default-deny controls.",
      "SARIF and GitHub check run output so developers see findings where they work.",
      "Auto-fix preparation for Semgrep autofix, SCA version bumps, and reviewer-friendly patch synthesis.",
    ],
    workflow: [
      "Connect or register a repository and choose a branch, scan profile, and scanner policy.",
      "Stage the source safely, fan out language-specific scanners, and capture raw scanner output.",
      "Normalize results into repo findings with file, line, rule, severity, scanner, and remediation metadata.",
      "Merge code results with SCA, IaC, secrets, and runtime context to reduce duplicate triage.",
      "Send annotations, SARIF, reports, fix PRs, or dashboard tasks depending on the workflow.",
    ],
    evidence: [
      "File path, line number, rule id, scanner name, confidence, language, and vulnerable snippet context.",
      "Suggested fix, fixed-version data when applicable, and status across suppressions or rechecks.",
      "GitHub check output, SARIF upload, comments, and links back into the finding record.",
      "Cross-finding signals when a code pattern aligns with runtime exploitation.",
    ],
    controls: [
      "Scanner choices are explicit and permissively licensed where used in the repo pipeline.",
      "Secrets are handled as findings rather than echoed into broad UI surfaces.",
      "CI gates can be tuned by severity, reachability, policy, and target branch.",
      "Generated fixes remain reviewer-owned and trace back to original scanner evidence.",
    ],
    docs: [
      "apps/docs/pages/repos/connect.mdx",
      "apps/docs/pages/repos/scanners.mdx",
      "apps/docs/pages/quickstart/repo-scan.mdx",
      "apps/docs/pages/features/auto-fix.mdx",
      "apps/docs/pages/features/github-check-runs.mdx",
    ],
  },
  sca: {
    badge: "Supply chain",
    summary:
      "SCA and SBOM workflows connect vulnerable components, manifests, package URLs, fixed versions, reachability, EPSS, KEV, SSVC, and license evidence to the same findings and reports as application testing.",
    capabilities: [
      "OSV.dev, NVD 2.0, GitHub Advisory Database, RustSec, GoVulnDB, EPSS, CISA KEV, and SSVC enrichment.",
      "Manifest support for npm, PyPI, Go modules, Cargo, Ruby, Composer, Maven, OS packages, and container packages.",
      "SPDX 2.3 and CycloneDX 1.5 SBOM generation with optional Syft enrichment.",
      "Reachability annotation that separates exploited, reachable, present, and unknown risk.",
      "License policy checks and deterministic version-bump remediation for eligible dependencies.",
    ],
    workflow: [
      "Parse repository manifests, lockfiles, or container package inventories.",
      "Resolve packages to advisories, fixed versions, package URLs, and known exploitation signals.",
      "Annotate reachability from imports, call paths, runtime evidence, or scanner context.",
      "Generate SBOM output and link component rows back to findings.",
      "Prioritize remediation by exploitability, reachability, business criticality, and compliance impact.",
    ],
    evidence: [
      "Package name, ecosystem, installed version, fixed version, advisory id, CVSS, EPSS, KEV, and SSVC.",
      "SBOM component records with PURL, supplier, version, license, and dependency relationships.",
      "Reachability state, import evidence, or reason the vulnerable component is currently only present.",
      "Audit appendix output for procurement, compliance, and release records.",
    ],
    controls: [
      "Dependency risk is not sorted by CVSS alone; operational signals influence priority.",
      "SBOM generation is repeatable and latest-generation output replaces stale records.",
      "License and vulnerability policy can be used as release-gate input.",
      "Version-bump fixes are deterministic when advisory metadata supports them.",
    ],
    docs: [
      "apps/docs/pages/features/sca.mdx",
      "apps/docs/pages/features/sbom.mdx",
      "apps/docs/pages/quickstart/sbom.mdx",
      "apps/docs/pages/features/epss-kev.mdx",
      "apps/docs/pages/features/reachability.mdx",
    ],
  },
  infra: {
    badge: "Infrastructure and assets",
    summary:
      "Infrastructure coverage links AWS, Azure, and GCP cloud posture, IaC, containers, registries, Kubernetes admission, network services, Active Directory, mobile static analysis, and attack-surface discovery into a single risk view.",
    capabilities: [
      "Cloud Account, Serverless Functions, Cloud Storage, Load Balancer / CDN, Database, and Secrets Manager targets with provider-specific authorization.",
      "Read-only CSPM, CIEM, DSPM, serverless, edge, database, storage, audit-logging, and secrets-metadata checks.",
      "Terraform, Kubernetes YAML, Helm, Dockerfiles, CloudFormation, Trivy config, Checkov, tfsec, Kubesec, and Hadolint-style checks.",
      "Container image vulnerability and misconfiguration scanning with registry and admission-control workflows.",
      "Attack surface management for subdomains, exposed hosts, cloud edges, certificates, services, and drift.",
      "Network VA for host CVEs, service misconfiguration, TLS, headers, and authenticated host checks.",
      "Active Directory, internal network, Android/iOS static analysis, exported component checks, and mobile secret sweeps.",
    ],
    workflow: [
      "Register assets directly or discover them through ASM, repository manifests, or infrastructure files.",
      "Run IaC and container checks before deployment, then pair results with runtime surface discovery.",
      "Use network and internal checks to identify exposed services, certificate issues, AD paths, or host CVEs.",
      "Normalize infra findings with source, asset, environment, severity, remediation, and compliance mappings.",
      "Gate releases, schedule recurring checks, or produce audit bundles for platform and cloud teams.",
    ],
    evidence: [
      "Affected resource, manifest path, image reference, package, host, service, port, certificate, or mobile artifact.",
      "Rule id, scanner provenance, misconfiguration description, exploitability notes, and remediation.",
      "Cloud, Kubernetes, container, or network context needed by platform owners.",
      "Compliance mapping for configuration management, technical vulnerability, and supplier controls.",
    ],
    controls: [
      "Registry and admission policies can prevent risky images or manifests from progressing.",
      "ASM and network checks are scoped to authorized assets and known workspace boundaries.",
      "Infrastructure findings can be tied back to repos and deployment pipelines for ownership.",
      "Mobile and internal findings remain in the same evidence and reporting workflow as web findings.",
    ],
    docs: [
      "apps/docs/pages/features/cloud-security.mdx",
      "apps/docs/pages/tutorials/cloud-targets.mdx",
      "apps/docs/pages/features/iac.mdx",
      "apps/docs/pages/features/container.mdx",
      "apps/docs/pages/features/admission-webhook.mdx",
      "apps/docs/pages/features/asm.mdx",
      "apps/docs/pages/features/network-va.mdx",
      "apps/docs/pages/features/active-directory.mdx",
      "apps/docs/pages/features/mobile-security.mdx",
    ],
  },
  ai: {
    badge: "AI security",
    summary:
      "AI security coverage tests LLM endpoints, chatbots, RAG workflows, tool-calling agents, memory, connectors, runtime guardrails, and policy controls against realistic adversarial prompts and workflows.",
    capabilities: [
      "OWASP LLM Top 10 coverage for prompt injection, sensitive information disclosure, supply chain, data leakage, plugins, agency, overreliance, and model theft.",
      "Jailbreak strategies, roleplay, encoding, payload splitting, multilingual variants, custom datasets, and judge-backed scoring.",
      "Agentic tests for tool authorization, memory poisoning, context exfiltration, planner hijacking, and unsafe side effects.",
      "Sentry runtime guardrails, HTTP sidecars, LiteLLM plugins, MCP middleware, PII, secrets, unsafe HTML, and tool authorization checks.",
      "AI governance mapping to OWASP LLM, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001, GDPR, and SOC 2.",
    ],
    workflow: [
      "Register an LLM endpoint, chatbot, model gateway, MCP host, or agent workflow.",
      "Choose built-in categories, datasets, guardrails, custom prompts, and optional judge settings.",
      "Run adversarial campaigns across prompt, tool, memory, retrieval, output, and policy paths.",
      "Classify failures by category, strategy, severity, transcript, token cost, and guardrail recommendation.",
      "Turn passing and failing prompts into regression suites for releases and model upgrades.",
    ],
    evidence: [
      "Prompt, response, tool call, policy decision, transcript, category, strategy, judge result, and confidence.",
      "Recommended guardrails with exact unsafe behavior, enforcement point, and regression prompt.",
      "Token usage, model/provider metadata, retry behavior, and cost-oriented observability.",
      "Governance mappings for AI risk, safety, privacy, and compliance programs.",
    ],
    controls: [
      "Tests can be run through HTTP, chat-completions, LiteLLM, MCP, or custom adapters.",
      "Guardrail recommendations stay tied to the scan that exposed the failure.",
      "Agentic testing focuses on authorization, context boundaries, and side-effect control.",
      "Runtime policy checks can be placed before prompts, after responses, or around tools.",
    ],
    docs: [
      "apps/docs/pages/features/llm-redteam.mdx",
      "apps/docs/pages/quickstart/llm-redteam.mdx",
      "apps/docs/pages/features/sentry.mdx",
      "apps/docs/pages/features/swarm.mdx",
      "apps/docs/pages/features/compliance-mapping.mdx",
    ],
  },
  reporting: {
    badge: "Risk, reporting, and compliance",
    summary:
      "Reporting turns raw scanner output into evidence-backed decisions: executive posture, technical dossiers, compliance mappings, retest history, threat models, and clear remediation ownership.",
    capabilities: [
      "Executive dashboard, letter grade, risk trends, severity rollups, and portfolio posture.",
      "Technical dossier with findings, reproduction, affected components, remediation, evidence, and re-examination state.",
      "Compliance mapping for OWASP, PCI DSS, SOC 2, NIST, ISO 27001, HIPAA, OWASP LLM, MITRE ATLAS, NIST AI RMF, EU AI Act, and GDPR.",
      "Threat modeling with STRIDE, DREAD, attack trees, abuse cases, mitigations, and scan context.",
      "Unified findings stream, AI triage, advisory enrichment, comments, suppressions, and audit appendices.",
    ],
    workflow: [
      "Collect findings from runtime, repo, supply chain, infrastructure, AI, and manual sources.",
      "Normalize severity, confidence, category, exploitability, reachability, and owner state.",
      "Generate executive, engineering, compliance, or retest views from the same source record.",
      "Track suppression, comments, fixes, re-examinations, and residual risk across scan history.",
      "Export reports and feed integrations without losing the underlying evidence chain.",
    ],
    evidence: [
      "Executive summaries, trend charts, severity counts, grade drivers, and business impact language.",
      "Technical evidence, scanner provenance, reproduction steps, remediation, and references.",
      "Framework control mappings and audit appendix entries tied to actual findings.",
      "Retest and verification history for closure and residual risk decisions.",
    ],
    controls: [
      "Compliance rollups are deterministic and recomputed from finding state.",
      "Triage output distinguishes verified facts from advisory context.",
      "Reports inherit the same authorization and workspace boundaries as scans.",
      "Executives and auditors can read summaries while engineers keep deep evidence.",
    ],
    docs: [
      "apps/docs/pages/features/compliance-mapping.mdx",
      "apps/docs/pages/features/threat-model.mdx",
      "apps/docs/pages/features/executive-dashboard.mdx",
      "apps/docs/pages/features/dashboards.mdx",
      "apps/docs/pages/reference/unified-findings.mdx",
    ],
  },
  integrations: {
    badge: "Integrations and operations",
    summary:
      "Operational pages connect Pencheff to the rest of the security program: notifications, ticketing, SIEM, schedules, observability, API access, support, onboarding, and deployment operations.",
    capabilities: [
      "Slack, Teams, Google Chat, Discord, PagerDuty, Opsgenie, Splunk HEC, signed webhooks, GitHub Issues, and Jira.",
      "Schedules for recurring scans, release gates, retests, continuous monitoring, and drift checks.",
      "OpenTelemetry spans, logs, metrics, trace waterfalls, audit hash chain, SLO, and cost dashboards.",
      "API keys, REST references, MCP tool access, webhooks, and CI/CD automation.",
      "Workspace onboarding, support, trust, pricing, self-hosting, partnerships, and enterprise deployment workflows.",
    ],
    workflow: [
      "Connect a target, workspace, integration endpoint, or automation credential.",
      "Choose event routing by target, severity, status, schedule, or release workflow.",
      "Deliver findings to chat, ticketing, paging, SIEM, GitHub, webhooks, or dashboards.",
      "Use traces, audit logs, SLOs, and cost views to operate scans with confidence.",
      "Review support, pricing, or deployment requirements when scaling the program.",
    ],
    evidence: [
      "Integration delivery status, target mapping, event payload, severity filters, and test results.",
      "Trace spans for HTTP requests, subprocesses, LLM calls, scan phases, and errors.",
      "Audit log records with actor, action, IP, user agent, and hash-chain verification.",
      "API and MCP references for automation, CI/CD, and internal platform workflows.",
    ],
    controls: [
      "Credentials are stored as integration configuration and used only for the selected destination.",
      "Signed webhooks and target-specific routing reduce noisy or unauthenticated delivery.",
      "Observability is opt-in and can be disabled globally by environment policy.",
      "Support and pricing pages route users to the right commercial or operational next step.",
    ],
    docs: [
      "apps/docs/pages/integrations/overview.mdx",
      "apps/docs/pages/reference/integrations.mdx",
      "apps/docs/pages/features/observability.mdx",
      "apps/docs/pages/reference/api-keys.mdx",
      "apps/docs/pages/ci-cd/generic.mdx",
    ],
  },
  "security-lake": {
    badge: "Audit & data",
    summary:
      "Findings normalized to OCSF 1.3.0 and written to an Apache Iceberg table on Cloudflare R2. Query, trend, and correlate across scan history, or export NDJSON/Parquet and pull into your own SIEM or data lake.",
    capabilities: [
      "OCSF 1.3.0 schema: Vulnerability Finding, Compliance Finding, and Detection Finding classes.",
      "Apache Iceberg table on Cloudflare R2, org-scoped across all scans.",
      "Strict schema validation before write — invalid records quarantined, not silently dropped.",
      "Append-only event log with latest-state-per-finding dedup on read.",
      "Export as NDJSON or Parquet for downstream SIEM and data-lake ingestion.",
    ],
    workflow: [
      "Enable Security Lake in Settings (disabled by default).",
      "Pencheff ingests and validates findings against OCSF on every completed scan.",
      "Query via the API or export NDJSON/Parquet for external tooling.",
      "Disable at any time; lake data is retained for a 7-day grace window then purged.",
    ],
    evidence: [
      "OCSF class_uid, severity_id, time_dt, finding uid, and affected asset per record.",
      "Trend counts bucketed by day, week, or month for posture charting.",
      "Correlation results grouped by asset, CWE, rule id, or OCSF category.",
      "Quarantine log for records that fail OCSF validation.",
    ],
    controls: [
      "Disabled by default; opt-in per org in Settings.",
      "All endpoints return 403 when the lake is disabled.",
      "Disabling stops ingestion and purges data after the 7-day grace window.",
      "Data is org-scoped; no cross-org access.",
    ],
    docs: [
      "apps/docs/pages/features/security-lake.mdx",
      "apps/docs/pages/features/compliance-mapping.mdx",
      "apps/docs/pages/features/findings-stream.mdx",
    ],
  },
  "custom-llm-providers": {
    badge: "AI operations",
    summary:
      "Register your own OpenAI, Anthropic, Google Gemini, Azure OpenAI, or OpenAI-compatible endpoint. The active provider powers all of Pencheff's AI features, bypasses Pencheff's AI quotas, and is fail-closed — no silent fallback to Pencheff's key.",
    capabilities: [
      "Supported kinds: OpenAI, Anthropic, Google Gemini, Azure OpenAI, and any OpenAI-compatible endpoint.",
      "One active provider per org; powers triage, grading, AI-Triage-2.0, fix proposals, the agentic fixer, and the scan agent.",
      "API key encrypted at rest (Fernet), never returned by the API — only a key-set flag and last-4 hint.",
      "Test action runs a live credential check before activation.",
      "Fail-closed: provider errors surface as feature-unavailable, never fall back to Pencheff's key.",
    ],
    workflow: [
      "Org owner or admin opens Settings → AI → LLM Providers and creates a provider record.",
      "Run the Test action to verify credentials before activating.",
      "Activate the provider; all AI features switch to it immediately.",
      "To revert, deactivate or select Use Pencheff defaults.",
    ],
    evidence: [
      "Provider kind, name, model, key-set flag, last-4 key hint, and activation state.",
      "Test result: ok or error message from the live credential check.",
      "Per-request AI usage still recorded in fix_llm_usage when BYO provider is active.",
    ],
    controls: [
      "Create/edit/delete restricted to org owners and admins.",
      "Exactly one active provider at a time; DELETE returns 409 on the active record.",
      "Tool-calling agents (scan agent, agentic fixer) honor BYO only for OpenAI-compatible providers.",
      "Deactivate reverts to Pencheff defaults without deleting the provider record.",
    ],
    docs: [
      "apps/docs/pages/features/custom-llm-providers.mdx",
      "apps/docs/pages/features/auto-fix.mdx",
      "apps/docs/pages/features/ai-triage.mdx",
    ],
  },
};

function chooseProfile(topic: MarketingTopic): DetailProfile {
  const text =
    `${topic.menu.label} ${topic.item.title} ${topic.item.body}`.toLowerCase();
  if (
    /apk|aab|ipa|android app|ios app|browser extension|crx|xpi|electron|desktop app|masvs|mobile app|firmware|iot device|ics|scada|plc|embedded/.test(
      text,
    )
  ) {
    return PROFILES.client;
  }
  if (
    /llm|agent|prompt|guardrail|sentry|jailbreak|model|tool authorization|memory|planner|swarm|governance/.test(
      text,
    )
  ) {
    return PROFILES.ai;
  }
  if (
    /sca|sbom|dependency|package|advisory|epss|kev|ssvc|license|reachability|supply/.test(
      text,
    )
  ) {
    return PROFILES.sca;
  }
  if (
    /sast|repo|source|secret|language|semgrep|bandit|gosec|brakeman|eslint|auto-fix|github|sarif/.test(
      text,
    )
  ) {
    return PROFILES.code;
  }
  if (
    /dast|url|web |api|injection|client-side|authentication|proxy|fuzzer|oauth|jwt|graphql|websocket|spa/.test(
      text,
    )
  ) {
    return PROFILES.dast;
  }
  if (
    /iac|container|cloud|kubernetes|terraform|helm|docker|asm|asset|network|active directory|mobile|self-host|deployment/.test(
      text,
    )
  ) {
    return PROFILES.infra;
  }
  if (
    /report|compliance|audit|threat|letter grade|executive|finding|triage|dashboard|dossier|framework/.test(
      text,
    )
  ) {
    return PROFILES.reporting;
  }
  if (
    /integration|slack|teams|discord|pagerduty|opsgenie|splunk|webhook|jira|schedule|observability|api key|support|pricing|onboarding|company|partner|trust/.test(
      text,
    )
  ) {
    return PROFILES.integrations;
  }
  return DEFAULT_PROFILE;
}

function mergeDetails(topic: MarketingTopic, profile: DetailProfile) {
  const itemSpecific = topic.isOverview
    ? [
        topic.menu.title,
        topic.menu.body,
        `Dropdown section: ${topic.menu.eyebrow}.`,
      ]
    : [
        topic.item.body,
        `This page is part of ${topic.menu.label} under ${topic.groupTitle}.`,
        `It links back into the broader ${topic.menu.title.toLowerCase()} experience.`,
      ];

  return {
    capabilities: [...itemSpecific, ...profile.capabilities],
    workflow: profile.workflow,
    evidence: profile.evidence,
    controls: profile.controls,
    docs: profile.docs,
  };
}

// ── Visual kind ────────────────────────────────────────────────────────────
// A finer-grained classification than the content profile, used only to pick
// the hero "proof artifact". It is derived from the same topic/profile signals
// (no new content) and is total — every topic resolves to exactly one kind.
type VisualKind =
  | "dast"
  | "code"
  | "ai"
  | "infra"
  | "method"
  | "reporting"
  | "overview"
  | "resource";

function resolveVisualKind(
  topic: MarketingTopic,
  profile: DetailProfile,
): VisualKind {
  const menu = getMenuSlug(topic.menu.label);
  const isResourceMenu =
    menu === "resources" || menu === "support" || menu === "company";

  // Overview pages split by menu: product menus get the surface router,
  // docs/company menus get the task router.
  if (topic.isOverview) return isResourceMenu ? "resource" : "overview";

  const text =
    `${topic.menu.label} ${topic.groupTitle} ${topic.item.title} ${topic.item.body}`.toLowerCase();

  // Specific content kinds resolve before the broad `reporting` catch, so a
  // page that merely mentions "reporting agents" or "export reports" still maps
  // to its real family (matches the spec's suggested kinds: e.g. agent swarms /
  // the engine → ai).
  if (/methodology|adversarial cycle|engagement profile/.test(text))
    return "method";
  if (
    /llm|prompt|jailbreak|guardrail|sentry|agent|swarm|engine|\bmodel\b|governance|judge|token/.test(
      text,
    )
  )
    return "ai";
  if (
    /dast|web dast|authenticated|\bapi\b|\bspa\b|proxy|fuzzer|injection|client-side|xss|oauth|crawl/.test(
      text,
    )
  )
    return "dast";
  if (
    /sast|secret|repo|source code|semgrep|gitleaks|auto-fix|re-examination|\bsca\b|sbom|dependency|package|language scanner/.test(
      text,
    )
  )
    return "code";
  if (
    /cloud|infrastructure|\biac\b|container|kubernetes|\basm\b|asset|network|registry|terraform|active directory|mobile/.test(
      text,
    )
  )
    return "infra";
  if (
    /report|letter grade|dossier|compliance|threat model|export|audit|executive|dashboard/.test(
      text,
    )
  )
    return "reporting";

  if (isResourceMenu) return "resource";

  // Fall back through the resolved content profile so the artifact still fits.
  switch (profile.badge) {
    case PROFILES.ai.badge:
      return "ai";
    case PROFILES.code.badge:
    case PROFILES.sca.badge:
      return "code";
    case PROFILES.infra.badge:
      return "infra";
    case PROFILES.dast.badge:
      return "dast";
    case PROFILES.reporting.badge:
      return "reporting";
    case PROFILES.integrations.badge:
      return "resource";
    default:
      return "overview";
  }
}

// Per-kind hero-artifact configuration. Labels are real domain terms; any
// number rendered is derived from the actual content arrays on the page, so
// the artifact never prints invented telemetry.
type ArtifactKind = "matrix" | "heat" | "phases" | "grade";

const ARTIFACT_CONFIG: Record<
  VisualKind,
  {
    head: string;
    status: string;
    shape: ArtifactKind;
    chips: string[];
    note: string;
  }
> = {
  dast: {
    head: "Attack coverage",
    status: "verified",
    shape: "matrix",
    chips: ["Recon", "Crawl", "Active probe", "OAST", "Verify"],
    note: "Bars track the four sections on this page, scaled to the coverage retained from the nav source.",
  },
  code: {
    head: "Scanner pipeline",
    status: "SARIF-ready",
    shape: "matrix",
    chips: ["Semgrep", "gitleaks", "SARIF", "Fix PR", "SBOM"],
    note: "Source findings carry scanner provenance, line evidence, and fix state through the same pipeline.",
  },
  ai: {
    head: "OWASP LLM Top 10",
    status: "judged",
    shape: "heat",
    chips: ["Transcript", "Judge", "Tokens", "Guardrail"],
    note: "Coverage maps to the OWASP LLM Top 10 categories tested below, with judge-backed verdicts.",
  },
  infra: {
    head: "Asset & policy map",
    status: "monitored",
    shape: "matrix",
    chips: ["Cloud", "IaC", "Container", "ASM", "Network"],
    note: "Posture, drift, and policy gates resolve into the same finding schema as application testing.",
  },
  method: {
    head: "The adversarial cycle",
    status: "deterministic",
    shape: "phases",
    chips: ["Profile", "Scope", "Consent", "Budget"],
    note: "Every engagement follows the same five phases before a finding is promoted to evidence.",
  },
  reporting: {
    head: "Deliverable preview",
    status: "audit-ready",
    shape: "grade",
    chips: ["DOCX", "PDF", "SARIF", "SPDX", "CycloneDX"],
    note: "Letter grade, compliance mappings, and exports recompute deterministically from finding state.",
  },
  overview: {
    head: "Surface router",
    status: "unified",
    shape: "matrix",
    chips: ["URL", "Repo", "API", "AI", "Cloud"],
    note: "One queue routes every target kind into a single normalized findings and evidence model.",
  },
  resource: {
    head: "Task router",
    status: "documented",
    shape: "matrix",
    chips: ["Docs", "API", "Reports", "Support"],
    note: "Operational paths point to setup, references, and the right next task for the workflow.",
  },
};

// OWASP LLM Top 10 (2025) short labels — real category names, used by the AI
// heatmap artifact. Heat intensity is a fixed deterministic pattern (no random).
const OWASP_LLM = [
  "Prompt injection",
  "Sensitive disclosure",
  "Supply chain",
  "Data poisoning",
  "Output handling",
  "Excessive agency",
  "System prompt leak",
  "Vector weakness",
  "Misinformation",
  "Unbounded use",
];

const METHOD_PHASES = ["Recon", "Exploit", "Evidence", "Normalize", "Deliver"];

function clampPct(n: number, max: number) {
  if (max <= 0) return 0;
  // 38–96% band so even the smallest bucket reads as a meaningful bar.
  return Math.round(38 + (n / max) * 58);
}

function FeatureArtifact({
  kind,
  counts,
}: {
  kind: VisualKind;
  counts: {
    coverage: number;
    execution: number;
    evidence: number;
    controls: number;
  };
}) {
  const cfg = ARTIFACT_CONFIG[kind];
  const rows = [
    { label: "Coverage", value: counts.coverage },
    { label: "Execution", value: counts.execution },
    { label: "Evidence", value: counts.evidence },
    { label: "Controls", value: counts.controls },
  ];
  const max = Math.max(...rows.map((r) => r.value), 1);

  return (
    <div className="lp-feature-art slot" id="proof">
      <div className="lp-feature-art-head">
        <span>{cfg.head}</span>
        <em>{cfg.status}</em>
      </div>

      <div className="lp-feature-art-metrics">
        <div className="lp-feature-metric">
          <strong>{counts.coverage}</strong>
          <span>coverage areas</span>
        </div>
        <div className="lp-feature-metric">
          <strong>{counts.execution}</strong>
          <span>operator steps</span>
        </div>
        <div className="lp-feature-metric">
          <strong>{counts.evidence}</strong>
          <span>evidence fields</span>
        </div>
      </div>

      {cfg.shape === "matrix" && (
        <div className="lp-feature-matrix">
          {rows.map((r) => (
            <div className="lp-feature-matrix-row" key={r.label}>
              <span>{r.label}</span>
              <span className="lp-feature-bar">
                <i style={{ width: `${clampPct(r.value, max)}%` }} />
              </span>
              <span className="lp-feature-bar-val">{r.value}</span>
            </div>
          ))}
        </div>
      )}

      {cfg.shape === "heat" && (
        <div className="lp-feature-heat" aria-hidden="true">
          {OWASP_LLM.map((label, i) => (
            <div
              className="lp-feature-heat-cell"
              data-heat={["lo", "mid", "hi"][(i * 2 + 1) % 3]}
              key={label}
            >
              <b>{String(i + 1).padStart(2, "0")}</b>
              <span>{label}</span>
            </div>
          ))}
        </div>
      )}

      {cfg.shape === "phases" && (
        <ol className="lp-feature-phases">
          {METHOD_PHASES.map((p, i) => (
            <li key={p}>
              <span>{String(i + 1).padStart(2, "0")}</span>
              {p}
            </li>
          ))}
        </ol>
      )}

      {cfg.shape === "grade" && (
        <div className="lp-feature-grade">
          <div className="lp-feature-grade-mark">
            <strong>A–F</strong>
            <span>Letter grade</span>
          </div>
          <div className="lp-feature-matrix lp-feature-grade-bars">
            {rows.map((r) => (
              <div className="lp-feature-matrix-row" key={r.label}>
                <span>{r.label}</span>
                <span className="lp-feature-bar">
                  <i style={{ width: `${clampPct(r.value, max)}%` }} />
                </span>
                <span className="lp-feature-bar-val">{r.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="lp-feature-chips">
        {cfg.chips.map((c) => (
          <span key={c}>{c}</span>
        ))}
      </div>

      <p className="lp-feature-note">{cfg.note}</p>
    </div>
  );
}

// The navigable destination for a topic. Alias topics auto-build a
// `/<menu>/<slug>` href that is intentionally excluded from
// generateStaticParams (see getMarketingStaticParams) — under `output:export`
// there is no runtime fallback, so linking the auto-built href 404s. Always
// link the resolved canonical destination instead.
function resolveTopicHref(topic: MarketingTopic): string {
  return isAliasTopic(topic) ? aliasTarget(topic) : topic.href;
}

function RelatedLinks({ topic }: { topic: MarketingTopic }) {
  // Dedupe by resolved destination: many aliases in one menu collapse onto the
  // same canonical page (e.g. several Capabilities entries → /platform/web-dast).
  const seen = new Set<string>([resolveTopicHref(topic)]);
  const related: { href: string; group: string; title: string }[] = [];
  for (const candidate of getTopicsForMenu(getMenuSlug(topic.menu.label))) {
    const href = resolveTopicHref(candidate);
    if (seen.has(href.split("#")[0])) continue;
    seen.add(href.split("#")[0]);
    related.push({
      href,
      group: candidate.groupTitle,
      title: candidate.item.title,
    });
    if (related.length >= 6) break;
  }

  return (
    <div className="lp-dossier-related">
      {related.map((candidate) => (
        <Link href={candidate.href} key={candidate.href}>
          <span>{candidate.group}</span>
          <strong>{candidate.title}</strong>
        </Link>
      ))}
    </div>
  );
}

// Compact, scannable card for one synthesized section. Every bullet from the
// source array is retained — long sections simply grow taller.
function FeatureBlock({
  id,
  num,
  title,
  eyebrow,
  items,
}: {
  id: string;
  num: string;
  title: string;
  eyebrow: string;
  items: string[];
}) {
  return (
    <article className="lp-feature-block" id={id}>
      <div className="lp-feature-block-head">
        <span className="lp-feature-block-num">{num}</span>
        <div>
          <p className="lp-eyebrow">{eyebrow}</p>
          <h2>{title}</h2>
        </div>
      </div>
      <ul className="lp-feature-block-list">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </article>
  );
}

// Pages that warrant TechArticle schema — deep technical methodology and
// reference content most likely to be cited by AI engines.
const TECH_ARTICLE_PAGES: Record<
  string,
  { datePublished: string; about: string[] }
> = {
  "platform:methodology-v4-2": {
    datePublished: "2026-01-15",
    about: ["OWASP", "NIST 800-53", "MITRE ATT&CK", "penetration testing"],
  },
  "ai-security:owasp-llm-top-10": {
    datePublished: "2026-02-01",
    about: [
      "OWASP LLM Top 10",
      "MITRE ATLAS",
      "LLM security",
      "prompt injection",
    ],
  },
  "platform:letter-grade": {
    datePublished: "2026-01-15",
    about: ["application security", "risk scoring", "security grading"],
  },
  "platform:the-adversarial-cycle": {
    datePublished: "2026-01-15",
    about: ["adversarial testing", "penetration testing", "exploit chaining"],
  },
};

// CTA/utility pages that have no substantive content of their own.
// These orphan slugs are generated from menu CTA titles and quickLinks that
// redirect to app routes. Noindex them so they don't dilute crawl signals.
const NOINDEX_SLUGS = new Set([
  "explore-platform-coverage",
  "dashboard",
  "targets",
  "start-a-new-assessment",
  "run-an-ai-target",
  "talk-to-pencheff",
  "contact-support",
  "contact-us",
]);

// Keyword-rich <title> + keyword overrides for high-intent term pages.
// SEO/<title> only — nav labels and on-page H1 keep the short topic.item.title.
// Targets the head terms people actually search for.
const SEO_TITLE_OVERRIDES: Record<string, string> = {
  "web-dast": "Open-Source DAST — Dynamic Application Security Testing",
  "sast-and-secrets": "Open-Source SAST & Secrets Scanning",
  "llm-red-team": "LLM Red Teaming — OWASP LLM Top 10 Testing",
  "cloud-and-infrastructure":
    "Cloud Security & CNAPP — KSPM, CWPP, IaC Scanning",
  "android-app-security-testing":
    "Android App Security Testing — APK/AAB Static Analysis (OWASP MASVS)",
  "ios-app-security-testing":
    "iOS App Security Testing — IPA Static Analysis (OWASP MASVS)",
  "browser-extension-security-testing":
    "Browser Extension Security Testing — Chrome, Firefox & Edge (CRX/XPI)",
  "desktop-app-security-testing":
    "Desktop App Security Testing — Electron, Java, .NET & Qt",
  "firmware-security-testing":
    "Firmware Security Analysis — Embedded Keys, Default Creds & CVEs",
  "iot-device-security-testing":
    "IoT Device Security Testing — Camera, Drone & Router Firmware",
  "ot-ics-scada-security-testing":
    "OT / ICS / SCADA Security Testing — PLC & Controller Firmware",
};
const SEO_KEYWORD_OVERRIDES: Record<string, string[]> = {
  "web-dast": [
    "DAST",
    "DAST tools",
    "open source DAST",
    "dynamic application security testing",
  ],
  "sast-and-secrets": [
    "SAST",
    "SAST tools",
    "open source SAST",
    "static application security testing",
    "secrets scanning",
  ],
  "llm-red-team": [
    "LLM red teaming",
    "AI red teaming",
    "prompt injection testing",
    "OWASP LLM Top 10",
  ],
  "android-app-security-testing": [
    "Android app security testing",
    "APK security analysis",
    "mobile app pentest",
    "OWASP MASVS",
    "static APK analysis",
  ],
  "ios-app-security-testing": [
    "iOS app security testing",
    "IPA security analysis",
    "mobile app pentest",
    "OWASP MASVS",
    "static IPA analysis",
  ],
  "browser-extension-security-testing": [
    "browser extension security testing",
    "Chrome extension security",
    "CRX analysis",
    "malicious extension detection",
  ],
  "desktop-app-security-testing": [
    "desktop app security testing",
    "Electron security",
    "Electron app audit",
    "binary security analysis",
  ],
  "firmware-security-testing": [
    "firmware security analysis",
    "firmware analysis tool",
    "embedded security testing",
    "firmware reverse engineering",
  ],
  "iot-device-security-testing": [
    "IoT security testing",
    "IoT device security",
    "IoT firmware analysis",
    "camera security testing",
    "router firmware security",
  ],
  "ot-ics-scada-security-testing": [
    "OT security testing",
    "ICS security testing",
    "SCADA security",
    "PLC firmware security",
  ],
  "cloud-and-infrastructure": [
    "CNAPP",
    "KSPM",
    "IaC scanning",
    "container scanning",
  ],
};

export function getMarketingDetailMetadata(
  menuSlug: string,
  slug: string,
): Metadata {
  const topic = getMarketingTopic(menuSlug, slug);
  if (!topic) {
    return {
      title: "Pencheff",
      robots: {
        index: false,
        follow: false,
      },
    };
  }

  // Alias topics 301-redirect to a different canonical URL — explicitly
  // noindex so search engines stop trying to index the alternate path
  // until the redirect crawl propagates.
  const isAlias = isAliasTopic(topic);
  // Support section pages duplicate content from canonical menu sections.
  const isSupportSection = menuSlug === "support";
  const isOrphanCta = NOINDEX_SLUGS.has(slug);
  const noIndex = isAlias || isSupportSection || isOrphanCta;

  return createMetadata({
    title: SEO_TITLE_OVERRIDES[slug] ?? topic.item.title,
    description: topic.item.body,
    path: topic.href,
    noIndex,
    keywords: [
      topic.item.title,
      topic.groupTitle,
      topic.menu.label,
      "Pencheff",
      "open source security platform",
      "application security",
      "penetration testing",
      "security evidence",
      ...(SEO_KEYWORD_OVERRIDES[slug] ?? []),
    ],
  });
}

// Only static-render canonical-destination topics. Alias topics are still
// reachable via the dynamic route (Next.js falls back to runtime rendering
// for params not in the prebuilt set), where MarketingDetailPage 301-redirects
// them to their real destination.
export function getMarketingStaticParams(menuSlug: string) {
  return getTopicsForMenu(menuSlug)
    .filter((topic) => !isAliasTopic(topic))
    .map((topic) => ({ slug: topic.slug }));
}

function ReferencesSection({ refs }: { refs: ExternalRef[] }) {
  return (
    <section className="lp-dossier-refs" id="references">
      <div className="lp-dossier-section-head">
        <span className="lp-dossier-num">§</span>
        <div>
          <p className="lp-eyebrow">References</p>
          <h2>Authoritative sources</h2>
        </div>
      </div>
      <ul className="lp-dossier-refs-list">
        {refs.map((ref) => (
          <li key={ref.url}>
            <a href={ref.url} target="_blank" rel="noopener">
              {ref.name}
            </a>
          </li>
        ))}
      </ul>
    </section>
  );
}

function FaqSection({ faqs }: { faqs: FaqItem[] }) {
  return (
    <section className="lp-dossier-faq" id="faq">
      <div className="lp-dossier-section-head">
        <span className="lp-dossier-num">?</span>
        <div>
          <p className="lp-eyebrow">FAQ</p>
          <h2>Common questions</h2>
        </div>
      </div>
      <dl className="lp-dossier-faq-list">
        {faqs.map((item) => (
          <div className="lp-dossier-faq-item" key={item.q}>
            <dt>{item.q}</dt>
            <dd>{item.a}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

export function MarketingDetailPage({
  menuSlug,
  slug,
}: {
  menuSlug: string;
  slug: string;
}) {
  const topic = getMarketingTopic(menuSlug, slug);
  if (!topic) notFound();
  // Alias topics (nav entries whose ``item.href`` points elsewhere) 301
  // to the canonical destination so search engines consolidate signals
  // instead of clustering near-duplicates. See marketing-nav::isAliasTopic.
  if (isAliasTopic(topic)) {
    permanentRedirect(aliasTarget(topic));
  }

  const profile = chooseProfile(topic);
  const details = mergeDetails(topic, profile);
  const docSections: DocSection[] = hasDocMapping(topic.menu.label, topic.slug)
    ? loadDocSections(topic.menu.label, topic.slug)
    : [];
  const faqs = MARKETING_FAQS[`${menuSlug}:${slug}`] ?? [];
  const refs = MARKETING_REFERENCES[`${menuSlug}:${slug}`] ?? [];
  const articleMeta = TECH_ARTICLE_PAGES[`${menuSlug}:${slug}`];

  const jsonLdItems = [
    webPageJsonLd({
      name: topic.item.title,
      description: topic.item.body,
      path: topic.href,
    }),
    breadcrumbJsonLd([
      { name: "Home", path: "/" },
      { name: topic.menu.label, path: getMenuOverviewHref(topic.menu) },
      { name: topic.item.title, path: topic.href },
    ]),
    ...(faqs.length > 0 ? [faqJsonLd(faqs)] : []),
    ...(articleMeta
      ? [
          techArticleJsonLd({
            headline: topic.item.title,
            description: topic.item.body,
            path: topic.href,
            datePublished: articleMeta.datePublished,
            about: articleMeta.about,
          }),
        ]
      : []),
  ];

  const docsBase =
    process.env.NEXT_PUBLIC_DOCS_URL ?? "https://docs.pencheff.com";
  const menuIndex = String(
    Math.max(
      0,
      NAV_MENUS.findIndex((m) => m.label === topic.menu.label),
    ) + 1,
  ).padStart(2, "0");

  const visualKind = resolveVisualKind(topic, profile);
  const counts = {
    coverage: details.capabilities.length,
    execution: details.workflow.length,
    evidence: details.evidence.length,
    controls: details.controls.length,
  };

  // One unified table of contents: the proof artifact, the four synthesized
  // sections (now always rendered), the deep reference, then refs/FAQ/related.
  // Every anchor below maps to an id that exists in the rendered tree.
  const toc: { id: string; label: string }[] = [
    { id: "proof", label: "Proof artifact" },
    { id: "coverage", label: "Coverage" },
    { id: "execution", label: "Execution" },
    { id: "evidence", label: "Evidence" },
    { id: "controls", label: "Controls" },
  ];
  toc.push(
    docSections.length > 0
      ? { id: "doc-0", label: "Reference docs" }
      : { id: "documentation", label: "Documentation" },
  );
  if (refs.length > 0) toc.push({ id: "references", label: "References" });
  if (faqs.length > 0) toc.push({ id: "faq", label: "FAQ" });
  toc.push({ id: "related", label: "Related" });

  return (
    <div className="landing-root">
      <LandingNav />
      <JsonLd id={`pencheff-json-ld-${topic.slug}`} data={jsonLdItems} />
      <main className="lp-feature">
        <div className="lp-feature-shell">
          {/* ── Proof-object-first hero ── */}
          <header className="lp-feature-hero">
            <div className="lp-feature-hero-copy">
              <p className="lp-eyebrow">
                {profile.badge} · {topic.menu.label}
              </p>
              <h1>{topic.item.title}</h1>
              <p className="lp-feature-lead">{topic.item.body}</p>
              <p className="lp-feature-summary">{profile.summary}</p>
              <div className="lp-feature-actions">
                <Link href="/signup" className="lp-btn lp-btn-arrow">
                  Start free
                </Link>
                <Link href="/login" className="lp-btn lp-btn-ghost">
                  Sign in
                </Link>
              </div>
            </div>
            <FeatureArtifact kind={visualKind} counts={counts} />
          </header>

          {/* ── Compact spec-sheet metadata strip ── */}
          <section className="lp-feature-meta" aria-label="Spec sheet">
            <div>
              <b>Scope</b>
              <span>{topic.groupTitle}</span>
            </div>
            <div>
              <b>Section</b>
              <span>{topic.menu.label}</span>
            </div>
            <div>
              <b>Method</b>
              <span>Deterministic-first</span>
            </div>
            <div>
              <b>Output</b>
              <span>Unified evidence</span>
            </div>
            <div>
              <b>Profile</b>
              <span>{profile.badge}</span>
            </div>
          </section>

          <div className="lp-feature-content">
            <aside className="lp-feature-rail">
              <div className="lp-feature-rail-inner">
                <p className="lp-feature-index">
                  <span>{topic.menu.label}</span>
                  <em>{menuIndex}</em>
                </p>
                <nav className="lp-feature-toc" aria-label="On this page">
                  {toc.map((entry, i) => (
                    <a href={`#${entry.id}`} key={entry.id}>
                      <span>{String(i + 1).padStart(2, "0")}</span>
                      {entry.label}
                    </a>
                  ))}
                </nav>
              </div>
            </aside>

            <div className="lp-feature-body">
              {/* Coverage / Execution / Evidence / Controls — always shown. */}
              <div className="lp-feature-quad">
                <FeatureBlock
                  id="coverage"
                  num="01"
                  eyebrow="Coverage"
                  title={`What does ${topic.item.title} test?`}
                  items={details.capabilities}
                />
                <FeatureBlock
                  id="execution"
                  num="02"
                  eyebrow="Execution"
                  title="How does Pencheff run this?"
                  items={details.workflow}
                />
                <FeatureBlock
                  id="evidence"
                  num="03"
                  eyebrow="Evidence"
                  title="What evidence does this produce?"
                  items={details.evidence}
                />
                <FeatureBlock
                  id="controls"
                  num="04"
                  eyebrow="Controls"
                  title="How is this kept safe to run?"
                  items={details.controls}
                />
              </div>

              {/* Deep reference body: doc-backed MDX, else fallback doc links. */}
              {docSections.length > 0 ? (
                <div className="lp-dossier-docs-stack">
                  {docSections.map((section, index) => (
                    <article
                      className="lp-dossier-doc"
                      id={`doc-${index}`}
                      key={`${section.href}-${section.title}-${index}`}
                    >
                      <header className="lp-dossier-doc-head">
                        <span className="lp-dossier-num">
                          {String(index + 1).padStart(2, "0")}
                        </span>
                        <div>
                          <p className="lp-eyebrow lp-eyebrow-gilt">
                            From the Pencheff docs
                          </p>
                          <h2>{section.title}</h2>
                          {section.sourceTitle ? (
                            <p className="lp-dossier-doc-source">
                              {section.sourceTitle}
                            </p>
                          ) : null}
                        </div>
                      </header>
                      {section.lead ? (
                        <p className="lp-dossier-doc-lead">{section.lead}</p>
                      ) : null}
                      <MarketingDocBody markdown={section.body} />
                    </article>
                  ))}
                </div>
              ) : (
                <section className="lp-dossier-readmore" id="documentation">
                  <div className="lp-dossier-section-head">
                    <span className="lp-dossier-num">↗</span>
                    <div>
                      <p className="lp-eyebrow">Documentation</p>
                      <h2>Read the full reference.</h2>
                    </div>
                  </div>
                  <ul>
                    {details.docs.map((doc) => {
                      const urlPath = doc
                        .replace(/^apps\/docs\/pages\//, "")
                        .replace(/\.mdx?$/, "");
                      const label = urlPath
                        .split("/")
                        .pop()!
                        .replace(/-/g, " ")
                        .replace(/\b\w/g, (c) => c.toUpperCase());
                      return (
                        <li key={doc}>
                          <a
                            href={`${docsBase}/${urlPath}`}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            <span>{label}</span>
                            <code>/{urlPath}</code>
                          </a>
                        </li>
                      );
                    })}
                  </ul>
                </section>
              )}

              {refs.length > 0 && <ReferencesSection refs={refs} />}
              {faqs.length > 0 && <FaqSection faqs={faqs} />}

              <section className="lp-dossier-next" id="related">
                <div className="lp-dossier-section-head">
                  <span className="lp-dossier-num">→</span>
                  <div>
                    <p className="lp-eyebrow">Related</p>
                    <h2>Keep exploring {topic.menu.label}.</h2>
                  </div>
                </div>
                <RelatedLinks topic={topic} />
              </section>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
