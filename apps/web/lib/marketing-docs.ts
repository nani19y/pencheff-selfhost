import fs from "node:fs";
import path from "node:path";

export type DocRef = {
  file: string;
  heading?: string;
  lead?: string;
};

const DOCS_ROOT = path.resolve(process.cwd(), "..", "docs", "pages");

const MAP: Record<string, DocRef[]> = {
  // CAPABILITIES — Mobile & Client Security (spec 002)
  "capabilities:android-app-security-testing": [
    { file: "features/mobile-security.mdx" },
    { file: "tutorials/android-apk-scanning.mdx" },
  ],
  "capabilities:ios-app-security-testing": [
    { file: "features/mobile-security.mdx" },
    { file: "tutorials/ios-ipa-scanning.mdx" },
  ],
  "capabilities:browser-extension-security-testing": [
    { file: "features/browser-extension.mdx" },
    { file: "tutorials/browser-extension-scanning.mdx" },
  ],
  "capabilities:desktop-app-security-testing": [
    { file: "features/desktop-app.mdx" },
    { file: "tutorials/desktop-app-static-scanning.mdx" },
  ],
  "capabilities:firmware-security-testing": [
    { file: "features/firmware-iot.mdx" },
    { file: "tutorials/firmware-scanning.mdx" },
  ],
  "capabilities:iot-device-security-testing": [
    { file: "features/firmware-iot.mdx" },
    { file: "tutorials/iot-device-scanning.mdx" },
  ],
  "capabilities:ot-ics-scada-security-testing": [
    { file: "features/firmware-iot.mdx" },
    { file: "tutorials/firmware-scanning.mdx" },
  ],

  // PLATFORM — Methodology
  "platform:methodology-v4-2": [
    { file: "reference/overview.mdx" },
    { file: "getting-started/concepts.mdx" },
  ],
  "platform:the-adversarial-cycle": [
    { file: "reference/overview.mdx" },
    { file: "quickstart/url-scan.mdx" },
  ],

  // PLATFORM — Security Surfaces
  "platform:web-dast": [{ file: "features/dast.mdx" }],
  "platform:sast-and-secrets": [
    { file: "repos/scanners.mdx" },
    { file: "features/github-check-runs.mdx" },
  ],
  "platform:sca-and-sbom": [
    { file: "features/sca.mdx" },
    { file: "features/sbom.mdx" },
    { file: "features/epss-kev.mdx" },
  ],
  "platform:iac-and-containers": [
    { file: "features/iac.mdx" },
    { file: "features/container.mdx" },
    { file: "features/admission-webhook.mdx" },
  ],
  "platform:asm-and-assets": [{ file: "features/asm.mdx" }],
  "platform:network-ad-mobile": [
    { file: "features/active-directory.mdx" },
    { file: "features/network-va.mdx" },
    { file: "features/mobile-security.mdx" },
  ],

  // PLATFORM — Operational Core
  "platform:unified-finding-stream": [
    { file: "features/findings-stream.mdx" },
    { file: "reference/unified-findings.mdx" },
  ],
  "platform:engagement-profiles": [
    { file: "reference/scans.mdx" },
    { file: "getting-started/concepts.mdx" },
  ],
  "platform:schedules": [{ file: "reference/schedules.mdx" }],
  "platform:observability": [
    { file: "features/observability.mdx" },
    { file: "reference/observability.mdx" },
  ],
  "platform:mcp-toolkit": [{ file: "reference/mcp-tools.mdx" }],
  "platform:audit-and-compliance": [
    { file: "features/compliance-mapping.mdx" },
    { file: "compliance/overview.mdx" },
  ],
  "platform:authenticated-coverage": [
    { file: "features/authentication.mdx" },
    { file: "tutorials/spa-authenticated.mdx" },
  ],
  "platform:threat-models": [{ file: "features/threat-model.mdx" }],
  "platform:cloud-and-infrastructure": [
    { file: "features/asm.mdx" },
    { file: "features/network-va.mdx" },
    { file: "tutorials/iac-cloud-hardening.mdx" },
  ],
  "platform:findings": [{ file: "features/findings-stream.mdx" }],
  "platform:reports": [{ file: "features/dashboards.mdx" }],

  // PLATFORM — AI Security
  "platform:llm-red-team": [
    { file: "features/llm-redteam.mdx" },
    { file: "quickstart/llm-redteam.mdx" },
  ],
  "platform:agent-swarms": [{ file: "features/swarm.mdx" }],
  "platform:ai-agents": [
    { file: "features/swarm.mdx" },
    { file: "features/sentry.mdx" },
  ],
  "platform:the-engine": [
    { file: "features/swarm.mdx" },
    { file: "features/auto-fix.mdx" },
  ],

  // PLATFORM — Deliverables
  "platform:letter-grade": [
    { file: "features/dashboards.mdx" },
    { file: "features/executive-dashboard.mdx" },
  ],
  "platform:technical-dossier": [
    { file: "features/dashboards.mdx" },
    { file: "tutorials/audit-ready-bundle.mdx" },
  ],
  "platform:executive-dossier": [
    { file: "features/executive-dashboard.mdx" },
    { file: "features/dashboards.mdx" },
  ],
  "platform:re-examination": [
    { file: "features/auto-fix.mdx" },
    { file: "reference/scans.mdx" },
  ],
  "platform:export": [
    { file: "features/dashboards.mdx" },
    { file: "tutorials/audit-ready-bundle.mdx" },
  ],

  // CAPABILITIES — quick links
  "capabilities:url-scan": [
    { file: "quickstart/url-scan.mdx" },
    { file: "features/dast.mdx" },
  ],
  "capabilities:repo-scan": [
    { file: "quickstart/repo-scan.mdx" },
    { file: "repos/scanners.mdx" },
  ],
  "capabilities:sbom": [
    { file: "quickstart/sbom.mdx" },
    { file: "features/sbom.mdx" },
  ],
  "capabilities:compare-scans": [{ file: "reference/scans.mdx" }],

  // CAPABILITIES — Dynamic Testing
  "capabilities:injection-coverage": [
    {
      file: "features/dast.mdx",
      lead: "Injection coverage — SQLi, NoSQLi, command injection, SSTI, XXE, SSRF, LDAP, deserialization, and prototype pollution — sits at the top of the DAST coverage map below.",
    },
  ],
  "capabilities:client-side-security": [
    {
      file: "features/dast.mdx",
      lead: "Client-side issues — XSS in every context, DOM-source/sink, CSRF, clickjacking, cache poisoning, and redirect chains — share the same coverage table and verification pipeline as server-side classes.",
    },
  ],
  "capabilities:authentication": [{ file: "features/authentication.mdx" }],
  "capabilities:api-and-spa-coverage": [
    { file: "features/api-discovery.mdx" },
    { file: "features/dast.mdx" },
  ],
  "capabilities:proxy-and-fuzzer": [
    { file: "features/proxy.mdx" },
    { file: "features/fuzzer.mdx" },
    { file: "features/passive-scan.mdx" },
  ],

  // CAPABILITIES — Code And Supply Chain
  "capabilities:language-scanners": [
    {
      file: "repos/scanners.mdx",
      heading: "Semgrep OSS — multi-language SAST",
    },
    { file: "repos/scanners.mdx", heading: "Bandit — Python SAST" },
    { file: "repos/scanners.mdx", heading: "gosec — Go SAST" },
    { file: "repos/scanners.mdx", heading: "Brakeman — Ruby on Rails SAST" },
    {
      file: "repos/scanners.mdx",
      heading: "ESLint + eslint-plugin-security — JS / TS SAST",
    },
    {
      file: "repos/scanners.mdx",
      heading: "Tree-sitter pack — niche-language SAST",
    },
  ],
  "capabilities:secrets-and-malware": [
    { file: "repos/scanners.mdx", heading: "gitleaks — secrets" },
    {
      file: "repos/scanners.mdx",
      heading: "YARA — malware / backdoor patterns",
    },
  ],
  "capabilities:dependency-intelligence": [
    { file: "features/sca.mdx" },
    { file: "features/epss-kev.mdx" },
    { file: "features/reachability.mdx" },
  ],
  "capabilities:auto-fix-prs": [
    { file: "features/auto-fix.mdx" },
    { file: "features/github-check-runs.mdx" },
  ],
  "capabilities:container-gates": [
    { file: "features/container.mdx" },
    { file: "features/admission-webhook.mdx" },
  ],

  // CAPABILITIES — Prioritization
  "capabilities:reachability": [{ file: "features/reachability.mdx" }],
  "capabilities:ai-triage": [
    { file: "features/ai-triage.mdx" },
    { file: "features/advisory-ai.mdx" },
  ],
  "capabilities:letter-grade": [
    { file: "features/dashboards.mdx" },
    { file: "features/executive-dashboard.mdx" },
  ],
  "capabilities:threat-modeling": [{ file: "features/threat-model.mdx" }],

  // AI SECURITY
  "ai-security:llm-red-team": [
    { file: "features/llm-redteam.mdx" },
    { file: "quickstart/llm-redteam.mdx" },
  ],
  "ai-security:ai-agents": [
    { file: "features/swarm.mdx" },
    { file: "features/sentry.mdx" },
  ],
  "ai-security:agent-swarms": [{ file: "features/swarm.mdx" }],
  "ai-security:recommended-guardrails": [
    { file: "features/sentry.mdx", heading: "Quick start" },
    { file: "features/sentry.mdx", heading: "What it detects" },
  ],

  // AI SECURITY — LLM Red Team group
  "ai-security:owasp-llm-top-10": [
    {
      file: "features/llm-redteam.mdx",
      heading: "OWASP LLM Top 10 (2025) modules",
    },
    { file: "plugin-sdk/llm-redteam.mdx" },
  ],
  "ai-security:attack-strategies": [
    {
      file: "features/llm-redteam.mdx",
      heading: "Strategies and composite stacking",
    },
    { file: "features/llm-redteam.mdx", heading: "Multi-turn Crescendo" },
    {
      file: "features/llm-redteam.mdx",
      heading: "Iterative search (PAIR · TAP · GOAT · Hydra)",
    },
    { file: "features/llm-redteam.mdx", heading: "Attacker-LLM synthesis" },
  ],
  "ai-security:transports": [
    { file: "features/llm-redteam.mdx", heading: "Provider transports" },
    {
      file: "features/llm-redteam.mdx",
      heading: "Rate limits, retries, and cost ceilings",
    },
  ],
  "ai-security:evidence-and-cost": [
    { file: "features/llm-redteam.mdx", heading: "Verdict pipeline" },
    { file: "features/llm-redteam.mdx", heading: "LLM-as-judge" },
    { file: "features/llm-redteam.mdx", heading: "Reporting" },
  ],

  // AI SECURITY — Agentic Testing group
  "ai-security:tool-authorization": [
    {
      file: "features/sentry.mdx",
      heading: "What it detects",
      lead: "Sentry's tool-call authorization sits between an agent and its tools — it inspects every requested action against the policy chain before the call is allowed to leave the gateway.",
    },
  ],
  "ai-security:memory-and-context": [
    {
      file: "features/sentry.mdx",
      heading: "What it detects",
      lead: "Memory and retrieval attacks try to poison the agent's working state. Sentry inspects prompts, RAG context, and tool responses for exfiltration, prompt poisoning, and PII leakage before they reach the model.",
    },
    { file: "features/sentry.mdx", heading: "Audit log" },
  ],
  "ai-security:planner-attacks": [
    {
      file: "features/swarm.mdx",
      heading: "Phase 2: Breakers (parallel fan-out)",
      lead: "Planner-style attacks emerge in the breaker phase: each agent gets a goal, a budget, and a planner that can chain tool calls — and Pencheff's killswitch + audit trail keep the planner on a leash.",
    },
    { file: "features/swarm.mdx", heading: "Catastrophic fallback" },
  ],
  "ai-security:swarm-orchestration": [
    { file: "features/swarm.mdx", heading: "Pipeline shape" },
    { file: "features/swarm.mdx", heading: "The 19 agents" },
    { file: "features/swarm.mdx", heading: "Configuration" },
  ],

  // AI SECURITY — Guardrails group
  "ai-security:sentry-runtime-guardrail": [{ file: "features/sentry.mdx" }],
  "ai-security:sidecars-and-middleware": [
    { file: "features/sentry.mdx", heading: "Modes" },
    { file: "features/sentry.mdx", heading: "LiteLLM plugin" },
    { file: "features/sentry.mdx", heading: "Extending the detector chain" },
  ],
  "ai-security:ai-governance": [
    { file: "compliance/overview.mdx" },
    { file: "features/compliance-mapping.mdx" },
  ],
  "ai-security:regression-tests": [
    { file: "features/llm-redteam.mdx", heading: "Anatomy of an LLM scan" },
    { file: "features/llm-redteam.mdx", heading: "Profiles" },
    { file: "features/llm-redteam.mdx", heading: "Grading" },
  ],

  // SOLUTIONS
  "solutions:engineers": [
    { file: "tutorials/ci-gate.mdx" },
    { file: "repos/connect.mdx" },
    { file: "features/ide.mdx" },
  ],
  "solutions:auditors": [
    { file: "compliance/overview.mdx" },
    { file: "features/compliance-mapping.mdx" },
  ],
  "solutions:executives": [{ file: "features/executive-dashboard.mdx" }],
  "solutions:security-teams": [
    { file: "features/findings-stream.mdx" },
    { file: "features/ai-triage.mdx" },
  ],
  "solutions:ci-cd-gates": [
    { file: "ci-cd/generic.mdx" },
    { file: "ci-cd/github-actions.mdx" },
    { file: "features/github-check-runs.mdx" },
  ],
  "solutions:authenticated-app-pentest": [
    { file: "features/authentication.mdx" },
    { file: "tutorials/api-pentest.mdx" },
  ],
  "solutions:ai-product-release": [
    { file: "features/llm-redteam.mdx" },
    { file: "features/sentry.mdx" },
    { file: "quickstart/llm-redteam.mdx" },
  ],
  "solutions:continuous-asm": [{ file: "features/asm.mdx" }],
  "solutions:cli-and-ci": [
    { file: "cli/reference.mdx" },
    { file: "ci-cd/generic.mdx" },
  ],
  "solutions:mcp-server": [{ file: "reference/mcp-tools.mdx" }],
  "solutions:saas-app": [
    { file: "getting-started/installation.mdx" },
    { file: "getting-started/first-scan.mdx" },
  ],
  "solutions:self-hosting": [
    { file: "getting-started/installation.mdx" },
    { file: "getting-started/concepts.mdx" },
  ],

  // RESOURCES
  "resources:methodology": [{ file: "reference/overview.mdx" }],
  "resources:api-reference": [
    { file: "reference/overview.mdx" },
    { file: "reference/scans.mdx" },
    { file: "reference/findings.mdx" },
    { file: "reference/api-keys.mdx" },
  ],
  "resources:issued-reports": [
    { file: "tutorials/audit-ready-bundle.mdx" },
    { file: "features/dashboards.mdx" },
  ],
  "resources:findings-register": [
    { file: "reference/findings.mdx" },
    { file: "features/findings-stream.mdx" },
  ],
  "resources:url-scan": [{ file: "quickstart/url-scan.mdx" }],
  "resources:repo-scan": [{ file: "quickstart/repo-scan.mdx" }],
  "resources:llm-redteam": [
    { file: "quickstart/llm-redteam.mdx" },
    { file: "features/llm-redteam.mdx" },
  ],
  "resources:llm-red-team": [
    { file: "quickstart/llm-redteam.mdx" },
    { file: "features/llm-redteam.mdx" },
  ],
  "resources:threat-model": [{ file: "features/threat-model.mdx" }],
  "resources:scans-and-schedules": [
    { file: "reference/scans.mdx" },
    { file: "reference/schedules.mdx" },
  ],
  "resources:integrations": [
    { file: "integrations/overview.mdx" },
    { file: "reference/integrations.mdx" },
  ],
  "resources:observability": [
    { file: "features/observability.mdx" },
    { file: "reference/observability.mdx" },
  ],
  "resources:change-log": [{ file: "release-notes.mdx" }],
  "resources:open-documentation": [{ file: "index.mdx" }],

  // SUPPORT
  "support:trust-and-compliance": [
    { file: "compliance/overview.mdx" },
    { file: "features/compliance-mapping.mdx" },
  ],
  "support:partners": [{ file: "features/partner-triage.mdx" }],
  "support:api-keys": [{ file: "reference/api-keys.mdx" }],
  "support:integrations-support": [
    { file: "integrations/overview.mdx" },
    { file: "reference/integrations.mdx" },
  ],
  "support:onboarding": [
    { file: "getting-started/installation.mdx" },
    { file: "getting-started/first-scan.mdx" },
    { file: "getting-started/concepts.mdx" },
  ],
  "support:auditors": [
    { file: "compliance/overview.mdx" },
    { file: "compliance/soc2.mdx" },
    { file: "compliance/pci-dss.mdx" },
  ],
  "support:case-studies": [
    { file: "tutorials/audit-ready-bundle.mdx" },
    { file: "tutorials/api-pentest.mdx" },
  ],
  "support:security-disclosure": [
    { file: "faq.mdx" },
    { file: "compliance/overview.mdx" },
  ],
  "support:self-hosting": [
    { file: "getting-started/installation.mdx" },
    { file: "getting-started/concepts.mdx" },
  ],
  "support:pricing": [
    { file: "getting-started/concepts.mdx" },
    { file: "getting-started/installation.mdx" },
  ],
  "support:our-discipline": [
    { file: "reference/overview.mdx" },
    { file: "getting-started/concepts.mdx" },
  ],
  "support:brand-and-press": [{ file: "reference/overview.mdx" }],

  // COMPANY
  "company:our-discipline": [
    { file: "reference/overview.mdx" },
    { file: "getting-started/concepts.mdx" },
  ],
  "company:our-auditors": [
    { file: "compliance/overview.mdx" },
    { file: "compliance/soc2.mdx" },
    { file: "compliance/pci-dss.mdx" },
  ],
  "company:our-partners": [{ file: "features/partner-triage.mdx" }],
  "company:case-studies": [
    { file: "tutorials/audit-ready-bundle.mdx" },
    { file: "tutorials/api-pentest.mdx" },
    { file: "tutorials/web-app-pentest.mdx" },
  ],
  "company:trust-and-compliance": [
    { file: "compliance/overview.mdx" },
    { file: "features/compliance-mapping.mdx" },
    { file: "compliance/soc2.mdx" },
  ],
  "company:trust-compliance": [
    { file: "compliance/overview.mdx" },
    { file: "features/compliance-mapping.mdx" },
  ],
  "company:newsroom": [{ file: "release-notes.mdx" }],
  "company:contact": [
    { file: "faq.mdx" },
    { file: "getting-started/concepts.mdx" },
  ],
  "company:careers": [{ file: "reference/overview.mdx" }],
  "company:leadership": [{ file: "reference/overview.mdx" }],
  "company:brand-and-press": [{ file: "reference/overview.mdx" }],
  "company:brand-press": [{ file: "reference/overview.mdx" }],
};

export type DocSection = {
  title: string;
  body: string;
  href: string;
  lead?: string;
  sourceTitle?: string;
};

function escapeRegExp(str: string) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function extractSection(raw: string, heading: string): string {
  const pattern = new RegExp(`^##\\s+${escapeRegExp(heading)}\\s*$`, "m");
  const match = pattern.exec(raw);
  if (!match) return raw;
  const startIdx = match.index;
  const tail = raw.slice(startIdx + match[0].length);
  const next = /\n##\s+/.exec(tail);
  const block = next ? tail.slice(0, next.index) : tail;
  return block.trim();
}

function stripFrontmatter(raw: string) {
  if (raw.startsWith("---")) {
    const end = raw.indexOf("\n---", 3);
    if (end !== -1) {
      const after = raw.slice(end + 4);
      return after.replace(/^\s*\n/, "");
    }
  }
  return raw;
}

function readTitleFromFrontmatter(raw: string) {
  if (raw.startsWith("---")) {
    const end = raw.indexOf("\n---", 3);
    if (end !== -1) {
      const block = raw.slice(3, end);
      const titleLine = block
        .split("\n")
        .find((line) => line.trim().startsWith("title:"));
      if (titleLine) {
        return titleLine
          .replace(/^title:\s*/, "")
          .trim()
          .replace(/^['"]|['"]$/g, "");
      }
    }
  }
  const heading = raw.match(/^#\s+(.+)$/m);
  return heading?.[1] ?? null;
}

export function loadDocSections(menuLabel: string, slug: string): DocSection[] {
  const key = `${slugifyMenu(menuLabel)}:${slug}`;
  const refs = MAP[key];
  if (!refs) return [];

  return refs
    .map((ref): DocSection | null => {
      const fullPath = path.join(DOCS_ROOT, ref.file);
      try {
        const raw = fs.readFileSync(fullPath, "utf8");
        const docTitle = readTitleFromFrontmatter(raw) ?? ref.file;
        const stripped = stripFrontmatter(raw).trim();
        const body = ref.heading
          ? extractSection(stripped, ref.heading)
          : stripped;
        const title = ref.heading ? ref.heading : docTitle;
        const docHref = `/${ref.file.replace(/\.mdx?$/, "")}`;
        const section: DocSection = { title, body, href: docHref };
        if (ref.heading) section.sourceTitle = docTitle;
        if (ref.lead) section.lead = ref.lead;
        return section;
      } catch (err) {
        if (process.env.NODE_ENV !== "production") {
          console.warn(`[marketing-docs] missing doc: ${ref.file}`, err);
        }
        return null;
      }
    })
    .filter((section): section is DocSection => section !== null);
}

export function hasDocMapping(menuLabel: string, slug: string) {
  const key = `${slugifyMenu(menuLabel)}:${slug}`;
  return Boolean(MAP[key]);
}

function slugifyMenu(label: string) {
  return label
    .toLowerCase()
    .replace(/&/g, "and")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
