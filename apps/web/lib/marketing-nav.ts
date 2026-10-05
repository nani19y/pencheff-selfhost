export type NavItem = {
  title: string;
  body: string;
  href: string;
};

export type NavGroup = {
  title: string;
  items: NavItem[];
};

export type NavMenu = {
  label: string;
  eyebrow: string;
  title: string;
  body: string;
  cta: NavItem;
  quickLinks: NavItem[];
  groups: NavGroup[];
};

export const NAV_MENUS: NavMenu[] = [
  {
    label: "Platform",
    eyebrow: "What Pencheff does",
    title: "A complete adversarial security platform",
    body: "Run web, API, code, dependency, cloud, AI, and internal-network assessments from one queue with unified findings, evidence, remediation, and audit output.",
    cta: {
      title: "Explore platform coverage",
      body: "See the full surface map on this page.",
      href: "#coverage",
    },
    quickLinks: [
      {
        title: "Dashboard",
        body: "Live risk, grade, scan status, and operational metrics.",
        href: "/dashboard",
      },
      {
        title: "Targets",
        body: "URLs, repos, AI apps, APIs, and infrastructure scopes.",
        href: "/targets/new",
      },
      {
        title: "Findings",
        body: "Verified evidence, severity, remediation, and owners.",
        href: "/findings",
      },
      {
        title: "Reports",
        body: "Executive, technical, compliance, and retest deliverables.",
        href: "/platform/reports",
      },
    ],
    groups: [
      {
        title: "Methodology",
        items: [
          {
            title: "Methodology v4.2",
            body: "The adversarial assessment standard: evidence rules, scope categories, phase definitions, and rationale.",
            href: "/platform/methodology-v4-2",
          },
          {
            title: "The Adversarial Cycle",
            body: "Five phases every engagement follows: recon, exploit, evidence, normalize, and deliver.",
            href: "/platform/the-adversarial-cycle",
          },
        ],
      },
      {
        title: "Security Surfaces",
        items: [
          {
            title: "Web DAST",
            body: "Authenticated crawling, API discovery, active probes, exploit chains, and request evidence.",
            href: "/platform/web-dast",
          },
          {
            title: "SAST and secrets",
            body: "Semgrep, Bandit, gosec, Brakeman, ESLint security, tree-sitter rules, and gitleaks.",
            href: "/platform/sast-and-secrets",
          },
          {
            title: "SCA and SBOM",
            body: "OSV, NVD, GHSA, RustSec, GoVulnDB, SPDX, CycloneDX, EPSS, KEV, and SSVC.",
            href: "/resources/repo-scan",
          },
          {
            title: "IaC and containers",
            body: "Terraform, Kubernetes, Helm, Dockerfiles, Checkov, Trivy, tfsec, Kubesec, and registry gates.",
            href: "/platform/cloud-and-infrastructure",
          },
          {
            title: "ASM and assets",
            body: "Discovery, exposed services, subdomains, cloud edges, certificates, and drift.",
            href: "/asm",
          },
          {
            title: "Network, AD, mobile",
            body: "Internal VA, Active Directory checks, APK/IPA analysis, and mobile static findings.",
            href: "#coverage",
          },
        ],
      },
      {
        title: "Operational Core",
        items: [
          {
            title: "Unified finding stream",
            body: "One schema for DAST, SAST, SCA, IaC, AI, mobile, network, and manual evidence.",
            href: "/findings",
          },
          {
            title: "Engagement profiles",
            body: "Quick, Standard, Deep, Red-Team, AI-Only, Compliance, CI, and Continuous modes.",
            href: "/platform/engagement-profiles",
          },
          {
            title: "Schedules",
            body: "Continuous scans, release gates, recurring retests, and monitoring cadence.",
            href: "/schedules",
          },
          {
            title: "Observability",
            body: "OpenTelemetry traces, audit hash chain, SLOs, cost dashboards, and retention controls.",
            href: "/observability",
          },
          {
            title: "MCP toolkit",
            body: "Tool-calling security automation exposed through the Pencheff MCP server.",
            href: "/resources/api-reference",
          },
          {
            title: "Audit and compliance",
            body: "Evidence packs mapped to OWASP, PCI DSS, SOC 2, ISO 27001, HIPAA, NIST, and GDPR.",
            href: "/platform/audit-and-compliance",
          },
          {
            title: "Security Lake",
            body: "OCSF 1.3.0-normalized findings in an Apache Iceberg table — query, trend, export NDJSON/Parquet, or pull into your SIEM.",
            href: "/platform/security-lake",
          },
          {
            title: "Custom LLM providers",
            body: "Bring your own OpenAI, Anthropic, Gemini, Azure OpenAI, or compatible endpoint. One active provider powers all AI features; fail-closed, quotas bypassed.",
            href: "/platform/custom-llm-providers",
          },
          {
            title: "Authenticated coverage",
            body: "Session macros, role-aware crawling, OAuth, JWT, MFA, and business-logic coverage.",
            href: "/platform/authenticated-coverage",
          },
          {
            title: "Threat models",
            body: "Deterministic STRIDE and DREAD analysis with attack trees and generated mitigations.",
            href: "/platform/threat-models",
          },
          {
            title: "Cloud and infrastructure",
            body: "TLS, headers, subdomain takeover, cloud metadata signals, and certificate monitoring.",
            href: "/platform/cloud-and-infrastructure",
          },
        ],
      },
      {
        title: "AI Security",
        items: [
          {
            title: "LLM red team",
            body: "OWASP LLM Top 10 attack modules with jailbreak corpora, judges, and token accounting.",
            href: "/platform/llm-red-team",
          },
          {
            title: "Agent swarms",
            body: "Recon, breaker, exploit, synthesis, and reporting agent roles for automated testing.",
            href: "/platform/agent-swarms",
          },
          {
            title: "AI agents",
            body: "Tool-calling scan agent for testing LLM apps, chatbots, and agentic workflows.",
            href: "/platform/ai-agents",
          },
          {
            title: "The engine",
            body: "Autonomous orchestration, remediation pipeline, and auto-patching coordination.",
            href: "/platform/the-engine",
          },
        ],
      },
      {
        title: "Deliverables",
        items: [
          {
            title: "Letter grade",
            body: "Heuristic A–F verdict derived from severity, reachability, and evidence quality.",
            href: "/platform/letter-grade",
          },
          {
            title: "Technical dossier",
            body: "Engineering evidence, reproduction steps, fix guidance, and compliance mappings.",
            href: "/platform/technical-dossier",
          },
          {
            title: "Executive dossier",
            body: "Leadership summary with business risk, grade, posture trends, and audit-ready output.",
            href: "/platform/executive-dossier",
          },
          {
            title: "Re-examination",
            body: "Verify any fix on demand with targeted re-test probes against the same finding.",
            href: "/platform/re-examination",
          },
          {
            title: "Export",
            body: "DOCX, PDF, JSON, CSV, SARIF, SPDX, and CycloneDX output for every workflow.",
            href: "/platform/export",
          },
        ],
      },
    ],
  },
  {
    label: "Capabilities",
    eyebrow: "Everything the engine tests",
    title: "From live exploits to source-code proof",
    body: "Pencheff combines deterministic scanners, AI-guided probes, curated payloads, external tools, and evidence normalization so every signal lands in one remediation workflow.",
    cta: {
      title: "Start a new assessment",
      body: "Create a URL, repo, API, or AI target.",
      href: "/targets/new",
    },
    quickLinks: [
      {
        title: "URL scan",
        body: "DAST for live applications and APIs.",
        href: "/resources/url-scan",
      },
      {
        title: "Repo scan",
        body: "SAST, secrets, dependency, and IaC coverage.",
        href: "/resources/repo-scan",
      },
      {
        title: "SBOM",
        body: "SPDX and CycloneDX output with vulnerability context.",
        href: "/resources/repo-scan",
      },
      {
        title: "Compare scans",
        body: "Track fixes, regressions, and residual risk.",
        href: "/scans/compare",
      },
    ],
    groups: [
      {
        title: "Dynamic Testing",
        items: [
          {
            title: "Injection coverage",
            body: "SQLi, NoSQLi, command injection, SSTI, XXE, LDAP, path traversal, and deserialization.",
            href: "/platform/web-dast",
          },
          {
            title: "Client-side security",
            body: "Reflected, stored, and DOM XSS, CSRF, CORS, clickjacking, cache poisoning, and open redirect.",
            href: "/platform/web-dast",
          },
          {
            title: "Authentication",
            body: "Sessions, cookies, JWT, OAuth/OIDC, MFA bypass, brute force, IDOR, and privilege escalation.",
            href: "/platform/authenticated-coverage",
          },
          {
            title: "API and SPA coverage",
            body: "GraphQL, WebSockets, REST, OpenAPI, browser crawls, authenticated flows, and business logic.",
            href: "/platform/web-dast",
          },
          {
            title: "Proxy and fuzzer",
            body: "Intercepting proxy, passive scanner, parameter fuzzer, OAST callbacks, and replayable evidence.",
            href: "#coverage",
          },
        ],
      },
      {
        title: "Code And Supply Chain",
        items: [
          {
            title: "Language scanners",
            body: "Python, Go, Rails, JavaScript, Solidity, Kotlin, Swift, Scala, Dart, Lua, Erlang, and COBOL scaffolds.",
            href: "/platform/sast-and-secrets",
          },
          {
            title: "Secrets and malware",
            body: "gitleaks, YARA indicators, suspicious payloads, backdoor patterns, and evidence metadata.",
            href: "/capabilities/secrets-and-malware",
          },
          {
            title: "Dependency intelligence",
            body: "Fixed versions, exploitability, reachability, EPSS, KEV, SSVC, licenses, and advisory enrichment.",
            href: "/resources/repo-scan",
          },
          {
            title: "Auto-fix PRs",
            body: "Deterministic patches, branch output, GitHub checks, SARIF, and reviewer-ready remediation.",
            href: "/platform/re-examination",
          },
          {
            title: "Container gates",
            body: "Images, registries, admission webhooks, Kubernetes policies, and deployment blocking.",
            href: "/platform/cloud-and-infrastructure",
          },
        ],
      },
      {
        title: "Prioritization",
        items: [
          {
            title: "Reachability",
            body: "Connect code and dependency issues to reachable runtime paths and attack context.",
            href: "#delivery",
          },
          {
            title: "AI triage",
            body: "Deduplication, exploit narratives, severity reasoning, and remediation prioritization.",
            href: "#delivery",
          },
          {
            title: "Letter grade",
            body: "Executive-grade risk scoring across app, repo, AI, cloud, and compliance posture.",
            href: "/platform/letter-grade",
          },
          {
            title: "Threat modeling",
            body: "STRIDE, DREAD, attack trees, abuse cases, and generated mitigations per engagement.",
            href: "/platform/threat-models",
          },
        ],
      },
      {
        title: "Mobile And Client Security",
        items: [
          {
            title: "Android app security testing",
            body: "Static analysis of uploaded APK/AAB files — AndroidManifest, exported components, hardcoded secrets, weak crypto, and cleartext traffic, mapped to OWASP MASVS.",
            href: "/capabilities/android-app-security-testing",
          },
          {
            title: "iOS app security testing",
            body: "Static analysis of uploaded IPA files — Info.plist/ATS, custom URL schemes, Mach-O protections, embedded secrets, and third-party SDK CVEs, mapped to OWASP MASVS.",
            href: "/capabilities/ios-app-security-testing",
          },
          {
            title: "Browser extension security testing",
            body: "Static analysis of Chrome, Firefox, and Edge extensions (CRX/XPI) — permission and CSP scoring, remote-code and DOM-sink detection, and hardcoded secrets.",
            href: "/capabilities/browser-extension-security-testing",
          },
          {
            title: "Desktop app security testing",
            body: "Static analysis of Electron, Java/JAR, .NET, and Qt/native apps — insecure Electron config, dangerous calls, outdated runtimes, and embedded secrets.",
            href: "/capabilities/desktop-app-security-testing",
          },
        ],
      },
      {
        title: "OT, IoT And Firmware Security",
        items: [
          {
            title: "Firmware security testing",
            body: "Static analysis of firmware/embedded images — embedded private keys & certificates, default/hardcoded credentials, telnet/debug services, cleartext update endpoints, secrets, and vulnerable component versions.",
            href: "/capabilities/firmware-security-testing",
          },
          {
            title: "IoT device security testing",
            body: "Static firmware analysis for IoT devices — cameras, drones, robot vacuums, routers — finding default credentials (the Mirai-class compromise vector), embedded keys, insecure services, and vulnerable components.",
            href: "/capabilities/iot-device-security-testing",
          },
          {
            title: "OT / ICS / SCADA security testing",
            body: "Static analysis of controller/PLC firmware and config exports — embedded keys, hardcoded credentials, insecure services, and vulnerable components. No active industrial-protocol probing.",
            href: "/capabilities/ot-ics-scada-security-testing",
          },
        ],
      },
    ],
  },
  {
    label: "AI Security",
    eyebrow: "LLM and agentic systems",
    title: "Red team models, agents, tools, and guardrails",
    body: "Test AI products before attackers do: prompt attacks, tool abuse, data leakage, unsafe output, guardrail bypass, multi-agent workflows, and runtime policy enforcement.",
    cta: {
      title: "Run an AI target",
      body: "Create an LLM, chatbot, API, or agentic workflow test.",
      href: "/targets/new",
    },
    quickLinks: [
      {
        title: "LLM red team",
        body: "OWASP LLM Top 10 campaigns with datasets and judges.",
        href: "/platform/llm-red-team",
      },
      {
        title: "AI agents",
        body: "Tool-use, planner, memory, and workflow security tests.",
        href: "/platform/ai-agents",
      },
      {
        title: "Agent swarms",
        body: "Recon, breaker, exploit, synthesis, and reporting agents.",
        href: "/platform/agent-swarms",
      },
      {
        title: "Recommended guardrails",
        body: "Scan-specific policy controls and runtime mitigations.",
        href: "#ai",
      },
    ],
    groups: [
      {
        title: "LLM Red Team",
        items: [
          {
            title: "OWASP LLM Top 10",
            body: "Prompt injection, insecure output, training data exposure, DoS, supply chain, data leakage, plugins, agency, overreliance, and model theft.",
            href: "/platform/llm-red-team",
          },
          {
            title: "Attack strategies",
            body: "Roleplay, payload splitting, obfuscation, encoding, jailbreak corpora, regression suites, and judge-backed scoring.",
            href: "/platform/llm-red-team",
          },
          {
            title: "Transports",
            body: "Chat completions, HTTP endpoints, LiteLLM, MCP tools, hosted chatbots, and custom adapters.",
            href: "/platform/llm-red-team",
          },
          {
            title: "Evidence and cost",
            body: "Conversation traces, pass/fail judges, token accounting, retries, and reproducible prompts.",
            href: "/ai-security/evidence-and-cost",
          },
        ],
      },
      {
        title: "Agentic Testing",
        items: [
          {
            title: "Tool authorization",
            body: "Abuse tests for tool calls, privilege boundaries, connector permissions, and unsafe side effects.",
            href: "/platform/ai-agents",
          },
          {
            title: "Memory and context",
            body: "Prompt persistence, data exfiltration, cross-session leakage, and retrieval poisoning.",
            href: "/platform/ai-agents",
          },
          {
            title: "Planner attacks",
            body: "Goal hijacking, policy bypass, hidden instructions, and chained tool misuse.",
            href: "/platform/agent-swarms",
          },
          {
            title: "Swarm orchestration",
            body: "Scope, recon, crawler, vuln, exploit, post-exploitation, detection, and report specialists.",
            href: "/platform/agent-swarms",
          },
        ],
      },
      {
        title: "Guardrails",
        items: [
          {
            title: "Sentry runtime guardrail",
            body: "Policy checks for prompts, responses, tools, HTML, secrets, PII, and unsafe actions.",
            href: "#ai",
          },
          {
            title: "Sidecars and middleware",
            body: "HTTP proxy, LiteLLM plugin, MCP middleware, and app-level enforcement patterns.",
            href: "#ai",
          },
          {
            title: "AI governance",
            body: "OWASP LLM, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001, GDPR, and SOC 2 mapping.",
            href: "#ai",
          },
          {
            title: "Regression tests",
            body: "Keep known jailbreaks, unsafe outputs, and policy bypasses from returning after releases.",
            href: "/platform/llm-red-team",
          },
        ],
      },
    ],
  },
  {
    label: "Solutions",
    eyebrow: "For teams and workflows",
    title: "Security programs without fragmented tooling",
    body: "Use the same platform for sprint gates, release assurance, audit prep, AI product validation, executive risk, and continuous attack-surface monitoring.",
    cta: {
      title: "Talk to Pencheff",
      body: "Discuss a workflow, deployment model, or assessment plan.",
      href: "/enquiries",
    },
    quickLinks: [
      {
        title: "Security teams",
        body: "Verified risk, exploitability, and remediation queues.",
        href: "/audience/security-disclosures",
      },
      {
        title: "Engineers",
        body: "Developer-ready evidence, PRs, SARIF, and CI feedback.",
        href: "/audience/for-engineers",
      },
      {
        title: "Auditors",
        body: "Compliance appendices, evidence packs, and retest history.",
        href: "/audience/for-auditors",
      },
      {
        title: "Executives",
        body: "Letter grade, business risk, portfolio posture, and trends.",
        href: "/audience/for-executives",
      },
    ],
    groups: [
      {
        title: "Program Workflows",
        items: [
          {
            title: "CI/CD gates",
            body: "Repo, dependency, IaC, container, GitHub checks, SARIF, and policy blocking.",
            href: "#delivery",
          },
          {
            title: "Authenticated app pentest",
            body: "Session macros, role-aware coverage, browser crawling, business logic, and evidence.",
            href: "/platform/authenticated-coverage",
          },
          {
            title: "AI product release",
            body: "LLM red team, agentic tool tests, guardrails, policy reports, and regression suites.",
            href: "#ai",
          },
          {
            title: "Continuous ASM",
            body: "Asset discovery, exposed services, retest cadence, and drift monitoring.",
            href: "/asm",
          },
        ],
      },
      {
        title: "Deployment Models",
        items: [
          {
            title: "SaaS app",
            body: "Dashboards, reports, integrations, schedules, and multi-workspace operations.",
            href: "/signup",
          },
          {
            title: "CLI and CI",
            body: "Run deterministic checks in pipelines and pass artifacts into the platform.",
            href: "/resources/api-reference",
          },
          {
            title: "MCP server",
            body: "Expose scanning and security automation tools to compatible AI agents.",
            href: "/resources/api-reference",
          },
          {
            title: "Self-hosting",
            body: "Operate the SaaS API, web app, observability, database, and workers in your environment.",
            href: "/resources/overview",
          },
        ],
      },
    ],
  },
  {
    label: "Resources",
    eyebrow: "Docs, references, and playbooks",
    title: "Everything needed to operate Pencheff",
    body: "Jump into setup guides, feature references, reporting conventions, API documentation, methodology pages, and workflow-specific playbooks.",
    cta: {
      title: "Open documentation",
      body: "Read the user guide and implementation references.",
      href: "/resources/overview",
    },
    quickLinks: [
      {
        title: "Methodology",
        body: "The adversarial assessment cycle and evidence rules.",
        href: "/platform/methodology-v4-2",
      },
      {
        title: "API reference",
        body: "Authentication, targets, scans, findings, assets, and MCP tools.",
        href: "/resources/api-reference",
      },
      {
        title: "Issued reports",
        body: "Executive and technical dossier structure.",
        href: "/resources/issued-reports",
      },
      {
        title: "Findings register",
        body: "Finding lifecycle, severity, verification, and comments.",
        href: "/resources/findings-register",
      },
    ],
    groups: [
      {
        title: "Quickstarts",
        items: [
          {
            title: "URL scan",
            body: "Create a target, choose profile, run DAST, review evidence, and export reports.",
            href: "/resources/url-scan",
          },
          {
            title: "Repo scan",
            body: "Connect code, run SAST/SCA/IaC, review findings, and produce PR-ready fixes.",
            href: "/resources/repo-scan",
          },
          {
            title: "LLM red team",
            body: "Configure a model endpoint, run attack categories, inspect traces, and tune guardrails.",
            href: "/platform/llm-red-team",
          },
          {
            title: "Threat model",
            body: "Generate STRIDE and DREAD analysis attached to the scan record.",
            href: "/resources/threat-model",
          },
        ],
      },
      {
        title: "Reference Areas",
        items: [
          {
            title: "Scans and schedules",
            body: "Status, profiles, assets, recurrence, compare view, and retest behavior.",
            href: "/scans",
          },
          {
            title: "Integrations",
            body: "Slack, Teams, Google Chat, Discord, PagerDuty, Opsgenie, Splunk, Jira, GitHub, and webhooks.",
            href: "/integrations",
          },
          {
            title: "Observability",
            body: "Traces, audit logs, metrics, cost, SLOs, retention, and partition pruning.",
            href: "/observability",
          },
          {
            title: "Change log",
            body: "New capabilities, documentation updates, and platform releases.",
            href: "/resources/overview",
          },
        ],
      },
    ],
  },
  {
    label: "Support",
    eyebrow: "Help and contact",
    title: "Get the right help for security work",
    body: "Reach the team for onboarding, enterprise deployments, security disclosures, partnerships, support, and compliance conversations.",
    cta: {
      title: "Contact support",
      body: "Send an enquiry to the Pencheff team.",
      href: "/enquiries",
    },
    quickLinks: [
      {
        title: "Security disclosure",
        body: "Responsible disclosure and vulnerability reporting.",
        href: "/audience/security-disclosures",
      },
      {
        title: "Trust and compliance",
        body: "Program controls, evidence posture, and compliance focus.",
        href: "/compliance",
      },
      {
        title: "Partners",
        body: "Pentest triage, channel work, and managed security workflows.",
        href: "/company/our-partners",
      },
      {
        title: "API keys",
        body: "Manage credentials and automation access.",
        href: "/settings/api-keys",
      },
    ],
    groups: [
      {
        title: "Operational Help",
        items: [
          {
            title: "Self-hosting",
            body: "Deployment notes for web, API, workers, database, and observability.",
            href: "/resources/overview",
          },
          {
            title: "Integrations support",
            body: "Configure notifications, ticketing, webhooks, SIEM, and source-control workflows.",
            href: "/integrations",
          },
          {
            title: "Onboarding",
            body: "Set up workspace, targets, roles, schedules, and first reports.",
            href: "/onboarding",
          },
        ],
      },
      {
        title: "Company",
        items: [
          {
            title: "Our discipline",
            body: "How Pencheff thinks about methodology, evidence, and engineering.",
            href: "/company/our-discipline",
          },
          {
            title: "Auditors",
            body: "Guidance for readers validating scope, evidence, and compliance output.",
            href: "/company/our-auditors",
          },
          {
            title: "Case studies",
            body: "Examples of how programs use Pencheff across security workflows.",
            href: "/company/case-studies",
          },
          {
            title: "Brand and press",
            body: "Company identity, press references, and approved language.",
            href: "/company/newsroom",
          },
        ],
      },
    ],
  },
  {
    label: "Company",
    eyebrow: "About Pencheff",
    title: "The practice behind the platform",
    body: "Pencheff is built around the principle that evidence-backed, adversarial testing should be as rigorous as a formal audit — readable by engineers, executives, and compliance teams on the same page.",
    cta: {
      title: "Contact us",
      body: "Send an enquiry to the Pencheff team.",
      href: "/enquiries",
    },
    quickLinks: [
      {
        title: "Our discipline",
        body: "How Pencheff thinks about methodology, evidence, and engineering.",
        href: "/company/our-discipline",
      },
      {
        title: "Trust and compliance",
        body: "Program controls, evidence posture, and compliance focus.",
        href: "/compliance",
      },
      {
        title: "Contact",
        body: "Direct correspondence with the Pencheff team.",
        href: "/company/contact",
      },
      {
        title: "Careers",
        body: "Open positions and the standing committee.",
        href: "/company/careers",
      },
    ],
    groups: [
      {
        title: "Our Practice",
        items: [
          {
            title: "Our discipline",
            body: "How Pencheff thinks about methodology, evidence, and engineering.",
            href: "/company/our-discipline",
          },
          {
            title: "Our auditors",
            body: "Guidance for readers validating scope, evidence, and compliance output.",
            href: "/company/our-auditors",
          },
          {
            title: "Our partners",
            body: "Implementation specialists, channel partners, and managed security workflows.",
            href: "/company/our-partners",
          },
          {
            title: "Case studies",
            body: "Examples of how programs use Pencheff across security workflows.",
            href: "/company/case-studies",
          },
          {
            title: "Trust and compliance",
            body: "SOC 2, ISO 27001, and GDPR posture with program controls evidence.",
            href: "/compliance",
          },
        ],
      },
      {
        title: "Correspondence",
        items: [
          {
            title: "Newsroom",
            body: "Press coverage, bulletins, and platform announcements.",
            href: "/company/newsroom",
          },
          {
            title: "Contact",
            body: "Direct correspondence with the Pencheff team.",
            href: "/company/contact",
          },
          {
            title: "Careers",
            body: "Open positions and the standing committee.",
            href: "/company/careers",
          },
          {
            title: "Leadership",
            body: "The editorial board and founding team.",
            href: "/company/leadership",
          },
          {
            title: "Brand and press",
            body: "Logos, likeness, approved language, and press kit.",
            href: "/company/newsroom",
          },
        ],
      },
    ],
  },
];

export function slugifyNavTitle(value: string) {
  return value
    .toLowerCase()
    .replace(/&/g, "and")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export function getMenuSlug(label: string) {
  return slugifyNavTitle(label);
}

export function getMenuOverviewHref(menu: NavMenu | string) {
  const label = typeof menu === "string" ? menu : menu.label;
  return `/${getMenuSlug(label)}/overview`;
}

export function getNavItemHref(menu: NavMenu | string, item: NavItem | string) {
  const label = typeof menu === "string" ? menu : menu.label;
  const title = typeof item === "string" ? item : item.title;
  return `/${getMenuSlug(label)}/${slugifyNavTitle(title)}`;
}

export type MarketingTopic = {
  menu: NavMenu;
  item: NavItem;
  slug: string;
  href: string;
  groupTitle: string;
  isOverview?: boolean;
};

export function getMarketingTopics() {
  return NAV_MENUS.flatMap((menu) => {
    const overview: MarketingTopic = {
      menu,
      item: {
        title: `${menu.label} overview`,
        body: menu.body,
        href: getMenuOverviewHref(menu),
      },
      slug: "overview",
      href: getMenuOverviewHref(menu),
      groupTitle: menu.eyebrow,
      isOverview: true,
    };
    const cta: MarketingTopic = {
      menu,
      item: menu.cta,
      slug: slugifyNavTitle(menu.cta.title),
      href: getNavItemHref(menu, menu.cta),
      groupTitle: "Featured action",
    };
    const quick = menu.quickLinks.map((item) => ({
      menu,
      item,
      slug: slugifyNavTitle(item.title),
      href: getNavItemHref(menu, item),
      groupTitle: "Featured",
    }));
    const grouped = menu.groups.flatMap((group) =>
      group.items.map((item) => ({
        menu,
        item,
        slug: slugifyNavTitle(item.title),
        href: getNavItemHref(menu, item),
        groupTitle: group.title,
      })),
    );
    return [overview, cta, ...quick, ...grouped];
  });
}

export function getMarketingTopic(menuSlug: string, itemSlug: string) {
  return getMarketingTopics().find(
    (topic) =>
      getMenuSlug(topic.menu.label) === menuSlug && topic.slug === itemSlug,
  );
}

export function getTopicsForMenu(menuSlug: string) {
  return getMarketingTopics().filter(
    (topic) => getMenuSlug(topic.menu.label) === menuSlug,
  );
}

// An "alias" topic is a nav entry whose data-supplied ``item.href`` points
// somewhere other than the auto-built ``/<menuSlug>/<slug>`` route. These
// entries exist so the marketing menu can reuse a single concept (e.g.
// "Agent swarms") across multiple menus while still linking to one canonical
// page (e.g. ``/platform/agent-swarms``). The auto-built alias URL is not
// where users navigate — but Next.js was still pre-rendering it under
// /<menuSlug>/<slug>, which produced near-duplicate content and caused
// Google to mark them as "Alternate page with proper canonical tag" or
// "Excluded by noindex" (GSC Page Indexing report 2026-05-18).
//
// Now: alias topics are skipped from static-param generation, served with
// a permanent redirect to the canonical destination, and excluded from
// the sitemap. Self-canonical topics (item.href === topic.href, or no
// explicit item.href on overview entries) still render normally.
export function isAliasTopic(topic: MarketingTopic): boolean {
  const itemHref = topic.item?.href;
  if (!itemHref) return false;
  if (itemHref.startsWith("#")) return true; // anchor-only — alias to overview
  return itemHref !== topic.href;
}

export function aliasTarget(topic: MarketingTopic): string {
  const itemHref = topic.item.href;
  if (itemHref.startsWith("#")) {
    // Anchor-only: send the user to the menu overview with the anchor
    // preserved so the in-page jump still works.
    return `${getMenuOverviewHref(topic.menu)}${itemHref}`;
  }
  return itemHref;
}
