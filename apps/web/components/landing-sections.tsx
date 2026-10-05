import Link from "next/link";
import { LandingFAQ } from "@/components/landing-faq";

const PILLARS = [
  {
    n: "01",
    label: "Methodology",
    title: "An assessment, not a scan.",
    body: "Pencheff follows an adversarial methodology modelled on manual penetration testing — reconnaissance, authenticated coverage, business-logic probing, and exploit chaining — delivered with the consistency of automation.",
    href: "#process",
    foot: "Read the procedure",
  },
  {
    n: "02",
    label: "Coverage",
    title: "Forty-nine instruments. One verdict.",
    body: "Injection, access control, authentication, cryptography, client-side, infrastructure, cloud, and API — examined with Pencheff's first-party probes. Auxiliary tools are optional and operator-managed.",
    href: "#coverage",
    foot: "See the instruments",
  },
  {
    n: "03",
    label: "Reporting",
    title: "Audit-ready, the moment it finishes.",
    body: "Every assessment yields a formal report with executive summary, letter grade, and evidence — mapped to OWASP Top 10, SOC 2, PCI-DSS, NIST 800-53, ISO 27001, and HIPAA categories.",
    href: "#deliverables",
    foot: "Inspect a dossier",
  },
];

const PHASES = [
  {
    ord: "PHASE 01 / V",
    name: "Reconnaissance",
    desc: "Passive enumeration: subdomains, DNS, certificate transparency, public artefacts, technology fingerprint.",
    p: 0.92,
  },
  {
    ord: "PHASE 02 / V",
    name: "Surface Mapping",
    desc: "Authenticated and unauthenticated crawls, API discovery, endpoint inventory, parameter cataloguing.",
    p: 0.86,
  },
  {
    ord: "PHASE 03 / V",
    name: "Probing",
    desc: "Forty-nine instruments fired against the surface — injection, access control, OAuth, cloud, business logic.",
    p: 0.78,
  },
  {
    ord: "PHASE 04 / V",
    name: "Verification",
    desc: "Each finding re-fired with crafted payloads. Request and response evidence captured. False positives discarded.",
    p: 0.66,
  },
  {
    ord: "PHASE 05 / V",
    name: "Exploit Chaining",
    desc: "Single findings composed into multi-step attacks: SSRF → metadata, XSS → session theft, IDOR → privilege escalation.",
    p: 0.42,
  },
];

const INSTRUMENTS: Array<[string, string, string]> = [
  ["R-01", "Passive Reconnaissance", "Recon"],
  ["R-02", "Active Surface Discovery", "Recon"],
  ["R-03", "API Discovery", "Recon"],
  ["I-07", "SQL Injection", "Injection"],
  ["I-09", "Command Injection", "Injection"],
  ["A-03", "Broken Authentication", "Auth"],
  ["A-08", "OAuth & OIDC Flaws", "Auth"],
  ["Z-04", "Broken Access Control", "Authz"],
  ["Z-11", "Insecure Direct Object Reference", "Authz"],
  ["C-02", "Reflected & Stored XSS", "Client"],
  ["C-05", "DOM-based XSS", "Client"],
  ["X-01", "XML External Entity", "Injection"],
  ["S-06", "Server-Side Request Forgery", "Server"],
  ["F-03", "File Upload & Path Traversal", "File"],
  ["K-02", "Cloud Metadata Exposure", "Cloud"],
  ["B-04", "Business-Logic Probing", "Business"],
  ["Y-08", "Subdomain Takeover", "Infrastructure"],
  ["S-01", "Repo scanning (Semgrep + OSV)", "Supply chain"],
  ["S-02", "SBOM generation (SPDX/CycloneDX)", "Supply chain"],
  ["M-01", "Threat model (STRIDE/DREAD)", "Model"],
  ["L-01", "LLM red team (OWASP LLM Top 10)", "AI"],
  ["Σ-01", "Agent swarm execution", "AI"],
];

const CHAPTERS = [
  {
    ord: "Step 01 — Register",
    title: "Provide a target.",
    body: "Provide a target URL and, optionally, credentials for authenticated coverage. All secrets are encrypted at rest.",
  },
  {
    ord: "Step 02 — Assess",
    title: "Commission the engagement.",
    body: "Commission a quick, standard, or deep assessment. Progress streams live; stages are logged for review.",
  },
  {
    ord: "Step 03 — Review",
    title: "Triage with evidence.",
    body: "Triage findings with full request/response evidence. Re-examine any finding after remediation with a single action.",
  },
  {
    ord: "Step 04 — Remediate",
    title: "Close the file.",
    body: "Download a formal DOCX or PDF report, dispatch to ticketing, and close out with verified evidence.",
  },
];

type TierBullet = string;
type Tier = {
  id: string;
  eyebrow: string;
  eyebrowGilt?: boolean;
  name: string;
  price: string;
  cadence: string;
  tagline: string;
  bullets: TierBullet[];
  ctaLabel: string;
  ctaHref: string;
  ctaVariant?: "pink" | "lime" | "plain";
  featured?: boolean;
  comingSoon?: boolean;
};

const TIERS: Tier[] = [
  {
    id: "free",
    eyebrow: "Free forever",
    eyebrowGilt: true,
    name: "Free",
    price: "₹0",
    cadence: "/mo · $0",
    tagline:
      "The full platform, metered. Sign up, paste a URL or connect a repo, and run the pipeline with a monthly allowance to see Pencheff in action.",
    bullets: [
      "5 security scans / month",
      "3 AI auto-fixes / month (Instant model)",
      "Web DAST — full OWASP Top 10 coverage with manual-grade exploitation",
      "Repo scanning (GitHub URL or local folder) — Semgrep OSS + OSV advisories",
      "Secrets detection (gitleaks), YARA, Trivy IaC, Checkov",
      "SBOM generation (SPDX 2.3, CycloneDX 1.5) for dependency evidence bundles",
      "Threat models (STRIDE / DREAD) attached to engagements",
      "Compliance mapping (OWASP · PCI-DSS · SOC 2 · NIST · ISO 27001 · HIPAA)",
      "Formal DOCX & PDF reports, JSON & CSV export",
      "Per-finding re-examination, suppression, and workflow",
      "Role-based access (owner · admin · member)",
    ],
    ctaLabel: "Open an account",
    ctaHref: "/signup",
    ctaVariant: "pink",
    featured: true,
  },
  {
    id: "pro",
    eyebrow: "Most popular",
    name: "Pro",
    price: "₹499",
    cadence: "/mo · $5.99",
    tagline:
      "Pencheff doesn't just find vulnerabilities — it fixes them. The Expert model, a generous monthly allowance, and verified pull requests.",
    bullets: [
      "20 security scans / month",
      "40 AI auto-fixes / month (Expert model)",
      "Automated remediation — opens a single PR that fixes every triaged finding",
      "DAST exploitation — proves impact with verified PoCs, not scanner noise",
      "SAST auto-patching — semantic, reviewer-friendly diffs grounded in scanner evidence",
      "AI Triage 2.0 — per-finding walkthroughs and grading",
      "Priority correspondence and a private Slack channel",
    ],
    ctaLabel: "Upgrade to Pro",
    ctaHref: "/signup?plan=pro",
    ctaVariant: "pink",
  },
  {
    id: "team",
    eyebrow: "For organisations",
    name: "Team",
    price: "Custom",
    cadence: "talk to us",
    tagline:
      "When security is a shared responsibility. Unlimited workspaces, unlimited seats, dedicated support, and the full Pro feature set at general availability.",
    bullets: [
      "Unlimited workspaces, seats, and registered targets",
      "Branded reporting & custom compliance mappings",
      "Single sign-on (SAML / OIDC)",
      "Dedicated Slack correspondence channel",
      "Priority vulnerability response & onboarding",
      "Full automated remediation pipeline at general availability with SLAs",
      "Custom data residency & deployment options",
    ],
    ctaLabel: "Contact us",
    ctaHref:
      "mailto:hello@pencheff.com?subject=Pencheff%20Team%20enquiry",
    ctaVariant: "pink",
  },
];

const TECH_ITEMS = [
  "Request & response evidence for every finding.",
  "CVSS 3.1 score and vector.",
  "CWE classification.",
  "Remediation guidance with illustrative code.",
  "On-demand re-examination to confirm a fix.",
];

const EXEC_ITEMS = [
  "Executive summary with letter grade and severity counts.",
  "Findings mapped to OWASP Top 10 (2021) categories.",
  "SOC 2 CC6 / CC7 control mapping.",
  "PCI-DSS 4.0, NIST 800-53, ISO 27001:2022, HIPAA mapping.",
  "Audit-ready DOCX and PDF.",
];

const COMPARISON_ROWS: {
  label: string;
  cells: { value: string; variant?: "present" | "absent" | "plain" }[];
}[] = [
  {
    label: "Web DAST (OWASP Top 10, exploitation-grade)",
    cells: [
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
    ],
  },
  {
    label: "Repo scanning — Semgrep OSS + OSV advisories",
    cells: [
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
    ],
  },
  {
    label: "IaC + container scanning (Trivy, Checkov)",
    cells: [
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
    ],
  },
  {
    label: "Authenticated assessments (encrypted credentials)",
    cells: [
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
    ],
  },
  {
    label: "Compliance mapping (OWASP · PCI · SOC 2 · NIST · ISO · HIPAA)",
    cells: [
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
    ],
  },
  {
    label: "Formal DOCX & PDF reports",
    cells: [
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
      { value: "Branded", variant: "plain" },
    ],
  },
  {
    label: "Automated remediation — fix-PR for every finding",
    cells: [
      { value: "—", variant: "absent" },
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
    ],
  },
  {
    label: "DAST exploitation — verified PoCs",
    cells: [
      { value: "—", variant: "absent" },
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
    ],
  },
  {
    label: "SAST Auto-Patching (semantic diffs)",
    cells: [
      { value: "—", variant: "absent" },
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
    ],
  },
  {
    label: "Continuous scan-on-push loop",
    cells: [
      { value: "—", variant: "absent" },
      { value: "·", variant: "present" },
      { value: "·", variant: "present" },
    ],
  },
  {
    label: "Single sign-on (SAML / OIDC)",
    cells: [
      { value: "—", variant: "absent" },
      { value: "—", variant: "absent" },
      { value: "·", variant: "present" },
    ],
  },
  {
    label: "Dedicated Slack channel & priority response",
    cells: [
      { value: "—", variant: "absent" },
      { value: "—", variant: "absent" },
      { value: "·", variant: "present" },
    ],
  },
  {
    label: "Custom data residency & deployment",
    cells: [
      { value: "—", variant: "absent" },
      { value: "—", variant: "absent" },
      { value: "·", variant: "present" },
    ],
  },
];

function SecTag({ n, label }: { n: string; label: string }) {
  return (
    <span className="lp-sec-tag lp-fade-up">
      <span className="lp-tag-num">{n}</span>
      <span className="lp-tag-label">{label}</span>
    </span>
  );
}

function TierCtaButton({ tier }: { tier: Tier }) {
  const variantClass =
    tier.ctaVariant === "pink"
      ? "lp-btn-pink"
      : tier.ctaVariant === "lime"
        ? "lp-btn-lime"
        : "";
  if (tier.comingSoon) {
    return (
      <span aria-disabled="true" className={`lp-btn ${variantClass}`.trim()}>
        {tier.ctaLabel}
      </span>
    );
  }
  return (
    <Link
      className={`lp-btn lp-btn-arrow ${variantClass}`.trim()}
      href={tier.ctaHref}
    >
      {tier.ctaLabel}
    </Link>
  );
}

export function LandingPillarsSection() {
  return (
    <section className="lp-pillars" id="methodology">
      <div className="lp-shell">
        <div className="lp-pillars-head">
          <div>
            <SecTag n="01." label="The methodology" />
            <h2 className="lp-h-section lp-fade-up">
              A discipline, <span className="lp-italic-gilt">not a scan.</span>
            </h2>
          </div>
          <div>
            <p
              className="lp-lede lp-fade-up"
              style={{ ["--lp-d" as string]: "200ms" } as React.CSSProperties}
            >
              Pencheff is built around three orthogonal commitments —
              methodology, coverage, and reporting. Each is enforced by the
              engine, not the operator.
            </p>
          </div>
        </div>

        <div className="lp-pillars-grid">
          {PILLARS.map((p, i) => (
            <article
              key={p.n}
              className="lp-pillar lp-fade-spring"
              style={
                { ["--lp-d" as string]: `${i * 120}ms` } as React.CSSProperties
              }
            >
              <span className="lp-pillar-tag">
                <span>{p.n}</span> {p.label}
              </span>
              <h3>{p.title}</h3>
              <p>{p.body}</p>
              <Link className="lp-pillar-foot" href={p.href}>
                {p.foot}
              </Link>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

export function LandingPhasesSection() {
  return (
    <section className="lp-phases">
      <div className="lp-blob lp-blob-gilt lp-blob-x" aria-hidden />
      <div className="lp-shell">
        <div className="lp-phases-head">
          <div>
            <SecTag n="02." label="The adversarial cycle" />
            <h2
              className="lp-h-section lp-fade-up"
              style={{ ["--lp-d" as string]: "80ms" } as React.CSSProperties}
            >
              Five phases, <span className="lp-italic-gilt">in lockstep.</span>
            </h2>
          </div>
          <p
            className="lp-lede lp-fade-up"
            style={{ ["--lp-d" as string]: "200ms" } as React.CSSProperties}
          >
            Each engagement traces the same adversarial path — from passive
            reconnaissance to multi-step exploit chaining — so that two
            assessments of the same target, six months apart, are directly
            comparable.
          </p>
        </div>

        <div className="lp-phase-track" role="list">
          {PHASES.map((ph, i) => (
            <article
              key={ph.name}
              className="lp-phase lp-fade-spring"
              role="listitem"
              style={
                {
                  ["--lp-d" as string]: `${i * 120}ms`,
                  ["--lp-p" as string]: ph.p,
                } as React.CSSProperties
              }
            >
              <span className="lp-phase-ord">{ph.ord}</span>
              <h4 className="lp-phase-name">{ph.name}</h4>
              <p className="lp-phase-desc">{ph.desc}</p>
              <div className="lp-phase-meter" aria-hidden />
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

export function LandingCoverageSection() {
  return (
    <section className="lp-coverage" id="coverage">
      <div className="lp-blob lp-blob-royal lp-blob-x" aria-hidden />
      <div className="lp-shell">
        <div className="lp-coverage-head">
          <div>
            <SecTag n="03." label="The Pencheff battery" />
            <h2
              className="lp-h-section lp-fade-up"
              style={{ ["--lp-d" as string]: "80ms" } as React.CSSProperties}
            >
              A library of probes, each{" "}
              <span className="lp-italic-gilt">authored by hand.</span>
            </h2>
          </div>
          <p
            className="lp-lede lp-fade-up"
            style={{ ["--lp-d" as string]: "200ms" } as React.CSSProperties}
          >
            Forty-nine first-party instruments cover the modern attack surface —
            injection, access control, authentication, cryptography,
            client-side, infrastructure, cloud, and API — and can be composed
            with repo scanning, threat models, compliance rollups, SBOM output,
            and LLM red team workflows. Auxiliary tools (nmap, sqlmap, nuclei,
            ffuf, hydra, nikto) remain optional and operator-managed.
          </p>
        </div>

        <div className="lp-coverage-counter">
          <div className="lp-big lp-num">
            <span data-count-to="49">0</span>
            <span className="lp-italic-gilt"></span>
          </div>
          <p className="lp-counter-desc lp-fade-up">
            First-party probes — exhaustively catalogued, individually verified,
            weighted by severity. Re-examination of any finding is unlimited on
            every plan.
          </p>
          <div className="lp-counter-legend">
            <div>1 / 49</div>
            <div style={{ marginTop: 6, color: "var(--lp-gilt-deep)" }}>
              Composing the Pencheff Battery
            </div>
          </div>
        </div>

        <div className="lp-coverage-grid" id="coverage-grid">
          {INSTRUMENTS.map((it, i) => (
            <article
              key={it[0]}
              className="lp-instr lp-fade-spring"
              style={
                { ["--lp-d" as string]: `${i * 40}ms` } as React.CSSProperties
              }
            >
              <span className="lp-instr-num">{it[0]}</span>
              <div>
                <div className="lp-instr-name">{it[1]}</div>
                <div className="lp-instr-cat">{it[2]}</div>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

export function LandingProcessSection() {
  return (
    <section className="lp-process" id="process">
      <div className="lp-blob lp-blob-gilt lp-blob-1" aria-hidden />
      <div className="lp-blob lp-blob-ink lp-blob-2" aria-hidden />
      <div className="lp-shell">
        <div className="lp-process-head">
          <div>
            <SecTag n="04." label="The procedure" />
            <h2
              className="lp-h-section lp-fade-up"
              style={{ ["--lp-d" as string]: "80ms" } as React.CSSProperties}
            >
              Four steps,{" "}
              <span className="lp-italic-gilt">every engagement.</span>
            </h2>
          </div>
          <p
            className="lp-lede lp-fade-up"
            style={{ ["--lp-d" as string]: "200ms" } as React.CSSProperties}
          >
            From registration to remediation, the same procedure governs every
            assessment — so that the engineer who runs it, the operator who
            reviews it, and the auditor who reads it are all working from the
            same record.
          </p>
        </div>

        <div className="lp-process-rail">
          {CHAPTERS.map((c, i) => (
            <article
              key={c.title}
              className="lp-step lp-fade-spring"
              style={
                { ["--lp-d" as string]: `${i * 140}ms` } as React.CSSProperties
              }
            >
              <div className="lp-marker lp-mono"></div>
              <div className="lp-step-ord">{c.ord}</div>
              <h3>{c.title}</h3>
              <p>{c.body}</p>
            </article>
          ))}
        </div>
      </div>

      <div className="lp-stats" aria-label="Engagement metrics">
        <div className="lp-shell">
          <div className="lp-stats-grid">
            <div className="lp-stat lp-fade-spring">
              <div className="lp-stat-num">
                <span className="lp-num" data-count-to="49">
                  0
                </span>
              </div>
              <div className="lp-stat-lab">
                First-party instruments per assessment.
              </div>
            </div>
            <div
              className="lp-stat lp-fade-spring"
              style={{ ["--lp-d" as string]: "120ms" } as React.CSSProperties}
            >
              <div className="lp-stat-num">
                <span className="lp-num" data-count-to="6">
                  0
                </span>
                <span className="lp-italic-gilt">/6</span>
              </div>
              <div className="lp-stat-lab">
                Compliance frameworks mapped to every finding — OWASP, PCI, SOC
                2, NIST, ISO, HIPAA.
              </div>
            </div>
            <div
              className="lp-stat lp-fade-spring"
              style={{ ["--lp-d" as string]: "240ms" } as React.CSSProperties}
            >
              <div className="lp-stat-num">
                <span className="lp-num" data-count-to="1">
                  0
                </span>
              </div>
              <div className="lp-stat-lab">
                Letter grade verdict per engagement, audit-ready.
              </div>
            </div>
            <div
              className="lp-stat lp-fade-spring"
              style={{ ["--lp-d" as string]: "360ms" } as React.CSSProperties}
            >
              <div className="lp-stat-num">
                <span className="lp-num">∞</span>
              </div>
              <div className="lp-stat-lab">
                Re-examinations per finding, per workspace, per engagement — on
                every plan, free forever.
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export function LandingPricingSection({
  ctaHref = "/#pricing",
}: {
  ctaHref?: string;
}) {
  return (
    <section className="lp-pricing" id="pricing">
      <div className="lp-blob lp-blob-gilt lp-blob-x" aria-hidden />
      <div className="lp-shell">
        <div className="lp-pricing-head">
          <div>
            <SecTag n="05." label="Subscriptions" />
            <h2
              className="lp-h-section lp-fade-up"
              style={{ ["--lp-d" as string]: "80ms" } as React.CSSProperties}
            >
              Free during beta. Automated remediation lands on{" "}
              <span className="lp-italic-gilt">Pro.</span>
            </h2>
          </div>
          <p
            className="lp-lede lp-fade-up"
            style={{ ["--lp-d" as string]: "200ms" } as React.CSSProperties}
          >
            Pencheff is in <em>open beta</em>. Every feature is unlocked at the
            Free tier today — DAST, SAST, IaC, container scanning, compliance
            reporting, the lot. Pro adds automated remediation that
            doesn&rsquo;t just find vulnerabilities, it fixes them with verified
            pull requests. Team is for organisations that need unlimited scale
            and dedicated support.
          </p>
        </div>

        <div className="lp-tier-grid">
          {TIERS.map((t, i) => {
            const hrefTier = t.id === "pro" ? { ...t, ctaHref } : t;
            return (
              <article
                key={t.id}
                className={`lp-tier lp-fade-spring${t.featured ? " lp-featured" : ""}${t.comingSoon ? " lp-coming-soon" : ""}`}
                style={
                  {
                    ["--lp-d" as string]: `${i * 120}ms`,
                  } as React.CSSProperties
                }
              >
                {t.featured && <div className="lp-gilt-ribbon">Open beta</div>}
                <span
                  className={`lp-eyebrow lp-tier-eyebrow${t.eyebrowGilt ? " lp-eyebrow-gilt" : ""}`}
                >
                  {t.eyebrow}
                </span>
                <h3 className="lp-name">{t.name}</h3>
                <div className="lp-price-row">
                  <span className="lp-price">{t.price}</span>
                  <span className="lp-cadence">{t.cadence}</span>
                </div>
                <p className="lp-tagline">{t.tagline}</p>
                <ul>
                  {t.bullets.map((b) => (
                    <li key={b}>{b}</li>
                  ))}
                </ul>
                <div className="lp-cta-slot">
                  <TierCtaButton tier={hrefTier} />
                </div>
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}

export function LandingDeliverablesSection() {
  return (
    <section className="lp-deliverables" id="deliverables">
      <div className="lp-shell">
        <div className="lp-del-head">
          <div>
            <SecTag n="06." label="Deliverables" />
            <h2
              className="lp-h-section lp-fade-up"
              style={{ ["--lp-d" as string]: "80ms" } as React.CSSProperties}
            >
              Contents of the{" "}
              <span className="lp-italic-gilt">formal report.</span>
            </h2>
          </div>
          <p
            className="lp-lede lp-fade-up"
            style={{ ["--lp-d" as string]: "200ms" } as React.CSSProperties}
          >
            Two dossiers, issued together. Engineering receives the technical
            record; audit and executive readers receive the framework-mapped
            summary. Bound by a single grade and a single date of issue.
          </p>
        </div>

        <div className="lp-del-grid">
          <article className="lp-del-card lp-fade-spring">
            <span className="lp-stamp">For Engineering</span>
            <div className="lp-kicker">Card A</div>
            <h3>
              The technical <em>dossier.</em>
            </h3>
            <ol>
              {TECH_ITEMS.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ol>
          </article>

          <article
            className="lp-del-card lp-fade-spring"
            style={{ ["--lp-d" as string]: "160ms" } as React.CSSProperties}
          >
            <span className="lp-stamp">For Executive</span>
            <div className="lp-kicker">Card B</div>
            <h3>
              The executive <em>dossier.</em>
            </h3>
            <ol>
              {EXEC_ITEMS.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ol>
          </article>
        </div>
      </div>
    </section>
  );
}

export function LandingComparisonSection() {
  return (
    <section className="lp-comparison" id="comparison">
      <div className="lp-shell">
        <div className="lp-cmp-head">
          <SecTag n="07." label="Comparison" />
          <h2
            className="lp-h-section lp-fade-up"
            style={{ ["--lp-d" as string]: "80ms" } as React.CSSProperties}
          >
            Subscription tiers{" "}
            <span className="lp-italic-gilt">in detail.</span>
          </h2>
        </div>

        <div className="lp-cmp-wrap lp-fade-up">
          <table className="lp-cmp-table">
            <thead>
              <tr>
                <th style={{ width: "44%" }}>Provision</th>
                <th className="lp-tier-th lp-featured-th">
                  Free
                  <span className="lp-tsub">$0 · during beta</span>
                </th>
                <th className="lp-tier-th">
                  Pro
                  <span className="lp-tsub">Coming soon</span>
                </th>
                <th className="lp-tier-th">
                  Team
                  <span className="lp-tsub">Custom</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {COMPARISON_ROWS.map((row) => (
                <tr key={row.label}>
                  <td className="lp-feature">{row.label}</td>
                  {row.cells.map((c, idx) => (
                    <td key={idx} className="lp-cell">
                      {c.variant === "present" ? (
                        <span className="lp-yes">·</span>
                      ) : c.variant === "absent" ? (
                        <span className="lp-no">—</span>
                      ) : (
                        <span className="lp-partial">{c.value}</span>
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

export function LandingEnquiriesSection() {
  return (
    <section className="lp-faq" id="enquiries">
      <div className="lp-shell">
        <div className="lp-faq-head">
          <div>
            <SecTag n="08." label="Enquiries" />
            <h2
              className="lp-h-section lp-fade-up"
              style={{ ["--lp-d" as string]: "80ms" } as React.CSSProperties}
            >
              Frequently considered{" "}
              <span className="lp-italic-gilt">questions.</span>
            </h2>
          </div>
          <p
            className="lp-lede lp-fade-up"
            style={{ ["--lp-d" as string]: "200ms" } as React.CSSProperties}
          >
            Direct answers — on authorisation, scope, plans, audit acceptance,
            self-hosting, and credential handling. For anything else, write to
            us.
          </p>
        </div>

        <LandingFAQ />
      </div>
    </section>
  );
}

export function LandingClosingSection() {
  return (
    <section className="lp-closing">
      <div className="lp-blob lp-blob-gilt lp-blob-1" aria-hidden />
      <div className="lp-blob lp-blob-royal lp-blob-2" aria-hidden />
      <div className="lp-shell">
        <div className="lp-closing-grid">
          <div>
            <span className="lp-eyebrow lp-fade-up">Begin</span>
            <h2
              className="lp-h-section lp-fade-up"
              style={
                {
                  ["--lp-d" as string]: "120ms",
                  marginTop: 14,
                } as React.CSSProperties
              }
            >
              Commission your first <em>assessment.</em>
            </h2>
            <p
              className="lp-lede lp-fade-up"
              style={
                {
                  ["--lp-d" as string]: "240ms",
                  marginTop: 18,
                } as React.CSSProperties
              }
            >
              A complimentary assessment takes under three minutes to commission
              and under thirty to complete. No credit card, no sales call.
            </p>
          </div>
          <div
            className="lp-closing-cta lp-fade-up"
            style={{ ["--lp-d" as string]: "360ms" } as React.CSSProperties}
          >
            <Link className="lp-btn lp-btn-arrow" href="/signup">
              Open an account
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}

export function LandingColophon() {
  return (
    <footer className="lp-colophon">
      <div className="lp-shell">
        <div className="lp-colophon-grid">
          <div className="lp-colophon-brand-block lp-fade-up">
            <div className="lp-colophon-brand">
              Pen<span className="lp-italic-gilt">cheff</span>
            </div>
            <p className="lp-colophon-brand-tag">
              An instrument of assurance. Adversarial security assessments
              delivered with the rigour of an audit — issued from the only
              periodical your engineers and auditors will read together.
            </p>
          </div>
          <div className="lp-colophon-cols">
            <div>
              <h5>Methodology</h5>
              <ul>
                <li>
                  <Link href="/platform/methodology-v4-2">Three pillars</Link>
                </li>
                <li>
                  <Link href="/platform/methodology-v4-2#coverage">
                    Forty-nine instruments
                  </Link>
                </li>
                <li>
                  <Link href="/process">Engagement process</Link>
                </li>
                <li>
                  <Link href="/deliverables">Reporting</Link>
                </li>
              </ul>
            </div>
            <div>
              <h5>Periodical</h5>
              <ul>
                <li>
                  <Link href="/enquiries">Enquiries</Link>
                </li>
                <li>
                  <Link href="/resources/overview">
                    Documentation
                  </Link>
                </li>
                <li>
                  <Link href="/resources/repo-scan">Repository (AGPL-3.0)</Link>
                </li>
              </ul>
            </div>
            <div>
              <h5>Account</h5>
              <ul>
                <li>
                  <Link href="/signup">Open an account</Link>
                </li>
                <li>
                  <Link href="/login">Sign in</Link>
                </li>
                <li>
                  <Link href="/dashboard">Dashboard</Link>
                </li>
                <li>
                  <Link href="/audience/security-disclosures">
                    Security disclosures
                  </Link>
                </li>
                <li>
                  <Link href="/privacy">Privacy policy</Link>
                </li>
                <li>
                  <Link href="/terms">Terms & conditions</Link>
                </li>
              </ul>
            </div>
          </div>
        </div>

        <div className="lp-colophon-bar">
          <span>
            Pencheff · {new Date().getFullYear()} · All rights reserved.
          </span>
          <span className="lp-gilt">For authorised testing only.</span>
        </div>
        <p className="lp-colophon-notice">
          Third-party product names are used only for identification. Pencheff
          is not affiliated with, endorsed by, or sponsored by those owners.
          OWASP and OWASP Top 10 are trademarks or service marks of the OWASP
          Foundation; Pencheff is not affiliated with or endorsed by OWASP.
        </p>
      </div>
    </footer>
  );
}
