"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { LogoMark } from "@/components/logo";
import { ThemeToggle } from "@/components/theme-toggle";

// LandingMasthead is exported for backward compatibility but renders nothing —
// the date strip was removed during the design refresh. Kept as a no-op so
// any older import continues to type-check.
export function LandingMasthead() {
  return null;
}

type MegaKey = "platform" | "capabilities" | "ai-security";

type MegaLink = {
  glyph: string;
  title: string;
  desc: string;
  href: string;
  ext?: boolean;
};

type MegaColumn = {
  heading: string;
  links: MegaLink[];
};

const PLATFORM_COLS: MegaColumn[] = [
  {
    heading: "Methodology",
    links: [
      {
        glyph: "",
        title: "Methodology v4.2",
        desc: "The adversarial assessment standard.",
        href: "/platform/methodology-v4-2",
      },
      {
        glyph: "V",
        title: "The Adversarial Cycle",
        desc: "Five phases, every engagement.",
        href: "/platform/the-adversarial-cycle",
      },
      {
        glyph: "¶",
        title: "Engagement Profiles",
        desc: "Quick, Standard, and Deep modes.",
        href: "/platform/engagement-profiles",
      },
    ],
  },
  {
    heading: "Capabilities",
    links: [
      {
        glyph: "W",
        title: "URL Scanning (DAST)",
        desc: "Live web and API exploit testing.",
        href: "/platform/web-dast",
      },
      {
        glyph: "S",
        title: "Repo Scanning",
        desc: "SAST, secrets, and dependency analysis.",
        href: "/platform/sast-and-secrets",
      },
      {
        glyph: "I",
        title: "IaC + Container",
        desc: "Terraform, Kubernetes, and Dockerfile policy.",
        href: "/platform/cloud-and-infrastructure",
      },
      {
        glyph: "A",
        title: "Authenticated Coverage",
        desc: "Session-aware crawling and authz checks.",
        href: "/platform/authenticated-coverage",
      },
      {
        glyph: "T",
        title: "Threat Models",
        desc: "Deterministic STRIDE and DREAD analysis.",
        href: "/platform/threat-models",
      },
      {
        glyph: "R",
        title: "LLM Red Team",
        desc: "OWASP LLM Top 10 attack modules.",
        href: "/platform/llm-red-team",
      },
      {
        glyph: "Σ",
        title: "Agent Swarms",
        desc: "Recon, breaker, and synthesis agents.",
        href: "/platform/agent-swarms",
      },
      {
        glyph: "Ω",
        title: "AI Agents",
        desc: "Tool-calling scan agent for LLM apps.",
        href: "/platform/ai-agents",
      },
      {
        glyph: "E",
        title: "The Engine",
        desc: "Autonomous remediation and auto-patching.",
        href: "/platform/the-engine",
      },
      {
        glyph: "K",
        title: "Cloud & Infrastructure",
        desc: "AWS, Azure, GCP, CSPM, CIEM, DSPM.",
        href: "/platform/cloud-and-infrastructure",
      },
    ],
  },
  {
    heading: "Deliverables",
    links: [
      {
        glyph: "A",
        title: "Letter Grade",
        desc: "Heuristic A–F verdict per assessment.",
        href: "/platform/letter-grade",
      },
      {
        glyph: "†",
        title: "Technical Dossier",
        desc: "Engineering evidence and remediation.",
        href: "/platform/technical-dossier",
      },
      {
        glyph: "‡",
        title: "Executive Dossier",
        desc: "Audit and leadership summary.",
        href: "/platform/executive-dossier",
      },
      {
        glyph: "↻",
        title: "Re-examination",
        desc: "Verify any fix on demand.",
        href: "/platform/re-examination",
      },
      {
        glyph: "↧",
        title: "Export",
        desc: "DOCX, PDF, JSON, CSV, and SBOM.",
        href: "/platform/export",
      },
    ],
  },
];

const CAPABILITIES_COLS: MegaColumn[] = [
  {
    heading: "Dynamic Testing",
    links: [
      {
        glyph: "I",
        title: "Injection coverage",
        desc: "SQLi, command, SSTI, XXE, SSRF, LDAP.",
        href: "/platform/web-dast",
      },
      {
        glyph: "X",
        title: "Client-side security",
        desc: "XSS, CSRF, CORS, clickjacking, redirects.",
        href: "/platform/web-dast",
      },
      {
        glyph: "K",
        title: "Authentication",
        desc: "Sessions, JWT, OAuth, MFA, IDOR.",
        href: "/platform/authenticated-coverage",
      },
      {
        glyph: "A",
        title: "API and SPA coverage",
        desc: "GraphQL, WebSockets, REST, OpenAPI.",
        href: "/platform/web-dast",
      },
      {
        glyph: "~",
        title: "Proxy and fuzzer",
        desc: "Intercepting proxy with OAST callbacks.",
        href: "/platform/web-dast",
      },
    ],
  },
  {
    heading: "Code & Supply Chain",
    links: [
      {
        glyph: "S",
        title: "Language scanners",
        desc: "15+ languages, parallel static analysis.",
        href: "/platform/sast-and-secrets",
      },
      {
        glyph: "G",
        title: "Secrets and malware",
        desc: "gitleaks, YARA, backdoor detection.",
        href: "/capabilities/secrets-and-malware",
      },
      {
        glyph: "↻",
        title: "Auto-fix PRs",
        desc: "Deterministic patches with SARIF output.",
        href: "/platform/re-examination",
      },
      {
        glyph: "C",
        title: "Container gates",
        desc: "Image scans and Kubernetes policy.",
        href: "/platform/cloud-and-infrastructure",
      },
    ],
  },
  {
    heading: "Prioritization",
    links: [
      {
        glyph: "R",
        title: "Reachability",
        desc: "Link findings to live attack paths.",
        href: "/capabilities/overview",
      },
      {
        glyph: "Σ",
        title: "AI triage",
        desc: "Dedup, narratives, and severity reasoning.",
        href: "/capabilities/overview",
      },
      {
        glyph: "A",
        title: "Letter grade",
        desc: "Executive-grade risk scoring.",
        href: "/platform/letter-grade",
      },
      {
        glyph: "T",
        title: "Threat modeling",
        desc: "STRIDE, DREAD, abuse cases.",
        href: "/platform/threat-models",
      },
    ],
  },
];

const AI_SECURITY_COLS: MegaColumn[] = [
  {
    heading: "LLM Red Team",
    links: [
      {
        glyph: "Ω",
        title: "OWASP LLM Top 10",
        desc: "Full coverage of the 2025 standard.",
        href: "/platform/llm-red-team",
      },
      {
        glyph: "↯",
        title: "Attack strategies",
        desc: "Jailbreak corpora and regression suites.",
        href: "/platform/llm-red-team",
      },
      {
        glyph: "⟶",
        title: "Transports",
        desc: "Chat, HTTP, LiteLLM, MCP, chatbots.",
        href: "/platform/llm-red-team",
      },
      {
        glyph: "",
        title: "Evidence and cost",
        desc: "Traces, judges, and token accounting.",
        href: "/ai-security/evidence-and-cost",
      },
    ],
  },
  {
    heading: "Agentic Testing",
    links: [
      {
        glyph: "T",
        title: "Tool authorization",
        desc: "Probe tool calls and privilege boundaries.",
        href: "/platform/ai-agents",
      },
      {
        glyph: "M",
        title: "Memory and context",
        desc: "Exfiltration and retrieval poisoning.",
        href: "/platform/ai-agents",
      },
      {
        glyph: "P",
        title: "Planner attacks",
        desc: "Goal hijacking and policy bypass.",
        href: "/platform/agent-swarms",
      },
      {
        glyph: "Σ",
        title: "Swarm orchestration",
        desc: "Multi-agent recon and exploit roles.",
        href: "/platform/agent-swarms",
      },
    ],
  },
  {
    heading: "Guardrails",
    links: [
      {
        glyph: "G",
        title: "Sentry runtime guardrail",
        desc: "Policy checks on prompts and responses.",
        href: "/platform/ai-agents",
      },
      {
        glyph: "⊕",
        title: "Sidecars and middleware",
        desc: "Proxy, LiteLLM, and MCP enforcement.",
        href: "/platform/ai-agents",
      },
      {
        glyph: "↻",
        title: "Regression tests",
        desc: "Block known jailbreaks after release.",
        href: "/platform/llm-red-team",
      },
    ],
  },
];

function MegaPanel({
  id,
  cols,
  feature,
  newsletter,
  isOpen,
  onMouseEnter,
  onMouseLeave,
  onLinkClick,
}: {
  id: string;
  cols: MegaColumn[];
  feature?: {
    eyebrow: string;
    new?: boolean;
    title: React.ReactNode;
    body: string;
    cta: string;
    href: string;
  };
  newsletter?: { eyebrow: string; title: React.ReactNode; body: string };
  isOpen: boolean;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
  onLinkClick: () => void;
}) {
  const className = `lp-mega${isOpen ? " lp-is-open" : ""}${newsletter ? " lp-has-newsletter" : ""}${feature ? " lp-has-feature" : ""}${feature && !newsletter && cols.length === 2 ? " lp-two-col" : ""}`;
  return (
    <div
      className={className}
      id={id}
      data-mega={id.replace("mega-", "")}
      aria-hidden={!isOpen}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
    >
      <div className="lp-mega-grid">
        {newsletter && (
          <aside className="lp-mega-newsletter">
            <div className="lp-news-eyebrow">{newsletter.eyebrow}</div>
            <h4>{newsletter.title}</h4>
            <p>{newsletter.body}</p>
            <form className="lp-news-form" onSubmit={(e) => e.preventDefault()}>
              <input
                type="email"
                placeholder="your@correspondence.com"
                aria-label="Email address"
              />
              <button type="submit" className="lp-news-btn">
                Subscribe to the periodical
              </button>
            </form>
          </aside>
        )}

        {cols.map((col, ci) => (
          <div className="lp-mega-col" key={`${id}-${ci}`}>
            <h6>{col.heading}</h6>
            <div
              className={`lp-mega-col-stack${
                col.links.length > 6 ? " lp-mega-scroll" : ""
              }`}
            >
              {col.links.map((l, li) => {
                const delay = 120 + (ci * col.links.length + li) * 32;
                const isExternal =
                  l.ext ||
                  /^https?:/.test(l.href) ||
                  l.href.startsWith("mailto:");
                const props = {
                  className: "lp-mega-link",
                  style: {
                    ["--lp-md" as string]: `${delay}ms`,
                  } as React.CSSProperties,
                  onClick: onLinkClick,
                };
                const inner = (
                  <>
                    <span className="lp-mega-glyph">{l.glyph}</span>
                    <div>
                      <div className="lp-mega-link-title">
                        {l.title}
                        {l.ext && <span className="lp-ext">↗</span>}
                      </div>
                      <div className="lp-mega-link-desc">{l.desc}</div>
                    </div>
                  </>
                );
                return isExternal ? (
                  <a
                    key={l.title}
                    href={l.href}
                    target={l.ext ? "_blank" : undefined}
                    rel={l.ext ? "noreferrer" : undefined}
                    {...props}
                  >
                    {inner}
                  </a>
                ) : (
                  <Link key={l.title} href={l.href} {...props}>
                    {inner}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}

        {feature && (
          <aside className="lp-mega-feature">
            <div>
              <div className="lp-feature-eyebrow">
                {feature.eyebrow}
                {feature.new && <span className="lp-feature-new">New</span>}
              </div>
              <h4>{feature.title}</h4>
              <p>{feature.body}</p>
            </div>
            <Link
              className="lp-feature-cta"
              href={feature.href}
              onClick={onLinkClick}
            >
              {feature.cta}
            </Link>
          </aside>
        )}
      </div>
    </div>
  );
}

export function LandingNav() {
  const [openKey, setOpenKey] = useState<MegaKey | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [mobileSection, setMobileSection] = useState<MegaKey | "root" | null>(
    null,
  );
  const closeTimer = useRef<number | null>(null);
  const openTimers = useRef<Record<string, number>>({});

  const HOVER_DELAY = 80;
  const CLOSE_DELAY = 220;

  function cancelClose() {
    if (closeTimer.current) {
      window.clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
  }
  function scheduleClose() {
    cancelClose();
    closeTimer.current = window.setTimeout(() => setOpenKey(null), CLOSE_DELAY);
  }
  function scheduleOpen(key: MegaKey) {
    cancelClose();
    if (openTimers.current[key]) window.clearTimeout(openTimers.current[key]);
    openTimers.current[key] = window.setTimeout(
      () => setOpenKey(key),
      HOVER_DELAY,
    );
  }
  function cancelScheduledOpen(key: MegaKey) {
    if (openTimers.current[key]) {
      window.clearTimeout(openTimers.current[key]);
      delete openTimers.current[key];
    }
  }
  function toggle(key: MegaKey) {
    cancelClose();
    setOpenKey((curr) => (curr === key ? null : key));
  }
  function close() {
    cancelClose();
    setOpenKey(null);
    setMobileOpen(false);
    setMobileSection(null);
  }

  // Escape key to close
  useEffect(() => {
    if (!openKey) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") close();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openKey]);

  // Close on big scroll
  useEffect(() => {
    if (!openKey) return;
    let lastY = window.scrollY;
    function onScroll() {
      if (Math.abs(window.scrollY - lastY) > 80) {
        close();
      }
      lastY = window.scrollY;
    }
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, [openKey]);

  function trigger(key: MegaKey, label: string) {
    return (
      <div
        className={`lp-nav-item${openKey === key ? " lp-is-open" : ""}`}
        onMouseEnter={() => scheduleOpen(key)}
        onMouseLeave={() => {
          cancelScheduledOpen(key);
          scheduleClose();
        }}
      >
        <button
          type="button"
          className="lp-nav-trigger"
          aria-haspopup="true"
          aria-expanded={openKey === key}
          aria-controls={`mega-${key}`}
          onClick={() => toggle(key)}
        >
          {label}
          <span className="lp-caret" aria-hidden>
            ▾
          </span>
        </button>
      </div>
    );
  }

  return (
    <>
      <div
        className={`lp-mega-backdrop${openKey ? " lp-open" : ""}`}
        aria-hidden
        onClick={close}
      />

      <div
        className={`lp-mobile-backdrop${mobileOpen ? " lp-open" : ""}`}
        aria-hidden
        onClick={close}
      />

      <div className={`lp-mobile-sheet${mobileOpen ? " lp-open" : ""}`}>
        <div className="lp-mobile-head">
          <div className="lp-mobile-title">Pencheff</div>
          <button
            type="button"
            className="lp-mobile-close"
            aria-label="Close menu"
            onClick={close}
          >
            ✕
          </button>
        </div>

        <div className="lp-mobile-body">
          <div className="lp-mobile-section">
            <button
              type="button"
              className="lp-mobile-sec-btn"
              aria-expanded={mobileSection === "platform"}
              onClick={() =>
                setMobileSection((v) =>
                  v === "platform" ? "root" : "platform",
                )
              }
            >
              Platform <span aria-hidden>▾</span>
            </button>
            {mobileSection === "platform" && (
              <div className="lp-mobile-links">
                {PLATFORM_COLS.flatMap((c) => c.links).map((l) => (
                  <Link
                    key={`m-plat-${l.title}`}
                    href={l.href}
                    className="lp-mobile-link"
                    onClick={close}
                  >
                    {l.title}
                  </Link>
                ))}
              </div>
            )}
          </div>

          <div className="lp-mobile-section">
            <button
              type="button"
              className="lp-mobile-sec-btn"
              aria-expanded={mobileSection === "capabilities"}
              onClick={() =>
                setMobileSection((v) =>
                  v === "capabilities" ? "root" : "capabilities",
                )
              }
            >
              Capabilities <span aria-hidden>▾</span>
            </button>
            {mobileSection === "capabilities" && (
              <div className="lp-mobile-links">
                {CAPABILITIES_COLS.flatMap((c) => c.links).map((l) => (
                  <Link
                    key={`m-cap-${l.title}`}
                    href={l.href}
                    className="lp-mobile-link"
                    onClick={close}
                  >
                    {l.title}
                  </Link>
                ))}
              </div>
            )}
          </div>

          <div className="lp-mobile-section">
            <button
              type="button"
              className="lp-mobile-sec-btn"
              aria-expanded={mobileSection === "ai-security"}
              onClick={() =>
                setMobileSection((v) =>
                  v === "ai-security" ? "root" : "ai-security",
                )
              }
            >
              AI Security <span aria-hidden>▾</span>
            </button>
            {mobileSection === "ai-security" && (
              <div className="lp-mobile-links">
                {AI_SECURITY_COLS.flatMap((c) => c.links).map((l) => (
                  <Link
                    key={`m-ai-${l.title}`}
                    href={l.href}
                    className="lp-mobile-link"
                    onClick={close}
                  >
                    {l.title}
                  </Link>
                ))}
              </div>
            )}
          </div>

          <div className="lp-mobile-links lp-mobile-links-tight">
            <a
              href={
                process.env.NEXT_PUBLIC_DOCS_URL ?? "https://docs.pencheff.com"
              }
              target="_blank"
              rel="noreferrer"
              className="lp-mobile-link"
              onClick={() => setMobileOpen(false)}
            >
              Docs ↗
            </a>
            <Link href="/dashboard" className="lp-mobile-link" onClick={close}>
              Dashboard
            </Link>
          </div>
        </div>
      </div>

      <nav className="lp-nav" aria-label="Pencheff">
        <div className="lp-nav-inner">
          <Link href="/" className="lp-brand" aria-label="Pencheff">
            <span className="lp-monogram" aria-hidden>
              <LogoMark size={32} priority />
            </span>
            <span className="lp-wordmark">Pencheff</span>
            <span
              className="lp-beta-pill"
              title="Pencheff is free and open source (MIT licence)."
            >
              Open source
            </span>
          </Link>

          <div className="lp-nav-links">
            {trigger("platform", "Platform")}
            {trigger("capabilities", "Capabilities")}
            {trigger("ai-security", "AI Security")}
            <a
              className="lp-nav-link"
              href={
                process.env.NEXT_PUBLIC_DOCS_URL ?? "https://docs.pencheff.com"
              }
              target="_blank"
              rel="noreferrer"
            >
              Docs ↗
            </a>
          </div>

          <div className="lp-nav-cta">
            <button
              type="button"
              className="lp-nav-mobile-btn"
              aria-label="Open menu"
              aria-expanded={mobileOpen}
              onClick={() => {
                setMobileOpen((v) => !v);
                setMobileSection("root");
              }}
            >
              Menu
              <span className="lp-caret" aria-hidden>
                ▾
              </span>
            </button>
            <ThemeToggle variant="landing" />
            <Link
              className="lp-nav-signin"
              href="/dashboard"
              style={{ whiteSpace: "nowrap" }}
            >
              Dashboard
            </Link>
          </div>
        </div>

        <div
          className="lp-mega-stack"
          role="region"
          aria-label="Site navigation menus"
        >
          <MegaPanel
            id="mega-platform"
            cols={PLATFORM_COLS}
            isOpen={openKey === "platform"}
            onMouseEnter={cancelClose}
            onMouseLeave={scheduleClose}
            onLinkClick={close}
          />
          <MegaPanel
            id="mega-capabilities"
            cols={CAPABILITIES_COLS}
            isOpen={openKey === "capabilities"}
            onMouseEnter={cancelClose}
            onMouseLeave={scheduleClose}
            onLinkClick={close}
          />
          <MegaPanel
            id="mega-ai-security"
            cols={AI_SECURITY_COLS}
            isOpen={openKey === "ai-security"}
            onMouseEnter={cancelClose}
            onMouseLeave={scheduleClose}
            onLinkClick={close}
          />
        </div>
      </nav>
    </>
  );
}
