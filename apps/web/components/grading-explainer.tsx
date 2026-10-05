"use client";

import { useState } from "react";

/**
 * Explainer for how grades, scores, severities, and the rest of the
 * scan-page metrics are computed and what each term means.
 *
 * The numbers below mirror ``apps/api/pencheff_api/services/grader.py``
 * (severity weights + caps + grade thresholds). Keep them in sync — when
 * grader.py changes, update this component too.
 *
 * Two flavours:
 *   * ``<GradingExplainer />`` — full collapsible panel for the scan-detail
 *     page. Defaults closed.
 *   * ``<GradingSummary />``   — single-line one-link version for the
 *     scans index / dashboard.
 */

const WEIGHTS: Array<{
  sev: "critical" | "high" | "medium" | "low" | "info";
  perFinding: number;
  cap: number;
  bar: string;
  blurb: string;
}> = [
  {
    sev: "critical",
    perFinding: 25,
    cap: 75,
    bar: "bg-sev-critical",
    blurb:
      "Direct, demonstrable compromise — RCE, auth bypass, key extraction. ~3 unsuppressed criticals already deduct 75 points.",
  },
  {
    sev: "high",
    perFinding: 8,
    cap: 40,
    bar: "bg-sev-high",
    blurb:
      "Serious flaw with a clear exploit path but extra hops needed (e.g. SQLi requiring auth, IDOR on sensitive resource). ~5 highs hit the bucket cap.",
  },
  {
    sev: "medium",
    perFinding: 3,
    cap: 25,
    bar: "bg-sev-medium",
    blurb:
      "Real defect, lower exploit value or harder pre-conditions (CSRF on idempotent action, weak TLS cipher). ~8 mediums hit the cap so a noisy scan can't dominate the grade.",
  },
  {
    sev: "low",
    perFinding: 1,
    cap: 15,
    bar: "bg-sev-low",
    blurb:
      "Hygiene issues — missing security headers, verbose errors, etc. Capped at 15 so a flood of lows can't drop a tidy app below B.",
  },
  {
    sev: "info",
    perFinding: 0,
    cap: 0,
    bar: "bg-sev-info",
    blurb:
      "Observations, not vulnerabilities. Always 0 deduction — listed for completeness in reports.",
  },
];

const GRADE_BANDS: Array<{ grade: string; min: number; copy: string }> = [
  { grade: "A", min: 90, copy: "No critical, no high. Clean enough to ship." },
  { grade: "B", min: 80, copy: "Minor issues. No criticals; highs only after suppressing or remediating." },
  { grade: "C", min: 65, copy: "Real exposure — at least one high or stack of mediums." },
  { grade: "D", min: 50, copy: "Significant risk; remediation required before exposure to end users." },
  { grade: "F", min: 0, copy: "Critical exposure. Take down or fix immediately." },
];

const SAFETY_RAILS = [
  "Any unsuppressed critical caps the grade at C — you can't earn an A or B with a live RCE on the scoreboard.",
  "Any unsuppressed high caps the grade at B — an A requires zero criticals AND zero highs.",
  "Suppressed findings (accepted-risk, false-positive, won't-fix, out-of-scope) do not deduct.",
];

const GLOSSARY: Array<{ term: string; def: string }> = [
  {
    term: "Score (0–100)",
    def: "Starts at 100; each unsuppressed finding deducts its severity weight, with a per-bucket cap so high-volume noise never dominates a focused report.",
  },
  {
    term: "Grade (A–F)",
    def: "Letter band derived from the score, then clamped by the safety rails above.",
  },
  {
    term: "Severity",
    def: "How dangerous a single finding is, set by the scanner module that produced it. Drives both deductions and ordering in the UI.",
  },
  {
    term: "CVSS",
    def: "Common Vulnerability Scoring System (v3.1). 0–10 numeric reflecting attack vector, complexity, privileges, user interaction, scope, and CIA impact. Used to color-code findings and compare risk across reports.",
  },
  {
    term: "CWE",
    def: "Common Weakness Enumeration ID (e.g. CWE-89 = SQL Injection). The taxonomy bug class — orthogonal to severity.",
  },
  {
    term: "OWASP",
    def: "OWASP Top 10 2021 / Mobile Top 10 / LLM Top 10 / API Top 10 mapping. Surface-level grouping for executive summaries and compliance crosswalks.",
  },
  {
    term: "EPSS",
    def: "Exploit Prediction Scoring System — daily-updated probability (0–1) that a CVE will be exploited in the next 30 days. Pulled from FIRST.org. Surfaced on findings tied to a CVE.",
  },
  {
    term: "KEV",
    def: "CISA Known Exploited Vulnerabilities catalog. A KEV-flagged finding has confirmed in-the-wild exploitation; treat as drop-everything.",
  },
  {
    term: "SLA",
    def: "Service Level Agreement window — number of days to remediate, set per severity and per workspace. ‘SLA breached’ means the due date has passed without resolution.",
  },
  {
    term: "Verification status",
    def: "How the finding has been triaged: unverified · true positive (confirmed exploitable) · false positive · true negative · fixed. Only true-positive + unverified count toward the score.",
  },
  {
    term: "Suppressed",
    def: "User has waived the finding (accepted-risk, won't-fix, false-positive, duplicate, out-of-scope). Suppressed findings are listed in reports but never deduct from the score.",
  },
  {
    term: "Profile",
    def: "Scan recipe — quick (≈5 min surface pass) · standard (~15 min OWASP Top 10 coverage) · deep (45+ min, every elite module). The profile picks both depth and module list.",
  },
  {
    term: "Source repos",
    def: "Code repositories attached to a URL target. SAST runs against each in parallel with DAST so the report covers running code and source code in one pass.",
  },
  {
    term: "Auto-fix",
    def: "Fix proposal generated for a finding. Scanner-native (free) when semgrep / pip-audit / npm-audit / detect-secrets emit a deterministic fix. LLM-generated (Pro+) otherwise. Always opens a PR rather than touching the working tree.",
  },
];

const SEVERITY_PILL: Record<string, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};


export function GradingExplainer({ defaultOpen = false }: { defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-3 text-left group"
        aria-expanded={open}
        aria-controls="grading-explainer-body"
      >
        <span className="eyebrow-gilt">Methodology</span>
        <span className="font-display text-[18px] text-ink group-hover:underline underline-offset-[6px] decoration-gilt decoration-1">
          How is this grade calculated?
        </span>
        <span className="font-mono text-[12px] text-mist">
          {open ? "▾ collapse" : "▸ expand"}
        </span>
      </button>
      {open && (
        <div
          id="grading-explainer-body"
          className="mt-5 formal-surface p-8 space-y-10"
        >
          {/* Formula */}
          <div>
            <p className="eyebrow mb-3">01  Score</p>
            <p className="text-[14px] leading-[1.7] text-graphite max-w-[68ch]">
              Every scan starts at <strong>100</strong>. Each unsuppressed
              finding deducts a per-severity weight, with a per-bucket cap so
              a long tail of low-severity issues never tanks the grade
              unfairly. The remainder is the score; the score becomes a
              letter via the bands below; the safety rails clamp the letter.
            </p>
            <div className="mt-5 grid grid-cols-[max-content_max-content_max-content_1fr] gap-x-5 gap-y-3 items-baseline">
              <span className="font-mono text-[11px] text-mist tracking-[0.08em]">Severity</span>
              <span className="font-mono text-[11px] text-mist tracking-[0.08em]">/finding</span>
              <span className="font-mono text-[11px] text-mist tracking-[0.08em]">cap</span>
              <span className="font-mono text-[11px] text-mist tracking-[0.08em]">when it applies</span>
              {WEIGHTS.map((w) => (
                <Row key={w.sev} {...w} />
              ))}
            </div>
          </div>

          {/* Bands */}
          <div>
            <p className="eyebrow mb-3">02  Letter bands</p>
            <ul className="grid sm:grid-cols-2 gap-3">
              {GRADE_BANDS.map((b) => (
                <li
                  key={b.grade}
                  className="flex items-baseline gap-4 border border-hairline rounded-sm p-4 bg-paper"
                >
                  <span className="font-display text-[28px] text-ink leading-none">
                    {b.grade}
                  </span>
                  <span className="font-mono text-[11px] text-mist whitespace-nowrap">
                    ≥ {b.min}
                  </span>
                  <span className="text-[13px] text-graphite leading-[1.55]">
                    {b.copy}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          {/* Safety rails */}
          <div>
            <p className="eyebrow mb-3">03  Safety rails</p>
            <ul className="space-y-2 text-[13px] text-graphite leading-[1.65]">
              {SAFETY_RAILS.map((s) => (
                <li key={s} className="flex gap-3">
                  <span className="font-mono text-mist">✦</span>
                  <span>{s}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Glossary */}
          <div>
            <p className="eyebrow mb-3">04  Glossary</p>
            <dl className="grid md:grid-cols-2 gap-x-8 gap-y-4">
              {GLOSSARY.map((g) => (
                <div key={g.term}>
                  <dt className="font-mono text-[12px] text-ink tracking-[0.04em]">
                    {g.term}
                  </dt>
                  <dd className="mt-1 text-[13px] text-graphite leading-[1.6]">
                    {g.def}
                  </dd>
                </div>
              ))}
            </dl>
          </div>

          {/* Worked example */}
          <div>
            <p className="eyebrow mb-3">05  Worked example</p>
            <p className="text-[13px] text-graphite leading-[1.7] max-w-[68ch]">
              A scan finds 1 critical, 2 highs, 6 mediums, 12 lows, 3 info.
              Deductions: critical = min(25, 75) = <strong>25</strong>,
              high = min(2 × 8, 40) = <strong>16</strong>,
              medium = min(6 × 3, 25) = <strong>18</strong>,
              low = min(12 × 1, 15) = <strong>12</strong>,
              info = 0. Total <strong>71</strong> → score <strong>29</strong>{" "}
              → letter <strong>F</strong>. The unsuppressed critical also
              triggers the rail — so even if the score had landed in B/A
              territory, the displayed grade would have been clamped at C.
            </p>
          </div>
        </div>
      )}
    </section>
  );
}


function Row({
  sev, perFinding, cap, bar, blurb,
}: typeof WEIGHTS[number]) {
  return (
    <>
      <span className="flex items-center gap-3">
        <span className={`inline-block w-2 h-2 rounded-sm ${SEVERITY_PILL[sev] ?? bar}`} />
        <span className="font-mono text-[13px] text-graphite capitalize">{sev}</span>
      </span>
      <span className="font-mono text-[13px] text-graphite tabular-nums">−{perFinding}</span>
      <span className="font-mono text-[13px] text-graphite tabular-nums">{cap > 0 ? `≤ ${cap}` : "—"}</span>
      <span className="text-[13px] text-graphite leading-[1.55]">{blurb}</span>
    </>
  );
}


export function GradingSummary() {
  return (
    <p className="font-body text-[12px] text-slate italic max-w-[72ch]">
      Score starts at 100; severities deduct (critical −25, high −8, medium
      −3, low −1, info 0) with per-bucket caps so noisy scans can&rsquo;t
      dominate. Letter bands: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, else F. An
      unsuppressed critical caps the letter at C; an unsuppressed high
      caps it at B. Suppressed findings never deduct.
    </p>
  );
}
