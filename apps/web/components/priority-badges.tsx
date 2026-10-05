"use client";

import { cn } from "@/lib/cn";

/**
 * Pencheff's prioritisation surface — three small badges that appear
 * everywhere a finding shows up: reachability state, SSVC action class,
 * and the unified 0-100 risk score. These are the primary sort/filter
 * signals on the unified-findings page and on individual scan results.
 */

const REACH_TONE: Record<
  string,
  { label: string; bg: string; ring: string }
> = {
  exploited: {
    label: "Exploited",
    bg: "bg-oxblood text-paper",
    ring: "border-oxblood",
  },
  reachable: {
    label: "Reachable",
    bg: "bg-sev-high/15 text-sev-high",
    ring: "border-sev-high",
  },
  present: {
    label: "Present",
    bg: "bg-sev-low/15 text-sev-low",
    ring: "border-sev-low",
  },
  unknown: {
    label: "Unknown",
    bg: "bg-paper text-mist",
    ring: "border-hairline",
  },
};

export function ReachabilityBadge({ value }: { value: string | null | undefined }) {
  const v = (value || "unknown").toLowerCase();
  const tone = REACH_TONE[v] || REACH_TONE.unknown;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm border px-2 py-0.5",
        "font-body text-[11px] font-medium uppercase tracking-[0.16em]",
        tone.bg,
        tone.ring
      )}
      title={
        v === "exploited"
          ? "Pencheff DAST verified this issue is live and reachable."
          : v === "reachable"
          ? "Static taint analysis or import probe says user input reaches the sink."
          : v === "present"
          ? "Vulnerable code/dependency exists, no usage evidence found."
          : "No reachability data yet."
      }
    >
      {tone.label}
    </span>
  );
}

const SSVC_TONE: Record<string, { label: string; bg: string }> = {
  act: { label: "Act", bg: "bg-oxblood text-paper" },
  attend: { label: "Attend", bg: "bg-sev-high/15 text-sev-high" },
  track_star: { label: "Track*", bg: "bg-sev-medium/15 text-sev-medium" },
  track: { label: "Track", bg: "bg-sev-low/15 text-sev-low" },
};

export function SsvcBadge({ value }: { value: string | null | undefined }) {
  if (!value) return null;
  const v = value.toLowerCase();
  const tone = SSVC_TONE[v];
  if (!tone) return null;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm px-2 py-0.5",
        "font-body text-[11px] font-medium uppercase tracking-[0.16em]",
        tone.bg
      )}
      title={`SSVC action class: ${v.replace("_", " ")}. CISA's Stakeholder-Specific Vulnerability Categorization.`}
    >
      SSVC · {tone.label}
    </span>
  );
}

export function RiskScoreChip({ score }: { score: number | null | undefined }) {
  if (score == null) return null;
  // Heat-map colour: 0-30 cool, 30-65 warm, 65+ hot.
  const tone =
    score >= 65
      ? "bg-oxblood text-paper border-oxblood"
      : score >= 30
      ? "bg-sev-medium/15 text-sev-medium border-sev-medium"
      : "bg-paper text-graphite border-hairline";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-sm border px-2 py-0.5",
        "font-mono text-[11px] font-semibold tracking-[0.04em]",
        tone
      )}
      title="Pencheff priority — CVSS × EPSS × KEV × SSVC × reachability."
    >
      <span className="font-body text-[9px] font-medium uppercase tracking-[0.18em] opacity-70">
        Risk
      </span>
      {score.toFixed(0)}
    </span>
  );
}

export function EpssChip({ value }: { value: number | null | undefined }) {
  if (value == null) return null;
  const pct = Math.round(value * 100);
  const tone =
    value >= 0.5
      ? "bg-sev-high/15 text-sev-high border-sev-high"
      : "bg-paper text-mist border-hairline";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-sm border px-2 py-0.5",
        "font-mono text-[11px] tracking-[0.04em]",
        tone
      )}
      title={`EPSS ${value.toFixed(4)} — probability of in-the-wild exploitation in the next 30 days (FIRST.org).`}
    >
      <span className="font-body text-[9px] font-medium uppercase tracking-[0.18em] opacity-70">
        EPSS
      </span>
      {pct}%
    </span>
  );
}

export function KevBadge({ value }: { value: boolean | null | undefined }) {
  if (!value) return null;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-sm px-2 py-0.5",
        "bg-oxblood/10 text-oxblood border border-oxblood",
        "font-body text-[11px] font-medium uppercase tracking-[0.16em]"
      )}
      title="On the CISA Known Exploited Vulnerabilities catalog — confirmed in-the-wild exploitation."
    >
      KEV
    </span>
  );
}

/**
 * Compact horizontal strip — drop on top of a finding card / detail
 * header to summarise prioritisation at a glance. Hides components
 * that don't have data so it never renders empty placeholders.
 */
export function PriorityStrip({
  riskScore,
  reachability,
  ssvc,
  epss,
  kev,
}: {
  riskScore?: number | null;
  reachability?: string | null;
  ssvc?: string | null;
  epss?: number | null;
  kev?: boolean | null;
}) {
  const hasAny =
    riskScore != null || reachability || ssvc || epss != null || kev;
  if (!hasAny) return null;
  return (
    <div className="flex flex-wrap items-center gap-2">
      <RiskScoreChip score={riskScore} />
      <ReachabilityBadge value={reachability} />
      <SsvcBadge value={ssvc} />
      <EpssChip value={epss} />
      <KevBadge value={kev} />
    </div>
  );
}
