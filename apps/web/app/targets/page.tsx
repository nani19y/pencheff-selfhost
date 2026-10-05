"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { Input } from "@/components/brutal";
import { CommissionScanModal } from "@/components/commission-scan-modal";
import { PageLoading } from "@/components/loading";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { IntelDivider } from "@/components/app/intel-panel";

// ── Types ────────────────────────────────────────────────────────────────────
type SupportedKind =
  | "url"
  | "repo"
  | "llm"
  | "host"
  | "web_app"
  | "rest_api"
  | "graphql"
  | "websocket"
  | "grpc"
  | "source_code"
  | "cicd_pipeline"
  | "iac"
  | "container_image"
  | "k8s_cluster"
  | "package_registry"
  | "sbom"
  | "memory"
  | "mcp"
  | "rag"
  | "ml_model"
  | "voice";
type Target = {
  id: string;
  name: string;
  base_url: string;
  has_credentials: boolean;
  kind?: SupportedKind;
  kind_config?: Record<string, unknown> | null;
  repository_id?: string | null;
  created_at?: string;
};
type Scan = {
  id: string;
  target_id: string;
  status: string;
  score: number | null;
  grade: string | null;
  summary: Record<string, number | string> | null;
  // Per-scan consent record. Carries the operator's previously-typed
  // ``authorization_text`` so the commission modal can re-offer it on
  // the next scan of the same target without forcing a retype.
  consent_payload: { authorization_text?: string } | null;
  created_at: string;
  finished_at: string | null;
};
type Schedule = {
  id: string;
  target_id: string;
  name: string;
  enabled: boolean;
  next_run_at: string | null;
};
type Repo = {
  id: string;
  full_name?: string;
  name?: string;
  last_scan_id?: string | null;
  last_scan_at?: string | null;
  severity_counts?: Record<string, number> | null;
  provider?: string;
  integration_id?: string | null;
};

// ── Helpers ───────────────────────────────────────────────────────────────────
// Feature 001 widened SupportedKind from 3 → 15 wire values. The list page
// keeps its existing "url-ish / repo-ish / llm-ish" tri-grouping for the
// summary tile/filter UI (operators don't think in 15 buckets), so
// effectiveKind() maps every kind into one of those three groups while
// typeLabel() / TypeBadge / coverageBadges show the precise kind.
type DisplayKind = "url" | "repo" | "llm";

const DAST_KINDS: ReadonlySet<string> = new Set([
  "url",
  "web_app",
  "rest_api",
  "graphql",
  "websocket",
  "grpc",
]);
const REPO_LIKE_KINDS: ReadonlySet<string> = new Set([
  "repo",
  "source_code",
  "iac",
  "container_image",
  "k8s_cluster",
  "cicd_pipeline",
  "package_registry",
  "sbom",
]);

function effectiveKind(t: Target): DisplayKind {
  const k = t.kind ?? "url";
  if (k === "llm") return "llm";
  if (k === "mcp") return "llm";
  if (k === "rag") return "llm";
  if (k === "ml_model") return "llm";
  if (k === "voice") return "llm";
  if (t.repository_id) return "repo"; // legacy repo-mirror heuristic
  if (REPO_LIKE_KINDS.has(k)) return "repo";
  if (DAST_KINDS.has(k)) return "url";
  return "url";
}

const TYPE_BADGE_BY_KIND: Record<string, string> = {
  url: "WEB APP",
  web_app: "WEB APP",
  rest_api: "REST API",
  graphql: "GRAPHQL",
  websocket: "WEBSOCKET",
  grpc: "GRPC",
  repo: "REPOSITORY",
  source_code: "SOURCE CODE",
  cicd_pipeline: "CI/CD",
  iac: "IAC",
  container_image: "CONTAINER",
  k8s_cluster: "K8S CLUSTER",
  package_registry: "PACKAGE REGISTRY",
  sbom: "SBOM",
  llm: "LLM ENDPOINT",
  mcp: "MCP / AGENT",
  rag: "RAG / VECTOR DB",
  ml_model: "ML MODEL",
  voice: "VOICE / SPEECH AI",
};

function typeLabel(t: Target): string {
  const wireKind = t.kind ?? "url";
  // Legacy repo-mirror rows (kind="url" + repository_id set) come from the
  // pre-feature-001 era — display them as REPOSITORY rather than WEB APP.
  if (t.repository_id && wireKind === "url") return "REPOSITORY";
  const mapped = TYPE_BADGE_BY_KIND[wireKind];
  if (mapped) return mapped;
  // Fall-through for legacy "url" rows: keep the historical hostname-sniff
  // heuristic so existing assessments keep their REST API label.
  if (wireKind === "url") {
    const url = (t.base_url ?? "").toLowerCase();
    if (url.includes("api.") || url.includes("/api") || url.includes("-api"))
      return "REST API";
    return "WEB APP";
  }
  return wireKind.toUpperCase();
}
// Risk level is derived from the highest-severity unsuppressed finding,
// not from ``scan.score``. The grader returns a 0–100 *health* score
// (100 = clean) — a target with eight criticals can land at score 0 and
// would otherwise be tagged "LOW" by a naive ≥7 = critical mapping.
function riskFromFindings(findings: Record<string, number | string> | null) {
  if (!findings)
    return {
      level: "—",
      color: "text-mist",
      bg: "bg-mist",
      border: "border-mist/30",
    };
  const crit = Number(findings.critical) || 0;
  const high = Number(findings.high) || 0;
  const med = Number(findings.medium) || 0;
  const low = Number(findings.low) || 0;

  if (crit > 0)
    return {
      level: "CRITICAL",
      color: "text-sev-critical",
      bg: "bg-sev-critical",
      border: "border-sev-critical/40",
    };
  if (high > 0)
    return {
      level: "HIGH",
      color: "text-sev-high",
      bg: "bg-sev-high",
      border: "border-sev-high/40",
    };
  if (med > 0)
    return {
      level: "MEDIUM",
      color: "text-sev-medium",
      bg: "bg-sev-medium",
      border: "border-sev-medium/40",
    };
  if (low > 0)
    return {
      level: "LOW",
      color: "text-sev-low",
      bg: "bg-sev-low",
      border: "border-sev-low/40",
    };
  return {
    level: "LOW",
    color: "text-sev-low",
    bg: "bg-sev-low",
    border: "border-sev-low/40",
  };
}

function displayRiskScore(
  findings: Record<string, number | string> | null,
  healthScore: number | null | undefined,
): number | null {
  if (!findings && (healthScore === null || healthScore === undefined)) {
    return null;
  }
  if (healthScore !== null && healthScore !== undefined) {
    return Math.max(0, Math.min(100, 100 - Number(healthScore)));
  }
  const crit = Number(findings?.critical) || 0;
  const high = Number(findings?.high) || 0;
  const med = Number(findings?.medium) || 0;
  const low = Number(findings?.low) || 0;
  if (crit > 0) return 100;
  if (high > 0) return 75;
  if (med > 0) return 50;
  if (low > 0) return 25;
  return 0;
}

// Top-risky ranking key: lower is better. Critical findings dominate,
// then highs, then mediums, then lows. Falls back to the 0–100 health
// score (inverted so smaller = riskier) for tie-breaks.
function riskRank(
  findings: Record<string, number | string> | null,
  score: number | null,
): number {
  const crit = Number(findings?.critical) || 0;
  const high = Number(findings?.high) || 0;
  const med = Number(findings?.medium) || 0;
  const low = Number(findings?.low) || 0;
  const healthPenalty = score === null ? 0 : (100 - score) / 1000;
  return crit * 1000 + high * 100 + med * 10 + low + healthPenalty;
}

function hasCriticalOrHigh(
  findings: Record<string, number | string> | null,
): boolean {
  if (!findings) return false;
  return (
    (Number(findings.critical) || 0) > 0 || (Number(findings.high) || 0) > 0
  );
}

// Feature 001 per-kind coverage badge map (spec 10.3 normative table).
// Falls back to the legacy DisplayKind grouping for unknown values.
const COVERAGE_BADGES_BY_KIND: Record<string, string[]> = {
  url: ["DAST"],
  repo: ["SAST", "SCA", "SECRETS"],
  llm: ["LLM RED TEAM"],
  web_app: ["DAST"],
  rest_api: ["DAST", "API"],
  graphql: ["DAST", "API"],
  websocket: ["DAST", "API"],
  grpc: ["DAST", "API"],
  source_code: ["SAST", "SCA", "SECRETS"],
  cicd_pipeline: ["CI", "SAST", "SECRETS"],
  iac: ["IAC"],
  container_image: ["CONTAINER", "SCA", "SECRETS"],
  k8s_cluster: ["K8S"],
  package_registry: ["SCA"],
  sbom: ["SBOM", "SCA"],
  mcp: ["MCP", "AGENT"],
  rag: ["RAG", "VECTOR DB"],
  ml_model: ["ML MODEL"],
  voice: ["VOICE", "SPEECH AI"],
};

function coverageBadges(
  input: DisplayKind | string,
  wireKind?: string,
): string[] {
  // Prefer exact wire-kind match when supplied (feature-001 callers); fall
  // back to DisplayKind grouping for legacy callers.
  const lookup =
    wireKind && COVERAGE_BADGES_BY_KIND[wireKind]
      ? COVERAGE_BADGES_BY_KIND[wireKind]
      : COVERAGE_BADGES_BY_KIND[input as string];
  return lookup ?? ["DAST"];
}
function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return iso.replace("T", " ").slice(0, 16);
}
function relativeDate(iso: string | null): string {
  if (!iso) return "";
  const diff = Date.now() - new Date(iso).getTime();
  const days = Math.floor(diff / 86400000);
  if (days === 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 7) return `${days}d ago`;
  if (days < 30) return `${Math.floor(days / 7)}w ago`;
  return `${Math.floor(days / 30)}mo ago`;
}
function relativeFromNow(iso: string | null): string {
  if (!iso) return "";
  const diff = new Date(iso).getTime() - Date.now();
  if (diff <= 0) return "soon";
  const hours = Math.floor(diff / 3600000);
  if (hours < 24) return `in ${hours}h`;
  const days = Math.floor(diff / 86400000);
  if (days < 7) return `in ${days}d`;
  return `in ${Math.floor(days / 7)}w`;
}

// ── Inline SVG icons ──────────────────────────────────────────────────────────
const GlobeIcon = () => (
  <svg
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-5 h-5"
  >
    <circle cx="10" cy="10" r="8" />
    <path d="M10 2c0 0-4 3-4 8s4 8 4 8M10 2c0 0 4 3 4 8s-4 8-4 8M2 10h16" />
    <path d="M3 6.5h14M3 13.5h14" />
  </svg>
);
const RepoIcon = () => (
  <svg
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-5 h-5"
  >
    <path d="M7 4l-3 6 3 6M13 4l3 6-3 6M11.5 4.5l-3 11" />
  </svg>
);
const BrainIcon = () => (
  <svg
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-5 h-5"
  >
    <path d="M10 3C7.5 3 5.5 4.8 5.5 7c0 .7.2 1.3.5 1.8C5.4 9.2 5 9.8 5 10.5c0 1 .6 1.9 1.5 2.3-.1.3-.2.6-.2.9 0 1.3 1 2.3 2.2 2.3H10" />
    <path d="M10 3c2.5 0 4.5 1.8 4.5 4 0 .7-.2 1.3-.5 1.8.6.4 1 1 1 1.7 0 1-.6 1.9-1.5 2.3.1.3.2.6.2.9 0 1.3-1 2.3-2.2 2.3H10" />
    <path d="M10 3v14" />
  </svg>
);
const CloudIcon = () => (
  <svg
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-5 h-5"
  >
    <path d="M5.5 14a3.5 3.5 0 0 1-.5-7A4.5 4.5 0 0 1 13.5 7h.5a3 3 0 0 1 0 6H14" />
    <path d="M5.5 14h9" />
  </svg>
);
const CubeIcon = () => (
  <svg
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-5 h-5"
  >
    <path d="M10 2.5L17 6.5V13.5L10 17.5L3 13.5V6.5L10 2.5Z" />
    <path d="M10 2.5V17.5M3 6.5L10 10.5L17 6.5" />
  </svg>
);
const LayersIcon = () => (
  <svg
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-5 h-5"
  >
    <path d="M2 10l8-5 8 5-8 5-8-5Z" />
    <path d="M2 14l8 5 8-5" />
    <path d="M2 6l8-5 8 5" />
  </svg>
);
const KeyIcon = () => (
  <svg
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-5 h-5"
  >
    <circle cx="7.5" cy="10" r="4" />
    <path d="M11.5 10H18M15.5 8v4M18 8v4" strokeLinecap="round" />
  </svg>
);
const CrosshairIcon = () => (
  <svg
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-5 h-5"
  >
    <circle cx="10" cy="10" r="6" />
    <circle cx="10" cy="10" r="2" />
    <path d="M10 2v4M10 14v4M2 10h4M14 10h4" />
  </svg>
);
const FilterIcon = () => (
  <svg
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4 h-4"
  >
    <path d="M3 5h14M5.5 10h9M8 15h4" strokeLinecap="round" />
  </svg>
);
const DotsIcon = () => (
  <svg viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4">
    <circle cx="5" cy="10" r="1.5" />
    <circle cx="10" cy="10" r="1.5" />
    <circle cx="15" cy="10" r="1.5" />
  </svg>
);
const CheckIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    className="w-3.5 h-3.5"
  >
    <path d="M3 8l3.5 3.5L13 5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const ShieldIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4 h-4"
  >
    <path d="M8 1.5L2 4v4c0 3 2.5 5.5 6 6.5 3.5-1 6-3.5 6-6.5V4L8 1.5Z" />
  </svg>
);

// ── Stat tile ─────────────────────────────────────────────────────────────────
interface StatTileProps {
  icon: React.ReactNode;
  label: string;
  count: number | string;
  newCount?: number;
  iconColor?: string;
  iconBg?: string;
  dimmed?: boolean;
}
function StatTile({
  icon,
  label,
  count,
  newCount,
  iconColor = "text-gilt",
  iconBg = "bg-gilt/10",
  dimmed,
}: StatTileProps) {
  return (
    <div
      className={cn(
        "flex items-start gap-3 border border-hairline rounded-sm p-3.5 bg-paper min-w-0",
        dimmed && "opacity-60",
      )}
    >
      <div
        className={cn(
          "w-9 h-9 rounded-sm flex items-center justify-center shrink-0 mt-0.5",
          iconBg,
          iconColor,
        )}
      >
        {icon}
      </div>
      <div className="min-w-0">
        <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist truncate">
          {label}
        </p>
        <p className="font-display text-[26px] 2xl:text-[20px] leading-none tracking-[-0.02em] text-ink mt-0.5">
          {count}
        </p>
        {newCount !== undefined && newCount > 0 && (
          <p className="font-mono text-[10px] text-forest mt-0.5">
            +{newCount} new
          </p>
        )}
      </div>
    </div>
  );
}

// ── Filter pill ───────────────────────────────────────────────────────────────
type FilterTab =
  "all" | "url" | "repo" | "llm" | "critical" | "authenticated" | "needs-scan";

interface FilterPillProps {
  label: string;
  count?: number;
  active: boolean;
  onClick: () => void;
}
function FilterPill({ label, count, active, onClick }: FilterPillProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-sm border px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.12em] transition-colors whitespace-nowrap",
        active
          ? "bg-ink text-paper border-ink"
          : "bg-paper text-slate border-hairline hover:border-graphite hover:text-graphite",
      )}
    >
      {label}
      {count !== undefined && (
        <span
          className={cn(
            "text-[10px] font-mono",
            active ? "text-paper/70" : "text-mist",
          )}
        >
          ({count})
        </span>
      )}
    </button>
  );
}

// ── Coverage badge ────────────────────────────────────────────────────────────
const COVERAGE_STYLES: Record<string, string> = {
  DAST: "bg-gilt/10 text-gilt border-gilt/30",
  SAST: "bg-forest/10 text-forest border-forest/30",
  SCA: "bg-sev-low/10 text-sev-low border-sev-low/30",
  SECRETS: "bg-sev-critical/10 text-sev-critical border-sev-critical/30",
  "LLM RED TEAM": "bg-sev-high/10 text-sev-high border-sev-high/30",
  // Feature 001 — new badge tokens for the 12 new target kinds. Re-use the
  // existing severity-palette colours to keep the visual vocabulary stable.
  API: "bg-gilt/10 text-gilt border-gilt/30",
  CI: "bg-graphite/10 text-graphite border-graphite/30",
  IAC: "bg-forest/10 text-forest border-forest/30",
  CONTAINER: "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
  K8S: "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
  SBOM: "bg-sev-low/10 text-sev-low border-sev-low/30",
  MCP: "bg-sev-high/10 text-sev-high border-sev-high/30",
  AGENT: "bg-sev-high/10 text-sev-high border-sev-high/30",
  RAG: "bg-sev-high/10 text-sev-high border-sev-high/30",
  "VECTOR DB": "bg-sev-high/10 text-sev-high border-sev-high/30",
};
function CoverageBadge({ label }: { label: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center border rounded-sm px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.12em]",
        COVERAGE_STYLES[label] ?? "bg-vellum text-slate border-hairline",
      )}
    >
      {label}
    </span>
  );
}

// ── Type badge ────────────────────────────────────────────────────────────────
function TypeBadge({ label }: { label: string }) {
  const styles: Record<string, string> = {
    "WEB APP": "bg-vellum text-graphite border-hairline",
    "REST API": "bg-gilt/10 text-gilt border-gilt/30",
    REPOSITORY: "bg-forest/10 text-forest border-forest/30",
    "LLM ENDPOINT": "bg-sev-high/10 text-sev-high border-sev-high/30",
    // Feature 001 — new type-label tokens (mirror TYPE_BADGE_BY_KIND above).
    GRAPHQL: "bg-gilt/10 text-gilt border-gilt/30",
    WEBSOCKET: "bg-gilt/10 text-gilt border-gilt/30",
    GRPC: "bg-gilt/10 text-gilt border-gilt/30",
    "SOURCE CODE": "bg-forest/10 text-forest border-forest/30",
    "CI/CD": "bg-graphite/10 text-graphite border-graphite/30",
    IAC: "bg-forest/10 text-forest border-forest/30",
    CONTAINER: "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
    "K8S CLUSTER": "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
    "PACKAGE REGISTRY": "bg-sev-low/10 text-sev-low border-sev-low/30",
    SBOM: "bg-sev-low/10 text-sev-low border-sev-low/30",
    "MCP / AGENT": "bg-sev-high/10 text-sev-high border-sev-high/30",
    "RAG / VECTOR DB": "bg-sev-high/10 text-sev-high border-sev-high/30",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center border rounded-sm px-2 py-0.5 font-mono text-[9px] uppercase tracking-[0.12em]",
        styles[label] ?? "bg-vellum text-slate border-hairline",
      )}
    >
      {label}
    </span>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
const ROWS_OPTIONS = [8, 20, 50] as const;

export default function TargetsListPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [loading, setLoading] = useState(true);
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [activeFilter, setActiveFilter] = useState<FilterTab>("all");
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] =
    useState<(typeof ROWS_OPTIONS)[number]>(8);
  const [commissionFor, setCommissionFor] = useState<{
    id: string;
    name: string;
    kind?: SupportedKind;
    kind_config?: Record<string, unknown> | null;
    repository_id?: string | null;
    priorAuthorizationText?: string | null;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      api<Target[]>("/targets").catch(() => [] as Target[]),
      api<Scan[]>("/scans").catch(() => [] as Scan[]),
      api<Schedule[]>("/schedules").catch(() => [] as Schedule[]),
      api<Repo[]>("/repos").catch(() => [] as Repo[]),
    ])
      .then(([t, s, sc, rps]) => {
        if (cancelled) return;
        setTargets(t);
        setScans(s);
        setSchedules(sc);
        setRepos(rps);
      })
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, []);

  const repoById = useMemo(() => {
    const m = new Map<string, Repo>();
    for (const r of repos) m.set(r.id, r);
    return m;
  }, [repos]);

  // ── Lookups ──
  const latestScanByTarget = useMemo(() => {
    const map = new Map<string, Scan>();
    for (const s of scans) {
      if (s.status !== "done") continue;
      const existing = map.get(s.target_id);
      if (!existing || s.created_at > existing.created_at) {
        map.set(s.target_id, s);
      }
    }
    return map;
  }, [scans]);

  const nextScheduleByTarget = useMemo(() => {
    const map = new Map<string, Schedule>();
    for (const s of schedules) {
      if (!s.enabled || !s.next_run_at) continue;
      const existing = map.get(s.target_id);
      if (
        !existing ||
        new Date(s.next_run_at) < new Date(existing.next_run_at!)
      ) {
        map.set(s.target_id, s);
      }
    }
    return map;
  }, [schedules]);

  // ── Stat counts ──
  const urlTargets = targets.filter((t) => effectiveKind(t) === "url");
  const repoTargets = targets.filter((t) => effectiveKind(t) === "repo");
  const llmTargets = targets.filter((t) => effectiveKind(t) === "llm");
  const authTargets = targets.filter((t) => t.has_credentials);
  const unscannedTargets = targets.filter((t) => {
    const kind = effectiveKind(t);
    if (kind === "repo" && t.repository_id) {
      const repo = repoById.get(t.repository_id);
      return !repo?.last_scan_at;
    }
    return !latestScanByTarget.has(t.id);
  });
  const criticalTargets = targets.filter((t) => {
    const kind = effectiveKind(t);
    if (kind === "repo" && t.repository_id) {
      const repo = repoById.get(t.repository_id);
      return hasCriticalOrHigh(repo?.severity_counts ?? null);
    }
    const scan = latestScanByTarget.get(t.id);
    return hasCriticalOrHigh(scan?.summary ?? null);
  });
  const unscannedPct =
    targets.length > 0
      ? Math.round((unscannedTargets.length / targets.length) * 100)
      : 0;

  // ── Filter counts ──
  const filterCounts: Record<FilterTab, number> = useMemo(() => {
    return {
      all: targets.length,
      url: urlTargets.length,
      repo: repoTargets.length,
      llm: llmTargets.length,
      critical: criticalTargets.length,
      authenticated: authTargets.length,
      "needs-scan": unscannedTargets.length,
    };
  }, [
    targets,
    urlTargets,
    repoTargets,
    llmTargets,
    criticalTargets,
    authTargets,
    unscannedTargets,
  ]);

  // ── Filtered targets ──
  const filtered = useMemo(() => {
    let result = targets;
    switch (activeFilter) {
      case "url":
        result = result.filter((t) => effectiveKind(t) === "url");
        break;
      case "repo":
        result = result.filter((t) => effectiveKind(t) === "repo");
        break;
      case "llm":
        result = result.filter((t) => effectiveKind(t) === "llm");
        break;
      case "critical":
        result = result.filter((t) => {
          const kind = effectiveKind(t);
          if (kind === "repo" && t.repository_id) {
            const repo = repoById.get(t.repository_id);
            return hasCriticalOrHigh(repo?.severity_counts ?? null);
          }
          const s = latestScanByTarget.get(t.id);
          return hasCriticalOrHigh(s?.summary ?? null);
        });
        break;
      case "authenticated":
        result = result.filter((t) => t.has_credentials);
        break;
      case "needs-scan":
        result = result.filter((t) => {
          const kind = effectiveKind(t);
          if (kind === "repo" && t.repository_id) {
            const repo = repoById.get(t.repository_id);
            return !repo?.last_scan_at;
          }
          return !latestScanByTarget.has(t.id);
        });
        break;
    }
    const q = query.trim().toLowerCase();
    if (q)
      result = result.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          t.base_url.toLowerCase().includes(q),
      );
    return result;
  }, [targets, activeFilter, query, latestScanByTarget, repoById]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / rowsPerPage));
  const safePage = Math.min(page, pageCount);
  const visible = filtered.slice(
    (safePage - 1) * rowsPerPage,
    safePage * rowsPerPage,
  );
  const showFrom = filtered.length === 0 ? 0 : (safePage - 1) * rowsPerPage + 1;
  const showTo = Math.min(safePage * rowsPerPage, filtered.length);

  useEffect(() => {
    if (page > pageCount) setPage(1);
  }, [pageCount, page]);

  // ── Delete ──
  // Repo-backed targets mirror a Repository row — the API enforces this and
  // requires the delete to go through /repos/{id}. Everything else uses the
  // ordinary /targets/{id} delete.
  async function deleteTarget(t: Target) {
    const isRepoMirror = effectiveKind(t) === "repo" && !!t.repository_id;
    const label = isRepoMirror ? "repository" : "target";
    if (
      !window.confirm(
        `Delete ${label} "${t.name}"?\n\nThis will also remove every assessment and finding recorded against it. This action cannot be undone.`,
      )
    )
      return;
    try {
      if (isRepoMirror && t.repository_id) {
        await api(`/repos/${t.repository_id}`, { method: "DELETE" });
        setRepos((prev) => prev.filter((r) => r.id !== t.repository_id));
      } else {
        await api(`/targets/${t.id}`, { method: "DELETE" });
      }
      setTargets((prev) => prev.filter((x) => x.id !== t.id));
    } catch (e: any) {
      alert(e?.message || `Unable to delete ${label}.`);
    }
  }

  // ── Intel panel data ──
  const topRiskyTargets = useMemo(() => {
    return targets
      .map((t) => ({ t, scan: latestScanByTarget.get(t.id) }))
      .filter((x) => x.scan !== undefined)
      .sort(
        (a, b) =>
          riskRank(b.scan?.summary ?? null, b.scan?.score ?? null) -
          riskRank(a.scan?.summary ?? null, a.scan?.score ?? null),
      )
      .slice(0, 5);
  }, [targets, latestScanByTarget]);

  const coverageGaps = useMemo(() => {
    const gaps: string[] = [];
    if (unscannedTargets.length > 0)
      gaps.push(
        `${unscannedTargets.length} target${unscannedTargets.length !== 1 ? "s" : ""} not yet scanned`,
      );
    const noAuth = targets.filter((t) => !t.has_credentials);
    if (noAuth.length > 0)
      gaps.push(
        `${noAuth.length} target${noAuth.length !== 1 ? "s" : ""} without credentials`,
      );
    if (criticalTargets.length > 0)
      gaps.push(
        `${criticalTargets.length} target${criticalTargets.length !== 1 ? "s" : ""} at high/critical risk`,
      );
    return gaps;
  }, [targets, unscannedTargets, criticalTargets]);

  if (loading && targets.length === 0)
    return <PageLoading title="Targets" cards={8} />;

  return (
    <div className="-mx-5 md:-mx-6 -mt-6 -mb-6 flex">
      {/* ── Main content ── */}
      <div className="flex-1 min-w-0 px-5 md:px-6 py-6 space-y-6">
        {/* Header */}
        <header>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-gilt">
            {targets.length} Asset Discovery
          </p>
          <div className="mt-3 flex items-end justify-between gap-4 flex-wrap">
            <div>
              <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
                Targets.
              </h1>
              <p className="mt-1.5 font-body text-[14px] text-slate">
                Your attack surface. One view. Total visibility.
              </p>
            </div>
            <div className="flex items-center gap-2.5 shrink-0">
              <Link href="/targets/new">
                <button className="flex items-center gap-2 border border-ink rounded-sm px-4 py-2 font-body text-[13px] font-medium text-ink hover:bg-ink hover:text-paper transition-colors">
                  Register target
                </button>
              </Link>
            </div>
          </div>
        </header>

        {/* ── 8-category stat bar ── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-8 gap-2.5">
          <StatTile
            icon={<GlobeIcon />}
            label="Web / API"
            count={urlTargets.length}
            iconColor="text-gilt"
            iconBg="bg-gilt/10"
          />
          <StatTile
            icon={<RepoIcon />}
            label="Repos"
            count={repoTargets.length}
            iconColor="text-forest"
            iconBg="bg-forest/10"
          />
          <StatTile
            icon={<BrainIcon />}
            label="LLM / AI"
            count={llmTargets.length}
            iconColor="text-sev-high"
            iconBg="bg-sev-high/10"
          />
          <StatTile
            icon={<CloudIcon />}
            label="Cloud"
            count={0}
            iconColor="text-slate"
            iconBg="bg-vellum"
            dimmed
          />
          <StatTile
            icon={<CubeIcon />}
            label="Containers"
            count={0}
            iconColor="text-slate"
            iconBg="bg-vellum"
            dimmed
          />
          <StatTile
            icon={<LayersIcon />}
            label="IaC"
            count={0}
            iconColor="text-slate"
            iconBg="bg-vellum"
            dimmed
          />
          <StatTile
            icon={<KeyIcon />}
            label="Credentials"
            count={authTargets.length}
            iconColor="text-sev-critical"
            iconBg="bg-sev-critical/10"
          />
          <StatTile
            icon={<CrosshairIcon />}
            label="Unscanned"
            count={`${unscannedPct}%`}
            iconColor="text-mist"
            iconBg="bg-vellum"
          />
        </div>

        {/* ── Filter tabs + search ── */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-1.5 flex-wrap">
            <FilterPill
              label="All"
              count={filterCounts.all}
              active={activeFilter === "all"}
              onClick={() => {
                setActiveFilter("all");
                setPage(1);
              }}
            />
            <FilterPill
              label="Web / API"
              count={filterCounts.url}
              active={activeFilter === "url"}
              onClick={() => {
                setActiveFilter("url");
                setPage(1);
              }}
            />
            <FilterPill
              label="Repo"
              count={filterCounts.repo}
              active={activeFilter === "repo"}
              onClick={() => {
                setActiveFilter("repo");
                setPage(1);
              }}
            />
            <FilterPill
              label="LLM"
              count={filterCounts.llm}
              active={activeFilter === "llm"}
              onClick={() => {
                setActiveFilter("llm");
                setPage(1);
              }}
            />
            <FilterPill
              label="Critical"
              count={filterCounts.critical}
              active={activeFilter === "critical"}
              onClick={() => {
                setActiveFilter("critical");
                setPage(1);
              }}
            />
            <FilterPill
              label="Authenticated"
              count={filterCounts.authenticated}
              active={activeFilter === "authenticated"}
              onClick={() => {
                setActiveFilter("authenticated");
                setPage(1);
              }}
            />
            <FilterPill
              label="Needs Scan"
              count={filterCounts["needs-scan"]}
              active={activeFilter === "needs-scan"}
              onClick={() => {
                setActiveFilter("needs-scan");
                setPage(1);
              }}
            />
          </div>
          <div className="flex items-center gap-2">
            <div className="w-[220px]">
              <Input
                type="search"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(1);
                }}
                placeholder="Search targets…"
                aria-label="Search targets"
              />
            </div>
            <button className="flex items-center gap-1.5 border border-hairline rounded-sm px-3 py-2 text-slate hover:border-ink hover:text-ink transition-colors">
              <FilterIcon />
              <span className="font-body text-[12px]">Filter</span>
            </button>
          </div>
        </div>

        {/* ── Table ── */}
        {targets.length === 0 ? (
          <div className="border border-hairline rounded-sm p-12 text-center bg-vellum/30">
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-gilt">
              No targets on file
            </p>
            <h3 className="mt-3 font-display text-[26px] text-ink">
              Register your first target.
            </h3>
            <p className="mt-2 font-body text-[14px] text-slate max-w-[52ch] mx-auto">
              Provide a URL, repository, or LLM endpoint and commission your
              first assessment.
            </p>
            <div className="mt-6 flex justify-center">
              <Link href="/targets/new">
                <button className="flex items-center gap-2 bg-ink text-paper rounded-sm px-5 py-2.5 font-body text-[14px] font-medium hover:bg-graphite transition-colors">
                  Register target
                </button>
              </Link>
            </div>
          </div>
        ) : filtered.length === 0 ? (
          <p className="font-body text-[14px] text-slate italic">
            No targets match the current filter.
          </p>
        ) : (
          <div className="border border-hairline rounded-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left min-w-[900px]">
                <thead>
                  <tr className="border-b border-hairline bg-vellum/80">
                    <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">
                      Target
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden sm:table-cell">
                      Type
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">
                      Risk
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden md:table-cell">
                      Last Scan
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">
                      <div className="inline-flex items-center gap-1.5 text-[9px]">
                        <span className="w-7 text-center text-sev-critical">
                          CRIT
                        </span>
                        <span className="text-mist/40">·</span>
                        <span className="w-7 text-center text-sev-high">
                          HIGH
                        </span>
                        <span className="text-mist/40">·</span>
                        <span className="w-7 text-center text-sev-medium">
                          MED
                        </span>
                        <span className="text-mist/40">·</span>
                        <span className="w-7 text-center text-sev-low">
                          LOW
                        </span>
                      </div>
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden lg:table-cell">
                      Coverage
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden xl:table-cell">
                      Creds
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden xl:table-cell">
                      Next Scan
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist text-right">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline">
                  {visible.map((t) => {
                    const kind = effectiveKind(t);
                    const isRepo = kind === "repo";
                    const repo =
                      isRepo && t.repository_id
                        ? repoById.get(t.repository_id)
                        : null;
                    const scan = latestScanByTarget.get(t.id);
                    const sched = nextScheduleByTarget.get(t.id);
                    const hasScan = scan || (isRepo && repo?.last_scan_at);
                    // Repo targets carry severity counts on the Repo row (last
                    // scan summary). DAST / LLM targets carry them on the
                    // latest Scan.summary.
                    const findings: Record<string, number | string> | null =
                      repo?.severity_counts
                        ? (repo.severity_counts as Record<
                            string,
                            number | string
                          >)
                        : (scan?.summary ?? null);
                    const risk = riskFromFindings(findings);
                    const score = scan?.score;
                    const riskScore = displayRiskScore(findings, score);
                    // Feature 001: pass wire-level Target.kind so per-kind badges
                    // (CONTAINER, IAC, K8S, CI, SBOM, API, …) show up; falls back
                    // to DisplayKind grouping for legacy rows.
                    const coverage = coverageBadges(kind, t.kind ?? undefined);
                    const tLabel = typeLabel(t);
                    // remove in sub-project B (OSExploitAgent)
                    const isHostKindUntilB = t.kind === "host";
                    // Memory targets aren't scanned via the Celery /scans
                    // pipeline — they use POST /v1/memory/scan from the
                    // detail-page MemoryPanel. Route the Scan action there.
                    const isMemory = t.kind === "memory";

                    return (
                      <tr
                        key={t.id}
                        className="hover:bg-vellum/40 transition-colors group"
                      >
                        {/* Target */}
                        <td className="px-4 py-2.5 align-top">
                          <Link
                            href={
                              isRepo
                                ? `/repos/${t.repository_id}`
                                : `/targets/${t.id}`
                            }
                            className="font-body text-[14px] font-semibold text-ink hover:underline underline-offset-4 decoration-gilt block"
                          >
                            {t.name}
                          </Link>
                          <span className="font-mono text-[11px] text-mist block mt-0.5 max-w-[220px] truncate">
                            {t.base_url}
                          </span>
                        </td>
                        {/* Type */}
                        <td className="px-4 py-2.5 align-top hidden sm:table-cell">
                          <TypeBadge label={tLabel} />
                        </td>
                        {/* Risk */}
                        <td className="px-4 py-2.5 align-top">
                          {hasScan ? (
                            <div className="flex items-center gap-2">
                              <div
                                className={cn(
                                  "w-[3px] h-[26px] rounded-full shrink-0",
                                  risk.bg,
                                )}
                              />
                              <div>
                                <p
                                  className={cn(
                                    "font-mono text-[10px] uppercase tracking-[0.12em] font-bold",
                                    risk.color,
                                  )}
                                >
                                  {risk.level}
                                </p>
                                {riskScore !== null && (
                                  <p className="font-mono text-[12px] text-ink">
                                    {riskScore}
                                    <span className="text-mist">/100</span>
                                  </p>
                                )}
                              </div>
                            </div>
                          ) : (
                            <div className="flex items-center gap-2">
                              <div className="w-[3px] h-[26px] rounded-full bg-hairline shrink-0" />
                              <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-mist">
                                Unscanned
                              </span>
                            </div>
                          )}
                        </td>
                        {/* Last Scan */}
                        <td className="px-4 py-3 hidden md:table-cell">
                          {scan ? (
                            <div>
                              <p className="font-mono text-[11px] text-ink">
                                {formatDate(
                                  scan.finished_at ?? scan.created_at,
                                )}
                              </p>
                              <p className="font-mono text-[10px] text-mist mt-0.5">
                                {relativeDate(
                                  scan.finished_at ?? scan.created_at,
                                )}
                              </p>
                            </div>
                          ) : repo?.last_scan_at ? (
                            <div>
                              <p className="font-mono text-[11px] text-ink">
                                {formatDate(repo.last_scan_at)}
                              </p>
                              <p className="font-mono text-[10px] text-mist mt-0.5">
                                {relativeDate(repo.last_scan_at)}
                              </p>
                            </div>
                          ) : (
                            <span className="font-mono text-[11px] text-mist">
                              Never
                            </span>
                          )}
                        </td>
                        {/* Findings (inline CRIT · HIGH · MED · LOW) */}
                        <td className="px-4 py-2.5 align-top">
                          {findings ? (
                            <div className="inline-flex items-center gap-1.5">
                              <span className="w-7 text-center font-mono text-[12px] font-bold text-sev-critical">
                                {Number(findings.critical) || 0}
                              </span>
                              <span className="text-mist/40 text-[10px]">
                                ·
                              </span>
                              <span className="w-7 text-center font-mono text-[12px] font-bold text-sev-high">
                                {Number(findings.high) || 0}
                              </span>
                              <span className="text-mist/40 text-[10px]">
                                ·
                              </span>
                              <span className="w-7 text-center font-mono text-[12px] font-bold text-sev-medium">
                                {Number(findings.medium) || 0}
                              </span>
                              <span className="text-mist/40 text-[10px]">
                                ·
                              </span>
                              <span className="w-7 text-center font-mono text-[12px] font-bold text-sev-low">
                                {Number(findings.low) || 0}
                              </span>
                            </div>
                          ) : (
                            <span className="font-mono text-[11px] text-mist">
                              —
                            </span>
                          )}
                        </td>
                        {/* Coverage */}
                        <td className="px-4 py-3 hidden lg:table-cell">
                          <div className="flex flex-wrap gap-1">
                            {coverage.map((c) => (
                              <CoverageBadge key={c} label={c} />
                            ))}
                          </div>
                        </td>
                        {/* Creds */}
                        <td className="px-4 py-3 hidden xl:table-cell">
                          {t.has_credentials ? (
                            <span className="inline-flex items-center gap-1 text-forest">
                              <CheckIcon />
                              <span className="font-mono text-[11px]">
                                On file
                              </span>
                            </span>
                          ) : (
                            <span className="font-mono text-[11px] text-mist">
                              —
                            </span>
                          )}
                        </td>
                        {/* Next Scan */}
                        <td className="px-4 py-3 hidden xl:table-cell">
                          {sched?.next_run_at ? (
                            <div>
                              <p className="font-mono text-[11px] text-ink">
                                {formatDate(sched.next_run_at)}
                              </p>
                              <p className="font-mono text-[10px] text-mist mt-0.5">
                                {relativeFromNow(sched.next_run_at)}
                              </p>
                            </div>
                          ) : (
                            <span className="font-mono text-[11px] text-mist">
                              Not scheduled
                            </span>
                          )}
                        </td>
                        {/* Actions */}
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              type="button"
                              onClick={() => {
                                if (isHostKindUntilB) return;
                                if (isMemory) {
                                  router.push(`/targets/${t.id}`);
                                  return;
                                }
                                setCommissionFor({
                                  id: t.id,
                                  name: t.name,
                                  kind,
                                  kind_config: t.kind_config ?? null,
                                  repository_id: t.repository_id ?? null,
                                  priorAuthorizationText:
                                    scan?.consent_payload?.authorization_text ??
                                    null,
                                });
                              }}
                              disabled={isHostKindUntilB}
                              title={
                                isHostKindUntilB
                                  ? "Host-target scanning ships in OSExploitAgent v2 (coming soon)."
                                  : isMemory
                                    ? "Scan memory items"
                                    : isRepo
                                      ? "Scan repository"
                                      : "Commission assessment"
                              }
                              aria-label={
                                isMemory
                                  ? "Scan memory items"
                                  : isRepo
                                    ? "Scan repository"
                                    : "Commission assessment"
                              }
                              className="p-1.5 text-mist hover:text-forest hover:bg-forest/8 rounded-sm transition-colors disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:text-mist disabled:hover:bg-transparent"
                            >
                              <svg
                                viewBox="0 0 16 16"
                                fill="currentColor"
                                className="w-3.5 h-3.5"
                              >
                                <path d="M5 3.5l8 4.5-8 4.5V3.5Z" />
                              </svg>
                            </button>
                            <Link
                              href={
                                isRepo && t.repository_id
                                  ? `/repos/${t.repository_id}/edit`
                                  : `/targets/${t.id}/edit`
                              }
                              title={isRepo ? "Edit repository" : "Edit target"}
                              aria-label={
                                isRepo ? "Edit repository" : "Edit target"
                              }
                              className="p-1.5 text-mist hover:text-graphite hover:bg-vellum rounded-sm transition-colors"
                            >
                              <svg
                                viewBox="0 0 16 16"
                                fill="none"
                                stroke="currentColor"
                                strokeWidth="1.4"
                                className="w-3.5 h-3.5"
                              >
                                <path
                                  d="M11 2.5l2.5 2.5-8 8H3v-2.5l8-8Z"
                                  strokeLinejoin="round"
                                />
                                <path
                                  d="M10 3.5l2.5 2.5"
                                  strokeLinecap="round"
                                />
                              </svg>
                            </Link>
                            <button
                              type="button"
                              onClick={() => deleteTarget(t)}
                              title={
                                isRepo ? "Delete repository" : "Delete target"
                              }
                              aria-label={
                                isRepo ? "Delete repository" : "Delete target"
                              }
                              className="p-1.5 text-mist hover:text-sev-critical hover:bg-sev-critical/8 rounded-sm transition-colors"
                            >
                              <svg
                                viewBox="0 0 16 16"
                                fill="none"
                                stroke="currentColor"
                                strokeWidth="1.4"
                                className="w-3.5 h-3.5"
                              >
                                <path
                                  d="M2 4h12M5 4V2.5h6V4M6 7.5v4M10 7.5v4M3 4l1 9.5h8L13 4"
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                />
                              </svg>
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* ── Bottom pagination bar ── */}
            <div className="flex items-center justify-between gap-4 px-4 py-3 border-t border-hairline bg-vellum/30 flex-wrap">
              <span className="font-mono text-[11px] text-mist whitespace-nowrap">
                Showing {showFrom} to {showTo} of {filtered.length} result
                {filtered.length !== 1 ? "s" : ""}
              </span>
              <div className="flex items-center gap-3">
                {/* Page buttons */}
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={safePage === 1}
                    className="px-2 py-1 font-mono text-[11px] text-slate disabled:opacity-30 hover:text-ink transition-colors"
                  >
                    ← Prev
                  </button>
                  {Array.from({ length: Math.min(5, pageCount) }, (_, i) => {
                    let pageNum: number;
                    if (pageCount <= 5) pageNum = i + 1;
                    else if (safePage <= 3) pageNum = i + 1;
                    else if (safePage >= pageCount - 2)
                      pageNum = pageCount - 4 + i;
                    else pageNum = safePage - 2 + i;
                    return (
                      <button
                        key={pageNum}
                        onClick={() => setPage(pageNum)}
                        className={cn(
                          "w-7 h-7 font-mono text-[11px] rounded-sm transition-colors",
                          safePage === pageNum
                            ? "bg-ink text-paper"
                            : "text-slate hover:text-ink hover:bg-vellum",
                        )}
                      >
                        {pageNum}
                      </button>
                    );
                  })}
                  <button
                    onClick={() => setPage((p) => Math.min(pageCount, p + 1))}
                    disabled={safePage === pageCount}
                    className="px-2 py-1 font-mono text-[11px] text-slate disabled:opacity-30 hover:text-ink transition-colors"
                  >
                    Next →
                  </button>
                </div>
                {/* Rows per page */}
                <div className="flex items-center gap-1.5">
                  <span className="font-mono text-[10px] text-mist whitespace-nowrap">
                    Rows per page:
                  </span>
                  <select
                    value={rowsPerPage}
                    onChange={(e) => {
                      setRowsPerPage(
                        Number(e.target.value) as (typeof ROWS_OPTIONS)[number],
                      );
                      setPage(1);
                    }}
                    className="border border-hairline rounded-sm px-2 py-1 font-mono text-[11px] text-graphite bg-paper focus:outline-none focus:border-ink"
                  >
                    {ROWS_OPTIONS.map((n) => (
                      <option key={n} value={n}>
                        {n}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Exposure Intelligence panel ── */}
      <aside className="w-[280px] shrink-0 border-l border-hairline px-5 py-6 space-y-5 hidden lg:block bg-vellum/20">
        {/* Header */}
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-gilt">
            Intelligence
          </p>
          <h3 className="font-display text-[17px] text-ink mt-1">
            Exposure Intelligence
          </h3>
        </div>

        {/* Top risky targets */}
        <div>
          <IntelDivider label="Top Risky Targets" />
          <div className="mt-3 space-y-2.5">
            {topRiskyTargets.length === 0 ? (
              <p className="font-body text-[12px] text-mist italic">
                No risk data yet — run an assessment.
              </p>
            ) : (
              topRiskyTargets.map(({ t, scan }) => {
                const risk = riskFromFindings(scan?.summary ?? null);
                return (
                  <div key={t.id} className="flex items-center gap-2.5">
                    <div
                      className={cn("w-2 h-2 rounded-full shrink-0", risk.bg)}
                    />
                    <div className="flex-1 min-w-0">
                      <p className="font-body text-[12px] text-ink font-medium truncate">
                        {t.name}
                      </p>
                      <p
                        className={cn(
                          "font-mono text-[10px] uppercase tracking-[0.1em]",
                          risk.color,
                        )}
                      >
                        {risk.level}{" "}
                        {scan?.score !== null && scan?.score !== undefined
                          ? `· ${scan.score}/100`
                          : ""}
                      </p>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Coverage gaps */}
        <div>
          <IntelDivider label="Coverage Gaps" />
          <div className="mt-3 space-y-2">
            {coverageGaps.length === 0 ? (
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-forest shrink-0" />
                <p className="font-body text-[12px] text-slate">
                  All targets covered.
                </p>
              </div>
            ) : (
              coverageGaps.map((gap, i) => (
                <div key={i} className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-sev-high mt-1 shrink-0" />
                  <p className="font-body text-[12px] text-slate">{gap}</p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Suggested next actions */}
        <div>
          <IntelDivider label="Suggested Actions" />
          <div className="mt-3 space-y-2">
            {unscannedTargets.length > 0 && (
              <div className="flex items-start gap-2">
                <span className="font-mono text-[11px] text-gilt mt-0.5">
                  →
                </span>
                <p className="font-body text-[12px] text-slate">
                  Commission a scan for{" "}
                  <span className="font-medium text-ink">
                    {unscannedTargets[0]?.name}
                  </span>
                </p>
              </div>
            )}
            {authTargets.length < targets.length && (
              <div className="flex items-start gap-2">
                <span className="font-mono text-[11px] text-gilt mt-0.5">
                  →
                </span>
                <p className="font-body text-[12px] text-slate">
                  Add credentials to {targets.length - authTargets.length}{" "}
                  unauthenticated target
                  {targets.length - authTargets.length !== 1 ? "s" : ""}
                </p>
              </div>
            )}
            {criticalTargets.length > 0 && (
              <div className="flex items-start gap-2">
                <span className="font-mono text-[11px] text-sev-high mt-0.5">
                  !
                </span>
                <p className="font-body text-[12px] text-slate">
                  Review {criticalTargets.length} high-risk target
                  {criticalTargets.length !== 1 ? "s" : ""} immediately
                </p>
              </div>
            )}
            {targets.length === 0 && (
              <div className="flex items-start gap-2">
                <span className="font-mono text-[11px] text-gilt mt-0.5">
                  →
                </span>
                <p className="font-body text-[12px] text-slate">
                  <Link
                    href="/targets/new"
                    className="underline underline-offset-4 decoration-gilt hover:text-ink"
                  >
                    Register your first target
                  </Link>{" "}
                  to begin security assessments.
                </p>
              </div>
            )}
            {targets.length > 0 &&
              unscannedTargets.length === 0 &&
              criticalTargets.length === 0 &&
              authTargets.length === targets.length && (
                <div className="flex items-start gap-2">
                  <span className="font-mono text-[11px] text-forest mt-0.5">
                    ✓
                  </span>
                  <p className="font-body text-[12px] text-slate">
                    All targets scanned and authenticated.
                  </p>
                </div>
              )}
          </div>
        </div>

        {/* Agents that will run */}
        <div>
          <IntelDivider label="Active Agents" />
          <div className="mt-3 space-y-2">
            {urlTargets.length > 0 && (
              <div className="flex items-center gap-2">
                <ShieldIcon />
                <div>
                  <p className="font-body text-[12px] text-ink font-medium">
                    DAST Agent
                  </p>
                  <p className="font-mono text-[10px] text-mist">
                    {urlTargets.length} web target
                    {urlTargets.length !== 1 ? "s" : ""}
                  </p>
                </div>
              </div>
            )}
            {repoTargets.length > 0 && (
              <div className="flex items-center gap-2">
                <ShieldIcon />
                <div>
                  <p className="font-body text-[12px] text-ink font-medium">
                    SAST + SCA Agent
                  </p>
                  <p className="font-mono text-[10px] text-mist">
                    {repoTargets.length} repo
                    {repoTargets.length !== 1 ? "s" : ""}
                  </p>
                </div>
              </div>
            )}
            {llmTargets.length > 0 && (
              <div className="flex items-center gap-2">
                <ShieldIcon />
                <div>
                  <p className="font-body text-[12px] text-ink font-medium">
                    LLM Red Team Agent
                  </p>
                  <p className="font-mono text-[10px] text-mist">
                    {llmTargets.length} LLM endpoint
                    {llmTargets.length !== 1 ? "s" : ""}
                  </p>
                </div>
              </div>
            )}
            {targets.length === 0 && (
              <p className="font-body text-[12px] text-mist italic">
                No agents configured yet.
              </p>
            )}
          </div>
        </div>

        {/* By type summary */}
        <div>
          <IntelDivider label="Asset Breakdown" />
          <div className="mt-3 space-y-2.5">
            {[
              { label: "Web / API", value: urlTargets.length },
              { label: "Repositories", value: repoTargets.length },
              { label: "LLM / AI", value: llmTargets.length },
            ].map(({ label, value }) => (
              <div key={label} className="space-y-1">
                <div className="flex items-baseline justify-between">
                  <span className="font-body text-[12px] text-slate">
                    {label}
                  </span>
                  <span className="font-mono text-[12px] text-ink">
                    {value}
                  </span>
                </div>
                <div className="h-[3px] w-full bg-vellum rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gilt rounded-full"
                    style={{
                      width:
                        targets.length > 0
                          ? `${Math.round((value / targets.length) * 100)}%`
                          : "0%",
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </aside>

      <CommissionScanModal
        targetId={commissionFor?.id ?? null}
        targetName={commissionFor?.name ?? null}
        targetKind={commissionFor?.kind}
        targetKindConfig={commissionFor?.kind_config ?? null}
        repositoryId={commissionFor?.repository_id ?? null}
        priorAuthorizationText={commissionFor?.priorAuthorizationText ?? null}
        onClose={() => setCommissionFor(null)}
      />
    </div>
  );
}
