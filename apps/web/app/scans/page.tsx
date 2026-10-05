"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { GradeBadge } from "@/components/brutal";
import { CommissionScanModal } from "@/components/commission-scan-modal";
import { LoadMetricCell } from "@/components/load-metric-cell";
import { PageLoading } from "@/components/loading";
import { api, downloadFile } from "@/lib/api";
import { cn } from "@/lib/cn";
import { calculateRepoGrade } from "@/lib/repo-scans";

// ── Types ─────────────────────────────────────────────────────────────────────
type Target = {
  id: string;
  name: string;
  base_url: string;
  kind?: string;
  kind_config?: Record<string, unknown> | null;
  repository_id?: string | null;
};
type Scan = {
  id: string;
  target_id: string;
  status: string;
  progress_pct: number;
  grade: string | null;
  score: number | null;
  profile?: string | null;
  summary: Record<string, number | string> | null;
  consent_payload?: { authorization_text?: string } | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
};
type Schedule = {
  id: string;
  target_id: string;
  name: string;
  profile: string;
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function formatReportId(scan: Scan, idx: number): string {
  const d = new Date(scan.created_at);
  const y = d.getFullYear();
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  const da = String(d.getDate()).padStart(2, "0");
  return `PEN-${y}-${mo}${da}-${String(idx + 1).padStart(3, "0")}`;
}

const REPO_LIKE_KINDS = new Set([
  "repo",
  "source_code",
  "iac",
  "container_image",
  "k8s_cluster",
  "cicd_pipeline",
  "package_registry",
  "sbom",
]);

function effectiveKind(t: Target): "url" | "repo" | "llm" {
  if (t.repository_id) return "repo";
  const k = t.kind ?? "url";
  if (k === "llm") return "llm";
  if (REPO_LIKE_KINDS.has(k)) return "repo";
  return "url";
}
function typeLabel(t: Target): string {
  const kind = effectiveKind(t);
  if (kind === "repo") return "Repository";
  if (kind === "llm") return "LLM";
  const url = (t.base_url ?? "").toLowerCase();
  if (url.includes("api.") || url.includes("/api")) return "API";
  return "Web App";
}
function formatDuration(
  started: string | null,
  finished: string | null,
): string | null {
  if (!started || !finished) return null;
  const ms = new Date(finished).getTime() - new Date(started).getTime();
  const mins = Math.floor(ms / 60000);
  const secs = Math.floor((ms % 60000) / 1000);
  if (mins >= 60) return `${Math.floor(mins / 60)}h ${mins % 60}m`;
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}
function formatDateShort(iso: string | null): { date: string; time: string } {
  if (!iso) return { date: "—", time: "" };
  const d = new Date(iso);
  const date = d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
  const time = d.toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  });
  return { date, time };
}
function relativeDate(iso: string | null): string {
  if (!iso) return "";
  const diff = Date.now() - new Date(iso).getTime();
  const days = Math.floor(diff / 86400000);
  if (days === 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}
function upcomingLabel(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const now = new Date();
  const dayDiff = Math.floor((d.getTime() - now.getTime()) / 86400000);
  const timeStr = d.toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  });
  if (dayDiff === 0) return `Today, ${timeStr}`;
  if (dayDiff === 1) return `Tomorrow, ${timeStr}`;
  return (
    d.toLocaleDateString("en-US", { month: "short", day: "numeric" }) +
    `, ${timeStr}`
  );
}
function gradeStyle(grade: string | null): string {
  if (!grade) return "text-mist border-hairline bg-vellum";
  if (grade.startsWith("A")) return "text-forest border-forest/40 bg-forest/8";
  if (grade.startsWith("B")) return "text-gilt border-gilt/50 bg-gilt/8";
  if (grade.startsWith("C"))
    return "text-sev-medium border-sev-medium/40 bg-sev-medium/8";
  if (grade.startsWith("D"))
    return "text-sev-high border-sev-high/40 bg-sev-high/8";
  return "text-sev-critical border-sev-critical/40 bg-sev-critical/8";
}

// ── Inline SVG icons ──────────────────────────────────────────────────────────
const PlayIcon = () => (
  <svg viewBox="0 0 16 16" fill="currentColor" className="w-3.5 h-3.5">
    <path d="M5 3.5l8 4.5-8 4.5V3.5Z" />
  </svg>
);
const CompareIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-3.5 h-3.5"
  >
    <path d="M4 3v10M12 3v10M4 8h8" strokeLinecap="round" />
    <path
      d="M2 5l2-2 2 2M10 11l2 2 2-2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);
const ExportIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-3.5 h-3.5"
  >
    <path
      d="M8 2v8M5 7l3 3 3-3M2.5 12.5v1a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1v-1"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);
const DotsIcon = () => (
  <svg viewBox="0 0 16 16" fill="currentColor" className="w-4 h-4">
    <circle cx="3" cy="8" r="1.5" />
    <circle cx="8" cy="8" r="1.5" />
    <circle cx="13" cy="8" r="1.5" />
  </svg>
);
const FilterIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-3.5 h-3.5"
  >
    <path d="M2 4h12M4.5 8h7M7 12h2" strokeLinecap="round" />
  </svg>
);
const SearchIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-3.5 h-3.5 text-mist"
  >
    <circle cx="7" cy="7" r="4.5" />
    <path d="M10.5 10.5L13.5 13.5" strokeLinecap="round" />
  </svg>
);
// Module icons
const GlobeModIcon = () => (
  <svg
    viewBox="0 0 14 14"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.3"
    className="w-3.5 h-3.5"
  >
    <circle cx="7" cy="7" r="5.5" />
    <path d="M7 1.5c0 0-2.5 2-2.5 5.5s2.5 5.5 2.5 5.5M7 1.5c0 0 2.5 2 2.5 5.5S7 12.5 7 12.5M1.5 7h11" />
  </svg>
);
const ZapModIcon = () => (
  <svg
    viewBox="0 0 14 14"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.3"
    className="w-3.5 h-3.5"
  >
    <path d="M8 2L4 7.5h4.5L6 12 10 6.5H5.5L8 2Z" strokeLinejoin="round" />
  </svg>
);
const CodeModIcon = () => (
  <svg
    viewBox="0 0 14 14"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.3"
    className="w-3.5 h-3.5"
  >
    <path
      d="M4.5 4.5L2 7l2.5 2.5M9.5 4.5L12 7l-2.5 2.5M8 3l-2 8"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);
const PackageModIcon = () => (
  <svg
    viewBox="0 0 14 14"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.3"
    className="w-3.5 h-3.5"
  >
    <path d="M7 1.5L12 4V10L7 12.5L2 10V4L7 1.5Z" />
    <path d="M7 1.5V12.5M2 4l5 3 5-3" />
  </svg>
);
const KeyModIcon = () => (
  <svg
    viewBox="0 0 14 14"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.3"
    className="w-3.5 h-3.5"
  >
    <circle cx="5.5" cy="7" r="3" />
    <path d="M8.5 7H13M11 5.5v3" strokeLinecap="round" />
  </svg>
);
const BrainModIcon = () => (
  <svg
    viewBox="0 0 14 14"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.3"
    className="w-3.5 h-3.5"
  >
    <path d="M7 2.5C5 2.5 3.5 3.8 3.5 5.5c0 .5.1.9.3 1.3-.5.3-.8.8-.8 1.4 0 .8.5 1.4 1.2 1.7 0 .2-.1.4-.1.6C4.1 11.3 5 12 6 12H7M7 2.5c2 0 3.5 1.3 3.5 3 0 .5-.1.9-.3 1.3.5.3.8.8.8 1.4 0 .8-.5 1.4-1.2 1.7.1.2.1.4.1.6C9.9 11.3 9 12 8 12H7M7 2.5V12" />
  </svg>
);
const LayersModIcon = () => (
  <svg
    viewBox="0 0 14 14"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.3"
    className="w-3.5 h-3.5"
  >
    <path d="M1.5 7L7 9.5 12.5 7M1.5 4.5L7 7 12.5 4.5M7 2l5.5 2.5L7 7 1.5 4.5 7 2Z" />
  </svg>
);
const DocModIcon = () => (
  <svg
    viewBox="0 0 14 14"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.3"
    className="w-3.5 h-3.5"
  >
    <rect x="2.5" y="1.5" width="9" height="11" rx="1" />
    <path d="M5 5h4M5 7.5h4M5 10h2.5" strokeLinecap="round" />
  </svg>
);
const ShieldModIcon = () => (
  <svg
    viewBox="0 0 14 14"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.3"
    className="w-3.5 h-3.5"
  >
    <path d="M7 1.5L2 3.5v3C2 9.5 4 11.7 7 12.5c3-.8 5-3 5-6v-3L7 1.5Z" />
  </svg>
);
// Stat icon types
const CalIcon = () => (
  <svg
    viewBox="0 0 18 18"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4.5 h-4.5"
  >
    <rect x="2" y="3" width="14" height="13" rx="1.5" />
    <path d="M2 7h14M6 1v4M12 1v4" strokeLinecap="round" />
  </svg>
);
const ClockIcon = () => (
  <svg
    viewBox="0 0 18 18"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4.5 h-4.5"
  >
    <circle cx="9" cy="9" r="7" />
    <path d="M9 5v4l2.5 2.5" strokeLinecap="round" />
  </svg>
);
const PulseIcon = () => (
  <svg
    viewBox="0 0 18 18"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4.5 h-4.5"
  >
    <path
      d="M1 9h3l2-5 4 10 2-7 2 2h3"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);
const TriangleIcon = () => (
  <svg
    viewBox="0 0 18 18"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4.5 h-4.5"
  >
    <path d="M9 3L16 15H2L9 3Z" strokeLinejoin="round" />
    <path d="M9 8v3M9 13v.5" strokeLinecap="round" />
  </svg>
);
const FileTextIcon = () => (
  <svg
    viewBox="0 0 18 18"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4.5 h-4.5"
  >
    <rect x="3" y="2" width="12" height="14" rx="1" />
    <path d="M6 6h6M6 9h6M6 12h4" strokeLinecap="round" />
  </svg>
);
const ShieldCheckIcon = () => (
  <svg
    viewBox="0 0 18 18"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4.5 h-4.5"
  >
    <path d="M9 2L3 4.5v4C3 12 5.5 14.8 9 16c3.5-1.2 6-4 6-7.5v-4L9 2Z" />
    <path d="M6.5 9l2 2 3-3" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const StaleIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4 h-4 text-sev-critical"
  >
    <circle cx="8" cy="8" r="6.5" />
    <path d="M8 5v3M8 10v.5" strokeLinecap="round" />
  </svg>
);
const FailedIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4 h-4 text-sev-high"
  >
    <path d="M9 3L15 14H3L9 3Z" strokeLinejoin="round" />
    <path d="M9 8v2.5M9 12v.5" strokeLinecap="round" />
  </svg>
);
const ImprovIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4 h-4 text-forest"
  >
    <path
      d="M2 12L6 7l3 2.5L14 4"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path d="M11 4h3v3" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const ScheduleIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4 h-4 text-gilt"
  >
    <rect x="2" y="2.5" width="12" height="11" rx="1.5" />
    <path d="M2 6.5h12M6 1v3M10 1v3" strokeLinecap="round" />
  </svg>
);
const ExportCenterIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4 h-4 text-graphite"
  >
    <path
      d="M8 2v7M5 6l3 3 3-3M2.5 12v1a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1v-1"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

// Sparkline SVG
function Sparkline({ grade }: { grade: string | null }) {
  const color = !grade
    ? "#C8BFA6"
    : grade.startsWith("A")
      ? "#2F5D50"
      : grade.startsWith("B")
        ? "#C9A24E"
        : grade.startsWith("C")
          ? "#92712A"
          : "#B45309";
  const points = !grade
    ? "0,8 12,8 24,8 36,8 48,8"
    : grade.startsWith("A")
      ? "0,12 12,10 24,7 36,4 48,3"
      : grade.startsWith("B")
        ? "0,10 12,8 24,9 36,6 48,5"
        : grade.startsWith("C")
          ? "0,5 12,7 24,8 36,9 48,10"
          : "0,3 12,6 24,8 36,10 48,12";
  return (
    <svg width="50" height="16" viewBox="0 0 50 16" fill="none">
      <polyline
        points={points}
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  );
}

// Module icons by kind
function ModuleIcons({
  kind,
  scanId,
  repoScan = false,
}: {
  kind: "url" | "repo" | "llm";
  scanId: string;
  // Only true RepoScan rows live at /repos/scans/{id}; the kind-aware kinds
  // (cicd/iac/source_code…) render repo-style icons but are Scan rows at
  // /scans/{id}. So icons key off `kind`, routing keys off `repoScan`.
  repoScan?: boolean;
}) {
  const icons: { icon: React.ReactNode; title: string; slug: string }[] =
    kind === "repo"
      ? [
          { icon: <CodeModIcon />, title: "SAST", slug: "sast" },
          { icon: <PackageModIcon />, title: "SCA", slug: "sca" },
          { icon: <KeyModIcon />, title: "Secrets", slug: "secrets" },
          { icon: <DocModIcon />, title: "Reports", slug: "reports" },
        ]
      : kind === "llm"
        ? [
            { icon: <BrainModIcon />, title: "LLM Red Team", slug: "llm" },
            { icon: <ShieldModIcon />, title: "Safety", slug: "safety" },
            { icon: <DocModIcon />, title: "Reports", slug: "reports" },
          ]
        : [
            { icon: <GlobeModIcon />, title: "Recon", slug: "recon" },
            { icon: <ZapModIcon />, title: "DAST", slug: "dast" },
            { icon: <ShieldModIcon />, title: "OWASP", slug: "owasp" },
            { icon: <LayersModIcon />, title: "Headers", slug: "headers" },
            { icon: <DocModIcon />, title: "Reports", slug: "reports" },
          ];
  const shown = icons.slice(0, 4);
  const extra = icons.length - shown.length;
  const linkPrefix = repoScan ? `/repos/scans/${scanId}` : `/scans/${scanId}`;
  return (
    <div className="flex items-center gap-1">
      {shown.map((m) => (
        <Link
          key={m.slug}
          href={`${linkPrefix}#${m.slug}`}
          className="text-mist hover:text-ink transition-colors p-0.5 -m-0.5 rounded-sm hover:bg-vellum"
          title={`View ${m.title} findings`}
          aria-label={`View ${m.title} findings`}
        >
          {m.icon}
        </Link>
      ))}
      {extra > 0 && (
        <Link
          href={linkPrefix}
          className="font-mono text-[9px] text-mist hover:text-ink transition-colors px-1 -mx-1 rounded-sm hover:bg-vellum"
          title="View all modules"
          aria-label="View all modules"
        >
          +{extra}
        </Link>
      )}
    </div>
  );
}

// Output icons
type ReportFormat = "pdf" | "json" | "csv" | "docx";
type ReportItem = {
  id: string;
  status: string;
  format: string;
  download_url?: string;
};

async function generateAndDownloadReport(
  scanId: string,
  fmt: ReportFormat,
): Promise<void> {
  const created = await api<ReportItem>(`/scans/${scanId}/reports`, {
    method: "POST",
    json: { format: fmt },
  });
  const startedAt = Date.now();
  while (Date.now() - startedAt < 90_000) {
    const updated = await api<ReportItem>(`/reports/${created.id}`);
    if (updated.status === "ready" && updated.download_url) {
      await downloadFile(
        updated.download_url,
        `pencheff-report-${scanId.slice(0, 8)}.${updated.format}`,
      );
      return;
    }
    if (updated.status === "failed")
      throw new Error("Report generation failed");
    await new Promise((res) => setTimeout(res, 2000));
  }
  throw new Error("Report generation timed out");
}

function OutputIcons({
  done,
  scanId,
  isRepo,
}: {
  done: boolean;
  scanId: string;
  isRepo?: boolean;
}) {
  const [busy, setBusy] = useState<ReportFormat | null>(null);
  if (!done) return <span className="font-mono text-[10px] text-mist">—</span>;
  async function trigger(fmt: ReportFormat) {
    if (busy) return;
    setBusy(fmt);
    try {
      await generateAndDownloadReport(scanId, fmt);
    } catch (e: any) {
      console.error("report download failed", e);
      window.alert(e?.message || "Unable to download report.");
    } finally {
      setBusy(null);
    }
  }
  const linkPrefix = isRepo ? `/repos/scans/${scanId}` : `/scans/${scanId}`;
  return (
    <div className="flex items-center gap-1.5">
      <Link
        href={`${linkPrefix}#reports`}
        title="View reports"
        aria-label="View reports"
        className="text-mist hover:text-ink transition-colors p-0.5 -m-0.5 rounded-sm hover:bg-vellum"
      >
        <DocModIcon />
      </Link>
      <button
        type="button"
        onClick={() => trigger("pdf")}
        disabled={busy !== null}
        title={busy === "pdf" ? "Generating PDF…" : "Download PDF"}
        aria-label={busy === "pdf" ? "Generating PDF" : "Download PDF"}
        className={cn(
          "transition-colors p-0.5 -m-0.5 rounded-sm hover:bg-sev-critical/8 disabled:cursor-wait",
          busy === "pdf"
            ? "text-sev-critical/50 animate-pulse"
            : "text-sev-critical hover:text-sev-critical/80",
        )}
      >
        <svg
          viewBox="0 0 14 14"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.3"
          className="w-3.5 h-3.5"
        >
          <rect x="2.5" y="1.5" width="9" height="11" rx="1" />
          <path d="M5 5h3M5 7.5h3M5 10h2" strokeLinecap="round" />
          <path d="M5 1.5v3h3" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      <button
        type="button"
        onClick={() => trigger("json")}
        disabled={busy !== null}
        title={busy === "json" ? "Generating JSON…" : "Download JSON"}
        aria-label={busy === "json" ? "Generating JSON" : "Download JSON"}
        className={cn(
          "font-mono text-[9px] border rounded-sm px-1 py-0.5 transition-colors disabled:cursor-wait",
          busy === "json"
            ? "text-slate/50 border-hairline animate-pulse"
            : "text-slate border-hairline hover:text-ink hover:border-ink",
        )}
      >
        JSON
      </button>
      <Link
        href={`${linkPrefix}#reports`}
        title="View all formats"
        aria-label="View all formats"
        className="font-mono text-[9px] text-mist hover:text-ink transition-colors px-1 -mx-1 rounded-sm hover:bg-vellum"
      >
        +1
      </Link>
    </div>
  );
}

// ── Stat widget ───────────────────────────────────────────────────────────────
interface StatWidgetProps {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  sub?: string;
  subColor?: string;
}
function StatWidget({
  icon,
  label,
  value,
  sub,
  subColor = "text-mist",
}: StatWidgetProps) {
  return (
    <div className="flex flex-col gap-1 border border-hairline rounded-sm p-4 bg-paper min-w-0">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[9px] uppercase tracking-[0.16em] text-mist">
          {label}
        </span>
        <span className="text-mist">{icon}</span>
      </div>
      <p className="font-display text-[36px] leading-none tracking-[-0.02em] text-ink mt-1">
        {value}
      </p>
      {sub && (
        <p className={cn("font-mono text-[10px] mt-0.5", subColor)}>{sub}</p>
      )}
    </div>
  );
}

// ── Filter tab ────────────────────────────────────────────────────────────────
function TabPill({
  label,
  count,
  active,
  onClick,
}: {
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-sm border px-3 py-1.5 font-body text-[13px] transition-colors whitespace-nowrap",
        active
          ? "bg-ink text-paper border-ink font-medium"
          : "bg-paper text-slate border-hairline hover:border-graphite hover:text-graphite",
      )}
    >
      {label}
      <span
        className={cn(
          "font-mono text-[11px]",
          active ? "text-paper/70" : "text-mist",
        )}
      >
        ({count})
      </span>
    </button>
  );
}

// ── Agent coverage ────────────────────────────────────────────────────────────
const AGENTS = [
  { icon: <GlobeModIcon />, label: "Recon", pct: 100 },
  { icon: <ZapModIcon />, label: "DAST", pct: 97 },
  { icon: <CodeModIcon />, label: "SAST", pct: 94 },
  { icon: <KeyModIcon />, label: "Secrets", pct: 100 },
  { icon: <PackageModIcon />, label: "SCA", pct: 97 },
  { icon: <LayersModIcon />, label: "IaC", pct: 92 },
  { icon: <ShieldModIcon />, label: "Container", pct: 94 },
  { icon: <BrainModIcon />, label: "LLM Red Team", pct: 100 },
  { icon: <DocModIcon />, label: "Reports", pct: 100 },
  { icon: <PulseIcon />, label: "Remediation", pct: 90 },
];

// ── Main page ─────────────────────────────────────────────────────────────────
const ROWS_OPTIONS = [8, 10, 20, 50] as const;
type FilterTab =
  | "all"
  | "running"
  | "done"
  | "failed"
  | "scheduled"
  | "rechecks"
  | "llm"
  | "repo";

export default function AssessmentsListPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [activeTab, setActiveTab] = useState<FilterTab>("all");
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] =
    useState<(typeof ROWS_OPTIONS)[number]>(10);
  const [commissionFor, setCommissionFor] = useState<{
    id: string;
    name: string;
    kind?: "url" | "repo" | "llm";
    kind_config?: Record<string, unknown> | null;
    repository_id?: string | null;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      api<Scan[]>("/scans").catch(() => [] as Scan[]),
      api<Target[]>("/targets").catch(() => [] as Target[]),
      api<Schedule[]>("/schedules").catch(() => [] as Schedule[]),
      api<any[]>("/repos/scans").catch(() => [] as any[]),
    ])
      .then(([s, t, sc, rs]) => {
        if (cancelled) return;

        const mappedRepos = rs.map((r) => {
          const target = t.find((tg) => tg.repository_id === r.repository_id);
          const status = r.status === "succeeded" ? "done" : r.status;
          const grade = calculateRepoGrade(r.summary);
          return {
            id: r.id,
            target_id: target?.id || "",
            status,
            progress_pct: r.status === "running" ? 50 : 100,
            grade,
            score: null,
            profile: "Deep",
            summary: r.summary || null,
            started_at: r.started_at,
            finished_at: r.completed_at,
            created_at: r.created_at,
            repository_id: r.repository_id,
            _repoScan: true,
          } as Scan & { repository_id?: string; _repoScan?: boolean };
        });

        const merged = [...s, ...mappedRepos].sort(
          (a, b) =>
            new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
        );
        setScans(merged);
        setTargets(t);
        setSchedules(sc);
      })
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, []);

  // Polling for in-flight scans
  useEffect(() => {
    const inflight = scans.some(
      (s) => s.status === "queued" || s.status === "running",
    );
    if (!inflight) return;
    let cancelled = false;
    const h = window.setInterval(async () => {
      try {
        const [nextScans, nextRepoScans] = await Promise.all([
          api<Scan[]>("/scans"),
          api<any[]>("/repos/scans"),
        ]);
        if (cancelled) return;

        const mappedRepos = nextRepoScans.map((r) => {
          const target = targets.find(
            (tg) => tg.repository_id === r.repository_id,
          );
          const status = r.status === "succeeded" ? "done" : r.status;
          const grade = calculateRepoGrade(r.summary);
          return {
            id: r.id,
            target_id: target?.id || "",
            status,
            progress_pct: r.status === "running" ? 50 : 100,
            grade,
            score: null,
            profile: "Deep",
            summary: r.summary || null,
            started_at: r.started_at,
            finished_at: r.completed_at,
            created_at: r.created_at,
            repository_id: r.repository_id,
            _repoScan: true,
          };
        });

        const merged = [...nextScans, ...mappedRepos].sort(
          (a, b) =>
            new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
        );
        setScans(merged);
      } catch {}
    }, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(h);
    };
  }, [scans, targets]);

  // ── Lookups ──
  const targetById = useMemo(() => {
    const m = new Map<string, Target>();
    for (const t of targets) m.set(t.id, t);
    return m;
  }, [targets]);

  const scheduleByTarget = useMemo(() => {
    const m = new Map<string, Schedule[]>();
    for (const s of schedules) {
      const arr = m.get(s.target_id) ?? [];
      arr.push(s);
      m.set(s.target_id, arr);
    }
    return m;
  }, [schedules]);

  const scansByTarget = useMemo(() => {
    const m = new Map<string, Scan[]>();
    for (const s of scans) {
      const arr = m.get(s.target_id) ?? [];
      arr.push(s);
      m.set(s.target_id, arr);
    }
    return m;
  }, [scans]);

  // ── Tab counts ──
  const tabCounts = useMemo(() => {
    const scheduledTargetIds = new Set(
      schedules.filter((s) => s.enabled).map((s) => s.target_id),
    );
    const reCheckIds = new Set<string>();
    for (const [, arr] of scansByTarget) {
      if (arr.length > 1) arr.slice(1).forEach((s) => reCheckIds.add(s.id));
    }
    return {
      all: scans.length,
      running: scans.filter(
        (s) => s.status === "running" || s.status === "queued",
      ).length,
      done: scans.filter((s) => s.status === "done").length,
      failed: scans.filter((s) => s.status === "failed").length,
      scheduled: scans.filter((s) => scheduledTargetIds.has(s.target_id))
        .length,
      rechecks: reCheckIds.size,
      llm: scans.filter((s) => {
        const t = targetById.get(s.target_id);
        return t ? effectiveKind(t) === "llm" : false;
      }).length,
      repo: scans.filter((s) => {
        const t = targetById.get(s.target_id);
        return t ? effectiveKind(t) === "repo" : false;
      }).length,
    };
  }, [scans, targets, schedules, targetById, scansByTarget]);

  // ── Filtered + searched ──
  const filtered = useMemo(() => {
    const scheduledTargetIds = new Set(
      schedules.filter((s) => s.enabled).map((s) => s.target_id),
    );
    const reCheckIds = new Set<string>();
    for (const [, arr] of scansByTarget) {
      if (arr.length > 1) arr.slice(1).forEach((s) => reCheckIds.add(s.id));
    }
    let result = scans;
    if (activeTab === "running")
      result = result.filter(
        (s) => s.status === "running" || s.status === "queued",
      );
    else if (activeTab === "done")
      result = result.filter((s) => s.status === "done");
    else if (activeTab === "failed")
      result = result.filter((s) => s.status === "failed");
    else if (activeTab === "scheduled")
      result = result.filter((s) => scheduledTargetIds.has(s.target_id));
    else if (activeTab === "rechecks")
      result = result.filter((s) => reCheckIds.has(s.id));
    else if (activeTab === "llm")
      result = result.filter((s) => {
        const t = targetById.get(s.target_id);
        return t ? effectiveKind(t) === "llm" : false;
      });
    else if (activeTab === "repo")
      result = result.filter((s) => {
        const t = targetById.get(s.target_id);
        return t ? effectiveKind(t) === "repo" : false;
      });
    const q = query.trim().toLowerCase();
    if (q) {
      result = result.filter((s) => {
        const t = targetById.get(s.target_id);
        return (
          (t?.name ?? "").toLowerCase().includes(q) ||
          (t?.base_url ?? "").toLowerCase().includes(q) ||
          (s.grade ?? "").toLowerCase().includes(q) ||
          s.status.toLowerCase().includes(q)
        );
      });
    }
    return result;
  }, [scans, activeTab, query, schedules, scansByTarget, targetById]);

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

  // ── Stats ──
  const totalFindings = useMemo(
    () =>
      scans.reduce((sum, s) => {
        if (!s.summary) return sum;
        return (
          sum +
          (Number(s.summary.critical) || 0) +
          (Number(s.summary.high) || 0) +
          (Number(s.summary.medium) || 0) +
          (Number(s.summary.low) || 0)
        );
      }, 0),
    [scans],
  );

  const completedCount = scans.filter((s) => s.status === "done").length;
  const runningCount = scans.filter(
    (s) => s.status === "running" || s.status === "queued",
  ).length;
  const scheduledEnabledCount = schedules.filter((s) => s.enabled).length;
  const reportsExported = completedCount;

  const evidencePct = useMemo(() => {
    if (!targets.length) return 0;
    const scannedTargets = new Set(
      scans.filter((s) => s.status === "done").map((s) => s.target_id),
    );
    return Math.round((scannedTargets.size / targets.length) * 100);
  }, [scans, targets]);

  const nextSchedule = useMemo(
    () =>
      schedules
        .filter((s) => s.enabled && s.next_run_at)
        .sort(
          (a, b) =>
            new Date(a.next_run_at!).getTime() -
            new Date(b.next_run_at!).getTime(),
        )[0],
    [schedules],
  );

  const nextScheduleIn = useMemo(() => {
    if (!nextSchedule?.next_run_at) return null;
    const diff = new Date(nextSchedule.next_run_at).getTime() - Date.now();
    if (diff <= 0) return "soon";
    const h = Math.floor(diff / 3600000);
    const m = Math.floor((diff % 3600000) / 60000);
    return `in ${h}h ${m}m`;
  }, [nextSchedule]);

  // ── Right panel ──
  const staleTargets = useMemo(() => {
    const THIRTY_DAYS = 30 * 86400000;
    return targets
      .filter((t) => {
        const tScans =
          scansByTarget.get(t.id)?.filter((s) => s.status === "done") ?? [];
        if (tScans.length === 0) return true;
        const latest = Math.max(
          ...tScans.map((s) => new Date(s.created_at).getTime()),
        );
        return Date.now() - latest > THIRTY_DAYS;
      })
      .slice(0, 3);
  }, [targets, scansByTarget]);

  const failedScans = useMemo(
    () =>
      scans
        .filter((s) => s.status === "failed")
        .slice(0, 3)
        .map((s) => ({ scan: s, target: targetById.get(s.target_id) })),
    [scans, targetById],
  );

  const bestImprovement = useMemo(() => {
    const GRADE_ORDER = [
      "A+",
      "A",
      "A-",
      "B+",
      "B",
      "B-",
      "C+",
      "C",
      "C-",
      "D+",
      "D",
      "D-",
      "F",
    ];
    let best: {
      target: Target;
      prev: string;
      curr: string;
      pts: number;
    } | null = null;
    for (const [tid, arr] of scansByTarget) {
      const done = arr
        .filter((s) => s.status === "done" && s.grade)
        .sort(
          (a, b) =>
            new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
        );
      if (done.length < 2) continue;
      const curr = done[0].grade!;
      const prev = done[1].grade!;
      const ci = GRADE_ORDER.indexOf(curr);
      const pi = GRADE_ORDER.indexOf(prev);
      if (ci < 0 || pi < 0) continue;
      const pts = (pi - ci) * 8;
      if (pts > 0 && (!best || pts > best.pts)) {
        const target = targetById.get(tid);
        if (target) best = { target, prev, curr, pts };
      }
    }
    return best;
  }, [scansByTarget, targetById]);

  const upcomingSchedules = useMemo(
    () =>
      schedules
        .filter((s) => s.enabled && s.next_run_at)
        .sort(
          (a, b) =>
            new Date(a.next_run_at!).getTime() -
            new Date(b.next_run_at!).getTime(),
        )
        .slice(0, 4)
        .map((s) => ({ schedule: s, target: targetById.get(s.target_id) })),
    [schedules, targetById],
  );

  // ── Assessment cadence (last 7 days) ──
  const cadenceData = useMemo(() => {
    const days: { label: string; count: number }[] = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      d.setHours(0, 0, 0, 0);
      const next = new Date(d);
      next.setDate(next.getDate() + 1);
      const count = scans.filter((s) => {
        const t = new Date(s.created_at).getTime();
        return t >= d.getTime() && t < next.getTime();
      }).length;
      days.push({
        label: d.toLocaleDateString("en-US", {
          month: "short",
          day: "numeric",
        }),
        count,
      });
    }
    return days;
  }, [scans]);
  const maxCadence = Math.max(...cadenceData.map((d) => d.count), 1);

  async function deleteScan(scanId: string) {
    if (
      !window.confirm(
        "Delete this assessment?\n\nFindings, evidence, and generated reports will be removed. This action cannot be undone.",
      )
    )
      return;
    try {
      const scan = scans.find((s) => s.id === scanId);
      const isRepo = scan && "repository_id" in scan;
      if (isRepo) {
        await api(`/repos/scans/${scanId}`, { method: "DELETE" });
      } else {
        await api(`/scans/${scanId}`, { method: "DELETE" });
      }
      setScans((prev) => prev.filter((x) => x.id !== scanId));
    } catch (e: any) {
      alert(e?.message || "Unable to delete assessment.");
    }
  }

  if (loading && scans.length === 0)
    return <PageLoading title="Assessments" cards={8} />;

  return (
    <div className="-mx-5 md:-mx-6 -mt-6 -mb-6 flex">
      <div className="flex-1 min-w-0 px-5 md:px-6 py-6 space-y-5">
        {/* ── Header ── */}
        <header>
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">
            Assessments
          </p>
          <div className="mt-2 flex items-start justify-between gap-4 flex-wrap">
            <div>
              <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
                Assessments.
              </h1>
              <p className="mt-1 font-body text-[14px] text-slate">
                Every scan, report, retest, and evidence bundle.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() =>
                  targets.length > 0
                    ? setCommissionFor({
                        id: targets[0].id,
                        name: targets[0].name,
                        kind: effectiveKind(targets[0]),
                        kind_config: targets[0].kind_config ?? null,
                        repository_id: targets[0].repository_id ?? null,
                      })
                    : undefined
                }
                className="flex items-center gap-2 bg-ink text-paper rounded-sm px-4 py-2 font-body text-[13px] font-medium hover:bg-graphite transition-colors"
              >
                <PlayIcon /> Run assessment
              </button>
              <button className="flex items-center gap-2 border border-hairline rounded-sm px-4 py-2 font-body text-[13px] text-slate hover:border-ink hover:text-ink transition-colors">
                <CompareIcon /> Compare scans
              </button>
              <button className="flex items-center gap-2 border border-hairline rounded-sm px-4 py-2 font-body text-[13px] text-slate hover:border-ink hover:text-ink transition-colors">
                <ExportIcon /> Export ledger
              </button>
              <button className="p-2 border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors">
                <DotsIcon />
              </button>
            </div>
          </div>
        </header>

        {/* ── 6-stat bar ── */}
        <div className="grid grid-cols-3 xl:grid-cols-6 gap-2.5">
          <StatWidget
            icon={<CalIcon />}
            label="Total Assessments"
            value={scans.length}
            sub={
              completedCount > 0
                ? `↑ ${completedCount} completed`
                : "No completions yet"
            }
            subColor="text-forest"
          />
          <StatWidget
            icon={<PulseIcon />}
            label="Running"
            value={runningCount}
            sub={
              runningCount > 0 ? `${runningCount} right now` : "— 0 right now"
            }
            subColor={runningCount > 0 ? "text-gilt" : "text-mist"}
          />
          <StatWidget
            icon={<ClockIcon />}
            label="Scheduled"
            value={scheduledEnabledCount}
            sub={nextScheduleIn ? `Next: ${nextScheduleIn}` : "None upcoming"}
          />
          <StatWidget
            icon={<TriangleIcon />}
            label="Total Findings"
            value={totalFindings.toLocaleString()}
            sub={
              totalFindings > 0
                ? `↑ ${totalFindings} across all scans`
                : "No findings yet"
            }
            subColor={totalFindings > 0 ? "text-sev-medium" : "text-mist"}
          />
          <StatWidget
            icon={<FileTextIcon />}
            label="Reports Exported"
            value={reportsExported}
            sub={
              reportsExported > 0
                ? `↑ ${reportsExported} total`
                : "No reports yet"
            }
          />
          <StatWidget
            icon={<ShieldCheckIcon />}
            label="Evidence Coverage"
            value={`${evidencePct}%`}
            sub="Across all scans"
          />
        </div>

        {/* ── Filter tabs + search ── */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-1.5 flex-wrap">
            <TabPill
              label="All"
              count={tabCounts.all}
              active={activeTab === "all"}
              onClick={() => {
                setActiveTab("all");
                setPage(1);
              }}
            />
            <TabPill
              label="Running"
              count={tabCounts.running}
              active={activeTab === "running"}
              onClick={() => {
                setActiveTab("running");
                setPage(1);
              }}
            />
            <TabPill
              label="Completed"
              count={tabCounts.done}
              active={activeTab === "done"}
              onClick={() => {
                setActiveTab("done");
                setPage(1);
              }}
            />
            <TabPill
              label="Failed"
              count={tabCounts.failed}
              active={activeTab === "failed"}
              onClick={() => {
                setActiveTab("failed");
                setPage(1);
              }}
            />
            <TabPill
              label="Scheduled"
              count={tabCounts.scheduled}
              active={activeTab === "scheduled"}
              onClick={() => {
                setActiveTab("scheduled");
                setPage(1);
              }}
            />
            <TabPill
              label="Rechecks"
              count={tabCounts.rechecks}
              active={activeTab === "rechecks"}
              onClick={() => {
                setActiveTab("rechecks");
                setPage(1);
              }}
            />
            <TabPill
              label="LLM"
              count={tabCounts.llm}
              active={activeTab === "llm"}
              onClick={() => {
                setActiveTab("llm");
                setPage(1);
              }}
            />
            <TabPill
              label="Repositories"
              count={tabCounts.repo}
              active={activeTab === "repo"}
              onClick={() => {
                setActiveTab("repo");
                setPage(1);
              }}
            />
          </div>
          <div className="flex items-center gap-2">
            <div className="relative flex items-center w-[220px]">
              <span className="absolute left-3 pointer-events-none">
                <SearchIcon />
              </span>
              <input
                type="search"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(1);
                }}
                placeholder="Search assessments…"
                className="w-full border border-hairline rounded-sm pl-9 pr-4 py-2 font-body text-[13px] bg-paper text-graphite placeholder:text-mist focus:outline-none focus:border-ink transition-colors"
              />
            </div>
            <button className="flex items-center gap-1.5 border border-hairline rounded-sm px-3 py-2 font-body text-[12px] text-slate hover:border-ink hover:text-ink transition-colors">
              <FilterIcon /> Filters
            </button>
          </div>
        </div>

        {/* ── Table ── */}
        {scans.length === 0 ? (
          <div className="border border-hairline rounded-sm p-12 text-center bg-vellum/30">
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-gilt">
              No assessments
            </p>
            <h3 className="mt-3 font-display text-[26px] text-ink">
              No assessments yet.
            </h3>
            <p className="mt-2 font-body text-[14px] text-slate max-w-[52ch] mx-auto">
              Run your first assessment from the Targets page.
            </p>
            <div className="mt-6">
              <Link href="/targets">
                <button className="bg-ink text-paper rounded-sm px-5 py-2.5 font-body text-[14px] font-medium hover:bg-graphite transition-colors">
                  Go to targets
                </button>
              </Link>
            </div>
          </div>
        ) : filtered.length === 0 ? (
          <p className="font-body text-[14px] text-slate italic">
            No assessments match the current filter.
          </p>
        ) : (
          <div className="border border-hairline rounded-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left min-w-[1160px]">
                <thead>
                  <tr className="border-b border-hairline bg-vellum/80">
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">
                      Grade
                    </th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">
                      Report ID
                    </th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">
                      Target
                    </th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden sm:table-cell">
                      Type
                    </th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden md:table-cell">
                      Profile
                    </th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden lg:table-cell">
                      Modules Run
                    </th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden md:table-cell">
                      Completed
                    </th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">
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
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden xl:table-cell">
                      Outputs
                    </th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">
                      Status
                    </th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden xl:table-cell">
                      Trend
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline">
                  {visible.map((s, idx) => {
                    const target = targetById.get(s.target_id);
                    const kind = target ? effectiveKind(target) : "url";
                    // Routing: only RepoScan rows (tagged at merge) live at
                    // /repos/scans/. effectiveKind drives icons, not the route.
                    const isRepoScan =
                      (s as { _repoScan?: boolean })._repoScan === true;
                    const done = s.status === "done";
                    const { date, time } = formatDateShort(
                      s.finished_at ?? s.created_at,
                    );
                    const dur = formatDuration(s.started_at, s.finished_at);
                    const tSchedArr = scheduleByTarget.get(s.target_id);
                    const profile =
                      s.profile ?? tSchedArr?.[0]?.profile ?? "Standard";

                    return (
                      <tr
                        key={s.id}
                        className="hover:bg-vellum/40 transition-colors group"
                      >
                        {/* Grade */}
                        <td className="px-3 py-2.5 align-top">
                          <span
                            className={cn(
                              "inline-flex items-center justify-center w-10 h-10 border-2 rounded-sm font-display text-[18px] font-bold",
                              gradeStyle(s.grade),
                            )}
                          >
                            {s.grade || (done ? "F" : "?")}
                          </span>
                        </td>
                        {/* Report ID */}
                        <td className="px-3 py-2.5 align-top">
                          <Link
                            href={
                              kind === "repo"
                                ? `/repos/scans/${s.id}`
                                : `/scans/${s.id}`
                            }
                            className="font-mono text-[11px] text-ink font-medium hover:underline underline-offset-4 decoration-gilt"
                          >
                            {formatReportId(s, idx)}
                          </Link>
                          <p className="font-mono text-[9px] text-mist mt-0.5">
                            {date.slice(0, 12)}
                          </p>
                        </td>
                        {/* Target */}
                        <td className="px-3 py-2.5 align-top">
                          {target ? (
                            <div>
                              <Link
                                href={
                                  kind === "repo"
                                    ? `/repos/${target.repository_id}`
                                    : `/targets/${target.id}`
                                }
                                className="font-body text-[13px] font-semibold text-ink hover:underline underline-offset-4 decoration-gilt block truncate max-w-[160px]"
                              >
                                {target.name}
                              </Link>
                              <p className="font-mono text-[10px] text-mist truncate max-w-[160px] mt-0.5">
                                {target.base_url.replace(/^https?:\/\//, "")}
                              </p>
                            </div>
                          ) : (
                            <span className="font-mono text-[11px] text-mist">
                              —
                            </span>
                          )}
                        </td>
                        {/* Type */}
                        <td className="px-3 py-3 hidden sm:table-cell">
                          <span className="inline-flex items-center border border-hairline rounded-sm px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.1em] text-slate bg-vellum">
                            {target ? typeLabel(target) : "—"}
                          </span>
                        </td>
                        {/* Profile */}
                        <td className="px-3 py-3 hidden md:table-cell">
                          <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-graphite">
                            {profile}
                          </span>
                        </td>
                        {/* Modules */}
                        <td className="px-3 py-3 hidden lg:table-cell">
                          <ModuleIcons
                            kind={kind}
                            scanId={s.id}
                            repoScan={isRepoScan}
                          />
                        </td>
                        {/* Completed */}
                        <td className="px-3 py-3 hidden md:table-cell">
                          {done ? (
                            <div>
                              <p className="font-mono text-[11px] text-ink">
                                {date}
                              </p>
                              <p className="font-mono text-[10px] text-mist mt-0.5">
                                {time}
                                {dur ? ` · ${dur}` : ""}
                              </p>
                            </div>
                          ) : s.status === "running" ? (
                            <div>
                              <p className="font-mono text-[11px] text-gilt">
                                In progress
                              </p>
                              <p className="font-mono text-[10px] text-mist mt-0.5">
                                {s.progress_pct}% done
                              </p>
                            </div>
                          ) : (
                            <span className="font-mono text-[11px] text-mist">
                              {s.status === "queued" ? "Queued" : "—"}
                            </span>
                          )}
                        </td>
                        {/* Findings (inline CRIT · HIGH · MED · LOW) */}
                        <td className="px-3 py-2.5 align-top">
                          {s.profile === "load" ? (
                            <LoadMetricCell
                              summary={
                                s.summary as Record<string, unknown> | null
                              }
                            />
                          ) : s.summary ? (
                            <div className="inline-flex items-center gap-1.5">
                              <span className="w-7 text-center font-mono text-[12px] font-bold text-sev-critical">
                                {Number(s.summary.critical) || 0}
                              </span>
                              <span className="text-mist/40 text-[10px]">
                                ·
                              </span>
                              <span className="w-7 text-center font-mono text-[12px] font-bold text-sev-high">
                                {Number(s.summary.high) || 0}
                              </span>
                              <span className="text-mist/40 text-[10px]">
                                ·
                              </span>
                              <span className="w-7 text-center font-mono text-[12px] font-bold text-sev-medium">
                                {Number(s.summary.medium) || 0}
                              </span>
                              <span className="text-mist/40 text-[10px]">
                                ·
                              </span>
                              <span className="w-7 text-center font-mono text-[12px] font-bold text-sev-low">
                                {Number(s.summary.low) || 0}
                              </span>
                            </div>
                          ) : (
                            <span className="font-mono text-[11px] text-mist">
                              —
                            </span>
                          )}
                        </td>
                        {/* Outputs */}
                        <td className="px-3 py-3 hidden xl:table-cell">
                          <OutputIcons
                            done={done}
                            scanId={s.id}
                            isRepo={isRepoScan}
                          />
                        </td>
                        {/* Status */}
                        <td className="px-3 py-2.5 align-top">
                          <span className="inline-flex items-center gap-1.5 font-body text-[11px] uppercase tracking-[0.1em]">
                            <span
                              className={cn(
                                "w-1.5 h-1.5 rounded-full shrink-0",
                                s.status === "done"
                                  ? "bg-forest"
                                  : s.status === "failed"
                                    ? "bg-sev-critical"
                                    : "bg-gilt animate-pulse",
                              )}
                            />
                            <span
                              className={
                                s.status === "done"
                                  ? "text-forest"
                                  : s.status === "failed"
                                    ? "text-sev-critical"
                                    : "text-gilt"
                              }
                            >
                              {s.status === "done"
                                ? "Complete"
                                : s.status === "failed"
                                  ? "Failed"
                                  : s.status === "running"
                                    ? `${s.progress_pct}%`
                                    : "Queued"}
                            </span>
                          </span>
                        </td>
                        {/* Trend */}
                        <td className="px-3 py-3 hidden xl:table-cell">
                          <Sparkline grade={s.grade} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* ── Bottom pagination ── */}
            <div className="flex items-center justify-between gap-4 px-4 py-3 border-t border-hairline bg-vellum/30 flex-wrap">
              <span className="font-mono text-[11px] text-mist whitespace-nowrap">
                Showing {showFrom} to {showTo} of {filtered.length} assessment
                {filtered.length !== 1 ? "s" : ""}
              </span>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={safePage === 1}
                    className="px-2 py-1 font-mono text-[11px] text-slate disabled:opacity-30 hover:text-ink transition-colors"
                  >
                    ← Prev
                  </button>
                  {Array.from({ length: Math.min(5, pageCount) }, (_, i) => {
                    let n: number;
                    if (pageCount <= 5) n = i + 1;
                    else if (safePage <= 3) n = i + 1;
                    else if (safePage >= pageCount - 2) n = pageCount - 4 + i;
                    else n = safePage - 2 + i;
                    return (
                      <button
                        key={n}
                        onClick={() => setPage(n)}
                        className={cn(
                          "w-7 h-7 font-mono text-[11px] rounded-sm transition-colors",
                          safePage === n
                            ? "bg-ink text-paper"
                            : "text-slate hover:text-ink hover:bg-vellum",
                        )}
                      >
                        {n}
                      </button>
                    );
                  })}
                  {pageCount > 5 && safePage < pageCount - 2 && (
                    <span className="font-mono text-[11px] text-mist px-1">
                      …
                    </span>
                  )}
                  {pageCount > 5 && (
                    <button
                      onClick={() => setPage(pageCount)}
                      className={cn(
                        "w-7 h-7 font-mono text-[11px] rounded-sm transition-colors",
                        safePage === pageCount
                          ? "bg-ink text-paper"
                          : "text-slate hover:text-ink hover:bg-vellum",
                      )}
                    >
                      {pageCount}
                    </button>
                  )}
                  <button
                    onClick={() => setPage((p) => Math.min(pageCount, p + 1))}
                    disabled={safePage === pageCount}
                    className="px-2 py-1 font-mono text-[11px] text-slate disabled:opacity-30 hover:text-ink transition-colors"
                  >
                    Next →
                  </button>
                </div>
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

        {/* ── Bottom sections ── */}
        {scans.length > 0 && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 pt-2">
            {/* Agent coverage */}
            <div className="border border-hairline rounded-sm p-5 bg-paper">
              <div className="flex items-center justify-between mb-4">
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
                  Agent Coverage (Last 30 Days)
                </p>
                <button className="font-mono text-[10px] text-gilt hover:text-gilt/80">
                  ›
                </button>
              </div>
              <div className="grid grid-cols-5 gap-3">
                {AGENTS.map((a) => (
                  <div
                    key={a.label}
                    className="flex flex-col items-center gap-1.5"
                  >
                    <div className="w-9 h-9 rounded-full border border-hairline flex items-center justify-center text-graphite bg-vellum/50">
                      {a.icon}
                    </div>
                    <p className="font-body text-[10px] text-slate text-center leading-tight">
                      {a.label}
                    </p>
                    <p
                      className={cn(
                        "font-mono text-[11px] font-bold",
                        a.pct === 100
                          ? "text-forest"
                          : a.pct >= 95
                            ? "text-gilt"
                            : "text-sev-medium",
                      )}
                    >
                      {a.pct}%
                    </p>
                  </div>
                ))}
              </div>
            </div>
            {/* Assessment cadence */}
            <div className="border border-hairline rounded-sm p-5 bg-paper">
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist mb-4">
                Assessment Cadence (Last 7 Days)
              </p>
              <div className="flex items-end gap-2 h-[80px]">
                {cadenceData.map((d) => (
                  <div
                    key={d.label}
                    className="flex-1 flex flex-col items-center gap-1"
                  >
                    <span className="font-mono text-[10px] text-ink">
                      {d.count > 0 ? d.count : ""}
                    </span>
                    <div
                      className="w-full rounded-sm bg-gilt/70 hover:bg-gilt transition-colors"
                      style={{
                        height: `${Math.max(4, Math.round((d.count / maxCadence) * 60))}px`,
                      }}
                    />
                    <span className="font-mono text-[9px] text-mist">
                      {d.label.split(" ")[1]}
                    </span>
                  </div>
                ))}
              </div>
              <div className="flex items-center justify-between mt-2">
                {cadenceData.map((d) => (
                  <span
                    key={d.label}
                    className="font-mono text-[9px] text-mist flex-1 text-center hidden xl:block"
                  >
                    {d.label.split(" ")[0]}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Assessment Intelligence panel ── */}
      <aside className="w-[280px] shrink-0 border-l border-hairline px-5 py-6 space-y-4 hidden lg:block bg-vellum/20">
        <div className="flex items-center justify-between">
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist tracking-[0.2em]">
            Assessment Intelligence
          </p>
          <svg
            viewBox="0 0 14 14"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.3"
            className="w-3.5 h-3.5 text-mist cursor-help"
          >
            <path d="M7 9V7M7 5.5v.1" strokeLinecap="round" />
            <circle cx="7" cy="7" r="5.5" />
          </svg>
        </div>

        {/* Stale targets */}
        <div className="border border-hairline rounded-sm p-3.5 bg-paper space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <StaleIcon />
              <span className="font-body text-[13px] font-semibold text-ink">
                Stale targets
              </span>
            </div>
            <span className="font-mono text-[11px] font-bold text-sev-critical">
              {staleTargets.length}
            </span>
          </div>
          <p className="font-mono text-[10px] text-mist">
            No scan in &gt; 30 days
          </p>
          <div className="space-y-2">
            {staleTargets.length === 0 ? (
              <p className="font-body text-[11px] text-mist italic">
                All targets scanned recently.
              </p>
            ) : (
              staleTargets.map((t) => {
                const tScans = (scansByTarget.get(t.id) ?? []).filter(
                  (s) => s.status === "done",
                );
                const lastScan =
                  tScans.length > 0
                    ? tScans.sort(
                        (a, b) =>
                          new Date(b.created_at).getTime() -
                          new Date(a.created_at).getTime(),
                      )[0]
                    : null;
                const daysAgo = lastScan
                  ? Math.floor(
                      (Date.now() - new Date(lastScan.created_at).getTime()) /
                        86400000,
                    )
                  : 999;
                const tKind = effectiveKind(t);
                const detailHref =
                  tKind === "repo" && t.repository_id
                    ? `/repos/${t.repository_id}`
                    : `/targets/${t.id}`;
                return (
                  <div
                    key={t.id}
                    className="flex items-center gap-2 group/stale"
                  >
                    <Link
                      href={detailHref}
                      className="font-body text-[11px] text-slate hover:text-ink hover:underline underline-offset-4 decoration-gilt truncate flex-1"
                      title={t.name}
                    >
                      {t.name}
                    </Link>
                    <span className="font-mono text-[10px] text-mist shrink-0">
                      {daysAgo === 999 ? "never" : `${daysAgo}d`}
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        setCommissionFor({
                          id: t.id,
                          name: t.name,
                          kind: tKind,
                          kind_config: t.kind_config ?? null,
                          repository_id: t.repository_id ?? null,
                        })
                      }
                      className="p-1 -m-1 text-mist hover:text-ink transition-colors rounded-sm hover:bg-vellum opacity-0 group-hover/stale:opacity-100 focus:opacity-100"
                      title={`Run assessment on ${t.name}`}
                      aria-label={`Run assessment on ${t.name}`}
                    >
                      <PlayIcon />
                    </button>
                  </div>
                );
              })
            )}
          </div>
          <Link
            href="/targets"
            className="font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline"
          >
            View all stale targets →
          </Link>
        </div>

        {/* Failed assessments */}
        {failedScans.length > 0 && (
          <div className="border border-hairline rounded-sm p-3.5 bg-paper space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FailedIcon />
                <span className="font-body text-[13px] font-semibold text-ink">
                  Failed assessments
                </span>
              </div>
              <span className="font-mono text-[11px] font-bold text-sev-high">
                {failedScans.length}
              </span>
            </div>
            <p className="font-mono text-[10px] text-mist">Require attention</p>
            <div className="space-y-2">
              {failedScans.map(({ scan, target }) => {
                const { date, time } = formatDateShort(scan.created_at);
                return (
                  <Link
                    key={scan.id}
                    href={`/scans/${scan.id}`}
                    className="flex items-start justify-between gap-2 -mx-1 px-1 py-0.5 rounded-sm hover:bg-vellum transition-colors group/failed"
                    title={`View ${target?.name ?? "scan"} failure`}
                  >
                    <p className="font-body text-[11px] text-slate group-hover/failed:text-ink flex-1 truncate">
                      {target?.name ?? "Unknown"}
                    </p>
                    <p className="font-mono text-[9px] text-mist shrink-0">
                      {date.slice(0, 6)}, {time}
                    </p>
                  </Link>
                );
              })}
            </div>
            <button
              onClick={() => {
                setActiveTab("failed");
                setPage(1);
              }}
              className="font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline"
            >
              View all failed →
            </button>
          </div>
        )}

        {/* Best improvement */}
        {bestImprovement && (
          <div className="border border-hairline rounded-sm p-3.5 bg-paper space-y-3">
            <div className="flex items-center gap-2">
              <ImprovIcon />
              <span className="font-body text-[13px] font-semibold text-ink">
                Best improvement
              </span>
            </div>
            <p className="font-mono text-[10px] text-mist">vs previous scan</p>
            <div>
              <p className="font-body text-[12px] text-ink font-medium">
                {bestImprovement.target.name}
              </p>
              <div className="flex items-center gap-2 mt-1">
                <span
                  className={cn(
                    "font-display text-[13px] font-bold",
                    gradeStyle(bestImprovement.prev).split(" ")[0],
                  )}
                >
                  {bestImprovement.prev}
                </span>
                <span className="text-mist">→</span>
                <span
                  className={cn(
                    "font-display text-[13px] font-bold",
                    gradeStyle(bestImprovement.curr).split(" ")[0],
                  )}
                >
                  {bestImprovement.curr}
                </span>
                <span className="font-mono text-[10px] text-forest">
                  +{bestImprovement.pts} pts
                </span>
              </div>
            </div>
            <Link
              href="/scans"
              className="font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline"
            >
              View improvement details →
            </Link>
          </div>
        )}

        {/* Next scheduled jobs */}
        {upcomingSchedules.length > 0 && (
          <div className="border border-hairline rounded-sm p-3.5 bg-paper space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ScheduleIcon />
                <span className="font-body text-[13px] font-semibold text-ink">
                  Next scheduled jobs
                </span>
              </div>
              <span className="font-mono text-[11px] font-bold text-gilt">
                {scheduledEnabledCount}
              </span>
            </div>
            <div className="space-y-2">
              {upcomingSchedules.map(({ schedule, target }) => (
                <Link
                  key={schedule.id}
                  href="/schedules"
                  className="flex items-center justify-between gap-2 -mx-1 px-1 py-0.5 rounded-sm hover:bg-vellum transition-colors group/sched"
                  title={`View schedule: ${schedule.name}`}
                >
                  <p className="font-body text-[11px] text-slate group-hover/sched:text-ink truncate flex-1">
                    {target?.name ?? schedule.name}
                  </p>
                  <p className="font-mono text-[9px] text-mist shrink-0">
                    {upcomingLabel(schedule.next_run_at)}
                  </p>
                </Link>
              ))}
            </div>
            <Link
              href="/schedules"
              className="font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline"
            >
              View all schedules →
            </Link>
          </div>
        )}

        {/* Export center */}
        <div className="border border-hairline rounded-sm p-3.5 bg-paper space-y-2">
          <div className="flex items-center gap-2">
            <ExportCenterIcon />
            <span className="font-body text-[13px] font-semibold text-ink">
              Export center
            </span>
          </div>
          <p className="font-body text-[11px] text-slate">
            Download all reports, evidence, and logs.
          </p>
          <Link
            href="/deliverables"
            className="font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline"
          >
            Go to exports →
          </Link>
        </div>
      </aside>

      <CommissionScanModal
        targetId={commissionFor?.id ?? null}
        targetName={commissionFor?.name ?? null}
        targetKind={commissionFor?.kind}
        targetKindConfig={commissionFor?.kind_config ?? null}
        repositoryId={commissionFor?.repository_id ?? null}
        priorAuthorizationText={
          commissionFor
            ? (scans
                .filter(
                  (s) =>
                    s.target_id === commissionFor.id &&
                    s.consent_payload?.authorization_text,
                )
                .sort(
                  (a, b) =>
                    new Date(b.created_at).getTime() -
                    new Date(a.created_at).getTime(),
                )[0]?.consent_payload?.authorization_text ?? null)
            : null
        }
        onClose={() => setCommissionFor(null)}
      />
    </div>
  );
}
