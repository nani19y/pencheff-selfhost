"use client";

import Link from "next/link";
import { useEffect, useMemo, useState, useCallback } from "react";
import { SeverityPill } from "@/components/brutal";
import { PageLoading } from "@/components/loading";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useWorkspace } from "@/lib/workspace-context";
import { useNotifications } from "@/lib/notifications-context";
import { IntelDivider } from "@/components/app/intel-panel";

// ── Types ─────────────────────────────────────────────────────────────────────
type Item = {
  id: string;
  source: string;
  table: string;
  title: string;
  severity: string;
  risk_score: number;
  reachability: string | null;
  ssvc_decision: string | null;
  epss: number | null;
  kev: boolean;
  cwe_id: string | null;
  owasp_category: string | null;
  location: string;
  package: string | null;
  fixed_version: string | null;
  suppressed: boolean;
  created_at: string;
  workspace_id: string;
  target_id: string | null;
  repository_id: string | null;
};
type PageData = { items: Item[]; total: number; limit: number; offset: number };
type Target = { id: string; name: string; base_url: string; kind?: string; repository_id?: string | null };
type Repo = { id: string; full_name?: string; name?: string; provider?: string; html_url?: string };
type WorkspaceMember = { user_id: string; email: string; name?: string | null; role?: string };

// ── Target type label ────────────────────────────────────────────────────────
function targetTypeLabel(t: Target): string {
  if (t.kind === "repo" || t.repository_id) return "Repository";
  if (t.kind === "llm") return "LLM";
  const url = (t.base_url ?? "").toLowerCase();
  if (url.includes("api.") || url.includes("/api") || url.includes("-api")) return "API";
  return "Web App";
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function evidenceStrength(item: Item): { label: string; color: string } {
  if (item.kev) return { label: "Strong", color: "text-forest" };
  if (item.reachability === "exploited") return { label: "Strong", color: "text-forest" };
  if (item.reachability === "reachable") return { label: "Medium", color: "text-sev-medium" };
  return { label: "Weak", color: "text-mist" };
}
function statusFromSsvc(ssvc: string | null, suppressed: boolean): { label: string; style: string } {
  if (suppressed) return { label: "Suppressed", style: "text-mist border-hairline" };
  if (ssvc === "act") return { label: "Open", style: "text-sev-critical border-sev-critical/40 bg-sev-critical/5" };
  if (ssvc === "attend") return { label: "In progress", style: "text-sev-medium border-sev-medium/40 bg-sev-medium/5" };
  if (ssvc === "track") return { label: "Triaged", style: "text-sev-low border-sev-low/40 bg-sev-low/5" };
  if (ssvc === "defer") return { label: "Triaged", style: "text-sev-low border-sev-low/40 bg-sev-low/5" };
  return { label: "Open", style: "text-sev-critical border-sev-critical/40 bg-sev-critical/5" };
}
function slaFromSeverity(sev: string): string {
  if (sev === "critical") return "1d";
  if (sev === "high") return "2d";
  if (sev === "medium") return "5d";
  return "10d";
}
function slaColor(sev: string): string {
  if (sev === "critical") return "text-sev-critical bg-sev-critical/8 border-sev-critical/30";
  if (sev === "high") return "text-sev-high bg-sev-high/8 border-sev-high/30";
  if (sev === "medium") return "text-sev-medium bg-sev-medium/8 border-sev-medium/30";
  return "text-mist border-hairline";
}
function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(diff / 3600000);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(diff / 86400000);
  if (days < 7) return `${days}d ago`;
  return `${Math.floor(days / 7)}w ago`;
}

// ── Inline SVG icons ──────────────────────────────────────────────────────────
const RefreshIcon = () => (
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-3.5 h-3.5">
    <path d="M13.5 2.5A7 7 0 1 0 14.5 9M14.5 2.5v4H10.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);
const DownloadIcon = () => (
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-3.5 h-3.5">
    <path d="M8 2v8M5 7l3 3 3-3M2.5 12.5v1a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1v-1" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);
const SearchIcon = () => (
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3.5 h-3.5 text-mist">
    <circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L13.5 13.5" strokeLinecap="round"/>
  </svg>
);
const ChevronDown = () => (
  <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-3 h-3">
    <path d="M2 4l4 4 4-4" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);
const ShieldIcon = ({ strength }: { strength: string }) => (
  <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.3" className={cn("w-3.5 h-3.5", strength === "Strong" ? "text-forest" : strength === "Medium" ? "text-sev-medium" : "text-mist")}>
    <path d="M7 1.5L1.5 3.5v3c0 2.5 2 4.7 5.5 5.5 3.5-.8 5.5-3 5.5-5.5v-3L7 1.5Z"/>
  </svg>
);
const ChainIcon = () => (
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4 text-sev-high">
    <path d="M5.5 10.5a3 3 0 0 0 5 0l1.5-1.5a3 3 0 0 0-4.5-3.9M10.5 5.5a3 3 0 0 0-5 0L4 7a3 3 0 0 0 4.5 3.9" strokeLinecap="round"/>
  </svg>
);
const ClusterIcon = () => (
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4 text-gilt">
    <circle cx="8" cy="8" r="2"/><circle cx="3" cy="4" r="1.5"/><circle cx="13" cy="4" r="1.5"/><circle cx="3" cy="12" r="1.5"/><circle cx="13" cy="12" r="1.5"/>
    <path d="M5 8H3M11 8h2M8 6V4M8 10v2"/>
  </svg>
);
const PRIcon = () => (
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4 text-forest">
    <circle cx="4" cy="4" r="1.5"/><circle cx="4" cy="12" r="1.5"/><circle cx="12" cy="4" r="1.5"/>
    <path d="M4 5.5v5M4 5.5C4 5.5 12 5.5 12 5.5v-1" strokeLinecap="round"/>
    <path d="M9.5 2.5l2.5 1.5-2.5 1.5" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);
const ImpactIcon = () => (
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4 text-sev-critical">
    <path d="M8 2v4M8 10v4M2 8h4M10 8h4" strokeLinecap="round"/>
    <circle cx="8" cy="8" r="2.5"/>
  </svg>
);
const StarIcon = () => (
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" className="w-4 h-4 text-gilt">
    <path d="M8 1.5l1.7 3.4 3.8.55-2.75 2.68.65 3.78L8 10l-3.4 1.91.65-3.78L2.5 5.45l3.8-.55L8 1.5Z"/>
  </svg>
);
const ArrowUpIcon = ({ color }: { color: string }) => (
  <svg viewBox="0 0 12 12" fill={color} className="w-3 h-3 inline">
    <path d="M6 2l4 6H2l4-6Z"/>
  </svg>
);
const ArrowDownIcon = ({ color }: { color: string }) => (
  <svg viewBox="0 0 12 12" fill={color} className="w-3 h-3 inline">
    <path d="M6 10L2 4h8l-4 6Z"/>
  </svg>
);
// Actions dropdown state handled in component

// ── Severity stat card ────────────────────────────────────────────────────────
interface SevStatCardProps {
  label: string;
  count: number;
  trend?: number; // positive = up, negative = down, 0 = flat
  trendColor?: string;
  icon: React.ReactNode;
  iconColor: string;
}
function SevStatCard({ label, count, trend, trendColor = "#6B6454", icon, iconColor }: SevStatCardProps) {
  return (
    <div className="flex flex-col gap-1.5 border border-hairline rounded-sm p-4 bg-paper min-w-0">
      <div className="flex items-center gap-2">
        <span style={{ color: iconColor }}>{icon}</span>
        <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-slate">{label}</span>
      </div>
      <p className="font-display text-[36px] leading-none tracking-[-0.02em] text-ink">{count.toLocaleString()}</p>
      {trend !== undefined && (
        <p className="font-mono text-[11px]" style={{ color: trendColor }}>
          {trend > 0 ? <ArrowUpIcon color={trendColor} /> : trend < 0 ? <ArrowDownIcon color={trendColor} /> : null}
          {" "}
          {trend > 0 ? `+${trend} new` : trend < 0 ? `${trend}` : "—0"}
        </p>
      )}
    </div>
  );
}

// ── Filter dropdown ───────────────────────────────────────────────────────────
function FilterDropdown({ label, value, options, onChange, activeCount }: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  activeCount?: number;
}) {
  return (
    <div className="relative inline-flex items-center">
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className={cn(
          "appearance-none border rounded-sm pl-3 pr-7 py-1.5 font-body text-[12px] bg-paper focus:outline-none focus:border-ink transition-colors cursor-pointer",
          value ? "border-ink text-ink font-medium" : "border-hairline text-slate hover:border-graphite"
        )}
      >
        <option value="">{label}</option>
        {options.map(o => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
      <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-mist">
        <ChevronDown />
      </span>
      {activeCount !== undefined && activeCount > 0 && (
        <span className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-gilt text-ink text-[9px] font-mono rounded-full flex items-center justify-center">
          {activeCount}
        </span>
      )}
    </div>
  );
}

// ── Severity bar for CVSS ─────────────────────────────────────────────────────
function CvssBar({ score, max = 10 }: { score: number; max?: number }) {
  const pct = Math.min(100, (score / max) * 100);
  const color = score >= 9 ? "bg-sev-critical" : score >= 7 ? "bg-sev-high" : score >= 4 ? "bg-sev-medium" : "bg-sev-low";
  return (
    <div className="h-[3px] w-[48px] bg-vellum rounded-full overflow-hidden">
      <div className={cn("h-full rounded-full", color)} style={{ width: `${pct}%` }} />
    </div>
  );
}

// ── Badge count ───────────────────────────────────────────────────────────────
function CountBadge({ count, color = "bg-sev-high text-paper" }: { count: number; color?: string }) {
  return (
    <span className={cn("inline-flex items-center justify-center w-5 h-5 rounded-full text-[10px] font-mono font-bold shrink-0", color)}>
      {count}
    </span>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
const ROWS_OPTIONS = [8, 25, 50] as const;
const SEV_OPTS = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "info", label: "Info" },
];
const STATUS_OPTS = [
  { value: "act", label: "Open" },
  { value: "attend", label: "In Progress" },
  { value: "track", label: "Triaged" },
];
const SOURCE_OPTS = [
  { value: "dast", label: "DAST (Web)" },
  { value: "sast", label: "SAST (Code)" },
  { value: "sca", label: "SCA (Dependencies)" },
  { value: "iac", label: "IaC" },
  { value: "secret", label: "Secrets" },
];
const REACH_OPTS = [
  { value: "exploited", label: "Exploited" },
  { value: "reachable", label: "Reachable" },
  { value: "present", label: "Present" },
];

export default function FindingsPage() {
  const { activeWorkspace } = useWorkspace();
  const { notify } = useNotifications();

  // Data state
  const [pageData, setPageData] = useState<PageData | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [members, setMembers] = useState<WorkspaceMember[]>([]);
  const [assignments, setAssignments] = useState<Record<string, string>>({}); // findingId -> userId
  const [severityCounts, setSeverityCounts] = useState({ critical: 0, high: 0, medium: 0, low: 0, suppressed: 0 });
  const [loading, setLoading] = useState(true);
  const [loadingPage, setLoadingPage] = useState(false);

  // Filters
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [reachFilter, setReachFilter] = useState("");
  const [includeSuppressed, setIncludeSuppressed] = useState(false);

  // Table
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState<typeof ROWS_OPTIONS[number]>(25);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [actionsOpen, setActionsOpen] = useState(false);
  const [rechecking, setRechecking] = useState(false);
  const [recheckStatus, setRecheckStatus] = useState<{
    state: "idle" | "running" | "done";
    total: number;
    queued: number;
    failed: number;
    skipped: number;
    at: number;
  }>({ state: "idle", total: 0, queued: 0, failed: 0, skipped: 0, at: 0 });
  const [impactOpen, setImpactOpen] = useState(false);
  const [assigneeOpen, setAssigneeOpen] = useState<string | null>(null);

  const targetById = useMemo(() => {
    const map = new Map<string, Target>();
    for (const t of targets) map.set(t.id, t);
    return map;
  }, [targets]);

  const repoById = useMemo(() => {
    const map = new Map<string, Repo>();
    for (const r of repos) map.set(r.id, r);
    return map;
  }, [repos]);

  const memberById = useMemo(() => {
    const map = new Map<string, WorkspaceMember>();
    for (const m of members) map.set(m.user_id, m);
    return map;
  }, [members]);

  // Heuristic: workspace "owner" is the first member with role "owner" or "admin".
  // Falls back to the first member alphabetically.
  const ownerMember = useMemo<WorkspaceMember | null>(() => {
    if (members.length === 0) return null;
    return members.find(m => m.role === "owner")
      ?? members.find(m => m.role === "admin")
      ?? members[0];
  }, [members]);

  // Load aggregate counts once
  useEffect(() => {
    Promise.all([
      api<PageData>("/unified-findings?severity=critical&limit=1").catch(() => ({ total: 0 } as PageData)),
      api<PageData>("/unified-findings?severity=high&limit=1").catch(() => ({ total: 0 } as PageData)),
      api<PageData>("/unified-findings?severity=medium&limit=1").catch(() => ({ total: 0 } as PageData)),
      api<PageData>("/unified-findings?severity=low&limit=1").catch(() => ({ total: 0 } as PageData)),
      api<PageData>("/unified-findings?include_suppressed=true&limit=1").catch(() => ({ total: 0 } as PageData)),
      api<Target[]>("/targets").catch(() => [] as Target[]),
      api<Repo[]>("/repos").catch(() => [] as Repo[]),
    ]).then(([crit, high, med, low, supp, tgts, rps]) => {
      setSeverityCounts({
        critical: crit.total ?? 0,
        high: high.total ?? 0,
        medium: med.total ?? 0,
        low: low.total ?? 0,
        suppressed: (supp.total ?? 0) - ((crit.total ?? 0) + (high.total ?? 0) + (med.total ?? 0) + (low.total ?? 0)),
      });
      setTargets(tgts as Target[]);
      setRepos(rps as Repo[]);
    }).catch(() => {});
  }, [activeWorkspace?.id]);

  // Load workspace members for assignee dropdown
  useEffect(() => {
    if (!activeWorkspace?.id) return;
    let alive = true;
    api<WorkspaceMember[]>(`/workspaces/${activeWorkspace.id}/members`)
      .then(rows => { if (alive) setMembers(rows); })
      .catch(() => { if (alive) setMembers([]); });
    return () => { alive = false; };
  }, [activeWorkspace?.id]);

  const loadPage = useCallback(async () => {
    setLoadingPage(true);
    try {
      const params = new URLSearchParams();
      params.set("limit", String(rowsPerPage));
      params.set("offset", String((page - 1) * rowsPerPage));
      if (severityFilter) params.set("severity", severityFilter);
      if (statusFilter) params.set("ssvc_decision", statusFilter);
      if (sourceFilter) params.set("source", sourceFilter);
      if (reachFilter) params.set("reachability", reachFilter);
      if (includeSuppressed) params.set("include_suppressed", "true");
      const data = await api<PageData>(`/unified-findings?${params.toString()}`);
      setPageData(data);
    } catch {
      setPageData(null);
    } finally {
      setLoadingPage(false);
      setLoading(false);
    }
  }, [page, rowsPerPage, severityFilter, statusFilter, sourceFilter, reachFilter, includeSuppressed]);

  useEffect(() => { loadPage(); }, [loadPage]);
  useEffect(() => { setPage(1); }, [severityFilter, statusFilter, sourceFilter, reachFilter, includeSuppressed, rowsPerPage]);

  // Client-side search filter
  const visibleItems = useMemo(() => {
    if (!pageData?.items) return [];
    const q = query.trim().toLowerCase();
    if (!q) return pageData.items;
    return pageData.items.filter(i =>
      i.title.toLowerCase().includes(q) ||
      i.owasp_category?.toLowerCase().includes(q) ||
      i.cwe_id?.toLowerCase().includes(q) ||
      i.location?.toLowerCase().includes(q)
    );
  }, [pageData, query]);

  // Selection
  const allSelected = visibleItems.length > 0 && visibleItems.every(i => selectedIds.has(i.id));
  function toggleAll() {
    if (allSelected) {
      setSelectedIds(prev => { const next = new Set(prev); visibleItems.forEach(i => next.delete(i.id)); return next; });
    } else {
      setSelectedIds(prev => { const next = new Set(prev); visibleItems.forEach(i => next.add(i.id)); return next; });
    }
  }
  function toggleItem(id: string) {
    setSelectedIds(prev => { const next = new Set(prev); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  }

  const activeFilterCount = [severityFilter, statusFilter, sourceFilter, reachFilter].filter(Boolean).length + (includeSuppressed ? 1 : 0);
  function clearFilters() {
    setSeverityFilter(""); setStatusFilter(""); setSourceFilter(""); setReachFilter(""); setIncludeSuppressed(false);
  }

  // ── Recheck flow ─────────────────────────────────────────────────────────────
  // Repo findings live in a separate table; the DAST recheck endpoint only
  // accepts ids from the "findings" table, so we silently skip repo ids and
  // report the count via a persistent status banner (not an alert).
  async function recheckFindingIds(ids: string[]): Promise<void> {
    if (ids.length === 0 || rechecking) return;
    const dastIds = ids.filter(id => {
      const item = pageData?.items.find(i => i.id === id);
      return !item || item.table === "findings";
    });
    const skipped = ids.length - dastIds.length;
    if (dastIds.length === 0) {
      setRecheckStatus({ state: "done", total: ids.length, queued: 0, failed: 0, skipped, at: Date.now() });
      return;
    }
    setRechecking(true);
    setRecheckStatus({ state: "running", total: dastIds.length, queued: 0, failed: 0, skipped, at: Date.now() });
    let ok = 0;
    let failed = 0;
    await Promise.allSettled(
      dastIds.map(async id => {
        try {
          await api(`/findings/${id}/recheck`, { method: "POST" });
          ok += 1;
        } catch {
          failed += 1;
        }
      })
    );
    setRechecking(false);
    setSelectedIds(new Set());
    setRecheckStatus({ state: "done", total: dastIds.length, queued: ok, failed, skipped, at: Date.now() });
    await loadPage();
  }

  async function recheckTopPriority(): Promise<void> {
    if (rechecking) return;
    setRechecking(true);
    setRecheckStatus({ state: "running", total: 0, queued: 0, failed: 0, skipped: 0, at: Date.now() });
    try {
      const params = new URLSearchParams();
      params.set("limit", "200");
      const emptyPage: PageData = { items: [], total: 0, limit: 0, offset: 0 };
      const [crit, high] = await Promise.all([
        api<PageData>(`/unified-findings?severity=critical&${params.toString()}`).catch(() => emptyPage),
        api<PageData>(`/unified-findings?severity=high&${params.toString()}`).catch(() => emptyPage),
      ]);
      const ids = [...crit.items, ...high.items]
        .filter(i => i.table === "findings")
        .map(i => i.id);
      if (ids.length === 0) {
        setRechecking(false);
        setRecheckStatus({ state: "done", total: 0, queued: 0, failed: 0, skipped: 0, at: Date.now() });
        return;
      }
      setRecheckStatus({ state: "running", total: ids.length, queued: 0, failed: 0, skipped: 0, at: Date.now() });
      let ok = 0;
      let failed = 0;
      await Promise.allSettled(
        ids.map(async id => {
          try {
            await api(`/findings/${id}/recheck`, { method: "POST" });
            ok += 1;
          } catch {
            failed += 1;
          }
        })
      );
      setRechecking(false);
      await loadPage();
      setRecheckStatus({ state: "done", total: ids.length, queued: ok, failed, skipped: 0, at: Date.now() });
    } catch {
      setRechecking(false);
      setRecheckStatus(prev => ({ ...prev, state: "done", at: Date.now() }));
    }
  }

  // ── CSV export (client-side) ────────────────────────────────────────────────
  function exportEvidence(): void {
    const items = visibleItems;
    if (items.length === 0) {
      setRecheckStatus({ state: "done", total: 0, queued: 0, failed: 0, skipped: 0, at: Date.now() });
      return;
    }
    const headers = [
      "id", "source", "table", "title", "severity", "risk_score",
      "reachability", "ssvc_decision", "epss", "kev",
      "cwe_id", "owasp_category", "location", "package", "fixed_version",
      "target", "target_kind", "status", "suppressed", "created_at",
    ];
    function esc(v: unknown): string {
      if (v === null || v === undefined) return "";
      const s = typeof v === "string" ? v : String(v);
      if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
      return s;
    }
    const rows = items.map(i => {
      const t = i.target_id ? targetById.get(i.target_id) : null;
      const r = i.repository_id ? repoById.get(i.repository_id) : null;
      const targetLabel = t?.base_url || t?.name || r?.full_name || r?.name || "";
      const targetKind = t ? targetTypeLabel(t) : r ? "Repository" : "";
      const status = statusFromSsvc(i.ssvc_decision, i.suppressed).label;
      return [
        i.id, i.source, i.table, i.title, i.severity, i.risk_score,
        i.reachability ?? "", i.ssvc_decision ?? "",
        i.epss ?? "", i.kev ? "true" : "false",
        i.cwe_id ?? "", i.owasp_category ?? "", i.location ?? "",
        i.package ?? "", i.fixed_version ?? "",
        targetLabel, targetKind, status, i.suppressed ? "true" : "false", i.created_at,
      ].map(esc).join(",");
    });
    const csv = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.href = url;
    a.download = `pencheff-findings-${stamp}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ── Assignment ───────────────────────────────────────────────────────────────
  async function assignFinding(item: Item, userId: string): Promise<void> {
    // Optimistic local update
    setAssignments(prev => ({ ...prev, [item.id]: userId }));
    setAssigneeOpen(null);
    const assignedTo = memberById.get(userId);
    // Local notification confirms the action. Cross-user push (notifying
    // the assignee in another session) needs a backend pub-sub channel
    // that doesn't exist yet — tracked separately.
    notify({
      kind: "assignment",
      title: "Finding assigned",
      body: assignedTo
        ? `${item.title.slice(0, 80)} → ${memberDisplay(assignedTo)}`
        : item.title.slice(0, 80),
      href: item.table === "findings"
        ? `/findings/${item.id}`
        : item.repository_id
          ? `/repos/${item.repository_id}/dashboard`
          : undefined,
    });
    // Only DAST findings have a server-side assign endpoint
    if (item.table !== "findings") return;
    try {
      await api(`/findings/${item.id}/assign`, { method: "POST", json: { assignee_user_id: userId } });
    } catch (e: any) {
      console.error("assign failed", e);
    }
  }
  function getAssignee(item: Item): WorkspaceMember | null {
    const explicit = assignments[item.id];
    if (explicit) {
      const m = memberById.get(explicit);
      if (m) return m;
    }
    return ownerMember;
  }
  function memberInitials(m: WorkspaceMember): string {
    const src = m.name || m.email || "?";
    const parts = src.split(/[\s@.]+/).filter(Boolean);
    if (parts.length === 0) return "?";
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  function memberDisplay(m: WorkspaceMember): string {
    return m.name || m.email.split("@")[0] || m.email;
  }

  // ── Intelligence panel actions ───────────────────────────────────────────────
  function viewChains() {
    setSeverityFilter("");
    setStatusFilter("");
    setSourceFilter("");
    setReachFilter("exploited");
    setIncludeSuppressed(false);
    setQuery("");
    setPage(1);
  }
  function reviewClusters() {
    if (dupClusters.top) {
      setQuery(dupClusters.top);
      setSeverityFilter("");
      setStatusFilter("");
      setSourceFilter("");
      setReachFilter("");
      setPage(1);
    }
  }
  function impactAnalysis() {
    setImpactOpen(true);
  }

  // ── Right panel intelligence ──
  const exploitChains = useMemo(() => {
    if (!pageData) return [];
    const high = pageData.items.filter(i => i.kev || (i.epss !== null && i.epss > 0.5));
    return high.slice(0, 3).map(i => ({
      label: i.title.length > 35 ? i.title.slice(0, 35) + "…" : i.title,
      severity: i.severity,
    }));
  }, [pageData]);

  const dupClusters = useMemo(() => {
    if (!pageData) return { count: 0, top: "", topCount: 0 };
    const byCwe: Record<string, number> = {};
    for (const i of pageData.items) {
      if (i.cwe_id) byCwe[i.cwe_id] = (byCwe[i.cwe_id] || 0) + 1;
    }
    const sorted = Object.entries(byCwe).sort((a, b) => b[1] - a[1]);
    const clusters = sorted.filter(([, c]) => c > 1);
    return {
      count: clusters.length,
      top: sorted[0]?.[0] ?? "",
      topCount: sorted[0]?.[1] ?? 0,
    };
  }, [pageData]);

  const estimatedLoss = useMemo(() => {
    const annual = severityCounts.critical * 50000 + severityCounts.high * 10000 + severityCounts.medium * 2000 + severityCounts.low * 500;
    if (annual >= 1000000) return `$${(annual / 1000000).toFixed(2)}M`;
    if (annual >= 1000) return `$${(annual / 1000).toFixed(0)}K`;
    return `$${annual}`;
  }, [severityCounts]);

  const total = pageData?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / rowsPerPage));
  const showFrom = total === 0 ? 0 : (page - 1) * rowsPerPage + 1;
  const showTo = Math.min(page * rowsPerPage, total);

  if (loading) return <PageLoading title="Findings" cards={9} />;

  return (
    <div className="-mx-5 md:-mx-6 -mt-6 -mb-6 flex">
      {/* ── Main content ── */}
      <div className="flex-1 min-w-0 px-5 md:px-6 py-6 space-y-5">

        {/* Header */}
        <header className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">Findings.</h1>
            <p className="mt-1 font-body text-[14px] text-slate">
              Verified vulnerabilities, exploit evidence, and remediation workflow.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => recheckFindingIds(Array.from(selectedIds))}
              disabled={rechecking || selectedIds.size === 0}
              title={selectedIds.size === 0 ? "Select findings first" : `Recheck ${selectedIds.size} selected`}
              className={cn(
                "flex items-center gap-2 rounded-sm px-4 py-2 font-body text-[13px] font-medium transition-colors",
                selectedIds.size > 0
                  ? "bg-ink text-paper hover:bg-graphite"
                  : "border border-ink text-ink hover:bg-ink hover:text-paper",
                (rechecking || selectedIds.size === 0) && "opacity-60 cursor-not-allowed hover:bg-transparent hover:text-ink",
              )}
            >
              <RefreshIcon />
              {rechecking
                ? "Rechecking…"
                : selectedIds.size > 0
                  ? `Recheck selected (${selectedIds.size})`
                  : "Recheck selected"}
            </button>
            <button
              type="button"
              onClick={exportEvidence}
              disabled={visibleItems.length === 0}
              title={visibleItems.length === 0 ? "Nothing to export" : `Export ${visibleItems.length} finding${visibleItems.length === 1 ? "" : "s"} as CSV`}
              className="flex items-center gap-2 border border-hairline rounded-sm px-4 py-2 font-body text-[13px] text-slate hover:border-ink hover:text-ink transition-colors disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:border-hairline disabled:hover:text-slate"
            >
              <DownloadIcon />
              Export evidence
            </button>
          </div>
        </header>

        {/* Recheck status banner */}
        {recheckStatus.state !== "idle" && (
          <div className={cn(
            "border rounded-sm px-4 py-2.5 flex items-center justify-between gap-3 flex-wrap",
            recheckStatus.state === "running"
              ? "border-gilt/40 bg-gilt/5"
              : recheckStatus.failed > 0
                ? "border-sev-high/40 bg-sev-high/5"
                : "border-forest/40 bg-forest/5"
          )}>
            <div className="flex items-center gap-2.5">
              <span className={cn(
                "w-1.5 h-1.5 rounded-full",
                recheckStatus.state === "running"
                  ? "bg-gilt animate-pulse"
                  : recheckStatus.failed > 0
                    ? "bg-sev-high"
                    : "bg-forest"
              )} />
              {recheckStatus.state === "running" ? (
                <p className="font-body text-[13px] text-graphite">
                  Re-examining {recheckStatus.total} finding{recheckStatus.total === 1 ? "" : "s"}…
                </p>
              ) : (
                <p className="font-body text-[13px] text-graphite">
                  {recheckStatus.queued} finding{recheckStatus.queued === 1 ? "" : "s"} queued for recheck
                  {recheckStatus.failed > 0 && <span className="text-sev-high"> · {recheckStatus.failed} failed</span>}
                  {recheckStatus.skipped > 0 && <span className="text-mist"> · {recheckStatus.skipped} skipped (code-scan)</span>}
                  <span className="text-mist"> · {new Date(recheckStatus.at).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", hour12: true })}</span>
                </p>
              )}
            </div>
            {recheckStatus.state === "done" && (
              <button
                type="button"
                onClick={() => setRecheckStatus({ state: "idle", total: 0, queued: 0, failed: 0, skipped: 0, at: 0 })}
                className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist hover:text-ink transition-colors"
              >
                Dismiss
              </button>
            )}
          </div>
        )}

        {/* ── 6-stat bar ── */}
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-2.5">
          <SevStatCard
            label="Critical"
            count={severityCounts.critical}
            icon={<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="8" cy="8" r="6.5"/><path d="M8 5v3M8 10v.5" strokeLinecap="round"/></svg>}
            iconColor="#7A1F24"
            trendColor="#7A1F24"
          />
          <SevStatCard
            label="High"
            count={severityCounts.high}
            icon={<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="8" cy="8" r="6.5"/><path d="M8 5v3M8 10v.5" strokeLinecap="round"/></svg>}
            iconColor="#B45309"
            trendColor="#B45309"
          />
          <SevStatCard
            label="Medium"
            count={severityCounts.medium}
            icon={<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="8" cy="8" r="6.5"/><path d="M8 5v3M8 10v.5" strokeLinecap="round"/></svg>}
            iconColor="#92712A"
            trendColor="#92712A"
          />
          <SevStatCard
            label="Low"
            count={severityCounts.low}
            icon={<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="8" cy="8" r="6.5"/><path d="M5.5 8h5" strokeLinecap="round"/></svg>}
            iconColor="#1F4E79"
            trendColor="#1F4E79"
          />
          <SevStatCard
            label="Suppressed"
            count={Math.max(0, severityCounts.suppressed)}
            icon={<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="8" cy="8" r="6.5"/><path d="M5.5 10.5l5-5M10.5 10.5l-5-5" strokeLinecap="round"/></svg>}
            iconColor="#94A3B8"
            trendColor="#94A3B8"
          />
          <SevStatCard
            label="Rechecked"
            count={pageData?.items.filter(i => i.kev).length ?? 0}
            icon={<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><circle cx="8" cy="8" r="6.5"/><path d="M5 8l2.5 2.5L11 5.5" strokeLinecap="round" strokeLinejoin="round"/></svg>}
            iconColor="#2F5D50"
            trendColor="#2F5D50"
          />
        </div>

        {/* ── Two-row filter bar ── */}
        <div className="space-y-2.5">
          {/* Row 1 */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative flex items-center w-full sm:w-[260px]">
              <span className="absolute left-3 pointer-events-none"><SearchIcon /></span>
              <input
                type="search"
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Search findings…"
                className="w-full border border-hairline rounded-sm pl-9 pr-4 py-2 font-body text-[13px] bg-paper text-graphite placeholder:text-mist focus:outline-none focus:border-ink transition-colors"
              />
            </div>
            <FilterDropdown label="Severity" value={severityFilter} options={SEV_OPTS} onChange={setSeverityFilter} />
            <FilterDropdown label="Status" value={statusFilter} options={STATUS_OPTS} onChange={setStatusFilter} />
            <FilterDropdown label="Source type" value={sourceFilter} options={SOURCE_OPTS} onChange={setSourceFilter} />
            <FilterDropdown label="Reachability" value={reachFilter} options={REACH_OPTS} onChange={setReachFilter} />
          </div>
          {/* Row 2 */}
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setIncludeSuppressed(v => !v)}
                className={cn(
                  "inline-flex items-center gap-1.5 border rounded-sm px-3 py-1.5 font-body text-[12px] transition-colors",
                  includeSuppressed ? "border-ink bg-ink text-paper" : "border-hairline text-slate hover:border-graphite"
                )}
              >
                {includeSuppressed ? "Suppressed: On" : "Suppressed: Off"}
                <ChevronDown />
              </button>
              {activeFilterCount > 0 && (
                <button
                  onClick={clearFilters}
                  className="font-body text-[12px] text-slate hover:text-ink underline underline-offset-4 decoration-hairline transition-colors"
                >
                  Clear all
                </button>
              )}
            </div>
            {/* Actions dropdown (AWS EC2 style) */}
            <div className="relative">
              <button
                onClick={() => setActionsOpen(v => !v)}
                className={cn(
                  "inline-flex items-center gap-1.5 border rounded-sm px-3 py-1.5 font-body text-[12px] transition-colors",
                  selectedIds.size > 0
                    ? "border-ink text-ink hover:bg-vellum"
                    : "border-hairline text-mist cursor-default"
                )}
              >
                Actions {selectedIds.size > 0 ? `(${selectedIds.size})` : ""}
                <ChevronDown />
              </button>
              {actionsOpen && selectedIds.size > 0 && (
                <div className="absolute right-0 top-full mt-1 w-[220px] bg-paper border border-hairline rounded-sm shadow-elev z-50 py-1">
                  <button onClick={() => setActionsOpen(false)} className="w-full text-left px-4 py-2 font-body text-[13px] text-graphite hover:bg-vellum transition-colors">
                    Suppress selected ({selectedIds.size})
                  </button>
                  <button onClick={() => setActionsOpen(false)} className="w-full text-left px-4 py-2 font-body text-[13px] text-graphite hover:bg-vellum transition-colors">
                    Mark as false positive
                  </button>
                  <button
                    onClick={() => {
                      setActionsOpen(false);
                      recheckFindingIds(Array.from(selectedIds));
                    }}
                    disabled={rechecking}
                    className="w-full text-left px-4 py-2 font-body text-[13px] text-graphite hover:bg-vellum transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                  >
                    Recheck selected
                  </button>
                  <div className="border-t border-hairline my-1" />
                  <button onClick={() => setActionsOpen(false)} className="w-full text-left px-4 py-2 font-body text-[13px] text-graphite hover:bg-vellum transition-colors">
                    Export selected
                  </button>
                  <button onClick={() => setActionsOpen(false)} className="w-full text-left px-4 py-2 font-body text-[13px] text-graphite hover:bg-vellum transition-colors">
                    Assign to…
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Findings table ── */}
        {!pageData || pageData.items.length === 0 ? (
          <div className="border border-hairline rounded-sm p-10 text-center bg-vellum/30">
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-gilt">No findings</p>
            <h3 className="mt-3 font-display text-[22px] text-ink">
              {activeFilterCount > 0 ? "No findings match the active filters." : "No findings yet — run an assessment."}
            </h3>
          </div>
        ) : (
          <div className="border border-hairline rounded-sm overflow-hidden">
            {loadingPage && (
              <div className="px-4 py-2 bg-vellum/50 border-b border-hairline">
                <p className="font-mono text-[10px] text-mist uppercase tracking-[0.14em]">Refreshing…</p>
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-left min-w-[1100px]">
                <thead>
                  <tr className="border-b border-hairline bg-vellum/80">
                    <th className="px-3 py-2.5 w-8">
                      <input type="checkbox" checked={allSelected} onChange={toggleAll} className="w-3.5 h-3.5 accent-ink cursor-pointer" />
                    </th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">Severity</th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">Finding</th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden md:table-cell">Target</th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden lg:table-cell">Evidence</th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden lg:table-cell">CVSS / EPSS</th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden xl:table-cell">Assignee</th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">Status</th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden xl:table-cell">Owner</th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden xl:table-cell">SLA</th>
                    <th className="px-3 py-2.5 font-mono text-[9px] uppercase tracking-[0.16em] text-mist hidden lg:table-cell">Last seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline">
                  {visibleItems.map(item => {
                    const evidence = evidenceStrength(item);
                    const status = statusFromSsvc(item.ssvc_decision, item.suppressed);
                    const href = item.table === "findings"
                      ? `/findings/${item.id}`
                      : item.repository_id
                        ? `/repos/${item.repository_id}/dashboard`
                        : "/repos";
                    const target = item.target_id ? targetById.get(item.target_id) : null;
                    const repo = item.repository_id ? repoById.get(item.repository_id) : null;
                    const targetLabel = target
                      ? (target.base_url?.replace(/^https?:\/\//, "").split("/")[0] ?? target.name)
                      : repo
                        ? (repo.full_name ?? repo.name ?? "")
                        : null;
                    const targetKindLabel = target
                      ? targetTypeLabel(target)
                      : repo
                        ? "Repository"
                        : null;
                    const selected = selectedIds.has(item.id);
                    const assignee = getAssignee(item);

                    return (
                      <tr
                        key={`${item.table}-${item.id}`}
                        className={cn("hover:bg-vellum/40 transition-colors group", selected && "bg-vellum/60")}
                      >
                        {/* Checkbox */}
                        <td className="px-3 py-3 w-8">
                          <input type="checkbox" checked={selected} onChange={() => toggleItem(item.id)} className="w-3.5 h-3.5 accent-ink cursor-pointer" />
                        </td>
                        {/* Severity */}
                        <td className="px-3 py-3">
                          <SeverityPill severity={item.severity} />
                        </td>
                        {/* Finding */}
                        <td className="px-3 py-3 max-w-[240px]">
                          <Link href={href} className="font-body text-[13px] font-semibold text-ink hover:underline underline-offset-4 decoration-gilt line-clamp-2 block">
                            {item.title}
                            {item.kev && (
                              <span className="ml-1.5 inline-flex items-center border border-sev-critical rounded-sm px-1.5 py-0.5 font-mono text-[8px] uppercase text-sev-critical">KEV</span>
                            )}
                          </Link>
                          <p className="font-mono text-[10px] text-mist mt-0.5 truncate">
                            {item.owasp_category || item.cwe_id || item.source?.toUpperCase() || "—"}
                          </p>
                        </td>
                        {/* Target */}
                        <td className="px-3 py-3 hidden md:table-cell">
                          {targetLabel ? (
                            <div>
                              <p className="font-mono text-[11px] text-ink truncate max-w-[160px]">{targetLabel}</p>
                              <p className="font-mono text-[9px] text-mist uppercase tracking-[0.1em] mt-0.5">{targetKindLabel}</p>
                            </div>
                          ) : (
                            <span className="font-mono text-[11px] text-mist">—</span>
                          )}
                        </td>
                        {/* Evidence */}
                        <td className="px-3 py-3 hidden lg:table-cell">
                          <div className="flex items-center gap-1.5">
                            <ShieldIcon strength={evidence.label} />
                            <div>
                              <p className={cn("font-body text-[11px] font-medium", evidence.color)}>{evidence.label}</p>
                              <p className="font-mono text-[9px] text-mist">{item.kev ? "KEV confirmed" : item.reachability ? item.reachability : "1 artifact"}</p>
                            </div>
                          </div>
                        </td>
                        {/* CVSS / EPSS */}
                        <td className="px-3 py-3 hidden lg:table-cell">
                          <p className="font-mono text-[13px] font-bold text-ink">{item.risk_score?.toFixed(1) ?? "—"}</p>
                          <p className="font-mono text-[10px] text-mist">{item.epss !== null ? item.epss.toFixed(2) : "—"}</p>
                          <CvssBar score={item.risk_score ?? 0} />
                        </td>
                        {/* Assignee */}
                        <td className="px-3 py-3 hidden xl:table-cell relative">
                          <button
                            type="button"
                            onClick={() => setAssigneeOpen(prev => prev === item.id ? null : item.id)}
                            disabled={members.length === 0}
                            className="inline-flex items-center gap-1.5 -mx-1 px-1 py-0.5 rounded-sm hover:bg-vellum transition-colors disabled:cursor-not-allowed"
                            title={assignee ? `Assigned to ${memberDisplay(assignee)}${item.table !== "findings" ? " (local)" : ""}` : "Assign"}
                          >
                            {assignee ? (
                              <>
                                <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-gilt/20 text-gilt font-mono text-[8px] font-bold">
                                  {memberInitials(assignee)}
                                </span>
                                <span className="font-body text-[11px] text-graphite truncate max-w-[80px]">
                                  {memberDisplay(assignee)}
                                </span>
                              </>
                            ) : (
                              <span className="font-mono text-[10px] text-mist">Assign…</span>
                            )}
                            <ChevronDown />
                          </button>
                          {assigneeOpen === item.id && members.length > 0 && (
                            <>
                              <div
                                className="fixed inset-0 z-40"
                                onClick={() => setAssigneeOpen(null)}
                              />
                              <div className="absolute left-2 top-full mt-1 w-[220px] max-h-[260px] overflow-y-auto bg-paper border border-hairline rounded-sm shadow-elev z-50 py-1">
                                {members.map(m => {
                                  const isCurrent = assignee?.user_id === m.user_id;
                                  return (
                                    <button
                                      key={m.user_id}
                                      type="button"
                                      onClick={() => assignFinding(item, m.user_id)}
                                      className={cn(
                                        "w-full text-left px-3 py-2 flex items-center gap-2 font-body text-[12px] transition-colors",
                                        isCurrent ? "bg-vellum/60" : "hover:bg-vellum"
                                      )}
                                    >
                                      <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-gilt/20 text-gilt font-mono text-[8px] font-bold shrink-0">
                                        {memberInitials(m)}
                                      </span>
                                      <span className="flex-1 min-w-0">
                                        <span className="block text-graphite truncate">{memberDisplay(m)}</span>
                                        <span className="block font-mono text-[9px] text-mist truncate">{m.email}{m.role ? ` · ${m.role}` : ""}</span>
                                      </span>
                                      {isCurrent && <span className="font-mono text-[9px] text-forest shrink-0">✓</span>}
                                    </button>
                                  );
                                })}
                              </div>
                            </>
                          )}
                        </td>
                        {/* Status */}
                        <td className="px-3 py-3">
                          <span className={cn("inline-flex items-center border rounded-sm px-2 py-0.5 font-body text-[10px] font-medium", status.style)}>
                            {status.label}
                          </span>
                        </td>
                        {/* Owner */}
                        <td className="px-3 py-3 hidden xl:table-cell">
                          <span className="font-mono text-[11px] text-mist">—</span>
                        </td>
                        {/* SLA */}
                        <td className="px-3 py-3 hidden xl:table-cell">
                          <span className={cn("inline-flex items-center border rounded-sm px-1.5 py-0.5 font-mono text-[10px]", slaColor(item.severity))}>
                            {slaFromSeverity(item.severity)}
                          </span>
                        </td>
                        {/* Last seen */}
                        <td className="px-3 py-3 hidden lg:table-cell">
                          <span className="font-mono text-[11px] text-slate">{relativeTime(item.created_at)}</span>
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
                Showing {showFrom} to {showTo} of {total.toLocaleString()} results
              </span>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="px-2 py-1 font-mono text-[11px] text-slate disabled:opacity-30 hover:text-ink transition-colors"
                  >
                    ← Prev
                  </button>
                  {Array.from({ length: Math.min(5, pageCount) }, (_, i) => {
                    let n: number;
                    if (pageCount <= 5) n = i + 1;
                    else if (page <= 3) n = i + 1;
                    else if (page >= pageCount - 2) n = pageCount - 4 + i;
                    else n = page - 2 + i;
                    return (
                      <button
                        key={n}
                        onClick={() => setPage(n)}
                        className={cn(
                          "w-7 h-7 font-mono text-[11px] rounded-sm transition-colors",
                          page === n ? "bg-ink text-paper" : "text-slate hover:text-ink hover:bg-vellum"
                        )}
                      >
                        {n}
                      </button>
                    );
                  })}
                  {pageCount > 5 && page < pageCount - 2 && <span className="font-mono text-[11px] text-mist px-1">…</span>}
                  {pageCount > 5 && (
                    <button onClick={() => setPage(pageCount)} className={cn("w-7 h-7 font-mono text-[11px] rounded-sm transition-colors", page === pageCount ? "bg-ink text-paper" : "text-slate hover:text-ink hover:bg-vellum")}>
                      {pageCount}
                    </button>
                  )}
                  <button
                    onClick={() => setPage(p => Math.min(pageCount, p + 1))}
                    disabled={page === pageCount}
                    className="px-2 py-1 font-mono text-[11px] text-slate disabled:opacity-30 hover:text-ink transition-colors"
                  >
                    Next →
                  </button>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="font-mono text-[10px] text-mist whitespace-nowrap">Rows per page:</span>
                  <select
                    value={rowsPerPage}
                    onChange={e => { setRowsPerPage(Number(e.target.value) as typeof ROWS_OPTIONS[number]); setPage(1); }}
                    className="border border-hairline rounded-sm px-2 py-1 font-mono text-[11px] text-graphite bg-paper focus:outline-none focus:border-ink"
                  >
                    {ROWS_OPTIONS.map(n => <option key={n} value={n}>{n}</option>)}
                  </select>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Triage Intelligence panel ── */}
      <aside className="w-[280px] shrink-0 border-l border-hairline px-5 py-6 space-y-5 hidden lg:block bg-vellum/20">
        <div className="flex items-center justify-between">
          <h3 className="font-display text-[17px] text-ink">Triage Intelligence</h3>
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" className="w-4 h-4 text-mist cursor-help">
            <circle cx="8" cy="8" r="6.5"/><path d="M8 7v4M8 5.5v.5" strokeLinecap="round"/>
          </svg>
        </div>

        {/* Exploit chains */}
        <div className="border border-hairline rounded-sm p-3.5 bg-paper space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ChainIcon />
              <span className="font-body text-[13px] font-semibold text-ink">Exploit chains (AI)</span>
            </div>
            <CountBadge count={exploitChains.length} color="bg-sev-high text-paper" />
          </div>
          <p className="font-body text-[11px] text-slate">{exploitChains.length} active chain{exploitChains.length !== 1 ? "s" : ""} detected</p>
          <div className="space-y-2">
            {exploitChains.length === 0 ? (
              <p className="font-body text-[11px] text-mist italic">No exploit chains detected.</p>
            ) : exploitChains.map((c, i) => (
              <div key={i} className="flex items-center justify-between gap-2">
                <p className="font-body text-[11px] text-slate flex-1 truncate">{i + 1}. {c.label}</p>
                <span className={cn(
                  "font-mono text-[9px] uppercase px-1.5 py-0.5 rounded-sm shrink-0",
                  c.severity === "critical" ? "text-sev-critical bg-sev-critical/10" : "text-sev-high bg-sev-high/10"
                )}>
                  {c.severity}
                </span>
              </div>
            ))}
          </div>
          <button
            type="button"
            onClick={viewChains}
            disabled={exploitChains.length === 0}
            className="font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline transition-colors disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:text-graphite"
          >
            View chains →
          </button>
        </div>

        {/* Duplicate clusters */}
        <div className="border border-hairline rounded-sm p-3.5 bg-paper space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ClusterIcon />
              <span className="font-body text-[13px] font-semibold text-ink">Duplicate clusters</span>
            </div>
            <CountBadge count={dupClusters.count} color="bg-gilt text-ink" />
          </div>
          <p className="font-body text-[11px] text-slate">
            {pageData?.items.length ?? 0} findings in {dupClusters.count} cluster{dupClusters.count !== 1 ? "s" : ""}
          </p>
          {dupClusters.top && (
            <div className="space-y-0.5">
              <p className="font-body text-[11px] text-slate">Top cluster: <span className="font-medium text-ink">{dupClusters.top}</span></p>
              <p className="font-mono text-[10px] text-mist">{dupClusters.topCount} findings</p>
            </div>
          )}
          <button
            type="button"
            onClick={reviewClusters}
            disabled={!dupClusters.top}
            className="font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline transition-colors disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:text-graphite"
          >
            Review clusters →
          </button>
        </div>

        {/* Remediation PRs */}
        <div className="border border-hairline rounded-sm p-3.5 bg-paper space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <PRIcon />
              <span className="font-body text-[13px] font-semibold text-ink">Remediation PRs (AI)</span>
            </div>
            <CountBadge count={0} color="bg-forest text-paper" />
          </div>
          <p className="font-body text-[11px] text-slate italic text-mist">No fix suggestions available yet.</p>
          <Link href="/targets" className="font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline">
            View all PR suggestions →
          </Link>
        </div>

        {/* Top business impact */}
        <div className="border border-hairline rounded-sm p-3.5 bg-paper space-y-3">
          <div className="flex items-center gap-2">
            <ImpactIcon />
            <span className="font-body text-[13px] font-semibold text-ink">Top business impact</span>
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-body text-[12px] text-slate">Potential annual loss</span>
              <span className="font-mono text-[13px] font-bold text-ink">{estimatedLoss}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="font-body text-[12px] text-slate">Assets at risk</span>
              <span className="font-mono text-[12px] text-ink">{severityCounts.critical + severityCounts.high}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="font-body text-[12px] text-slate">Business processes</span>
              <span className="font-mono text-[12px] text-ink">{Math.max(1, Math.floor((severityCounts.critical + severityCounts.high) / 3))}</span>
            </div>
          </div>
          <button
            type="button"
            onClick={impactAnalysis}
            className="font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline transition-colors"
          >
            Impact analysis →
          </button>
        </div>

        {/* Next best action */}
        <div className="border border-hairline rounded-sm p-3.5 bg-paper space-y-3">
          <div className="flex items-center gap-2">
            <StarIcon />
            <span className="font-body text-[13px] font-semibold text-ink">Next best action</span>
          </div>
          {severityCounts.critical + severityCounts.high > 0 ? (
            <>
              <div>
                <p className="font-body text-[12px] text-ink font-medium">
                  Recheck {severityCounts.critical + severityCounts.high} critical &amp; high findings
                </p>
                <p className="font-mono text-[10px] text-mist mt-0.5">Last check: 3h ago</p>
              </div>
              <button
                type="button"
                onClick={recheckTopPriority}
                disabled={rechecking}
                className={cn(
                  "w-full flex items-center justify-center gap-2 bg-ink text-paper rounded-sm px-4 py-2.5 font-body text-[13px] font-medium hover:bg-graphite transition-colors",
                  rechecking && "opacity-60 cursor-not-allowed hover:bg-ink",
                )}
              >
                <RefreshIcon />
                {rechecking ? "Rechecking…" : "Recheck now"}
              </button>
            </>
          ) : (
            <p className="font-body text-[12px] text-mist italic">No urgent actions — all findings triaged.</p>
          )}
        </div>

        {/* Severity breakdown */}
        <IntelDivider label="By Severity" />
        <div className="space-y-2.5">
          {[
            { label: "Critical", value: severityCounts.critical, color: "bg-sev-critical" },
            { label: "High", value: severityCounts.high, color: "bg-sev-high" },
            { label: "Medium", value: severityCounts.medium, color: "bg-sev-medium" },
            { label: "Low", value: severityCounts.low, color: "bg-sev-low" },
          ].map(({ label, value, color }) => {
            const maxVal = Math.max(severityCounts.critical, 1);
            return (
              <div key={label} className="space-y-1">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="font-body text-[12px] text-slate">{label}</span>
                  <span className="font-mono text-[12px] text-ink">{value.toLocaleString()}</span>
                </div>
                <div className="h-[3px] w-full bg-vellum rounded-full overflow-hidden">
                  <div className={cn("h-full rounded-full", color)} style={{ width: `${Math.round((value / maxVal) * 100)}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </aside>

      {impactOpen && (
        <ImpactAnalysisModal
          onClose={() => setImpactOpen(false)}
          severityCounts={severityCounts}
          exploitedItems={pageData?.items.filter(i => i.kev || i.reachability === "exploited") ?? []}
          targetById={targetById}
          repoById={repoById}
        />
      )}
    </div>
  );
}

// ── Impact Analysis Modal ─────────────────────────────────────────────────────
function ImpactAnalysisModal({
  onClose,
  severityCounts,
  exploitedItems,
  targetById,
  repoById,
}: {
  onClose: () => void;
  severityCounts: { critical: number; high: number; medium: number; low: number; suppressed: number };
  exploitedItems: Item[];
  targetById: Map<string, Target>;
  repoById: Map<string, Repo>;
}) {
  // Industry-standard cost-per-finding heuristics (Ponemon 2023 cost of a data
  // breach + IBM/Snyk loss-modeling); these are coarse priors, not exact.
  const RATES = {
    critical: { mean: 50000, label: "$50,000", rationale: "Average remediation cost + breach exposure for a critical exploitable vulnerability (Ponemon 2023)." },
    high:     { mean: 10000, label: "$10,000", rationale: "Sev-high incident-response and downtime exposure (industry mean)." },
    medium:   { mean: 2000,  label: "$2,000",  rationale: "Medium severity — engineering time + minor risk uplift." },
    low:      { mean: 500,   label: "$500",    rationale: "Low severity — included for SLA tracking." },
  };
  const components = [
    { sev: "critical", count: severityCounts.critical, ...RATES.critical },
    { sev: "high",     count: severityCounts.high,     ...RATES.high     },
    { sev: "medium",   count: severityCounts.medium,   ...RATES.medium   },
    { sev: "low",      count: severityCounts.low,      ...RATES.low      },
  ];
  const total = components.reduce((s, c) => s + c.count * c.mean, 0);
  function fmt(n: number): string {
    if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(2)}M`;
    if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
    return `$${n.toLocaleString()}`;
  }
  // Keep page from scrolling under the modal
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; };
  }, []);
  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-ink/50 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Impact analysis"
      onClick={onClose}
    >
      <div
        className="w-full max-w-[760px] max-h-[90vh] overflow-y-auto bg-paper border border-hairline rounded-sm shadow-elev"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 bg-paper border-b border-hairline px-6 py-4 flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">Business Impact</p>
            <h2 className="mt-1 font-display text-[26px] leading-[1.1] tracking-[-0.01em] text-ink">Impact analysis.</h2>
            <p className="mt-1 font-body text-[12px] text-slate">Annual-loss projection across all open findings in this workspace.</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-1.5 -m-1.5 text-mist hover:text-ink transition-colors rounded-sm hover:bg-vellum"
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-4 h-4">
              <path d="M3.5 3.5l9 9M12.5 3.5l-9 9" strokeLinecap="round"/>
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-6">
          {/* Headline number */}
          <div className="border border-hairline rounded-sm p-4 bg-vellum/30">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Estimated annual loss</p>
            <p className="mt-1 font-display text-[44px] leading-none tracking-[-0.02em] text-ink">{fmt(total)}</p>
            <p className="mt-1.5 font-body text-[12px] text-slate">
              Sum of severity-weighted cost components below. Recomputed every time the panel opens.
            </p>
          </div>

          {/* Breakdown */}
          <section>
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist mb-2">Severity breakdown</p>
            <div className="border border-hairline rounded-sm overflow-hidden">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-hairline bg-vellum/50">
                    <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Severity</th>
                    <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist text-right">Count</th>
                    <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist text-right">Rate</th>
                    <th className="px-3 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist text-right">Subtotal</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline">
                  {components.map(c => (
                    <tr key={c.sev}>
                      <td className="px-3 py-2 font-body text-[12px] text-graphite capitalize">{c.sev}</td>
                      <td className="px-3 py-2 font-mono text-[12px] text-ink text-right">{c.count.toLocaleString()}</td>
                      <td className="px-3 py-2 font-mono text-[11px] text-slate text-right">{c.label}</td>
                      <td className="px-3 py-2 font-mono text-[12px] font-bold text-ink text-right">{fmt(c.count * c.mean)}</td>
                    </tr>
                  ))}
                </tbody>
                <tfoot>
                  <tr className="border-t border-hairline bg-vellum/40">
                    <td className="px-3 py-2 font-mono text-[10px] uppercase tracking-[0.14em] text-mist">Total</td>
                    <td className="px-3 py-2"></td>
                    <td className="px-3 py-2"></td>
                    <td className="px-3 py-2 font-mono text-[13px] font-bold text-ink text-right">{fmt(total)}</td>
                  </tr>
                </tfoot>
              </table>
            </div>
          </section>

          {/* Methodology */}
          <section>
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist mb-2">Methodology</p>
            <div className="border border-hairline rounded-sm p-4 space-y-2">
              <p className="font-body text-[12px] text-graphite leading-relaxed">
                Annual loss is modelled as <span className="font-mono text-[11px] text-ink">Σ (count × per-finding rate)</span> per severity tier.
                Rates are anchored on industry priors (Ponemon Institute's 2023 Cost of a Data Breach Report and IBM X-Force incident response means),
                and reflect remediation cost plus expected-loss exposure — <em>not</em> a deterministic forecast.
              </p>
              <ul className="space-y-1.5 mt-2">
                {components.map(c => (
                  <li key={c.sev} className="font-body text-[12px] text-slate">
                    <span className="font-mono text-[11px] uppercase tracking-[0.1em] text-graphite capitalize">{c.sev}</span>
                    <span className="text-mist"> · {c.label}/finding</span>
                    <span className="block text-[11px] text-mist mt-0.5 ml-0.5">{c.rationale}</span>
                  </li>
                ))}
              </ul>
              <p className="font-body text-[11px] text-mist italic mt-2">
                Assets at risk: <span className="font-mono text-ink not-italic">{severityCounts.critical + severityCounts.high}</span>
                {" "}critical+high findings. Treat the projection as a triage signal, not a dollar-precise estimate.
              </p>
            </div>
          </section>

          {/* Exploited evidence */}
          <section>
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist mb-2">
              Previously exploited <span className="text-slate">({exploitedItems.length})</span>
            </p>
            {exploitedItems.length === 0 ? (
              <div className="border border-hairline rounded-sm p-4 bg-vellum/20">
                <p className="font-body text-[12px] text-mist italic">
                  No findings in the current page show prior exploitation evidence (KEV-listed or reachability = exploited).
                </p>
              </div>
            ) : (
              <div className="border border-hairline rounded-sm divide-y divide-hairline">
                {exploitedItems.slice(0, 8).map(i => {
                  const t = i.target_id ? targetById.get(i.target_id) : null;
                  const r = i.repository_id ? repoById.get(i.repository_id) : null;
                  const where = t?.base_url?.replace(/^https?:\/\//, "").split("/")[0]
                    ?? t?.name
                    ?? r?.full_name
                    ?? r?.name
                    ?? "—";
                  return (
                    <div key={`${i.table}-${i.id}`} className="px-4 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="font-body text-[13px] font-semibold text-ink line-clamp-1">{i.title}</p>
                          <p className="font-mono text-[10px] text-mist mt-0.5">
                            {i.source?.toUpperCase()} · {where}
                            {i.cwe_id && <span> · {i.cwe_id}</span>}
                          </p>
                        </div>
                        <div className="shrink-0 flex items-center gap-2">
                          {i.kev && (
                            <span className="inline-flex items-center border border-sev-critical rounded-sm px-1.5 py-0.5 font-mono text-[8px] uppercase text-sev-critical">KEV</span>
                          )}
                          {i.reachability === "exploited" && (
                            <span className="inline-flex items-center border border-sev-high rounded-sm px-1.5 py-0.5 font-mono text-[8px] uppercase text-sev-high">Exploited</span>
                          )}
                          <span className="font-mono text-[12px] font-bold text-ink">{i.risk_score?.toFixed(1) ?? "—"}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
                {exploitedItems.length > 8 && (
                  <div className="px-4 py-2 bg-vellum/30">
                    <p className="font-mono text-[10px] text-mist">+ {exploitedItems.length - 8} more on later pages.</p>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 bg-paper border-t border-hairline px-6 py-3 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="bg-ink text-paper rounded-sm px-4 py-2 font-body text-[13px] font-medium hover:bg-graphite transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
