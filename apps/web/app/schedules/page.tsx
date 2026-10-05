"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Input, Label } from "@/components/brutal";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useWorkspace } from "@/lib/workspace-context";

// ── Types ────────────────────────────────────────────────────────────────────
type Schedule = {
  id: string;
  target_id: string;
  name: string;
  cron_expression: string;
  profile: string;
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
};
type Target = {
  id: string;
  name: string;
  base_url: string;
  kind?: "url" | "repo" | "llm";
  repository_id?: string | null;
};
type Scan = {
  id: string;
  target_id: string;
  status: string;
  score: number | null;
  summary: Record<string, number | string> | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
};

// ── Profile display ──────────────────────────────────────────────────────────
const PROFILE_INFO: Record<
  string,
  { label: string; hex: string; bg: string; fg: string }
> = {
  standard: { label: "Web DAST", hex: "#3B82F6", bg: "#EFF6FF", fg: "#1D4ED8" },
  quick: { label: "Quick DAST", hex: "#0EA5E9", bg: "#F0F9FF", fg: "#0369A1" },
  deep: { label: "Deep DAST", hex: "#8B5CF6", bg: "#F5F3FF", fg: "#6D28D9" },
  "api-only": {
    label: "API DAST",
    hex: "#A855F7",
    bg: "#FAF5FF",
    fg: "#7E22CE",
  },
  cicd: { label: "Repo SAST", hex: "#22C55E", bg: "#F0FDF4", fg: "#15803D" },
  "supply-chain": {
    label: "Container CVE",
    hex: "#F97316",
    bg: "#FFF7ED",
    fg: "#C2410C",
  },
  "network-va": {
    label: "LLM Red Team",
    hex: "#EF4444",
    bg: "#FEF2F2",
    fg: "#DC2626",
  },
  continuous: {
    label: "IaC Drift",
    hex: "#14B8A6",
    bg: "#F0FDFA",
    fg: "#0F766E",
  },
  compliance: {
    label: "Compliance",
    hex: "#F59E0B",
    bg: "#FFFBEB",
    fg: "#B45309",
  },
};
function pInfo(profile: string) {
  return (
    PROFILE_INFO[profile] ?? {
      label: profile,
      hex: "#94A3B8",
      bg: "#F8FAFC",
      fg: "#64748B",
    }
  );
}

const PROFILES = [
  "quick",
  "standard",
  "deep",
  "api-only",
  "compliance",
  "cicd",
  "continuous",
  "supply-chain",
  "network-va",
];
const selectClass =
  "bg-paper border border-hairline rounded-sm px-3.5 py-2.5 font-body text-[14px] text-graphite w-full focus:outline-none focus:border-ink transition-colors";

// Full IANA timezone list straight from the platform (no library). Older
// engines without supportedValuesOf fall back to just UTC.
const TIMEZONES: string[] =
  typeof (Intl as any).supportedValuesOf === "function"
    ? (Intl as any).supportedValuesOf("timeZone")
    : ["UTC"];
// Operator's local zone, used as the create-form default.
const BROWSER_TZ =
  (typeof window !== "undefined" &&
    Intl.DateTimeFormat().resolvedOptions().timeZone) ||
  "UTC";

// ── Cron utilities ───────────────────────────────────────────────────────────
function parseCron(expr: string) {
  const p = expr.trim().split(/\s+/);
  if (p.length < 5)
    return {
      hour: 0,
      minute: 0,
      daysOfWeek: [0, 1, 2, 3, 4, 5, 6] as number[],
      everyNDays: null as number | null,
    };
  const [mn, hr, dom, , dow] = p;
  const minute = parseInt(mn) || 0;
  const hour = parseInt(hr) || 0;
  let everyNDays: number | null = null;
  if (dom !== "*" && dom.includes("/"))
    everyNDays = parseInt(dom.split("/")[1]) || null;
  let daysOfWeek: number[];
  if (dow === "*") daysOfWeek = [0, 1, 2, 3, 4, 5, 6];
  else if (dow.includes(","))
    daysOfWeek = dow
      .split(",")
      .map(Number)
      .filter((n) => !isNaN(n));
  else {
    const d = parseInt(dow);
    daysOfWeek = isNaN(d) ? [0, 1, 2, 3, 4, 5, 6] : [d];
  }
  return { hour, minute, daysOfWeek, everyNDays };
}

function fmtTime(h: number, m: number) {
  const hh = h % 12 || 12;
  return `${hh.toString().padStart(2, "0")}:${m.toString().padStart(2, "0")} ${h < 12 ? "AM" : "PM"}`;
}

function cronHuman(expr: string): { l1: string; l2: string } {
  const { hour, minute, daysOfWeek, everyNDays } = parseCron(expr);
  const t = fmtTime(hour, minute);
  const da = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  if (everyNDays) return { l1: `Every ${everyNDays} days`, l2: `${t} IST` };
  if (daysOfWeek.length === 7) return { l1: "Daily", l2: `${t} IST` };
  if (daysOfWeek.length === 1)
    return { l1: "Weekly", l2: `${da[daysOfWeek[0]]} ${t}` };
  if (daysOfWeek.length === 2)
    return {
      l1: "Twice weekly",
      l2: `${daysOfWeek.map((d) => da[d]).join(", ")} ${t}`,
    };
  return {
    l1: `${daysOfWeek.length}× weekly`,
    l2: daysOfWeek.map((d) => da[d]).join(", "),
  };
}

function runsOnDay(expr: string, date: Date): boolean {
  const { daysOfWeek, everyNDays } = parseCron(expr);
  if (everyNDays) return date.getDate() % everyNDays === 0;
  return daysOfWeek.includes(date.getDay());
}

// ── Date utilities ───────────────────────────────────────────────────────────
const MONTH_NAMES = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];
const DAY_ABBRS = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

function weekStart(d: Date) {
  const x = new Date(d);
  x.setDate(x.getDate() - x.getDay());
  x.setHours(0, 0, 0, 0);
  return x;
}
function addDays(d: Date, n: number) {
  const x = new Date(d);
  x.setDate(x.getDate() + n);
  return x;
}
function fmtWeekRange(start: Date) {
  const end = addDays(start, 6);
  const sm = MONTH_NAMES[start.getMonth()],
    em = MONTH_NAMES[end.getMonth()];
  return sm === em
    ? `${sm} ${start.getDate()} – ${end.getDate()}, ${start.getFullYear()}`
    : `${sm} ${start.getDate()} – ${em} ${end.getDate()}, ${start.getFullYear()}`;
}
function fmtMonthYear(d: Date) {
  return `${MONTH_NAMES[d.getMonth()]} ${d.getFullYear()}`;
}
function daysInMonth(y: number, m: number) {
  return new Date(y, m + 1, 0).getDate();
}

function timeUntil(iso: string | null) {
  if (!iso) return "—";
  const diff = new Date(iso).getTime() - Date.now();
  if (diff < 0) return "Overdue";
  const m = Math.floor(diff / 60000),
    h = Math.floor(diff / 3600000),
    dy = Math.floor(diff / 86400000);
  if (m < 60) return `${m}m`;
  if (h < 24) return `${h}h ${m % 60}m`;
  return `${dy}d ${h % 24}h`;
}
function fmtShort(iso: string | null) {
  if (!iso) return null;
  const d = new Date(iso);
  return {
    date: `${MONTH_NAMES[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`,
    time: fmtTime(d.getHours(), d.getMinutes()),
  };
}
function daysSince(iso: string) {
  return Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
}

function kindLabel(kind?: string | null) {
  if (kind === "repo") return "Repository";
  if (kind === "llm") return "LLM Endpoint";
  return "Web App";
}

// ── Inline SVGs ──────────────────────────────────────────────────────────────
const GlobeIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-3.5 h-3.5"
  >
    <circle cx="8" cy="8" r="6.5" />
    <path
      d="M2 8h12M8 1.5C6.5 3.5 5.5 5.5 5.5 8s1 4.5 2.5 6.5M8 1.5C9.5 3.5 10.5 5.5 10.5 8s-1 4.5-2.5 6.5"
      strokeLinecap="round"
    />
  </svg>
);
const RepoIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-3.5 h-3.5"
  >
    <rect x="1.5" y="2" width="13" height="11" rx="1.5" />
    <path
      d="M5.5 5.5L4 7l1.5 1.5M10.5 5.5L12 7l-1.5 1.5M8.5 5l-1.5 4"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);
const BrainIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-3.5 h-3.5"
  >
    <path
      d="M8 2.5C6.5 2.5 5 3.5 5 5c0 .8.4 1.5 1 2l-1.5 1A2.5 2.5 0 0 0 6 12.5h4a2.5 2.5 0 0 0 1.5-4.5L10 6.5c.6-.5 1-1.2 1-2 0-1.5-1.5-2.5-3-2Z"
      strokeLinejoin="round"
    />
  </svg>
);
const ClockIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4 h-4"
  >
    <circle cx="8" cy="8" r="6.5" />
    <path d="M8 5v3l2 2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const PlusIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    className="w-3.5 h-3.5"
  >
    <path d="M8 3v10M3 8h10" strokeLinecap="round" />
  </svg>
);
const PlayIcon = () => (
  <svg viewBox="0 0 16 16" fill="currentColor" className="w-3 h-3">
    <path d="M4 3l9 5-9 5V3Z" />
  </svg>
);
const PauseIcon = () => (
  <svg viewBox="0 0 16 16" fill="currentColor" className="w-3 h-3">
    <rect x="4" y="3" width="3" height="10" rx="0.5" />
    <rect x="9" y="3" width="3" height="10" rx="0.5" />
  </svg>
);
const ChevLeft = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    className="w-4 h-4"
  >
    <path d="M10 12L6 8l4-4" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const ChevRight = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    className="w-4 h-4"
  >
    <path d="M6 4l4 4-4 4" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const ChevDown = () => (
  <svg
    viewBox="0 0 12 12"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    className="w-3 h-3"
  >
    <path d="M2 4l4 4 4-4" strokeLinecap="round" strokeLinejoin="round" />
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
    <path d="M2 4h12M5 8h6M8 12h0" strokeLinecap="round" />
  </svg>
);
const RefreshIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    className="w-3.5 h-3.5"
  >
    <path
      d="M13.5 2.5A7 7 0 1 0 14.5 9M14.5 2.5v4H10.5"
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
const CheckIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    className="w-4 h-4"
  >
    <path d="M3 8l3.5 3.5L13 5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const AlertIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-3.5 h-3.5"
  >
    <circle cx="8" cy="8" r="6.5" />
    <path d="M8 5v3M8 10v.5" strokeLinecap="round" />
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
    <path d="M8 1.5L2 4v4c0 3 2.5 5.5 6 6 3.5-.5 6-3 6-6V4L8 1.5Z" />
  </svg>
);
const TrendIcon = () => (
  <svg
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.4"
    className="w-4 h-4"
  >
    <path d="M2 10L5 7l3 3 6-6" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

// ── Agent icons strip ────────────────────────────────────────────────────────
function AgentIcons({ profile }: { profile: string }) {
  const n =
    profile === "deep" || profile === "network-va"
      ? 5
      : profile === "compliance"
        ? 3
        : 4;
  const svgs = [
    <svg
      key="a"
      viewBox="0 0 14 14"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.3"
      className="w-3 h-3"
    >
      <circle cx="7" cy="7" r="5.5" />
      <path d="M7 4v3l2 2" strokeLinecap="round" />
    </svg>,
    <svg
      key="b"
      viewBox="0 0 14 14"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.3"
      className="w-3 h-3"
    >
      <path d="M7 1.5L2 4v3c0 2.5 2 4.5 5 5 3-.5 5-2.5 5-5V4L7 1.5Z" />
    </svg>,
    <svg
      key="c"
      viewBox="0 0 14 14"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.3"
      className="w-3 h-3"
    >
      <rect x="1.5" y="2" width="11" height="10" rx="1.5" />
      <path d="M4.5 5.5L3.5 7l1 1" strokeLinecap="round" />
    </svg>,
    <svg
      key="d"
      viewBox="0 0 14 14"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.3"
      className="w-3 h-3"
    >
      <path
        d="M3.5 10.5A3 3 0 0 1 3.5 4.5a3 3 0 0 1 5.5-1"
        strokeLinecap="round"
      />
    </svg>,
  ];
  return (
    <div className="flex items-center gap-1">
      {svgs.slice(0, 3).map((ico, i) => (
        <span
          key={i}
          className="w-5 h-5 rounded-full border border-hairline bg-vellum flex items-center justify-center text-slate"
        >
          {ico}
        </span>
      ))}
      {n > 3 && (
        <span className="w-5 h-5 rounded-full border border-hairline bg-vellum flex items-center justify-center font-mono text-[9px] text-slate">
          +{n - 3}
        </span>
      )}
    </div>
  );
}

// ── Stat tile ────────────────────────────────────────────────────────────────
function StatTile({
  label,
  value,
  sub,
  icon,
}: {
  label: string;
  value: React.ReactNode;
  sub: string;
  icon: React.ReactNode;
}) {
  return (
    <div className="border border-hairline rounded-sm p-4 bg-paper flex flex-col gap-1.5 min-w-0">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
          {label}
        </span>
        <span className="text-mist">{icon}</span>
      </div>
      <p className="font-display text-[34px] leading-none tracking-[-0.02em] text-ink">
        {value}
      </p>
      <p className="font-mono text-[11px] text-slate truncate">{sub}</p>
    </div>
  );
}

// ── Intel divider ─────────────────────────────────────────────────────────────
function Divider() {
  return (
    <div className="flex items-center gap-2 pt-1">
      <div className="flex-1 h-px bg-hairline" />
    </div>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────
export default function SchedulesPage() {
  const { activeWorkspace } = useWorkspace();

  // Data
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  // UI state
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<Schedule | null>(null);
  const [editForm, setEditForm] = useState({
    name: "",
    cron_expression: "0 2 * * *",
    profile: "standard",
    enabled: true,
  });
  const [editSubmitting, setEditSubmitting] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"week" | "month">("week");
  const [calDate, setCalDate] = useState(() => weekStart(new Date()));
  const [profileFilter, setProfileFilter] = useState("");
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({
    target_id: "",
    name: "",
    cron_expression: "0 2 * * *",
    profile: "standard",
    timezone: BROWSER_TZ,
  });

  async function reload() {
    setLoading(true);
    try {
      const [s, t, sc] = await Promise.all([
        api<Schedule[]>("/schedules").catch(() => [] as Schedule[]),
        api<Target[]>("/targets").catch(() => [] as Target[]),
        api<Scan[]>("/scans?limit=200").catch(() => [] as Scan[]),
      ]);
      setSchedules(Array.isArray(s) ? s : []);
      setTargets(Array.isArray(t) ? t : []);
      setScans(Array.isArray(sc) ? sc : []);
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    reload();
  }, [activeWorkspace?.id]);

  // Keep the page in sync while scans are in flight so a schedule's
  // "Last result" transitions Queued → Running → Success without a manual
  // refresh. Mirrors the polling in the assessments page.
  useEffect(() => {
    const inflight = scans.some(
      (s) => s.status === "queued" || s.status === "running",
    );
    if (!inflight) return;
    let cancelled = false;
    const handle = window.setInterval(async () => {
      try {
        const next = await api<Scan[]>("/scans?limit=200");
        if (!cancelled) setScans(Array.isArray(next) ? next : []);
      } catch {
        /* network blip — retry next tick */
      }
    }, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, [scans]);

  // ── Derived maps ──────────────────────────────────────────────────────────
  const targetById = useMemo(() => {
    const m = new Map<string, Target>();
    for (const t of targets) m.set(t.id, t);
    return m;
  }, [targets]);

  const lastScanByTarget = useMemo(() => {
    const m = new Map<string, Scan>();
    for (const sc of [...scans].sort(
      (a, b) =>
        new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    )) {
      m.set(sc.target_id, sc);
    }
    return m;
  }, [scans]);

  // Filtered schedules for table
  const filteredSchedules = useMemo(
    () =>
      profileFilter
        ? schedules.filter((s) => s.profile === profileFilter)
        : schedules,
    [schedules, profileFilter],
  );

  // Targets that have at least one schedule (for calendar rows)
  const calendarTargets = useMemo(() => {
    const seen = new Set<string>();
    const result: Target[] = [];
    for (const s of schedules) {
      if (!seen.has(s.target_id)) {
        const t = targetById.get(s.target_id);
        if (t) {
          seen.add(s.target_id);
          result.push(t);
        }
      }
    }
    return result;
  }, [schedules, targetById]);

  // Week days for calendar
  const weekDays = useMemo(
    () => Array.from({ length: 7 }, (_, i) => addDays(calDate, i)),
    [calDate],
  );
  const today = useMemo(() => {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    return d;
  }, []);

  function getSchedulesForCell(targetId: string, date: Date): Schedule[] {
    return (
      profileFilter
        ? schedules.filter((s) => s.profile === profileFilter)
        : schedules
    ).filter(
      (s) =>
        s.target_id === targetId &&
        s.enabled &&
        runsOnDay(s.cron_expression, date),
    );
  }

  // ── Intelligence computed ─────────────────────────────────────────────────
  const activeCount = schedules.filter((s) => s.enabled).length;
  const gateCount = schedules.filter((s) => s.profile === "cicd").length;
  const overdueCount = schedules.filter(
    (s) => s.enabled && s.next_run_at && new Date(s.next_run_at) < new Date(),
  ).length;
  // Scan.status from the backend is "done" / "running" / "failed" / "queued"
  // — the old comparison against "completed" never matched, which is why
  // completed scans showed up here as "Running" while the assessments page
  // correctly reported them as done.
  const successRate =
    scans.length === 0
      ? 100
      : Math.round(
          (scans.filter((s) => s.status === "done").length / scans.length) *
            100,
        );

  const nextRunSchedule = useMemo(
    () =>
      [...schedules]
        .filter((s) => s.enabled && s.next_run_at)
        .sort(
          (a, b) =>
            new Date(a.next_run_at!).getTime() -
            new Date(b.next_run_at!).getTime(),
        )[0] ?? null,
    [schedules],
  );

  const staleTargets = useMemo(
    () =>
      targets
        .filter((t) => {
          const last = lastScanByTarget.get(t.id);
          return !last || daysSince(last.created_at) > 14;
        })
        .slice(0, 5),
    [targets, lastScanByTarget],
  );

  const failedJobs = useMemo(
    () =>
      scans
        .filter((s) => s.status === "failed")
        .sort(
          (a, b) =>
            new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
        )
        .slice(0, 3)
        .map((s) => ({ scan: s, target: targetById.get(s.target_id) })),
    [scans, targetById],
  );

  const noisyWindows = useMemo(() => {
    const blocks: Record<
      string,
      { day: string; start: number; count: number }
    > = {};
    const dn = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    for (const s of schedules.filter((ss) => ss.enabled)) {
      const { hour, daysOfWeek } = parseCron(s.cron_expression);
      const block = Math.floor(hour / 2) * 2;
      for (const d of daysOfWeek) {
        const key = `${d}-${block}`;
        if (!blocks[key]) blocks[key] = { day: dn[d], start: block, count: 0 };
        blocks[key].count++;
      }
    }
    return Object.values(blocks)
      .sort((a, b) => b.count - a.count)
      .slice(0, 3)
      .map((b) => ({
        label: `${b.day} ${fmtTime(b.start, 0)} – ${fmtTime(b.start + 2, 0)}`,
        count: b.count,
        sev: b.count >= 5 ? "High" : b.count >= 3 ? "Medium" : "Low",
      }));
  }, [schedules]);

  const unscheduledTargets = useMemo(
    () =>
      targets
        .filter((t) => !schedules.some((s) => s.target_id === t.id))
        .slice(0, 3),
    [targets, schedules],
  );

  // Pagination
  const pageCount = Math.max(
    1,
    Math.ceil(filteredSchedules.length / rowsPerPage),
  );
  const tableRows = useMemo(() => {
    const start = (page - 1) * rowsPerPage;
    return filteredSchedules.slice(start, start + rowsPerPage);
  }, [filteredSchedules, page, rowsPerPage]);

  // ── Actions ───────────────────────────────────────────────────────────────
  async function createSchedule() {
    setCreating(true);
    try {
      // The operator picks the cron's IANA timezone in the form (defaulting to
      // their browser zone) so the backend interprets the cron expression in
      // that clock rather than UTC. Without this, "30 21 * * *" → 21:30 UTC =
      // 3:00 AM IST next day, not 9:30 PM IST as the cron-builder UI labels it.
      await api("/schedules", {
        method: "POST",
        json: form,
      });
      setShowCreate(false);
      setForm({
        target_id: "",
        name: "",
        cron_expression: "0 2 * * *",
        profile: "standard",
        timezone: BROWSER_TZ,
      });
      await reload();
    } finally {
      setCreating(false);
    }
  }

  async function toggle(id: string, enabled: boolean) {
    await api(`/schedules/${id}`, {
      method: "PATCH",
      json: { enabled: !enabled },
    });
    await reload();
  }

  async function remove(id: string) {
    if (!confirm("Delete this schedule?")) return;
    await api(`/schedules/${id}`, { method: "DELETE" });
    await reload();
  }

  function openEdit(s: Schedule) {
    setEditing(s);
    setEditForm({
      name: s.name,
      cron_expression: s.cron_expression,
      profile: s.profile,
      enabled: s.enabled,
    });
    setEditError(null);
  }

  async function submitEdit() {
    if (!editing) return;
    if (!editForm.name.trim()) {
      setEditError("Name is required.");
      return;
    }
    if (!editForm.cron_expression.trim()) {
      setEditError("Cadence (cron) is required.");
      return;
    }
    setEditSubmitting(true);
    setEditError(null);
    try {
      await api(`/schedules/${editing.id}`, {
        method: "PATCH",
        json: {
          name: editForm.name.trim(),
          cron_expression: editForm.cron_expression.trim(),
          profile: editForm.profile,
          enabled: editForm.enabled,
        },
      });
      setEditing(null);
      await reload();
    } catch (e: any) {
      setEditError(e?.message || "Failed to update schedule.");
    } finally {
      setEditSubmitting(false);
    }
  }

  async function runNow(s: Schedule) {
    await api("/scans", {
      method: "POST",
      json: { target_id: s.target_id, profile: s.profile },
    }).catch(() => {});
    await reload();
  }

  async function pauseAll() {
    if (!confirm("Pause all active schedules?")) return;
    await Promise.all(
      schedules
        .filter((s) => s.enabled)
        .map((s) =>
          api(`/schedules/${s.id}`, {
            method: "PATCH",
            json: { enabled: false },
          }),
        ),
    );
    await reload();
  }

  if (loading) {
    return (
      <div className="-mx-5 md:-mx-6 -mt-6 -mb-6 flex items-center justify-center h-[60vh]">
        <div className="text-center space-y-3">
          <div className="w-8 h-8 border-2 border-hairline border-t-ink rounded-full animate-spin mx-auto" />
          <p className="font-mono text-[11px] text-mist uppercase tracking-[0.14em]">
            Loading schedules…
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="-mx-5 md:-mx-6 -mt-6 -mb-6 flex">
      {/* ── Main content ── */}
      <div className="flex-1 min-w-0 px-5 md:px-6 py-6 space-y-6 overflow-hidden">
        {/* Header */}
        <header>
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
                Schedules.
              </h1>
              <p className="mt-1 font-body text-[14px] text-slate">
                Continuous scans, release gates, retests, and drift checks.
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0 flex-wrap">
              <button
                onClick={() => setShowCreate((v) => !v)}
                className="inline-flex items-center gap-1.5 bg-ink text-paper rounded-sm px-4 py-2 font-body text-[13px] font-medium hover:bg-graphite transition-colors"
              >
                <PlusIcon />
                {showCreate ? "Cancel" : "Create schedule"}
              </button>
              <button className="inline-flex items-center gap-1.5 border border-hairline rounded-sm px-4 py-2 font-body text-[13px] text-graphite hover:border-ink hover:text-ink transition-colors">
                <PlayIcon />
                Run now
              </button>
              <button
                onClick={pauseAll}
                className="inline-flex items-center gap-1.5 border border-hairline rounded-sm px-4 py-2 font-body text-[13px] text-graphite hover:border-ink hover:text-ink transition-colors"
              >
                <PauseIcon />
                Pause automation
              </button>
              <button className="p-2 border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors">
                <DotsIcon />
              </button>
            </div>
          </div>
        </header>

        {/* 6-stat bar */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <StatTile
            label="Active Schedules"
            value={activeCount}
            sub={
              activeCount > 0
                ? `↑ ${Math.min(2, activeCount)} vs last 7 days`
                : "None active"
            }
            icon={<ClockIcon />}
          />
          <StatTile
            label="Release Gates"
            value={gateCount}
            sub={gateCount > 0 ? `↑ 1 vs last 7 days` : "None configured"}
            icon={<ShieldIcon />}
          />
          <StatTile
            label="Retests Queued"
            value={scans.filter((s) => s.status === "running").length}
            sub={
              scans.filter((s) => s.status === "running").length > 0
                ? "In progress"
                : "All caught up"
            }
            icon={<RefreshIcon />}
          />
          <StatTile
            label="Overdue"
            value={overdueCount}
            sub={
              overdueCount === 0
                ? "All caught up"
                : `${overdueCount} need attention`
            }
            icon={<CheckIcon />}
          />
          <StatTile
            label="Success Rate (30D)"
            value={`${successRate}%`}
            sub="↑ 5% vs last 30 days"
            icon={<TrendIcon />}
          />
          <StatTile
            label="Next Run In"
            value={
              nextRunSchedule ? timeUntil(nextRunSchedule.next_run_at) : "—"
            }
            sub={
              nextRunSchedule
                ? (targetById.get(nextRunSchedule.target_id)?.name ?? "—")
                : "No active schedules"
            }
            icon={<ClockIcon />}
          />
        </div>

        {/* Create form */}
        {showCreate && (
          <div className="border border-hairline rounded-sm p-6 bg-vellum/30">
            <h2 className="font-display text-[22px] text-ink mb-5">
              Create Schedule
            </h2>
            <div className="grid gap-5 md:grid-cols-2">
              <div>
                <Label htmlFor="sch-target">Target</Label>
                <select
                  id="sch-target"
                  value={form.target_id}
                  onChange={(e) =>
                    setForm({ ...form, target_id: e.target.value })
                  }
                  className={selectClass}
                >
                  <option value="">Select a target…</option>
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name} — {t.base_url}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <Label htmlFor="sch-name">Schedule name</Label>
                <Input
                  id="sch-name"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="Nightly OWASP Top 10"
                />
              </div>
              <div>
                <Label htmlFor="sch-cron">Cron expression</Label>
                <Input
                  id="sch-cron"
                  value={form.cron_expression}
                  onChange={(e) =>
                    setForm({ ...form, cron_expression: e.target.value })
                  }
                  className="font-mono"
                />
                <p className="font-mono text-[10px] text-mist mt-1.5">
                  {cronHuman(form.cron_expression).l1} ·{" "}
                  {cronHuman(form.cron_expression).l2}
                </p>
              </div>
              <div>
                <Label htmlFor="sch-timezone">Timezone</Label>
                <select
                  id="sch-timezone"
                  value={form.timezone}
                  onChange={(e) =>
                    setForm({ ...form, timezone: e.target.value })
                  }
                  className={selectClass}
                >
                  {TIMEZONES.map((tz) => (
                    <option key={tz} value={tz}>
                      {tz}
                    </option>
                  ))}
                </select>
                <p className="font-mono text-[10px] text-mist mt-1.5">
                  Cron times run in this zone.
                </p>
              </div>
            </div>
            <div className="mt-5 flex items-center gap-3">
              <button
                onClick={createSchedule}
                disabled={creating || !form.target_id || !form.name}
                className="bg-ink text-paper rounded-sm px-5 py-2 font-body text-[13px] font-medium hover:bg-graphite transition-colors disabled:opacity-40"
              >
                {creating ? "Creating…" : "Create schedule"}
              </button>
              <button
                onClick={() => setShowCreate(false)}
                className="font-body text-[13px] text-slate hover:text-ink transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Calendar controls */}
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <button
              onClick={() =>
                setCalDate((d) =>
                  viewMode === "week"
                    ? addDays(d, -7)
                    : new Date(d.getFullYear(), d.getMonth() - 1, 1),
                )
              }
              className="p-1.5 border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors"
            >
              <ChevLeft />
            </button>
            <span className="font-body text-[14px] font-medium text-ink min-w-[200px] text-center">
              {viewMode === "week"
                ? fmtWeekRange(calDate)
                : fmtMonthYear(calDate)}
            </span>
            <button
              onClick={() =>
                setCalDate((d) =>
                  viewMode === "week"
                    ? addDays(d, 7)
                    : new Date(d.getFullYear(), d.getMonth() + 1, 1),
                )
              }
              className="p-1.5 border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors"
            >
              <ChevRight />
            </button>
            <button
              onClick={() => setCalDate(weekStart(new Date()))}
              className="border border-hairline rounded-sm px-3 py-1.5 font-body text-[12px] text-slate hover:border-ink hover:text-ink transition-colors"
            >
              Today
            </button>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {/* View toggle */}
            <div className="flex border border-hairline rounded-sm overflow-hidden">
              {(["week", "month"] as const).map((v, i) => (
                <button
                  key={v}
                  onClick={() => setViewMode(v)}
                  className={cn(
                    "px-3 py-1.5 font-body text-[12px] capitalize transition-colors",
                    i > 0 && "border-l border-hairline",
                    viewMode === v
                      ? "bg-ink text-paper"
                      : "text-slate hover:bg-vellum",
                  )}
                >
                  {v.charAt(0).toUpperCase() + v.slice(1)}
                </button>
              ))}
            </div>
            {/* Profile filter */}
            <div className="relative inline-flex items-center">
              <select
                value={profileFilter}
                onChange={(e) => setProfileFilter(e.target.value)}
                className="appearance-none border border-hairline rounded-sm pl-3 pr-7 py-1.5 font-body text-[12px] bg-paper text-graphite focus:outline-none focus:border-ink cursor-pointer transition-colors"
              >
                <option value="">All types</option>
                {PROFILES.map((p) => (
                  <option key={p} value={p}>
                    {pInfo(p).label}
                  </option>
                ))}
              </select>
              <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-mist">
                <ChevDown />
              </span>
            </div>
            <button className="inline-flex items-center gap-1.5 border border-hairline rounded-sm px-3 py-1.5 font-body text-[12px] text-slate hover:border-ink hover:text-ink transition-colors">
              <FilterIcon /> Filters
            </button>
          </div>
        </div>

        {/* ── Week calendar ── */}
        {viewMode === "week" && (
          <div className="border border-hairline rounded-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left min-w-[800px]">
                <thead>
                  <tr className="border-b border-hairline bg-vellum/60">
                    <th className="w-[180px] px-4 py-3 font-mono text-[9px] uppercase tracking-[0.16em] text-mist">
                      Target
                    </th>
                    {weekDays.map((day, i) => {
                      const isToday = day.getTime() === today.getTime();
                      return (
                        <th
                          key={i}
                          className={cn(
                            "px-2 py-3 font-mono text-center transition-colors",
                            isToday && "bg-ink/5",
                          )}
                        >
                          <div className="flex flex-col items-center gap-0.5">
                            <span className="text-[9px] uppercase tracking-[0.16em] text-mist">
                              {DAY_ABBRS[day.getDay()]}
                            </span>
                            <span
                              className={cn(
                                "w-6 h-6 flex items-center justify-center rounded-full font-display text-[14px]",
                                isToday ? "bg-ink text-paper" : "text-slate",
                              )}
                            >
                              {day.getDate()}
                            </span>
                          </div>
                        </th>
                      );
                    })}
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline">
                  {calendarTargets.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="px-4 py-12 text-center">
                        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-gilt mb-2">
                          Empty calendar
                        </p>
                        <p className="font-body text-[13px] text-mist">
                          Create a schedule to see it on the calendar.
                        </p>
                      </td>
                    </tr>
                  ) : (
                    calendarTargets.map((target) => (
                      <tr
                        key={target.id}
                        className="hover:bg-vellum/20 transition-colors"
                      >
                        {/* Target row header */}
                        <td className="px-4 py-3 w-[180px] align-top border-r border-hairline">
                          <div className="flex items-start gap-2">
                            <span className="text-mist shrink-0 mt-0.5">
                              {target.kind === "repo" ||
                              target.repository_id ? (
                                <RepoIcon />
                              ) : target.kind === "llm" ? (
                                <BrainIcon />
                              ) : (
                                <GlobeIcon />
                              )}
                            </span>
                            <div className="min-w-0">
                              <p className="font-body text-[12px] font-medium text-ink truncate">
                                {target.name}
                              </p>
                              <p className="font-mono text-[10px] text-mist">
                                {kindLabel(target.kind)}
                              </p>
                            </div>
                          </div>
                        </td>
                        {weekDays.map((day, di) => {
                          const cellSchedules = getSchedulesForCell(
                            target.id,
                            day,
                          );
                          const isToday = day.getTime() === today.getTime();
                          return (
                            <td
                              key={di}
                              className={cn(
                                "px-1.5 py-2 align-top",
                                isToday && "bg-ink/[0.015]",
                              )}
                            >
                              <div className="space-y-1">
                                {cellSchedules.map((s) => {
                                  const { hour, minute } = parseCron(
                                    s.cron_expression,
                                  );
                                  const pi = pInfo(s.profile);
                                  return (
                                    <div
                                      key={s.id}
                                      title={s.name}
                                      style={{
                                        backgroundColor: pi.bg,
                                        borderColor: `${pi.hex}40`,
                                      }}
                                      className="flex items-center gap-1 px-1.5 py-1 rounded-sm border cursor-pointer hover:opacity-80 transition-opacity min-w-0"
                                    >
                                      <span
                                        className="w-1.5 h-1.5 rounded-full shrink-0"
                                        style={{ backgroundColor: pi.hex }}
                                      />
                                      <span
                                        style={{ color: pi.fg }}
                                        className="font-mono text-[9px] whitespace-nowrap leading-tight"
                                      >
                                        {fmtTime(hour, minute)}{" "}
                                        <span className="font-semibold">
                                          {pi.label}
                                        </span>
                                      </span>
                                    </div>
                                  );
                                })}
                              </div>
                            </td>
                          );
                        })}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Month calendar ── */}
        {viewMode === "month" &&
          (() => {
            const year = calDate.getFullYear(),
              month = calDate.getMonth();
            const firstDay = new Date(year, month, 1).getDay();
            const total = daysInMonth(year, month);
            const cells: (number | null)[] = [
              ...Array(firstDay).fill(null),
              ...Array.from({ length: total }, (_, i) => i + 1),
            ];
            while (cells.length % 7 !== 0) cells.push(null);
            const weeks = Array.from({ length: cells.length / 7 }, (_, i) =>
              cells.slice(i * 7, i * 7 + 7),
            );
            return (
              <div className="border border-hairline rounded-sm overflow-hidden">
                <div className="grid grid-cols-7 border-b border-hairline bg-vellum/60">
                  {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map(
                    (d) => (
                      <div
                        key={d}
                        className="py-2 text-center font-mono text-[9px] uppercase tracking-[0.16em] text-mist"
                      >
                        {d}
                      </div>
                    ),
                  )}
                </div>
                {weeks.map((week, wi) => (
                  <div
                    key={wi}
                    className="grid grid-cols-7 border-b border-hairline last:border-none"
                  >
                    {week.map((day, di) => {
                      const date = day ? new Date(year, month, day) : null;
                      const isToday =
                        date?.toDateString() === new Date().toDateString();
                      const dayScheds = date
                        ? (profileFilter
                            ? schedules.filter(
                                (s) => s.profile === profileFilter,
                              )
                            : schedules
                          ).filter(
                            (s) =>
                              s.enabled && runsOnDay(s.cron_expression, date),
                          )
                        : [];
                      return (
                        <div
                          key={di}
                          className={cn(
                            "min-h-[80px] p-2 border-r border-hairline last:border-none transition-colors",
                            isToday && "bg-ink/[0.015]",
                            !day && "bg-vellum/20",
                          )}
                        >
                          {day && (
                            <>
                              <span
                                className={cn(
                                  "w-5 h-5 inline-flex items-center justify-center rounded-full font-display text-[12px] mb-1",
                                  isToday ? "bg-ink text-paper" : "text-slate",
                                )}
                              >
                                {day}
                              </span>
                              <div className="space-y-0.5">
                                {dayScheds.slice(0, 3).map((s) => {
                                  const pi = pInfo(s.profile);
                                  return (
                                    <div
                                      key={s.id}
                                      style={{ backgroundColor: pi.bg }}
                                      className="flex items-center gap-1 px-1 py-0.5 rounded-sm"
                                    >
                                      <span
                                        className="w-1 h-1 rounded-full shrink-0"
                                        style={{ backgroundColor: pi.hex }}
                                      />
                                      <span
                                        style={{ color: pi.fg }}
                                        className="font-mono text-[8px] truncate"
                                      >
                                        {pi.label}
                                      </span>
                                    </div>
                                  );
                                })}
                                {dayScheds.length > 3 && (
                                  <p className="font-mono text-[8px] text-mist pl-1">
                                    +{dayScheds.length - 3} more
                                  </p>
                                )}
                              </div>
                            </>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ))}
              </div>
            );
          })()}

        {/* ── All schedules table ── */}
        <div>
          <h2 className="font-body text-[15px] font-semibold text-ink mb-4">
            All schedules ({filteredSchedules.length})
          </h2>
          {filteredSchedules.length === 0 ? (
            <div className="border border-hairline rounded-sm p-10 text-center bg-vellum/30">
              <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-gilt">
                No schedules
              </p>
              <h3 className="mt-3 font-display text-[22px] text-ink">
                No schedules yet.
              </h3>
              <p className="mt-2 font-body text-[13px] text-slate max-w-[48ch] mx-auto">
                Create a cron-driven schedule to run scans automatically —
                nightly OWASP Top 10, hourly smoke, weekly compliance.
              </p>
            </div>
          ) : (
            <div className="border border-hairline rounded-sm overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left min-w-[1100px]">
                  <thead>
                    <tr className="border-b border-hairline bg-vellum/60">
                      <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">
                        Schedule name
                      </th>
                      <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">
                        Target
                      </th>
                      <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden sm:table-cell">
                        Cadence
                      </th>
                      <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden md:table-cell">
                        Profile
                      </th>
                      <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden lg:table-cell">
                        Agents
                      </th>
                      <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">
                        Next run
                      </th>
                      <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden lg:table-cell">
                        Last result
                      </th>
                      <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden xl:table-cell">
                        Owner
                      </th>
                      <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden xl:table-cell">
                        Notifications
                      </th>
                      <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">
                        Status
                      </th>
                      <th className="px-4 py-2.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist text-right">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-hairline">
                    {tableRows.map((s) => {
                      const target = targetById.get(s.target_id);
                      const cadence = cronHuman(s.cron_expression);
                      const pi = pInfo(s.profile);
                      const lastScan = lastScanByTarget.get(s.target_id);
                      const nextFmt = fmtShort(s.next_run_at);
                      const lastFmt = lastScan
                        ? fmtShort(lastScan.created_at)
                        : null;
                      const findingCount = lastScan?.summary
                        ? Object.values(lastScan.summary)
                            .filter((v) => typeof v === "number")
                            .reduce((a, b) => a + (b as number), 0)
                        : undefined;
                      return (
                        <tr
                          key={s.id}
                          className="hover:bg-vellum/20 transition-colors group"
                        >
                          {/* Name */}
                          <td className="px-4 py-3">
                            <p className="font-body text-[13px] font-semibold text-ink">
                              {s.name}
                            </p>
                          </td>
                          {/* Target */}
                          <td className="px-4 py-3">
                            <p className="font-mono text-[11px] text-ink truncate max-w-[150px]">
                              {target?.base_url
                                ?.replace(/^https?:\/\//, "")
                                .split("/")[0] ?? "—"}
                            </p>
                            <p className="font-mono text-[9px] text-mist uppercase tracking-[0.1em] mt-0.5">
                              {kindLabel(target?.kind)}
                            </p>
                          </td>
                          {/* Cadence */}
                          <td className="px-4 py-3 hidden sm:table-cell">
                            <p className="font-body text-[12px] text-ink">
                              {cadence.l1}
                            </p>
                            <p className="font-mono text-[10px] text-mist">
                              {cadence.l2}
                            </p>
                          </td>
                          {/* Profile */}
                          <td className="px-4 py-3 hidden md:table-cell">
                            <span
                              className="inline-flex items-center gap-1.5 border rounded-sm px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em]"
                              style={{
                                backgroundColor: pi.bg,
                                borderColor: `${pi.hex}40`,
                                color: pi.fg,
                              }}
                            >
                              <span
                                className="w-1.5 h-1.5 rounded-full shrink-0"
                                style={{ backgroundColor: pi.hex }}
                              />
                              {pi.label}
                            </span>
                          </td>
                          {/* Agents */}
                          <td className="px-4 py-3 hidden lg:table-cell">
                            <AgentIcons profile={s.profile} />
                          </td>
                          {/* Next run */}
                          <td className="px-4 py-3">
                            {nextFmt ? (
                              <div>
                                <p className="font-body text-[12px] text-ink">
                                  {nextFmt.date}
                                </p>
                                <p className="font-mono text-[10px] text-mist">
                                  {nextFmt.time}
                                </p>
                              </div>
                            ) : (
                              <span className="font-mono text-[11px] text-mist">
                                —
                              </span>
                            )}
                          </td>
                          {/* Last result */}
                          <td className="px-4 py-3 hidden lg:table-cell">
                            {lastScan ? (
                              <div>
                                <div className="flex items-center gap-1.5">
                                  <span
                                    className={cn(
                                      "w-1.5 h-1.5 rounded-full shrink-0",
                                      lastScan.status === "done"
                                        ? "bg-forest"
                                        : lastScan.status === "failed"
                                          ? "bg-sev-critical"
                                          : "bg-gilt animate-pulse",
                                    )}
                                  />
                                  <Link
                                    href={`/scans/${lastScan.id}`}
                                    className={cn(
                                      "font-body text-[11px] font-medium hover:underline underline-offset-4 decoration-gilt",
                                      lastScan.status === "done"
                                        ? "text-forest"
                                        : lastScan.status === "failed"
                                          ? "text-sev-critical"
                                          : "text-gilt",
                                    )}
                                    title="View this assessment"
                                  >
                                    {lastScan.status === "done"
                                      ? "Success"
                                      : lastScan.status === "failed"
                                        ? "Failed"
                                        : lastScan.status === "queued"
                                          ? "Queued"
                                          : "Running"}
                                  </Link>
                                </div>
                                {findingCount !== undefined &&
                                  lastScan.status === "done" && (
                                    <p className="font-mono text-[9px] text-mist mt-0.5">
                                      {findingCount} findings
                                    </p>
                                  )}
                                {lastScan.status !== "done" &&
                                  lastScan.status !== "failed" && (
                                    <p className="font-mono text-[9px] text-mist mt-0.5">
                                      In progress…
                                    </p>
                                  )}
                              </div>
                            ) : (
                              <span className="font-mono text-[11px] text-mist">
                                —
                              </span>
                            )}
                          </td>
                          {/* Owner */}
                          <td className="px-4 py-3 hidden xl:table-cell">
                            <span className="font-mono text-[11px] text-mist">
                              —
                            </span>
                          </td>
                          {/* Notifications */}
                          <td className="px-4 py-3 hidden xl:table-cell">
                            <span className="font-mono text-[11px] text-mist">
                              —
                            </span>
                          </td>
                          {/* Status */}
                          <td className="px-4 py-3">
                            <span
                              className={cn(
                                "inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.12em]",
                                s.enabled ? "text-forest" : "text-mist",
                              )}
                            >
                              <span
                                className={cn(
                                  "w-1.5 h-1.5 rounded-full",
                                  s.enabled ? "bg-forest" : "bg-hairline",
                                )}
                              />
                              {s.enabled ? "Active" : "Paused"}
                            </span>
                          </td>
                          {/* Actions */}
                          <td className="px-4 py-3 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => runNow(s)}
                                title="Run now"
                                className="p-1.5 text-mist hover:text-forest border border-transparent hover:border-forest/30 hover:bg-forest/5 rounded-sm transition-colors"
                              >
                                <PlayIcon />
                              </button>
                              <button
                                onClick={() => openEdit(s)}
                                className="font-body text-[11px] text-slate hover:text-ink underline underline-offset-4 decoration-hairline transition-colors"
                              >
                                Edit
                              </button>
                              <button
                                onClick={() => toggle(s.id, s.enabled)}
                                className="font-body text-[11px] text-slate hover:text-ink underline underline-offset-4 decoration-hairline transition-colors"
                              >
                                {s.enabled ? "Pause" : "Resume"}
                              </button>
                              <button
                                onClick={() => remove(s.id)}
                                className="font-body text-[11px] text-oxblood hover:text-sev-critical underline underline-offset-4 decoration-1 transition-colors"
                              >
                                Delete
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <div className="flex items-center justify-between gap-4 px-4 py-3 border-t border-hairline bg-vellum/30 flex-wrap">
                <span className="font-mono text-[11px] text-mist">
                  Showing{" "}
                  {Math.min(
                    (page - 1) * rowsPerPage + 1,
                    filteredSchedules.length,
                  )}{" "}
                  to {Math.min(page * rowsPerPage, filteredSchedules.length)} of{" "}
                  {filteredSchedules.length} result
                  {filteredSchedules.length !== 1 ? "s" : ""}
                </span>
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
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
                            page === n
                              ? "bg-ink text-paper"
                              : "text-slate hover:text-ink hover:bg-vellum",
                          )}
                        >
                          {n}
                        </button>
                      );
                    })}
                    <button
                      onClick={() => setPage((p) => Math.min(pageCount, p + 1))}
                      disabled={page === pageCount}
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
                        setRowsPerPage(Number(e.target.value));
                        setPage(1);
                      }}
                      className="border border-hairline rounded-sm px-2 py-1 font-mono text-[11px] text-graphite bg-paper focus:outline-none focus:border-ink"
                    >
                      {[10, 25, 50].map((n) => (
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
      </div>

      {/* ── Automation Intelligence panel ── */}
      <aside className="w-[280px] shrink-0 border-l border-hairline px-5 py-6 space-y-5 hidden lg:block bg-vellum/20 overflow-y-auto">
        <div className="flex items-center justify-between">
          <h3 className="font-display text-[17px] text-ink">
            Automation Intelligence
          </h3>
          <button
            onClick={reload}
            className="p-1 text-mist hover:text-ink transition-colors"
            title="Refresh"
          >
            <RefreshIcon />
          </button>
        </div>

        {/* Noisy windows */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
              Upcoming noisy windows
            </p>
            <Link
              href="/schedules"
              className="font-mono text-[10px] text-gilt hover:underline underline-offset-2"
            >
              View all
            </Link>
          </div>
          <div className="space-y-2.5">
            {noisyWindows.length === 0 ? (
              <p className="font-body text-[11px] text-mist italic">
                No concurrent windows found.
              </p>
            ) : (
              noisyWindows.map((w, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between gap-2"
                >
                  <div>
                    <p className="font-body text-[12px] text-ink">{w.label}</p>
                    <p className="font-mono text-[10px] text-mist">
                      {w.count} schedule{w.count !== 1 ? "s" : ""}
                    </p>
                  </div>
                  <span
                    className={cn(
                      "font-mono text-[10px] uppercase tracking-[0.1em] px-2 py-0.5 rounded-sm shrink-0",
                      w.sev === "High"
                        ? "text-sev-high bg-sev-high/10"
                        : w.sev === "Medium"
                          ? "text-gilt bg-gilt/10"
                          : "text-mist bg-vellum",
                    )}
                  >
                    {w.sev}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        <Divider />

        {/* Stale targets */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
              Stale targets
            </p>
            <Link
              href="/targets"
              className="font-mono text-[10px] text-gilt hover:underline underline-offset-2"
            >
              View all
            </Link>
          </div>
          <div className="space-y-2.5">
            {staleTargets.length === 0 ? (
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-forest shrink-0" />
                <p className="font-body text-[12px] text-slate">
                  All targets recently scanned.
                </p>
              </div>
            ) : (
              staleTargets.map((t) => {
                const last = lastScanByTarget.get(t.id);
                const days = last ? daysSince(last.created_at) : 999;
                const dot =
                  days > 20
                    ? "bg-sev-critical"
                    : days > 10
                      ? "bg-sev-high"
                      : "bg-sev-medium";
                return (
                  <div key={t.id} className="flex items-start gap-2">
                    <span
                      className={cn(
                        "w-1.5 h-1.5 rounded-full shrink-0 mt-1.5",
                        dot,
                      )}
                    />
                    <div>
                      <p className="font-body text-[12px] text-ink font-medium truncate">
                        {t.name}
                      </p>
                      <p className="font-mono text-[10px] text-mist">
                        {days === 999
                          ? "Never scanned"
                          : `No scan in ${days} days`}
                      </p>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        <Divider />

        {/* Suggested coverage */}
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist mb-3">
            Suggested coverage
          </p>
          <div className="space-y-3">
            {unscheduledTargets.length === 0 ? (
              <div className="flex items-start gap-2">
                <span className="text-forest mt-0.5 shrink-0">
                  <CheckIcon />
                </span>
                <p className="font-body text-[12px] text-slate">
                  All targets have schedules.
                </p>
              </div>
            ) : (
              unscheduledTargets.map((t) => (
                <div key={t.id} className="flex items-start gap-2">
                  <span className="text-gilt mt-0.5 shrink-0">
                    <AlertIcon />
                  </span>
                  <div>
                    <p className="font-body text-[12px] text-ink font-medium">
                      Add schedule for {t.name}
                    </p>
                    <p className="font-mono text-[10px] text-mist">
                      {kindLabel(t.kind)}
                    </p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Failed job replay */}
        {failedJobs.length > 0 && (
          <>
            <Divider />
            <div>
              <div className="flex items-center justify-between mb-3">
                <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
                  Failed job replay
                </p>
                <Link
                  href="/scans"
                  className="font-mono text-[10px] text-gilt hover:underline underline-offset-2"
                >
                  View all
                </Link>
              </div>
              <div className="space-y-3">
                {failedJobs.map(({ scan, target }) => {
                  const df = fmtShort(scan.created_at);
                  return (
                    <div
                      key={scan.id}
                      className="flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <p className="font-body text-[12px] text-ink font-medium truncate">
                          {target?.name ?? "Unknown"}
                        </p>
                        <p className="font-mono text-[10px] text-mist">
                          {df ? `${df.date.slice(0, 6)}, ${df.time}` : "—"}
                        </p>
                      </div>
                      <button
                        onClick={() =>
                          runNow({
                            id: scan.id,
                            target_id: scan.target_id,
                            name: target?.name ?? "",
                            cron_expression: "0 * * * *",
                            profile: "standard",
                            enabled: false,
                            next_run_at: null,
                            last_run_at: null,
                          })
                        }
                        className="shrink-0 border border-hairline rounded-sm px-2 py-0.5 font-mono text-[10px] text-slate hover:border-ink hover:text-ink transition-colors"
                      >
                        Retry
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          </>
        )}

        <Divider />

        {/* Webhook health */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
              Webhook health
            </p>
            <Link
              href="/integrations"
              className="font-mono text-[10px] text-gilt hover:underline underline-offset-2"
            >
              View all
            </Link>
          </div>
          <p className="font-body text-[11px] text-mist italic">
            No webhooks configured.
          </p>
          <Link
            href="/integrations"
            className="mt-2 inline-block font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline"
          >
            Set up integrations →
          </Link>
        </div>

        {/* Summary stats */}
        <Divider />
        <div className="space-y-2.5">
          <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
            Schedule summary
          </p>
          {[
            {
              label: "Active",
              value: activeCount,
              bar: schedules.length
                ? Math.round((activeCount / schedules.length) * 100)
                : 0,
              color: "bg-forest",
            },
            {
              label: "Paused",
              value: schedules.length - activeCount,
              bar: schedules.length
                ? Math.round(
                    ((schedules.length - activeCount) / schedules.length) * 100,
                  )
                : 0,
              color: "bg-mist",
            },
          ].map(({ label, value, bar, color }) => (
            <div key={label} className="space-y-1">
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-body text-[12px] text-slate">
                  {label}
                </span>
                <span className="font-mono text-[12px] text-ink">{value}</span>
              </div>
              <div className="h-[3px] w-full bg-vellum rounded-full overflow-hidden">
                <div
                  className={cn("h-full rounded-full transition-all", color)}
                  style={{ width: `${bar}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </aside>

      {/* Edit schedule modal */}
      {editing && (
        <div
          className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-ink/40 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
          aria-label="Edit schedule"
          onClick={() => !editSubmitting && setEditing(null)}
        >
          <div
            className="w-full max-w-[560px] max-h-[88vh] overflow-y-auto bg-paper border border-hairline rounded-sm shadow-elev"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="sticky top-0 bg-paper border-b border-hairline px-6 py-4 flex items-start justify-between">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
                  Schedule
                </p>
                <h2 className="font-display text-[24px] text-ink mt-1">
                  Edit schedule
                </h2>
                <p className="font-mono text-[10px] text-mist mt-1">
                  {targetById.get(editing.target_id)?.name ?? "Target"}
                </p>
              </div>
              <button
                type="button"
                onClick={() => !editSubmitting && setEditing(null)}
                aria-label="Close"
                className="p-1.5 -m-1.5 text-mist hover:text-ink hover:bg-vellum rounded-sm"
              >
                <svg
                  viewBox="0 0 16 16"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.6"
                  className="w-4 h-4"
                >
                  <path d="M4 4l8 8M12 4l-8 8" strokeLinecap="round" />
                </svg>
              </button>
            </div>
            <div className="px-6 py-5 space-y-4">
              <div>
                <Label htmlFor="edit-sched-name">Schedule name</Label>
                <Input
                  id="edit-sched-name"
                  value={editForm.name}
                  onChange={(e) =>
                    setEditForm((f) => ({ ...f, name: e.target.value }))
                  }
                  placeholder="Nightly assessment"
                />
              </div>
              <div>
                <Label htmlFor="edit-sched-cron">Cadence (cron)</Label>
                <Input
                  id="edit-sched-cron"
                  value={editForm.cron_expression}
                  onChange={(e) =>
                    setEditForm((f) => ({
                      ...f,
                      cron_expression: e.target.value,
                    }))
                  }
                  placeholder="0 2 * * *"
                  className="font-mono text-[13px]"
                />
                <p className="mt-1 font-mono text-[10px] text-mist">
                  Format:{" "}
                  <code>minute hour day-of-month month day-of-week</code>. e.g.{" "}
                  <code>0 7 * * *</code> = every day at 07:00.
                </p>
              </div>
              <label className="flex items-start gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={editForm.enabled}
                  onChange={(e) =>
                    setEditForm((f) => ({ ...f, enabled: e.target.checked }))
                  }
                  className="w-3.5 h-3.5 accent-ink mt-0.5"
                />
                <span className="flex flex-col">
                  <span className="font-body text-[13px] text-graphite">
                    Schedule active
                  </span>
                  <span className="font-mono text-[10px] text-mist">
                    Disable to pause runs without losing configuration.
                  </span>
                </span>
              </label>
              {editError && (
                <p className="font-mono text-[12px] text-sev-critical">
                  {editError}
                </p>
              )}
            </div>
            <div className="sticky bottom-0 bg-paper border-t border-hairline px-6 py-3 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setEditing(null)}
                disabled={editSubmitting}
                className="font-body text-[13px] border border-hairline rounded-sm px-3 py-1.5 text-slate hover:border-ink hover:text-ink transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={submitEdit}
                disabled={editSubmitting}
                className="font-body text-[13px] bg-ink text-paper rounded-sm px-4 py-1.5 hover:bg-graphite transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {editSubmitting ? "Saving…" : "Save changes"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
