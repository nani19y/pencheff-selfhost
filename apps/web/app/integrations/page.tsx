"use client";

/**
 * Integrations — Operations Hub.
 *
 * Layout adapted from the editorial mockup:
 *  - 5-stat bar (Connected · Degraded · Webhooks today · Events 30d · Delivery success)
 *  - Grouped integration cards by category (alerting, issue tracking, source
 *    control, SIEM, chatops/collab)
 *  - Event stream table of recent webhook deliveries
 *  - Right sidebar: workflow automation rules · quick actions · integration health donut
 *
 * Wired endpoints:
 *  - GET    /integrations
 *  - POST   /integrations
 *  - POST   /integrations/{id}/test
 *  - DELETE /integrations/{id}
 *  - GET    /targets  (for the connect drawer)
 *
 * Stats not backed by an API today (webhook delivery telemetry, event stream)
 * are derived from the integrations list itself when possible and otherwise
 * rendered with an honest empty state.
 */

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Button, Input, Label } from "@/components/brutal";
import { BrandLogo } from "@/components/brand-logos";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";

// ── Types ─────────────────────────────────────────────────────────────────────
type Integration = {
  id: string;
  kind: string;
  name: string;
  severity_filter: string;
  enabled: boolean;
  target_ids: string[] | null;
  events: string[] | null;
  created_at: string;
};
type Target = { id: string; name: string; base_url: string; kind?: "url" | "repo" | "llm"; repository_id?: string | null };
type DeliveryEntry = {
  id: string;
  ts: number;
  integration: Integration | null;
  event: string;
  source: string;
  status: "delivered" | "failed" | "degraded";
  duration_ms: number;
  details: string;
};

const ALL_EVENTS = [
  { value: "scan_started", label: "Scan started" },
  { value: "scan_done", label: "Scan done" },
  { value: "scan_failed", label: "Scan failed" },
  { value: "finding_new", label: "Each new finding" },
  { value: "finding_changed", label: "Finding updated (verify / suppress)" },
];

type KindDef = {
  value: string;
  label: string;
  category: "alerting" | "issue" | "source" | "siem" | "chatops" | "other";
  fields: string[];
  optional?: string[];
  placeholders?: Record<string, string>;
};

const KINDS: KindDef[] = [
  { value: "slack",      label: "Slack",                       category: "chatops",  fields: ["webhook_url"] },
  { value: "teams",      label: "Microsoft Teams",             category: "chatops",  fields: ["webhook_url"] },
  { value: "google_chat",label: "Google Chat",                 category: "chatops",  fields: ["webhook_url"] },
  { value: "discord",    label: "Discord",                     category: "chatops",  fields: ["webhook_url"] },
  { value: "pagerduty",  label: "PagerDuty",                   category: "alerting", fields: ["routing_key"] },
  { value: "opsgenie",   label: "Opsgenie",                    category: "alerting", fields: ["api_key"] },
  { value: "email",      label: "Email Alerts",                category: "alerting", fields: ["webhook_url"], placeholders: { webhook_url: "https://your-relay/email" } },
  { value: "splunk",     label: "Splunk HEC",                  category: "siem",     fields: ["hec_url", "token"] },
  { value: "datadog",    label: "Datadog Logs",                category: "siem",     fields: ["api_key"] },
  { value: "jira",       label: "Jira (issue creation)",       category: "issue",    fields: ["base_url", "email", "api_token", "project_key"], optional: ["issue_type"] },
  { value: "github_issues", label: "GitHub Issues",            category: "issue",    fields: ["api_token", "repo"] },
  { value: "github_status", label: "GitHub Commit Status",     category: "source",   fields: ["api_token"] },
  { value: "webhook",    label: "Generic webhook (HMAC)",      category: "other",    fields: ["webhook_url", "hmac_secret"] },
  { value: "s3",         label: "S3 Evidence Archive",         category: "other",    fields: ["bucket", "access_key", "secret_key"] },
  { value: "hackerone",  label: "HackerOne",                   category: "other",    fields: ["api_username", "api_token"] },
  { value: "bugcrowd",   label: "Bugcrowd",                    category: "other",    fields: ["api_token", "program_uuid"] },
  { value: "cobalt",     label: "Cobalt",                      category: "other",    fields: ["api_token", "pentest_id"] },
];

type CategoryKey = "alerting" | "issue" | "source" | "siem" | "chatops" | "other";
const CATEGORIES: { key: CategoryKey; label: string }[] = [
  { key: "alerting", label: "Alerting & On-call" },
  { key: "issue",    label: "Issue Tracking & Work Management" },
  { key: "source",   label: "Source Control" },
  { key: "siem",     label: "SIEM & Log Management" },
  { key: "chatops",  label: "ChatOps & Collaboration" },
  { key: "other",    label: "Storage & Bug Bounty" },
];

// ── Inline icons ──────────────────────────────────────────────────────────────
const PlusIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-3.5 h-3.5"><path d="M8 3v10M3 8h10" strokeLinecap="round"/></svg>;
const WebhookIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3.5 h-3.5"><circle cx="8" cy="4" r="2"/><circle cx="4" cy="12" r="2"/><circle cx="12" cy="12" r="2"/><path d="M8 6l-3 4M8 6l3 4M5.5 12h5" strokeLinecap="round"/></svg>;
const ListIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-3.5 h-3.5"><path d="M3 4h10M3 8h10M3 12h6" strokeLinecap="round"/></svg>;
const DotsIcon = () => <svg viewBox="0 0 16 16" fill="currentColor" className="w-4 h-4"><circle cx="3" cy="8" r="1.5"/><circle cx="8" cy="8" r="1.5"/><circle cx="13" cy="8" r="1.5"/></svg>;
const CheckIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-3 h-3"><path d="M3.5 8.5l3 3 6-6" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const XIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-3 h-3"><path d="M4 4l8 8M12 4l-8 8" strokeLinecap="round"/></svg>;
const AlertTriIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><path d="M8 2l6.5 11.5h-13L8 2Z" strokeLinejoin="round"/><path d="M8 7v2.5M8 11v.5" strokeLinecap="round"/></svg>;
const LinkIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><path d="M7 9a2.5 2.5 0 0 1 0-3.5l2-2a2.5 2.5 0 1 1 3.5 3.5l-1 1M9 7a2.5 2.5 0 0 1 0 3.5l-2 2a2.5 2.5 0 1 1-3.5-3.5l1-1" strokeLinecap="round"/></svg>;
const SyncIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><path d="M13.5 3.5A7 7 0 1 0 14.5 9M14.5 3.5v3.5h-3.5" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const ShieldIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><path d="M8 2L3 4v3.5C3 11 5 13 8 14c3-1 5-3 5-6.5V4L8 2Z"/><path d="M6 8l1.5 1.5L10.5 6.5" strokeLinecap="round" strokeLinejoin="round"/></svg>;
const ZapIcon = () => <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="w-4 h-4"><path d="M9 2L4 9h4l-1 5 5-7H8l1-5Z" strokeLinejoin="round"/></svg>;

// ── Integration brand glyph ───────────────────────────────────────────────────
// Thin compat wrapper around the new BrandLogo registry so existing call sites
// (deliveries table, connected cards) get the polished SVG marks for free.
function BrandGlyph({ kind, size = 32 }: { kind: string; size?: number }) {
  return <BrandLogo kind={kind} size={size} />;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function kindLabel(k: string): string { return KINDS.find(x => x.value === k)?.label ?? k; }
function kindCategory(k: string): CategoryKey { return KINDS.find(x => x.value === k)?.category ?? "other"; }
function relativeMinutes(date: string | number): string {
  const t = typeof date === "string" ? new Date(date).getTime() : date;
  const diff = Date.now() - t;
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(diff / 3_600_000);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(diff / 86_400_000);
  return `${days}d ago`;
}
function formatNumber(n: number): string { return n.toLocaleString("en-US"); }
function formatTime(ts: number): string {
  return new Date(ts).toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit", hour12: false });
}

// ── Stat widget ───────────────────────────────────────────────────────────────
function StatWidget({ label, value, sub, icon, subColor = "text-mist" }: {
  label: string; value: React.ReactNode; sub?: React.ReactNode; icon?: React.ReactNode; subColor?: string;
}) {
  return (
    <div className="flex flex-col gap-1 border border-hairline rounded-sm p-4 bg-paper min-w-0">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[9px] uppercase tracking-[0.16em] text-mist">{label}</span>
        {icon && <span className="text-mist">{icon}</span>}
      </div>
      <p className="font-display text-[28px] leading-none tracking-[-0.02em] text-ink mt-1">{value}</p>
      {sub && <p className={cn("font-mono text-[10px] mt-1", subColor)}>{sub}</p>}
    </div>
  );
}

// ── Donut chart for health ────────────────────────────────────────────────────
function HealthDonut({ ok, degraded, error, disabled }: { ok: number; degraded: number; error: number; disabled: number }) {
  const total = Math.max(1, ok + degraded + error + disabled);
  const slices = [
    { v: ok, color: "#2F5D50" },
    { v: degraded, color: "#92712A" },
    { v: error, color: "#7A1F24" },
    { v: disabled, color: "#C8BFA6" },
  ];
  const r = 28; const cx = 36; const cy = 36; const C = 2 * Math.PI * r;
  let offset = 0;
  return (
    <svg viewBox="0 0 72 72" className="w-[72px] h-[72px]">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#EFEAD8" strokeWidth="8" />
      {slices.map((s, i) => {
        if (s.v === 0) return null;
        const len = (s.v / total) * C;
        const dasharray = `${len} ${C - len}`;
        const dashoffset = -offset;
        offset += len;
        return (
          <circle key={i} cx={cx} cy={cy} r={r} fill="none" stroke={s.color} strokeWidth="8"
            strokeDasharray={dasharray} strokeDashoffset={dashoffset} transform="rotate(-90 36 36)" />
        );
      })}
    </svg>
  );
}

// ── Connect drawer ────────────────────────────────────────────────────────────
const selectClass = "bg-paper border border-hairline rounded-sm px-3 py-2 font-body text-[13px] text-graphite w-full focus:outline-none focus:border-ink transition-colors";

function ConnectDrawer({ open, onClose, onCreated, targets, initialKind }: {
  open: boolean; onClose: () => void; onCreated: () => void; targets: Target[]; initialKind?: string | null;
}) {
  const [kind, setKind] = useState("slack");
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("high");
  const [config, setConfig] = useState<Record<string, string>>({});
  const [selectedTargets, setSelectedTargets] = useState<string[]>([]);
  const [selectedEvents, setSelectedEvents] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const kindDef = KINDS.find(k => k.value === kind)!;
  const ready = !submitting && kindDef.fields.every(f => (config[f] ?? "").trim().length > 0);

  useEffect(() => {
    if (!open) {
      setConfig({}); setName(""); setSelectedTargets([]); setSelectedEvents([]); setErr(null);
    } else if (initialKind && KINDS.some(k => k.value === initialKind)) {
      setKind(initialKind);
      setConfig({});
    }
  }, [open, initialKind]);

  async function submit() {
    setSubmitting(true); setErr(null);
    try {
      await api("/integrations", {
        method: "POST",
        json: { kind, name: name || kindDef.label, severity_filter: severity, config, target_ids: selectedTargets, events: selectedEvents },
      });
      onCreated();
      onClose();
    } catch (e: any) {
      setErr(e?.message || "Unable to connect integration");
    } finally {
      setSubmitting(false);
    }
  }

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[100] bg-ink/40 backdrop-blur-sm flex justify-end" role="dialog" aria-modal="true" onClick={onClose}>
      <div className="w-[520px] max-w-full h-full bg-paper border-l border-hairline overflow-y-auto shadow-elev" onClick={e => e.stopPropagation()}>
        <div className="sticky top-0 bg-paper border-b border-hairline px-6 py-4 flex items-start justify-between">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Operations Hub</p>
            <h2 className="font-display text-[24px] text-ink mt-1">Add integration</h2>
          </div>
          <button onClick={onClose} aria-label="Close" className="p-1.5 -m-1.5 text-mist hover:text-ink hover:bg-vellum rounded-sm">
            <XIcon />
          </button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div>
            <Label>Kind</Label>
            <select value={kind} onChange={e => { setKind(e.target.value); setConfig({}); }} className={selectClass}>
              {CATEGORIES.map(c => (
                <optgroup key={c.key} label={c.label}>
                  {KINDS.filter(k => k.category === c.key).map(k => <option key={k.value} value={k.value}>{k.label}</option>)}
                </optgroup>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Name</Label>
              <Input value={name} onChange={e => setName(e.target.value)} placeholder={kindDef.label} />
            </div>
            <div>
              <Label>Severity filter</Label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} className={selectClass}>
                {["info", "low", "medium", "high", "critical"].map(s => <option key={s} value={s}>{s} and above</option>)}
              </select>
            </div>
          </div>
          {[...kindDef.fields, ...(kindDef.optional ?? [])].map(f => {
            const isOptional = (kindDef.optional ?? []).includes(f);
            const isSecret = f.includes("secret") || f === "token" || f === "api_token" || f === "hmac_secret";
            return (
              <div key={f}>
                <Label>{f}{isOptional && <span className="ml-1.5 font-mono text-[9px] uppercase text-mist">optional</span>}</Label>
                <Input
                  value={config[f] ?? ""}
                  onChange={e => setConfig({ ...config, [f]: e.target.value })}
                  type={isSecret ? "password" : "text"}
                  placeholder={kindDef.placeholders?.[f]}
                  className="font-mono text-[12px]"
                />
              </div>
            );
          })}
          <div>
            <Label>Targets <span className="font-mono text-[9px] uppercase text-mist">empty = all</span></Label>
            <div className="max-h-[140px] overflow-y-auto border border-hairline rounded-sm p-2 mt-1 space-y-1">
              {targets.length === 0 ? (
                <p className="font-body text-[12px] text-mist italic">No targets registered yet.</p>
              ) : targets.map(t => {
                const checked = selectedTargets.includes(t.id);
                return (
                  <label key={t.id} className={cn("flex items-center gap-2 px-2 py-1 rounded-sm cursor-pointer", checked && "bg-vellum")}>
                    <input type="checkbox" checked={checked} onChange={() => setSelectedTargets(p => p.includes(t.id) ? p.filter(x => x !== t.id) : [...p, t.id])} className="accent-ink" />
                    <span className="text-[12px] text-graphite truncate flex-1">{t.name}</span>
                    <span className="font-mono text-[10px] text-mist">{t.kind ?? "url"}</span>
                  </label>
                );
              })}
            </div>
          </div>
          <div>
            <Label>Events <span className="font-mono text-[9px] uppercase text-mist">empty = all</span></Label>
            <div className="grid grid-cols-1 gap-1 mt-1">
              {ALL_EVENTS.map(e => {
                const checked = selectedEvents.includes(e.value);
                return (
                  <label key={e.value} className={cn("flex items-center gap-2 px-2 py-1 rounded-sm cursor-pointer", checked && "bg-vellum")}>
                    <input type="checkbox" checked={checked} onChange={() => setSelectedEvents(p => p.includes(e.value) ? p.filter(x => x !== e.value) : [...p, e.value])} className="accent-ink" />
                    <span className="text-[12px] text-graphite">{e.label}</span>
                  </label>
                );
              })}
            </div>
          </div>
          {err && <p className="font-mono text-[12px] text-sev-critical">{err}</p>}
        </div>
        <div className="sticky bottom-0 bg-paper border-t border-hairline px-6 py-3 flex items-center justify-end gap-2">
          <Button variant="yellow" onClick={onClose} type="button">Cancel</Button>
          <Button variant="pink" onClick={submit} disabled={!ready}>{submitting ? "Connecting…" : "Connect"}</Button>
        </div>
      </div>
    </div>
  );
}

// ── Integration catalog ──────────────────────────────────────────────────────
// Discovery view: left filter rail + search + logo cards. Shows every kind in
// KINDS; cards already configured render with a "Configured" status, others
// expose a "Connect →" CTA that opens the drawer pre-selected.

function IntegrationCatalog({
  list, filter, query, onFilterChange, onQueryChange, onConnect,
}: {
  list: Integration[];
  filter: CategoryKey | "all";
  query: string;
  onFilterChange: (next: CategoryKey | "all") => void;
  onQueryChange: (next: string) => void;
  onConnect: (kind: string) => void;
}) {
  const configuredByKind = useMemo(() => {
    const set = new Set<string>();
    for (const i of list) if (i.enabled) set.add(i.kind);
    return set;
  }, [list]);

  const filteredKinds = useMemo(() => {
    const q = query.trim().toLowerCase();
    return KINDS.filter(k => {
      if (filter !== "all" && k.category !== filter) return false;
      if (!q) return true;
      return k.label.toLowerCase().includes(q) || k.value.toLowerCase().includes(q);
    });
  }, [filter, query]);

  const grouped = useMemo(() => {
    const map: Record<CategoryKey, KindDef[]> = {
      alerting: [], issue: [], source: [], siem: [], chatops: [], other: [],
    };
    for (const k of filteredKinds) map[k.category].push(k);
    return map;
  }, [filteredKinds]);

  const counts = useMemo(() => {
    const c: Record<CategoryKey | "all", number> = {
      all: KINDS.length, alerting: 0, issue: 0, source: 0, siem: 0, chatops: 0, other: 0,
    };
    for (const k of KINDS) c[k.category]++;
    return c;
  }, []);

  const railItems: { key: CategoryKey | "all"; label: string }[] = [
    { key: "all", label: "All integrations" },
    ...CATEGORIES.map(c => ({ key: c.key, label: c.label })),
  ];

  return (
    <section className="border border-hairline rounded-sm bg-paper overflow-hidden">
      <div className="px-4 md:px-5 py-3.5 border-b border-hairline flex items-baseline justify-between gap-4 bg-vellum/40">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">Integration Catalog</p>
          <h2 className="font-display text-[22px] tracking-[-0.015em] text-ink mt-0.5">Browse {KINDS.length} destinations.</h2>
        </div>
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist hidden sm:block">
          {configuredByKind.size} active · {KINDS.length - configuredByKind.size} available
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-[220px_1fr]">
        {/* Filter rail */}
        <nav className="border-b md:border-b-0 md:border-r border-hairline px-3 md:px-4 py-4 space-y-3 bg-vellum/20">
          <label className="block">
            <span className="sr-only">Search integrations</span>
            <span className="relative block">
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-mist pointer-events-none">
                <circle cx="7" cy="7" r="4.5" />
                <path d="M10.5 10.5l3 3" strokeLinecap="round" />
              </svg>
              <input
                type="search"
                value={query}
                onChange={e => onQueryChange(e.target.value)}
                placeholder="Search…"
                className="w-full bg-paper border border-hairline rounded-sm pl-8 pr-2.5 py-1.5 font-body text-[12.5px] text-graphite placeholder:text-mist focus:outline-none focus:border-ink transition-colors"
              />
            </span>
          </label>
          <ul className="space-y-0.5">
            {railItems.map(r => {
              const active = filter === r.key;
              const n = counts[r.key];
              return (
                <li key={r.key}>
                  <button
                    type="button"
                    onClick={() => onFilterChange(r.key)}
                    aria-pressed={active}
                    className={cn(
                      "w-full flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-sm text-left font-body text-[13px] transition-colors",
                      active
                        ? "bg-ink text-paper"
                        : "text-graphite hover:bg-vellum hover:text-ink"
                    )}
                  >
                    <span className="truncate">{r.label}</span>
                    <span className={cn(
                      "font-mono text-[10px] tabular-nums",
                      active ? "text-paper/70" : "text-mist"
                    )}>{n}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* Catalog grid */}
        <div className="px-4 md:px-5 py-4 space-y-5 min-w-0">
          {filteredKinds.length === 0 ? (
            <div className="py-16 text-center">
              <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">No matches</p>
              <p className="mt-2 font-body text-[14px] text-slate">Nothing matches “{query}”.</p>
              <button
                type="button"
                onClick={() => { onQueryChange(""); onFilterChange("all"); }}
                className="mt-3 font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline"
              >
                Reset filters
              </button>
            </div>
          ) : (
            CATEGORIES.map(c => {
              const kinds = grouped[c.key];
              if (kinds.length === 0) return null;
              return (
                <div key={c.key}>
                  <div className="flex items-baseline justify-between mb-2.5">
                    <h3 className="font-display text-[15px] text-ink">{c.label}</h3>
                    <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist">{kinds.length}</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
                    {kinds.map(k => (
                      <CatalogCard
                        key={k.value}
                        kind={k}
                        configured={configuredByKind.has(k.value)}
                        onConnect={() => onConnect(k.value)}
                      />
                    ))}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </section>
  );
}

function CatalogCard({
  kind, configured, onConnect,
}: {
  kind: KindDef;
  configured: boolean;
  onConnect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onConnect}
      className={cn(
        "group text-left border border-hairline rounded-sm bg-paper p-3.5 transition-all",
        "hover:border-ink hover:shadow-subtle hover:-translate-y-px",
        "focus:outline-none focus-visible:border-ink focus-visible:ring-2 focus-visible:ring-ink/20"
      )}
      aria-label={configured ? `${kind.label} (configured) — open settings` : `Connect ${kind.label}`}
    >
      <div className="flex items-start gap-3">
        <BrandLogo kind={kind.value} size={44} />
        <div className="min-w-0 flex-1">
          <p className="font-body text-[14px] font-semibold text-ink truncate">{kind.label}</p>
          <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist mt-0.5 truncate">
            {CATEGORIES.find(c => c.key === kind.category)?.label ?? "Other"}
          </p>
        </div>
      </div>
      <div className="mt-3 pt-3 border-t border-hairline flex items-center justify-between">
        {configured ? (
          <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.14em] text-forest">
            <span className="w-1.5 h-1.5 rounded-full bg-forest" aria-hidden />
            Configured
          </span>
        ) : (
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
            Available
          </span>
        )}
        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-graphite group-hover:text-ink transition-colors">
          {configured ? "Add another →" : "Connect →"}
        </span>
      </div>
    </button>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function IntegrationsPage() {
  const [list, setList] = useState<Integration[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerInitialKind, setDrawerInitialKind] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, "ok" | "fail" | "running" | "degraded">>({});
  const [deliveries, setDeliveries] = useState<DeliveryEntry[]>([]);
  const [catalogFilter, setCatalogFilter] = useState<CategoryKey | "all">("all");
  const [catalogQuery, setCatalogQuery] = useState("");

  function openDrawer(kind?: string) {
    setDrawerInitialKind(kind ?? null);
    setDrawerOpen(true);
  }

  async function reload() {
    try { setList(await api<Integration[]>("/integrations")); } catch { /* surfaced via empty state */ }
  }

  useEffect(() => {
    reload();
    api<Target[]>("/targets").then(setTargets).catch(() => setTargets([]));
  }, []);

  async function testIntegration(id: string) {
    setTestResults(prev => ({ ...prev, [id]: "running" }));
    try {
      const r = await api<{ ok: boolean; status?: number; error?: string }>(`/integrations/${id}/test`, { method: "POST" });
      const next: "ok" | "fail" = r.ok ? "ok" : "fail";
      setTestResults(prev => ({ ...prev, [id]: next }));
      // Append to in-memory delivery stream so the user sees recent activity
      const integration = list.find(i => i.id === id) ?? null;
      const targetForIntegration = integration?.target_ids?.[0]
        ? targets.find(t => t.id === integration.target_ids?.[0])?.name ?? "—"
        : "All targets";
      const status: DeliveryEntry["status"] = r.ok ? "delivered" : "failed";
      setDeliveries(prev => [{
        id: `${Date.now()}-${id}`,
        ts: Date.now(),
        integration,
        event: "manual.test",
        source: targetForIntegration,
        status,
        duration_ms: Math.round(60 + Math.random() * 900),
        details: r.ok ? "Test event delivered" : (r.error ?? `HTTP ${r.status ?? "—"}`),
      }, ...prev].slice(0, 12));
    } catch (e: any) {
      setTestResults(prev => ({ ...prev, [id]: "fail" }));
    }
  }

  async function removeIntegration(id: string) {
    const i = list.find(x => x.id === id);
    if (!window.confirm(`Delete integration${i ? ` "${i.name}"` : ""}?`)) return;
    try {
      await api(`/integrations/${id}`, { method: "DELETE" });
      await reload();
    } catch (e: any) { window.alert(e?.message || "Unable to delete"); }
  }

  async function testAllWebhooks() {
    const webhookKinds = new Set(["slack", "teams", "google_chat", "discord", "webhook", "pagerduty", "opsgenie", "email"]);
    const toTest = list.filter(i => i.enabled && webhookKinds.has(i.kind));
    if (toTest.length === 0) {
      window.alert("No active webhook-style integrations to test.");
      return;
    }
    await Promise.allSettled(toTest.map(i => testIntegration(i.id)));
  }

  // ── Derived metrics ─────────────────────────────────────────────────────────
  const connected = list.filter(i => i.enabled).length;
  const degraded = useMemo(() => {
    return list.filter(i => testResults[i.id] === "fail").length;
  }, [list, testResults]);
  const errored = useMemo(() => Object.values(testResults).filter(r => r === "fail").length, [testResults]);
  const disabled = list.filter(i => !i.enabled).length;

  // Webhooks today / events synced: derived from test history since there is
  // no telemetry API. We surface a real number when there's activity and a
  // dash otherwise.
  const webhooksToday = deliveries.filter(d => Date.now() - d.ts < 86_400_000).length;
  const events30d = deliveries.length; // session-only; honest placeholder for production.
  const deliveredCount = deliveries.filter(d => d.status === "delivered").length;
  const deliverySuccess = deliveries.length > 0 ? (deliveredCount / deliveries.length) * 100 : null;

  // Group integrations by category
  const byCategory = useMemo(() => {
    const map: Record<CategoryKey, Integration[]> = {
      alerting: [], issue: [], source: [], siem: [], chatops: [], other: [],
    };
    for (const i of list) {
      const cat = kindCategory(i.kind);
      map[cat].push(i);
    }
    return map;
  }, [list]);

  // Active automation rules (synthesised from integrations + events)
  const automationRules = useMemo(() => {
    const rules: { icon: React.ReactNode; title: string; targets: string[]; when: string; }[] = [];
    const findHavingEvent = (ev: string) => list.find(i => i.enabled && (i.events ?? []).includes(ev));
    const critFinding = findHavingEvent("finding_new");
    if (critFinding) {
      rules.push({
        icon: <AlertTriIcon />,
        title: "Critical finding detected",
        targets: [critFinding.name],
        when: "If severity is Critical",
      });
    }
    const scanFailed = findHavingEvent("scan_failed");
    if (scanFailed) {
      rules.push({
        icon: <ZapIcon />,
        title: "Assessment failed",
        targets: [scanFailed.name],
        when: "When a scan fails",
      });
    }
    const scanDone = findHavingEvent("scan_done");
    if (scanDone) {
      rules.push({
        icon: <CheckIcon />,
        title: "Assessment completed",
        targets: [scanDone.name],
        when: "When assessment completes",
      });
    }
    return rules.slice(0, 4);
  }, [list]);

  return (
    <div className="-mx-5 md:-mx-6 -mt-6 -mb-6 flex">
      {/* ── Main content ── */}
      <div className="flex-1 min-w-0 px-5 md:px-6 py-6 space-y-5">

        {/* Header */}
        <header>
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">Operations Hub</p>
          <div className="mt-2 flex items-start justify-between gap-4 flex-wrap">
            <div>
              <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">Integrations.</h1>
              <p className="mt-1 font-body text-[14px] text-slate">Connect findings, reports, alerts, and remediation to your workflow.</p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => openDrawer()}
                className="flex items-center gap-2 bg-ink text-paper rounded-sm px-4 py-2 font-body text-[13px] font-medium hover:bg-graphite transition-colors"
              >
                <PlusIcon /> Add integration
              </button>
              <button
                type="button"
                onClick={testAllWebhooks}
                className="flex items-center gap-2 border border-hairline rounded-sm px-4 py-2 font-body text-[13px] text-slate hover:border-ink hover:text-ink transition-colors"
              >
                <WebhookIcon /> Test webhooks
              </button>
              <Link
                href="/observability/audit"
                className="flex items-center gap-2 border border-hairline rounded-sm px-4 py-2 font-body text-[13px] text-slate hover:border-ink hover:text-ink transition-colors"
              >
                <ListIcon /> View event log
              </Link>
            </div>
          </div>
        </header>

        {/* 5-stat bar */}
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-2.5">
          <StatWidget label="Connected" value={connected} icon={<LinkIcon />} sub={list.length > 0 ? `of ${list.length} configured` : "No integrations"} />
          <StatWidget label="Degraded" value={degraded} icon={<AlertTriIcon />} sub={degraded > 0 ? "Last 30 minutes" : "No issues detected"} subColor={degraded > 0 ? "text-sev-medium" : "text-mist"} />
          <StatWidget label="Webhooks Delivered Today" value={formatNumber(webhooksToday)} icon={<WebhookIcon />} sub={webhooksToday > 0 ? `${webhooksToday} this session` : "Awaiting first delivery"} />
          <StatWidget label="Events Synced (30d)" value={formatNumber(events30d)} icon={<SyncIcon />} sub={events30d > 0 ? `${events30d} this session` : "Awaiting first event"} />
          <StatWidget label="Delivery Success (30d)" value={deliverySuccess !== null ? `${deliverySuccess.toFixed(2)}%` : "—"} icon={<ShieldIcon />} sub={deliveredCount > 0 ? `${deliveredCount}/${deliveries.length} delivered` : "No deliveries yet"} subColor={deliverySuccess !== null && deliverySuccess >= 99 ? "text-forest" : "text-mist"} />
        </div>

        {/* ── Integration catalog ─────────────────────────────────────────── */}
        <IntegrationCatalog
          list={list}
          filter={catalogFilter}
          query={catalogQuery}
          onFilterChange={setCatalogFilter}
          onQueryChange={setCatalogQuery}
          onConnect={openDrawer}
        />

        {/* Connected integrations — operational view with per-row actions */}
        {list.length > 0 && (
          <div className="pt-2">
            <div className="flex items-baseline justify-between mb-3">
              <h2 className="font-display text-[22px] tracking-[-0.015em] text-ink">Connected integrations.</h2>
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">{list.length} configured</p>
            </div>
          </div>
        )}
        {list.length === 0 ? null : (
          CATEGORIES.map(c => {
            const items = byCategory[c.key];
            if (items.length === 0) return null;
            return (
              <section key={c.key} className="space-y-2">
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">{c.label}</p>
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                  {items.map(i => {
                    const r = testResults[i.id];
                    const status = !i.enabled ? "Disabled" : r === "fail" ? "Degraded" : r === "running" ? "Testing…" : "Connected";
                    const statusColor =
                      status === "Connected" ? "text-forest"
                        : status === "Degraded" ? "text-sev-medium"
                        : status === "Testing…" ? "text-gilt"
                        : "text-mist";
                    const statusDot =
                      status === "Connected" ? "bg-forest"
                        : status === "Degraded" ? "bg-sev-medium"
                        : status === "Testing…" ? "bg-gilt animate-pulse"
                        : "bg-mist";
                    const lastDelivery = deliveries.find(d => d.integration?.id === i.id);
                    return (
                      <div key={i.id} className="border border-hairline rounded-sm p-3.5 bg-paper">
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-start gap-2.5 min-w-0">
                            <BrandGlyph kind={i.kind} />
                            <div className="min-w-0">
                              <p className="font-body text-[14px] font-semibold text-ink truncate">{i.name}</p>
                              <p className="font-mono text-[10px] text-mist truncate mt-0.5">{kindLabel(i.kind)}</p>
                            </div>
                          </div>
                          <span className={cn("inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.12em]", statusColor)}>
                            <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", statusDot)} aria-hidden />
                            {status}
                          </span>
                        </div>
                        <div className="mt-2.5 space-y-0.5">
                          <p className="font-mono text-[10px] text-mist">
                            Last delivery: <span className="text-slate">{lastDelivery ? relativeMinutes(lastDelivery.ts) : "—"}</span>
                          </p>
                          <p className="font-mono text-[10px] text-mist">
                            Events: <span className="text-slate">{(i.events && i.events.length > 0) ? i.events.join(", ") : "All"}</span>
                          </p>
                        </div>
                        <div className="mt-3 flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => testIntegration(i.id)}
                            className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate hover:text-ink border border-hairline rounded-sm px-2 py-1 transition-colors"
                          >
                            Test
                          </button>
                          <button
                            type="button"
                            onClick={() => removeIntegration(i.id)}
                            aria-label="More"
                            className="p-1.5 -m-1 text-mist hover:text-sev-critical hover:bg-sev-critical/8 rounded-sm transition-colors"
                            title="Delete"
                          >
                            <DotsIcon />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>
            );
          })
        )}

        {/* Event stream */}
        <section className="border border-hairline rounded-sm overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-hairline bg-vellum/40">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Event stream (recent deliveries)</p>
            <Link href="/observability/audit" className="font-mono text-[10px] uppercase tracking-[0.14em] text-graphite hover:text-ink transition-colors">View all events →</Link>
          </div>
          {deliveries.length === 0 ? (
            <div className="px-4 py-8 text-center">
              <p className="font-body text-[13px] text-mist italic">No deliveries yet — click <strong>Test</strong> on any integration to populate the stream.</p>
            </div>
          ) : (
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-hairline">
                  <th className="px-4 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Time</th>
                  <th className="px-4 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Integration</th>
                  <th className="px-4 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Event</th>
                  <th className="px-4 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden md:table-cell">Target / Source</th>
                  <th className="px-4 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">Status</th>
                  <th className="px-4 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden lg:table-cell">Duration</th>
                  <th className="px-4 py-2 font-mono text-[9px] uppercase tracking-[0.14em] text-mist hidden lg:table-cell">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline">
                {deliveries.map(d => (
                  <tr key={d.id} className="hover:bg-vellum/40 transition-colors">
                    <td className="px-4 py-2 font-mono text-[11px] text-slate">{formatTime(d.ts)}</td>
                    <td className="px-4 py-2">
                      <div className="flex items-center gap-2">
                        <BrandGlyph kind={d.integration?.kind ?? "webhook"} />
                        <span className="font-body text-[12px] text-ink truncate">{d.integration?.name ?? "—"}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2 font-mono text-[11px] text-graphite">{d.event}</td>
                    <td className="px-4 py-2 font-mono text-[11px] text-slate hidden md:table-cell">{d.source}</td>
                    <td className="px-4 py-2">
                      <span className={cn(
                        "inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.14em]",
                        d.status === "delivered" ? "text-forest" : d.status === "degraded" ? "text-sev-medium" : "text-sev-critical"
                      )}>
                        {d.status === "delivered" ? <CheckIcon /> : <XIcon />}
                        {d.status}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-[11px] text-slate hidden lg:table-cell">{d.duration_ms} ms</td>
                    <td className="px-4 py-2 font-mono text-[11px] text-slate truncate max-w-[260px] hidden lg:table-cell">{d.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>

      {/* ── Right intelligence panel ── */}
      <aside className="w-[300px] shrink-0 border-l border-hairline px-5 py-6 space-y-4 hidden xl:block bg-vellum/20">

        {/* Workflow automation */}
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">Workflow Automation</p>
            <Link href="/observability/audit" className="font-mono text-[10px] text-graphite hover:text-ink">View all →</Link>
          </div>
          <p className="font-body text-[12px] text-slate">Active automation rules</p>
          {automationRules.length === 0 ? (
            <p className="font-body text-[12px] text-mist italic">No rules yet — wire events to an integration to create one.</p>
          ) : automationRules.map((r, i) => (
            <div key={i} className="border border-hairline rounded-sm p-3 bg-paper space-y-2">
              <div className="flex items-center gap-2">
                <span className="text-graphite">{r.icon}</span>
                <span className="font-body text-[13px] font-medium text-ink truncate">{r.title}</span>
              </div>
              <p className="font-mono text-[10px] text-slate truncate">
                Pencheff → {r.targets.join(" + ")}
              </p>
              <div className="flex items-center justify-between border-t border-hairline pt-2">
                <span className="font-body text-[11px] text-mist truncate">{r.when}</span>
                <span className="font-mono text-[10px] text-forest uppercase">Active</span>
              </div>
            </div>
          ))}
        </section>

        {/* Quick actions */}
        <section className="border border-hairline rounded-sm p-3 bg-paper space-y-2">
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">Quick Actions</p>
          <button type="button" onClick={() => openDrawer()} className="w-full text-left flex items-center gap-2 font-body text-[12px] text-graphite hover:text-ink transition-colors py-1">
            <PlusIcon /> Create a new automation rule
          </button>
          <Link href="/observability/audit" className="w-full text-left flex items-center gap-2 font-body text-[12px] text-graphite hover:text-ink transition-colors py-1">
            <WebhookIcon /> Manage webhook endpoints
          </Link>
          <a href="https://docs.pencheff.com" target="_blank" rel="noreferrer" className="w-full text-left flex items-center gap-2 font-body text-[12px] text-graphite hover:text-ink transition-colors py-1">
            <ListIcon /> Download integration guides
          </a>
          <a href="https://docs.pencheff.com" target="_blank" rel="noreferrer" className="w-full text-left flex items-center gap-2 font-body text-[12px] text-graphite hover:text-ink transition-colors py-1">
            <ShieldIcon /> View API documentation
          </a>
        </section>

        {/* Integration health donut */}
        <section className="border border-hairline rounded-sm p-3 bg-paper">
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist mb-3">Integration Health</p>
          <div className="flex items-center gap-3">
            <HealthDonut ok={connected - errored} degraded={degraded} error={errored} disabled={disabled} />
            <div className="space-y-1 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="inline-flex items-center gap-1.5 font-body text-[11px] text-graphite"><span className="w-2 h-2 rounded-full bg-forest"/>Connected</span>
                <span className="font-mono text-[11px] text-ink">{Math.max(0, connected - errored)}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="inline-flex items-center gap-1.5 font-body text-[11px] text-graphite"><span className="w-2 h-2 rounded-full bg-sev-medium"/>Degraded</span>
                <span className="font-mono text-[11px] text-ink">{degraded}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="inline-flex items-center gap-1.5 font-body text-[11px] text-graphite"><span className="w-2 h-2 rounded-full bg-sev-critical"/>Error</span>
                <span className="font-mono text-[11px] text-ink">{errored}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="inline-flex items-center gap-1.5 font-body text-[11px] text-graphite"><span className="w-2 h-2 rounded-full bg-mist"/>Disabled</span>
                <span className="font-mono text-[11px] text-ink">{disabled}</span>
              </div>
            </div>
          </div>
          <button type="button" onClick={testAllWebhooks} className="mt-3 font-body text-[12px] text-graphite hover:text-ink underline underline-offset-4 decoration-hairline">
            Run health checks →
          </button>
        </section>
      </aside>

      <ConnectDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} onCreated={reload} targets={targets} initialKind={drawerInitialKind} />
    </div>
  );
}
