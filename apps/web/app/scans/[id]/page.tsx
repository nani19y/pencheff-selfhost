"use client";

import Link from "next/link";
import { GradingExplainer } from "@/components/grading-explainer";
import { FixAllAgentButton } from "@/components/fix-all-agent-button";
import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { Badge, Button, GradeBadge, SeverityPill } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { PriorityStrip } from "@/components/priority-badges";
import { Markdown } from "@/components/markdown";
import { api, ApiError, downloadFile, streamUrl } from "@/lib/api";

type ConsentPayload = {
  version: number;
  acknowledged: boolean;
  // May be absent on partial/legacy consent payloads — never assume present.
  authorization_text?: string;
  disclosed_actions: string[];
  consent_given_at: string | null;
  consent_given_by_user_id: string | null;
};

type Scan = {
  id: string;
  target_id: string;
  status: string;
  progress_pct: number;
  current_stage: string | null;
  grade: string | null;
  score: number | null;
  // ``summary`` is a JSONB blob; severity counts live at the top level
  // and ``summary.swarm`` carries swarm-telemetry fields persisted by
  // services/agent_swarm/telemetry.persist_swarm_telemetry.
  summary:
    | (Record<string, number | string> & {
        swarm?: {
          used_fallback?: boolean;
          used_fallback_reason?: string | null;
          breakers?: Array<{
            agent: string;
            success: boolean;
            findings: number;
            turns: number;
            tool_calls: number;
            error: string | null;
          }>;
        } | null;
        // Delta vs the target's previous completed scan — populated by the runner
        // on a target's 2nd+ scan. Absent/null on a first scan.
        previous_comparison?: {
          previous_scan_id: string;
          previous_grade: string | null;
          previous_score: number | null;
          previous_created_at: string | null;
          counts: { new: number; fixed: number; persisted: number };
        } | null;
      })
    | null;
  log: string[] | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
  consent_payload?: ConsentPayload | null;
  has_threat_model?: boolean;
  target_kind?: "url" | "repo" | "llm" | null;
};

type Finding = {
  id: string;
  title: string;
  severity: string;
  category: string;
  owasp_category: string | null;
  endpoint: string | null;
  parameter: string | null;
  cvss_score: number | null;
  verification_status: string;
  // AI-agent exploitability verdict: true = verified exploitable ("hackable"),
  // false = verified false-positive, null = undetermined.
  hackable: boolean | null;
  suppressed: boolean;
  // Phase 1.3 + 2.5 — prioritisation surface
  risk_score: number | null;
  ssvc_decision: string | null;
  reachability: string | null;
  epss: number | null;
  kev: boolean;
};

type Report = {
  id: string;
  format: string;
  status: string;
  download_url: string | null;
  generated_at: string | null;
};

type LinkedRepo = {
  repository_id: string;
  full_name: string;
  provider: string | null;
  scan_url: string;
};

const STATUS_LABEL: Record<string, string> = {
  queued: "Queued",
  running: "In progress",
  done: "Complete",
  failed: "Failed",
};

const FILTERS = ["all", "critical", "high", "medium", "low", "info"] as const;

const FILTER_LABEL: Record<(typeof FILTERS)[number], string> = {
  all: "All",
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Informational",
};

const SEV_BAR: Record<string, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const VERIF_COPY: Record<string, string> = {
  unverified: "Unverified",
  true_positive: "Verified",
  false_positive: "False positive",
  fixed: "Fixed",
};

function shortId(id: string) {
  return id.slice(0, 8).toUpperCase();
}

export default function ScanDetailPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const id = mounted ? pathSegment(pathname, 2) : "";
  const router = useRouter();
  const [scan, setScan] = useState<Scan | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(
    new Set(),
  );
  // Set when the /findings fetch itself fails — so a fetch error surfaces on
  // screen instead of silently rendering an empty register (which looks
  // identical to "no findings").
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [reports, setReports] = useState<Report[]>([]);
  const [linkedRepos, setLinkedRepos] = useState<LinkedRepo[]>([]);
  // The target this assessment ran against — fetched so the header shows
  // which asset was assessed (name + URL/path), not just the report id.
  const [target, setTarget] = useState<{
    name: string;
    base_url: string;
    kind?: string;
  } | null>(null);
  const [filter, setFilter] = useState<string>("all");
  // Findings flagged false-positive by automated triage are hidden by
  // default. Toggle this on to surface them for manual review.
  const [showFalsePositives, setShowFalsePositives] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const esRef = useRef<EventSource | null>(null);

  async function deleteScan() {
    if (
      !window.confirm(
        "Delete this assessment?\n\nFindings, evidence, and generated reports will be removed. This action cannot be undone.",
      )
    ) {
      return;
    }
    try {
      await api(`/scans/${id}`, { method: "DELETE" });
      router.push("/dashboard");
    } catch (e: any) {
      alert(e?.message || "Unable to delete assessment.");
    }
  }

  useEffect(() => {
    if (!id) return;
    let alive = true;
    async function load() {
      try {
        const s = await api<Scan>(`/scans/${id}`);
        if (!alive) return;
        setScan(s);
        // Resolve the target so the header can show which asset was assessed.
        if (s.target_id) {
          api<{ name: string; base_url: string; kind?: string }>(
            `/targets/${s.target_id}`,
          )
            .then((t) => {
              if (alive) setTarget(t);
            })
            .catch(() => {
              /* target may be deleted — header falls back to id */
            });
        }
        // Hydrate the log tail from the persisted record so a page refresh
        // mid-scan doesn't lose the history.
        if (Array.isArray(s.log) && s.log.length > 0) {
          setLog(s.log.slice(-60));
        }
        if (s.status === "done" || s.status === "failed") {
          // Isolated: a findings-fetch error must NOT fall through to the outer
          // 404/not-found handler and must NOT silently leave an empty register.
          try {
            const f = await api<Finding[]>(
              `/findings?scan_id=${id}&include_suppressed=${showFalsePositives}`,
            );
            if (alive) {
              setFindings(f);
              setFindingsError(null);
            }
          } catch (fe) {
            if (alive)
              setFindingsError(
                fe instanceof ApiError
                  ? `Couldn't load findings (HTTP ${fe.status}).`
                  : String((fe as Error)?.message ?? fe),
              );
          }
        }
        // Reports are non-critical — isolate so a reports 404 can't mis-route the
        // whole page to "not found".
        try {
          const r = await api<Report[]>(`/scans/${id}/reports`);
          if (alive) setReports(r);
        } catch {
          /* reports unavailable — keep the scan + findings visible */
        }
        // Linked repos — when the URL target has attached repos, the
        // scan no longer mixes SAST findings inline. Show a link card
        // pointing the user to the repo's own assessment page.
        try {
          const lr = await api<LinkedRepo[]>(`/scans/${id}/linked-repos`);
          if (alive) setLinkedRepos(lr);
        } catch {
          /* endpoint may 404 on older deployments — silently skip */
        }
      } catch (e) {
        if (!alive) return;
        // /scans/{id} is the DAST route. Repo scans live at /repos/scans/{id};
        // a 404 here is usually a repo scan reached via a non-repo-aware link
        // (dashboard, search, target page, notifications, …). Self-correct by
        // redirecting to the repo route when that scan exists, instead of
        // spinning on "Loading assessment…" forever.
        if (e instanceof ApiError && e.status === 404) {
          try {
            await api(`/repos/scans/${id}`);
            if (alive) router.replace(`/repos/scans/${id}`);
            return;
          } catch {
            /* not a repo scan either — fall through to not-found */
          }
          if (alive) setNotFound(true);
        }
      }
    }
    load();
    return () => {
      alive = false;
    };
  }, [id, showFalsePositives]);

  // Polling safety net: if SSE drops (bad network, auth blip, proxy buffer)
  // the status can otherwise stay stuck at "queued". Poll /scans/{id} every
  // 5s while the scan is in flight, then stop once it's done/failed.
  useEffect(() => {
    if (!scan) return;
    if (scan.status !== "queued" && scan.status !== "running") return;

    let cancelled = false;
    const tick = async () => {
      try {
        const s = await api<Scan>(`/scans/${id}`);
        if (cancelled) return;
        setScan((prev) => (prev ? { ...prev, ...s } : s));
        // Mirror the persisted log into local state so the Assessment log
        // section ticks live on deployments where the SSE stream is
        // buffered by an upstream proxy (Next.js rewrites, CDN). SSE is
        // still preferred when it works; this is the always-on safety net.
        if (Array.isArray(s.log) && s.log.length > 0) {
          setLog(s.log.slice(-60));
        }
        if (s.status === "done" || s.status === "failed") {
          const f = await api<Finding[]>(
            `/findings?scan_id=${id}&include_suppressed=${showFalsePositives}`,
          );
          if (!cancelled) setFindings(f);
        }
      } catch {}
    };
    const handle = window.setInterval(tick, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, [scan?.status, id, showFalsePositives]);

  useEffect(() => {
    if (!scan) return;
    if (scan.status !== "queued" && scan.status !== "running") return;

    let es: EventSource | null = null;
    let cancelled = false;

    streamUrl(`/scans/${id}/stream`).then((url) => {
      if (cancelled) return;
      es = new EventSource(url);
      esRef.current = es;

      es.addEventListener("snapshot", (e: MessageEvent) => {
        try {
          const d = JSON.parse(e.data);
          setScan((prev) => (prev ? { ...prev, ...d } : prev));
        } catch {}
      });

      es.addEventListener("update", (e: MessageEvent) => {
        try {
          const d = JSON.parse(e.data);
          setLog((prev) => [
            ...prev.slice(-30),
            `${d.type}: ${d.label || d.stage || ""}`,
          ]);
          if (d.type === "stage_done" || d.type === "stage_start") {
            setScan((prev) =>
              prev
                ? {
                    ...prev,
                    progress_pct: d.pct ?? prev.progress_pct,
                    current_stage: d.label || prev.current_stage,
                    status: "running",
                  }
                : prev,
            );
          }
          if (d.type === "finished") {
            setScan((prev) =>
              prev
                ? {
                    ...prev,
                    status: "done",
                    grade: d.grade,
                    score: d.score,
                    summary: d.summary,
                    progress_pct: 100,
                    finished_at: new Date().toISOString(),
                  }
                : prev,
            );
            api<Finding[]>(
              `/findings?scan_id=${id}&include_suppressed=${showFalsePositives}`,
            )
              .then(setFindings)
              .catch(() => {});
            es?.close();
          }
          if (d.type === "failed") {
            setScan((prev) =>
              prev ? { ...prev, status: "failed", error: d.error } : prev,
            );
            es?.close();
          }
        } catch {}
      });

      es.onerror = () => {};
    });

    return () => {
      cancelled = true;
      es?.close();
    };
  }, [scan?.status, id]);

  const filtered = useMemo(() => {
    if (filter === "all") return findings;
    return findings.filter((f) => f.severity === filter);
  }, [findings, filter]);
  const openFindingIds = useMemo(
    () => findings.filter((f) => !f.suppressed).map((f) => f.id),
    [findings],
  );
  function toggleFindingGroup(rows: Finding[]) {
    const ids = rows.filter((row) => !row.suppressed).map((row) => row.id);
    setSelectedFindingIds((prev) => {
      const next = new Set(prev);
      const shouldSelect = ids.some((findingId) => !next.has(findingId));
      for (const findingId of ids) {
        if (shouldSelect) next.add(findingId);
        else next.delete(findingId);
      }
      return next;
    });
  }
  function toggleFinding(findingId: string) {
    setSelectedFindingIds((prev) => {
      const next = new Set(prev);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  }

  // Same-title findings across multiple endpoints usually represent ONE
  // underlying issue (e.g. "HSTS Not Configured" on every subdomain).
  // Collapse them into a single row by default so the dashboard reflects
  // the unique-issue count, not the per-endpoint replica count.
  const SEV_RANK: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  const grouped = useMemo(() => {
    const buckets = new Map<string, Finding[]>();
    for (const f of filtered) {
      const key = `${f.category}|${f.title}`;
      const arr = buckets.get(key) ?? [];
      arr.push(f);
      buckets.set(key, arr);
    }
    return Array.from(buckets.values()).map((rows) => {
      // Pick the row with the highest severity as the representative;
      // tiebreak by highest CVSS so the most exploitable one fronts.
      const rep = rows.slice().sort((a, b) => {
        const sev =
          (SEV_RANK[(b.severity || "info").toLowerCase()] || 0) -
          (SEV_RANK[(a.severity || "info").toLowerCase()] || 0);
        if (sev !== 0) return sev;
        return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
      })[0];
      const allSuppressed = rows.every((r) => r.suppressed);
      const endpoints = Array.from(
        new Set(rows.map((r) => r.endpoint || "").filter(Boolean)),
      );
      return { rep, rows, allSuppressed, endpoints };
    });
  }, [filtered]);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  function toggleGroup(key: string) {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  async function generate(fmt: "docx" | "pdf" | "csv" | "json") {
    const r = await api<Report>(`/scans/${id}/reports`, {
      method: "POST",
      json: { format: fmt },
    });
    setReports((prev) => [r, ...prev]);
    const poll = setInterval(async () => {
      try {
        const updated = await api<Report>(`/reports/${r.id}`);
        setReports((prev) => prev.map((x) => (x.id === r.id ? updated : x)));
        if (updated.status === "ready" || updated.status === "failed") {
          clearInterval(poll);
          if (updated.status === "ready" && updated.download_url) {
            try {
              await downloadFile(
                updated.download_url,
                `pencheff-report-${id.slice(0, 8)}.${updated.format}`,
              );
            } catch (e) {
              console.error("report download failed", e);
            }
          }
        }
      } catch {
        clearInterval(poll);
      }
    }, 2000);
  }

  if (notFound) {
    return (
      <div className="py-16 text-center">
        <p className="font-display text-[24px] text-ink">
          Assessment not found
        </p>
        <p className="mt-2 text-[13px] text-slate">
          This assessment may have been deleted, or the link points to the wrong
          scan type.
        </p>
        <Link href="/scans" className="inline-block mt-6">
          <Button variant="lime">← Assessments</Button>
        </Link>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="py-6">
        <InlineLoading label="Loading assessment…" />
      </div>
    );
  }

  const running = scan.status === "queued" || scan.status === "running";
  // Load-test scans carry a load_report and none of the security chrome
  // (findings, threat model, compliance, formal report) applies to them.
  const isLoad = !!(scan.summary as Record<string, unknown> | null)
    ?.load_report;
  const statusLabel = STATUS_LABEL[scan.status] || scan.status;
  const statusDot =
    scan.status === "done"
      ? "bg-forest"
      : scan.status === "failed"
        ? "bg-oxblood"
        : "bg-gilt";

  return (
    <div className="space-y-6">
      {/* --- Header ------------------------------------------------- */}
      <header className="flex items-start justify-between flex-wrap gap-6">
        <div>
          <p className="eyebrow-gilt">{isLoad ? "Load test" : "Assessment"}</p>
          {target ? (
            <>
              <h1 className="mt-4 font-display text-[36px] md:text-[42px] leading-[1.05] tracking-[-0.015em] text-ink">
                {target.name}
              </h1>
              <p className="mt-2 font-mono text-[12px] text-slate break-all">
                {target.base_url}
                <span className="text-mist">
                  {" "}
                  · Report № {shortId(scan.id)}
                </span>
              </p>
            </>
          ) : (
            <>
              <h1 className="mt-4 font-display text-[36px] md:text-[42px] leading-[1.05] tracking-[-0.015em] text-ink">
                Report № {shortId(scan.id)}
              </h1>
              <p className="mt-2 font-mono text-[12px] text-mist break-all">
                {scan.id}
              </p>
            </>
          )}
        </div>
        <div className="flex items-center gap-2">
          {scan.target_id && (
            <Link href={`/targets/${scan.target_id}`}>
              <Button variant="yellow">← {target?.name ?? "Target"}</Button>
            </Link>
          )}
          <Link href="/dashboard">
            <Button variant="lime">← Dashboard</Button>
          </Link>
          <Button variant="danger" onClick={deleteScan}>
            Delete
          </Button>
        </div>
      </header>

      {/* --- Summary card ------------------------------------------ */}
      <section className="formal-surface-elev p-8 md:p-10">
        <div className="grid md:grid-cols-[auto_1fr] gap-10 items-center">
          <GradeBadge
            grade={scan.grade || (scan.status === "done" ? "—" : "?")}
            size="lg"
          />

          <div>
            <div className="flex items-center gap-3">
              <span
                className={`inline-block w-1.5 h-1.5 rounded-full ${statusDot}`}
                aria-hidden
              />
              <span className="eyebrow">Status</span>
            </div>
            <h2 className="mt-2 font-display text-[28px] text-ink tracking-[-0.01em]">
              {statusLabel}
              {running && scan.current_stage && (
                <span className="text-slate font-body text-[15px] font-normal tracking-normal">
                  {" "}
                  — {scan.current_stage}
                </span>
              )}
            </h2>

            {running && (
              <div className="mt-6">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-[11px] text-mist tracking-[0.08em]">
                    Progress
                  </span>
                  <span className="font-mono text-[12px] text-graphite">
                    {scan.progress_pct}%
                  </span>
                </div>
                <div className="h-[2px] bg-hairline relative overflow-hidden rounded-full">
                  <div
                    className="absolute inset-y-0 left-0 bg-gilt transition-[width] duration-500 ease-out"
                    style={{ width: `${scan.progress_pct}%` }}
                  />
                </div>
              </div>
            )}

            {scan.summary &&
              !(scan.summary as Record<string, unknown>).load_report && (
                <dl className="mt-6 flex flex-wrap gap-x-8 gap-y-3">
                  {(["critical", "high", "medium", "low", "info"] as const).map(
                    (sev) => (
                      <div key={sev} className="flex items-center gap-2">
                        <SeverityPill severity={sev} />
                        <span className="font-mono text-[13px] text-graphite">
                          {scan.summary?.[sev] ?? 0}
                        </span>
                      </div>
                    ),
                  )}
                </dl>
              )}

            {(scan.summary as Record<string, unknown> | null)?.load_report ? (
              <LoadReportCard
                report={
                  (scan.summary as Record<string, unknown>)
                    .load_report as LoadReportShape
                }
              />
            ) : null}

            {scan.status === "done" && scan.summary?.previous_comparison && (
              <div className="mt-6 border border-hairline bg-vellum/40 px-4 py-3">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <p className="eyebrow-gilt text-[10px]">
                    Changes since last scan
                  </p>
                  {scan.summary.previous_comparison.previous_created_at && (
                    <span className="font-mono text-[11px] text-mist">
                      vs{" "}
                      {new Date(
                        scan.summary.previous_comparison.previous_created_at,
                      ).toLocaleDateString()}
                      {scan.summary.previous_comparison.previous_grade
                        ? ` · grade ${scan.summary.previous_comparison.previous_grade}`
                        : ""}
                    </span>
                  )}
                </div>
                <dl className="mt-3 flex flex-wrap gap-x-8 gap-y-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[11px] uppercase tracking-[0.1em] text-rust">
                      New
                    </span>
                    <span className="font-mono text-[13px] text-graphite">
                      {scan.summary.previous_comparison.counts.new}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[11px] uppercase tracking-[0.1em] text-forest">
                      Fixed
                    </span>
                    <span className="font-mono text-[13px] text-graphite">
                      {scan.summary.previous_comparison.counts.fixed}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[11px] uppercase tracking-[0.1em] text-mist">
                      Persisted
                    </span>
                    <span className="font-mono text-[13px] text-graphite">
                      {scan.summary.previous_comparison.counts.persisted}
                    </span>
                  </div>
                </dl>
                <Link
                  href={`/scans/compare?a=${scan.summary.previous_comparison.previous_scan_id}&b=${scan.id}`}
                  className="mt-3 inline-block font-mono text-[12px] text-rust underline underline-offset-4 hover:text-ink"
                >
                  View full comparison →
                </Link>
              </div>
            )}

            {scan.error && (
              <div className="mt-6 advisory-warn font-mono text-[12px] whitespace-pre-wrap">
                {scan.error}
              </div>
            )}

            {scan.summary?.swarm?.used_fallback && (
              <div className="mt-6 advisory-warn font-body text-[12px]">
                <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-rust">
                  Engine degraded
                </span>
                <span className="ml-3 text-graphite">
                  AI swarm could not run to completion
                  {scan.summary.swarm.used_fallback_reason
                    ? ` (${scan.summary.swarm.used_fallback_reason})`
                    : ""}
                  . Findings come from the deterministic engage pipeline only —
                  the grade may understate the target's true risk.
                </span>
              </div>
            )}
          </div>
        </div>

        {scan.status === "done" && !isLoad && (
          <div className="mt-8 border-t border-hairline pt-6">
            <p className="eyebrow-gilt mb-3 text-[10px]">Visual dashboard</p>
            <p className="mb-3 font-mono text-[12px] text-mist">
              Severity donut, CVSS histogram, OWASP coverage, top-risk list, and
              affected-endpoint treemap — the same data as below, charted for
              at-a-glance review.
            </p>
            <Link
              href={`/scans/${scan.id}/dashboard`}
              className="inline-block border border-graphite px-4 py-2 font-mono text-[12px] uppercase tracking-[0.08em] hover:bg-graphite hover:text-white"
            >
              View dashboard →
            </Link>
          </div>
        )}

        {scan.has_threat_model && !isLoad && (
          <div className="mt-8 border-t border-hairline pt-6">
            <p className="eyebrow-gilt mb-3 text-[10px]">Threat model</p>
            <p className="mb-3 font-mono text-[12px] text-mist">
              STRIDE / DREAD model attached to this scan — view the prioritised
              threats and module-priority bias the dispatcher used.
            </p>
            <Link
              href={`/scans/${scan.id}/threat-model`}
              className="inline-block border border-graphite px-4 py-2 font-mono text-[12px] uppercase tracking-[0.08em] hover:bg-graphite hover:text-white"
            >
              View threat model →
            </Link>
          </div>
        )}

        {scan.status === "done" && !isLoad && (
          <div className="mt-8 border-t border-hairline pt-6">
            <p className="eyebrow-gilt mb-3 text-[10px]">Compliance mapping</p>
            <p className="mb-3 font-mono text-[12px] text-mist">
              Every active finding fanned out across the frameworks that match
              this target&apos;s asset class — OWASP, PCI-DSS, NIST, SOC 2, ISO
              27001, HIPAA for URL targets; OWASP LLM Top 10, MITRE ATLAS, NIST
              AI RMF, EU AI Act, GDPR, ISO/IEC 42001:2023 for LLM endpoints.
            </p>
            <Link
              href={`/scans/${scan.id}/compliance`}
              className="inline-block border border-graphite px-4 py-2 font-mono text-[12px] uppercase tracking-[0.08em] hover:bg-graphite hover:text-white"
            >
              View compliance mapping →
            </Link>
          </div>
        )}

        {scan.status === "done" && scan.target_kind === "llm" && !isLoad && (
          <div className="mt-8 border-t border-hairline pt-6">
            <p className="eyebrow-gilt mb-3 text-[10px]">
              Recommended guardrails
            </p>
            <p className="mb-3 font-mono text-[12px] text-mist">
              Pencheff inspects this scan&apos;s OWASP-LLM-Top-10 failure
              breakdown and recommends an input + output Sentry guardrail
              configuration for this target. Even a clean scan surfaces the safe
              baseline; a one-click apply writes the recommended toggles onto
              the target&apos;s guardrails.
            </p>
            <Link
              href={`/scans/${scan.id}/recommended-guardrails`}
              className="inline-block border border-graphite px-4 py-2 font-mono text-[12px] uppercase tracking-[0.08em] hover:bg-graphite hover:text-white"
            >
              View recommended guardrails →
            </Link>
          </div>
        )}

        {typeof scan.summary?.executive_summary === "string" &&
          scan.summary.executive_summary.length > 0 && (
            <div className="mt-8 border-t border-hairline pt-6">
              <p className="eyebrow-gilt mb-3 text-[10px]">Executive summary</p>
              <Markdown>{scan.summary.executive_summary}</Markdown>
            </div>
          )}

        {/* TODO(post-batch-B): render scan.consent_payload in scan-detail UI
            for audit visibility. The consent_payload field is now fetched with
            the scan but only shown when a non-sentinel authorization_text is
            present. A dedicated "Authorization on file" section below the
            executive summary would surface the verbatim authorization text,
            timestamp, and disclosed action list for customer-facing audits. */}
        {scan.consent_payload?.authorization_text &&
          !scan.consent_payload.authorization_text.startsWith(
            "PRE_CONSENT_SCAN:",
          ) && (
            <div className="mt-8 border-t border-hairline pt-6">
              <p className="eyebrow-gilt mb-3 text-[10px]">
                Authorization on file
              </p>
              <p className="text-[13px] leading-[1.7] text-graphite max-w-[72ch] italic">
                {scan.consent_payload.authorization_text}
              </p>
              {scan.consent_payload.consent_given_at && (
                <p className="mt-2 font-mono text-[11px] text-mist">
                  Consented at:{" "}
                  {scan.consent_payload.consent_given_at
                    .replace("T", " · ")
                    .slice(0, 22)}{" "}
                  UTC
                </p>
              )}
            </div>
          )}
      </section>

      {/* --- Grading methodology --------------------------------- */}
      {!isLoad && <GradingExplainer />}

      {/* --- Live log -------------------------------------------- */}
      {log.length > 0 && (
        <section>
          <div className="flex items-baseline justify-between mb-3">
            <p className="eyebrow">
              {isLoad ? "Load-test log" : "Assessment log"}
            </p>
            <span className="font-mono text-[11px] text-mist">
              {running ? "Streaming" : "Archived"} · {log.length} entries
            </span>
          </div>
          <div className="formal-surface p-6 max-h-[260px] overflow-auto">
            <ul className="space-y-1 font-mono text-[12px] text-slate">
              {log.map((line, i) => (
                <li key={i}>
                  <span className="text-mist">› </span>
                  {line}
                </li>
              ))}
            </ul>
          </div>
        </section>
      )}

      {/* --- Report generation (also for load tests) ------------- */}
      {scan.status === "done" && (
        <section>
          <div className="flex items-baseline justify-between mb-4">
            <div>
              <p className="eyebrow-gilt">Deliverables</p>
              <h2 className="mt-2 font-display text-[24px] text-ink">
                {isLoad ? "Load-test report" : "Formal report"}
              </h2>
            </div>
          </div>

          <div className="formal-surface p-8">
            <p className="text-[14px] text-slate mb-5 max-w-[62ch]">
              Issue a formal report in the format required by your audience —
              engineers, auditors, or executives.
            </p>
            <div className="segmented">
              <button type="button" onClick={() => generate("docx")}>
                DOCX
              </button>
              <button type="button" onClick={() => generate("pdf")}>
                PDF
              </button>
              <button type="button" onClick={() => generate("csv")}>
                CSV
              </button>
              <button type="button" onClick={() => generate("json")}>
                JSON
              </button>
            </div>

            {!isLoad && linkedRepos.length > 0 && (
              <div className="mt-8 border-t border-hairline pt-6">
                <p className="eyebrow mb-3">Linked repositories</p>
                <p className="text-[12px] text-slate mb-3">
                  Source-code findings from the repos attached to this target
                  live on the repo's own assessment page — not mixed into this
                  scan. Open any repo to see its CodeQL · Semgrep · OSV ·
                  secret-scan results.
                </p>
                <ul className="divide-y divide-hairline">
                  {linkedRepos.map((r) => (
                    <li
                      key={r.repository_id}
                      className="flex items-center gap-4 py-3 font-body text-[13px]"
                    >
                      <span className="inline-flex items-center gap-1 border border-hairline rounded-sm px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.14em] text-slate">
                        {r.provider || "repo"}
                      </span>
                      <span className="font-bold text-ink truncate">
                        {r.full_name}
                      </span>
                      <span className="flex-1" />
                      <Link
                        href={r.scan_url}
                        className="text-[12px] underline underline-offset-4 text-ink hover:opacity-70"
                      >
                        Open assessment →
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {reports.length > 0 && (
              <div className="mt-8 border-t border-hairline pt-6">
                <p className="eyebrow mb-3">Issued reports</p>
                <ul className="divide-y divide-hairline">
                  {reports.map((r) => (
                    <li
                      key={r.id}
                      className="flex items-center gap-4 py-3 font-body text-[13px]"
                    >
                      <span className="inline-flex items-center gap-1 border border-hairline rounded-sm px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.14em] text-slate">
                        {r.format}
                      </span>
                      <span className="text-slate capitalize">{r.status}</span>
                      {r.generated_at && (
                        <span className="font-mono text-[11px] text-mist">
                          {r.generated_at.slice(0, 19).replace("T", " · ")}
                        </span>
                      )}
                      <span className="flex-1" />
                      {r.status === "ready" && r.download_url && (
                        <button
                          type="button"
                          onClick={() =>
                            downloadFile(
                              r.download_url!,
                              `pencheff-report-${id.slice(0, 8)}.${r.format}`,
                            ).catch((e) => console.error(e))
                          }
                          className="text-ink underline underline-offset-[6px] decoration-gilt decoration-1 cursor-pointer"
                        >
                          Download
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </section>
      )}

      {/* --- Findings (not applicable to load tests) ------------- */}
      {!isLoad && (
        <section>
          <div className="flex items-end justify-between flex-wrap gap-4 mb-6">
            <div>
              <p className="eyebrow-gilt">Findings register</p>
              <h2 className="mt-2 font-display text-[28px] text-ink tracking-[-0.01em]">
                Findings
              </h2>
            </div>
            <div className="flex items-center gap-4 flex-wrap min-w-0 max-w-full">
              <label className="inline-flex items-center gap-2 font-mono text-[12px] text-mist cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={showFalsePositives}
                  onChange={(e) => setShowFalsePositives(e.target.checked)}
                  className="accent-gilt"
                />
                <span>Show false positives</span>
              </label>
              <div className="segmented">
                {FILTERS.map((s) => (
                  <button
                    key={s}
                    type="button"
                    data-active={filter === s}
                    onClick={() => setFilter(s)}
                  >
                    {FILTER_LABEL[s]}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {scan.status === "done" && findings.length > 0 && (
            <div className="mb-6 flex flex-col gap-3">
              <div className="flex flex-wrap items-center gap-3 font-mono text-[12px] text-slate">
                <span>{selectedFindingIds.size} selected for remediation</span>
                <button
                  type="button"
                  onClick={() => setSelectedFindingIds(new Set(openFindingIds))}
                  className="underline underline-offset-4 hover:text-ink"
                >
                  Select all open findings ({openFindingIds.length})
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedFindingIds(new Set())}
                  className="underline underline-offset-4 hover:text-ink"
                >
                  Clear selection
                </button>
              </div>
              <FixAllAgentButton
                scope="scan"
                id={id}
                linkedRepos={linkedRepos}
                allowNoRepo={target?.base_url?.startsWith("upload://") ?? false}
                selectedFindingIds={[...selectedFindingIds]}
              />
            </div>
          )}

          {filtered.length === 0 ? (
            <div className="formal-surface p-10 text-center">
              {findingsError ? (
                <>
                  <p className="eyebrow-gilt">Couldn’t load findings</p>
                  <h3 className="mt-4 font-display text-[24px] text-ink">
                    {findingsError}
                  </h3>
                  <p className="mt-2 text-[13px] text-slate">
                    The findings for this scan were saved, but the browser
                    couldn’t fetch them. Reload the page; if it persists, check
                    you’re in the workspace that owns this scan.
                  </p>
                  <button
                    type="button"
                    onClick={() => {
                      setFindingsError(null);
                      api<Finding[]>(
                        `/findings?scan_id=${id}&include_suppressed=${showFalsePositives}`,
                      )
                        .then(setFindings)
                        .catch((fe) =>
                          setFindingsError(
                            fe instanceof ApiError
                              ? `Couldn't load findings (HTTP ${fe.status}).`
                              : String((fe as Error)?.message ?? fe),
                          ),
                        );
                    }}
                    className="mt-4 inline-flex items-center border border-ink rounded-sm px-3 py-1.5 font-mono text-[12px] uppercase tracking-[0.14em] text-ink hover:bg-ink hover:text-paper"
                  >
                    Retry
                  </button>
                </>
              ) : scan.status === "done" ? (
                <>
                  <p className="eyebrow-gilt">Clean</p>
                  <h3 className="mt-4 font-display text-[24px] text-ink">
                    No findings at this filter.
                  </h3>
                  <p className="mt-2 text-[13px] text-slate">
                    The assessment recorded nothing requiring attention at this
                    severity.
                    {!showFalsePositives && (
                      <>
                        {" "}
                        Toggle <em>Show false positives</em> above to surface
                        anything that was suppressed during automated triage.
                      </>
                    )}
                  </p>
                </>
              ) : (
                <p className="text-[14px] text-slate italic">
                  No findings recorded yet — the assessment is still in
                  progress.
                </p>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto border border-hairline rounded-md bg-paper">
              <table className="brutal-table">
                <thead>
                  <tr>
                    <th aria-label="Select findings for remediation" />
                    <th style={{ width: 180 }}>Severity</th>
                    <th>Finding</th>
                    <th style={{ width: 220 }}>Priority</th>
                    <th>Endpoint</th>
                    <th>Parameter</th>
                    <th className="text-right">CVSS</th>
                    <th>Status</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {grouped.map(({ rep: f, rows, allSuppressed, endpoints }) => {
                    const sev = (f.severity || "info").toLowerCase();
                    const bar = SEV_BAR[sev] || SEV_BAR.info;
                    const groupKey = `${f.category}|${f.title}`;
                    const isExpanded = expandedGroups.has(groupKey);
                    const groupSize = rows.length;
                    const selectableIds = rows
                      .filter((row) => !row.suppressed)
                      .map((row) => row.id);
                    const selectedInGroup = selectableIds.filter((findingId) =>
                      selectedFindingIds.has(findingId),
                    ).length;
                    return (
                      <Fragment key={groupKey}>
                        <tr className="group relative">
                          <td className="text-center">
                            <input
                              type="checkbox"
                              aria-label={`Select ${f.title} for remediation`}
                              checked={
                                selectableIds.length > 0 &&
                                selectedInGroup === selectableIds.length
                              }
                              ref={(node) => {
                                if (node) {
                                  node.indeterminate =
                                    selectedInGroup > 0 &&
                                    selectedInGroup < selectableIds.length;
                                }
                              }}
                              disabled={selectableIds.length === 0}
                              onChange={() => toggleFindingGroup(rows)}
                              className="accent-gilt"
                            />
                          </td>
                          <td className="relative">
                            <span
                              className={`absolute left-0 top-2 bottom-2 w-[3px] rounded-[1px] ${bar}`}
                              aria-hidden
                            />
                            <span className="pl-3 block">
                              <SeverityPill severity={f.severity} />
                            </span>
                          </td>
                          <td>
                            <span className="font-body text-[14px] font-medium text-ink">
                              {f.title}
                              {f.owasp_category ? (
                                <span className="font-mono text-[12px] text-slate ml-1">
                                  ({f.owasp_category})
                                </span>
                              ) : null}
                              {groupSize > 1 ? (
                                <button
                                  type="button"
                                  onClick={() => toggleGroup(groupKey)}
                                  className="ml-2 inline-flex items-center border border-hairline hover:border-ink rounded-sm px-2 py-0.5 font-mono text-[11px] text-slate transition-colors"
                                  aria-expanded={isExpanded}
                                  aria-label={`${
                                    isExpanded ? "Collapse" : "Expand"
                                  } ${groupSize} affected endpoints`}
                                >
                                  {isExpanded ? "▾" : "▸"} Affects{" "}
                                  {endpoints.length || groupSize} endpoint
                                  {endpoints.length === 1 ? "" : "s"}
                                </button>
                              ) : null}
                            </span>
                          </td>
                          <td>
                            <PriorityStrip
                              riskScore={f.risk_score}
                              reachability={f.reachability}
                              ssvc={f.ssvc_decision}
                              epss={f.epss}
                              kev={f.kev}
                            />
                          </td>
                          <td className="font-mono text-[12px] text-slate break-all max-w-[260px]">
                            {groupSize > 1
                              ? endpoints[0] || f.endpoint || "—"
                              : f.endpoint || "—"}
                          </td>
                          <td className="font-mono text-[12px] text-slate">
                            {f.parameter || "—"}
                          </td>
                          <td className="text-right font-mono text-[13px] text-graphite">
                            {f.cvss_score?.toFixed(1) || "—"}
                          </td>
                          <td>
                            <span className="inline-flex items-center gap-2 flex-wrap">
                              <span className="inline-flex items-center border border-hairline rounded-sm px-2 py-0.5 font-body text-[11px] font-medium uppercase tracking-[0.16em] text-slate">
                                {VERIF_COPY[f.verification_status] ||
                                  f.verification_status}
                              </span>
                              {f.hackable === true && (
                                <span
                                  title="AI agent verified this finding is exploitable"
                                  className="inline-flex items-center border border-oxblood rounded-sm px-2 py-0.5 font-body text-[11px] font-semibold uppercase tracking-[0.16em] text-paper bg-oxblood"
                                >
                                  Hackable
                                </span>
                              )}
                              {f.hackable === false && (
                                <span
                                  title="AI agent verified this finding is not exploitable"
                                  className="inline-flex items-center border border-hairline rounded-sm px-2 py-0.5 font-body text-[11px] font-medium uppercase tracking-[0.16em] text-mist"
                                >
                                  Not exploitable
                                </span>
                              )}
                              {allSuppressed && (
                                <span className="inline-flex items-center border border-ink rounded-sm px-2 py-0.5 font-body text-[11px] font-medium uppercase tracking-[0.16em] text-paper bg-ink">
                                  Suppressed
                                </span>
                              )}
                            </span>
                          </td>
                          <td className="text-right">
                            <Link href={`/scans/${id}/findings/${f.id}`}>
                              <Button
                                variant="lime"
                                className="text-[12px] px-3 py-1.5"
                              >
                                Review
                              </Button>
                            </Link>
                          </td>
                        </tr>
                        {isExpanded && groupSize > 1
                          ? rows.map((row) => (
                              <tr
                                key={`${groupKey}:${row.id}`}
                                className="bg-vellum/40"
                              >
                                <td className="text-center">
                                  <input
                                    type="checkbox"
                                    aria-label={`Select ${row.title} at ${row.endpoint || "this endpoint"} for remediation`}
                                    checked={selectedFindingIds.has(row.id)}
                                    disabled={row.suppressed}
                                    onChange={() => toggleFinding(row.id)}
                                    className="accent-gilt"
                                  />
                                </td>
                                <td />
                                <td colSpan={3}>
                                  <span className="pl-6 inline-flex items-center gap-3 font-mono text-[12px] text-slate">
                                    <span className="text-mist">↳</span>
                                    <span className="break-all">
                                      {row.endpoint || "—"}
                                    </span>
                                    {row.parameter ? (
                                      <span className="text-mist">
                                        [{row.parameter}]
                                      </span>
                                    ) : null}
                                  </span>
                                </td>
                                <td />
                                <td className="text-right font-mono text-[12px] text-slate">
                                  {row.cvss_score?.toFixed(1) || "—"}
                                </td>
                                <td>
                                  {row.suppressed ? (
                                    <span className="inline-flex items-center border border-ink rounded-sm px-2 py-0.5 font-body text-[11px] uppercase tracking-[0.16em] text-paper bg-ink">
                                      Suppressed
                                    </span>
                                  ) : (
                                    <span className="font-mono text-[11px] text-mist">
                                      Active
                                    </span>
                                  )}
                                </td>
                                <td className="text-right">
                                  <Link
                                    href={`/scans/${id}/findings/${row.id}`}
                                  >
                                    <Button
                                      variant="lime"
                                      className="text-[11px] px-2 py-1"
                                    >
                                      Review
                                    </Button>
                                  </Link>
                                </td>
                              </tr>
                            ))
                          : null}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
}

// ── Load-test report (profile="load") ──────────────────────────────────────

type LoadReportShape = {
  kind: string;
  ok: boolean;
  error?: string | null;
  duration_s: number;
  total_requests: number;
  error_count: number;
  error_rate: number;
  rps: number;
  latency_ms: Record<string, number>;
  by_target?: Array<{
    target: string;
    requests: number;
    errors: number;
    p95_ms: number;
  }>;
  extra?: Record<string, unknown>;
  stages?: Array<{
    vus: number;
    rps: number;
    p95_ms: number;
    error_rate: number;
    load_error_rate?: number;
    sla_hold?: boolean;
  }>;
  breaking_point?: {
    vus?: number;
    error_rate?: number;
    load_error_rate?: number;
    p95_ms?: number;
  } | null;
  threshold_results?: Array<{
    metric: string;
    limit: number;
    actual: number;
    pass: boolean;
  }>;
  agent_narrative?: string;
  cost_cents?: number;
};

function LoadStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="border border-hairline bg-vellum/40 px-3 py-2">
      <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
        {label}
      </p>
      <p className="mt-0.5 font-mono text-[16px] text-ink">{value}</p>
    </div>
  );
}

function LoadReportCard({ report }: { report: LoadReportShape }) {
  if (!report.ok) {
    return (
      <div className="mt-6 border border-hairline bg-vellum/40 px-4 py-3">
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-slate">
          Load test · {report.kind}
        </p>
        <p className="mt-1 font-body text-[13px] text-graphite">
          Not run: {report.error}
        </p>
      </div>
    );
  }
  const lat = report.latency_ms || {};
  const latKeys = Object.keys(lat).filter((k) => k !== "max");
  const extraTop = (report.extra || {}) as Record<string, unknown>;
  const loadEr =
    typeof extraTop.load_error_rate === "number"
      ? extraTop.load_error_rate
      : null;
  const statusBuckets =
    extraTop.status_buckets && typeof extraTop.status_buckets === "object"
      ? (extraTop.status_buckets as Record<string, number>)
      : null;
  return (
    <div className="mt-6 space-y-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-slate">
        Load test · {report.kind}
      </p>
      {report.stages?.length ? (
        report.breaking_point ? (
          <div className="border border-oxblood/40 bg-oxblood/5 px-4 py-3 font-body text-[13px] text-graphite">
            <strong className="text-oxblood">Breaking point:</strong> ~
            {report.breaking_point.vus} VUs
            {report.breaking_point.p95_ms
              ? ` · p95 ${report.breaking_point.p95_ms}ms`
              : ""}
            {report.breaking_point.load_error_rate != null
              ? ` · load errors ${(report.breaking_point.load_error_rate * 100).toFixed(1)}%`
              : report.breaking_point.error_rate != null
                ? ` · errors ${(report.breaking_point.error_rate * 100).toFixed(1)}%`
                : ""}
          </div>
        ) : (
          <div className="border border-forest/30 bg-forest/5 px-4 py-3 font-body text-[13px] text-forest">
            Held SLA through the full ladder — no breaking point up to{" "}
            {report.stages.at(-1)?.vus} VUs.
          </div>
        )
      ) : null}
      {report.agent_narrative ? (
        <p className="whitespace-pre-wrap font-body text-[13px] text-graphite">
          {report.agent_narrative}
        </p>
      ) : null}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <LoadStat label="Requests" value={report.total_requests} />
        <LoadStat label="Throughput" value={`${report.rps} rps`} />
        {loadEr != null ? (
          <LoadStat
            label="Load errors"
            value={`${(loadEr * 100).toFixed(1)}%`}
          />
        ) : null}
        <LoadStat
          label={loadEr != null ? "Non-2xx" : "Error rate"}
          value={`${(report.error_rate * 100).toFixed(1)}%`}
        />
        <LoadStat label="Duration" value={`${report.duration_s}s`} />
        {latKeys.map((k) => (
          <LoadStat key={k} label={k} value={`${lat[k]}ms`} />
        ))}
      </div>
      {statusBuckets && Object.values(statusBuckets).some((v) => v) ? (
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
            Status
          </span>
          {(
            [
              ["2xx", "lime"],
              ["3xx", "cyan"],
              ["4xx", "yellow"],
              ["429", "pink"],
              ["5xx", "danger"],
              ["err", "danger"],
            ] as const
          )
            .filter(([k]) => statusBuckets[k])
            .map(([k, variant]) => (
              <Badge key={k} variant={variant}>
                {k === "err" ? "timeout" : k}: {statusBuckets[k]}
              </Badge>
            ))}
        </div>
      ) : null}
      {report.by_target && report.by_target.length > 0 && (
        <div className="overflow-x-auto border border-hairline">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="border-b border-hairline bg-vellum/40 text-left font-mono text-[10px] uppercase tracking-[0.12em] text-mist">
                <th className="px-3 py-2">Endpoint</th>
                <th className="px-3 py-2">Requests</th>
                <th className="px-3 py-2">Errors</th>
                <th className="px-3 py-2">p95</th>
              </tr>
            </thead>
            <tbody>
              {report.by_target.map((t) => (
                <tr key={t.target} className="border-b border-hairline">
                  <td className="px-3 py-2 font-mono text-graphite break-all">
                    {t.target}
                  </td>
                  <td className="px-3 py-2 font-mono text-graphite">
                    {t.requests}
                  </td>
                  <td className="px-3 py-2 font-mono text-graphite">
                    {t.errors}
                  </td>
                  <td className="px-3 py-2 font-mono text-graphite">
                    {t.p95_ms}ms
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {report.stages && report.stages.length > 0 && (
        <div className="overflow-x-auto border border-hairline">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="border-b border-hairline bg-vellum/40 text-left font-mono text-[10px] uppercase tracking-[0.12em] text-mist">
                <th className="px-3 py-2">VUs</th>
                <th className="px-3 py-2">RPS</th>
                <th className="px-3 py-2">p95</th>
                <th className="px-3 py-2">Errors</th>
                <th className="px-3 py-2">SLA</th>
              </tr>
            </thead>
            <tbody>
              {report.stages.map((s, i) => (
                <tr key={i} className="border-b border-hairline">
                  <td className="px-3 py-2 font-mono text-graphite">{s.vus}</td>
                  <td className="px-3 py-2 font-mono text-graphite">
                    {s.rps?.toFixed(1)}
                  </td>
                  <td className="px-3 py-2 font-mono text-graphite">
                    {s.p95_ms}ms
                  </td>
                  <td className="px-3 py-2 font-mono text-graphite">
                    {(s.error_rate * 100).toFixed(1)}%
                  </td>
                  <td className="px-3 py-2 font-mono text-graphite">
                    {s.sla_hold ? "✓" : "✕"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {report.threshold_results && report.threshold_results.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {report.threshold_results.map((t, i) => {
            const isRate = t.metric.includes("rate");
            const label =
              t.metric === "p95_ms"
                ? "p95"
                : t.metric === "error_rate"
                  ? "error rate"
                  : t.metric;
            const fmt = (v: number) =>
              isRate ? `${(v * 100).toFixed(1)}%` : `${Math.round(v)}ms`;
            return (
              <Badge key={i} variant={t.pass ? "lime" : "danger"}>
                {label} {fmt(t.actual)} / SLA {fmt(t.limit)}{" "}
                {t.pass ? "✓" : "✕"}
              </Badge>
            );
          })}
        </div>
      )}
      {(() => {
        const extra = (report.extra || {}) as Record<string, unknown>;
        const personas = Array.isArray(extra.personas)
          ? (extra.personas as unknown[]).map(String)
          : [];
        const agentFindings = Array.isArray(extra.findings)
          ? (extra.findings as Array<Record<string, unknown>>)
          : [];
        const rest = Object.entries(extra).filter(
          ([k]) =>
            ![
              "personas",
              "findings",
              "status_buckets",
              "load_error_rate",
              "endpoints_tested",
              "endpoints_discovered",
            ].includes(k),
        );
        const cost = report.cost_cents ?? 0;
        const epTested =
          typeof extra.endpoints_tested === "number"
            ? extra.endpoints_tested
            : null;
        const epDiscovered =
          typeof extra.endpoints_discovered === "number"
            ? extra.endpoints_discovered
            : null;
        const hasMeta =
          personas.length > 0 ||
          cost > 0 ||
          epTested != null ||
          typeof extra.profile_shape === "string";
        return (
          <>
            {hasMeta && (
              <dl className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-[11px] text-slate">
                {typeof extra.profile_shape === "string" && (
                  <div>
                    <span className="text-mist">profile:</span>{" "}
                    {extra.profile_shape}
                  </div>
                )}
                {personas.length > 0 && (
                  <div>
                    <span className="text-mist">personas:</span>{" "}
                    {personas.join(", ")}
                  </div>
                )}
                {epTested != null && epDiscovered != null && (
                  <div>
                    <span className="text-mist">endpoints tested:</span>{" "}
                    {epTested}/{epDiscovered} (2xx under auth)
                  </div>
                )}
                {cost > 0 && (
                  <div>
                    <span className="text-mist">agent cost:</span> $
                    {(cost / 100).toFixed(2)}
                  </div>
                )}
              </dl>
            )}
            {agentFindings.length > 0 && (
              <div className="space-y-2">
                <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
                  Agent findings
                </p>
                <ul className="space-y-1.5">
                  {agentFindings.map((f, i) => (
                    <li key={i} className="font-body text-[13px] text-graphite">
                      <span className="font-mono text-[11px] uppercase text-slate">
                        {String(f.severity ?? "note")}
                      </span>{" "}
                      <strong>{String(f.title ?? "")}</strong>
                      {f.detail ? <> — {String(f.detail)}</> : null}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {rest.length > 0 && (
              <dl className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-[11px] text-slate">
                {rest.map(([k, v]) => (
                  <div key={k}>
                    <span className="text-mist">{k}:</span>{" "}
                    {typeof v === "object" ? JSON.stringify(v) : String(v)}
                  </div>
                ))}
              </dl>
            )}
          </>
        );
      })()}
    </div>
  );
}
