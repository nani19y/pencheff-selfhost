"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Button, GradeBadge, Input } from "@/components/brutal";
import { CommissionScanModal } from "@/components/commission-scan-modal";
import type { SupportedKind } from "@/components/register-target/target-types";
import { LoadMetricCell } from "@/components/load-metric-cell";
import { PageLoading } from "@/components/loading";
import { Paginator } from "@/components/paginator";
import { api } from "@/lib/api";
import { mapRepoScanToScan, type RepoScanRow } from "@/lib/repo-scans";
import { StatCard } from "@/components/app/stat-card";
import {
  IntelPanel,
  IntelRow,
  IntelDivider,
} from "@/components/app/intel-panel";

type Target = {
  id: string;
  name: string;
  base_url: string;
  has_credentials: boolean;
  kind?: SupportedKind;
  repository_id?: string | null;
  // Non-secret per-kind config (audio_probes, source_type, dynamic_invocation…).
  // The commission modal needs it to disclose kind-specific actions (e.g. voice
  // ⇒ voice_audio_probe), else the backend rejects the consent payload.
  kind_config?: Record<string, unknown> | null;
};
// Wire kind → short display label for the KIND column. Falls back to the raw
// kind (underscores → spaces, upper-cased) so a new kind is never mislabelled
// as "URL".
const KIND_LABEL: Record<string, string> = {
  url: "URL",
  repo: "REPO",
  llm: "LLM",
  host: "HOST",
  web_app: "WEB",
  rest_api: "REST API",
  graphql: "GRAPHQL",
  websocket: "WEBSOCKET",
  grpc: "GRPC",
  cloud_account: "CLOUD",
  serverless_function: "SERVERLESS",
  cloud_storage: "STORAGE",
  load_balancer_cdn: "LB / CDN",
  cloud_database: "DATABASE",
  secrets_manager: "SECRETS",
  k8s_cluster: "K8S",
  container_image: "CONTAINER",
  package_registry: "PACKAGES",
  iac: "IAC",
  sbom: "SBOM",
  cicd_pipeline: "CI/CD",
  source_code: "SOURCE",
  android_app: "ANDROID",
  ios_app: "IOS",
  browser_extension: "EXTENSION",
  desktop_app: "DESKTOP",
  firmware: "FIRMWARE",
  iot_device: "IOT",
  ot_ics_scada: "OT/ICS",
  ml_model: "ML MODEL",
  mcp: "MCP",
  agent: "AGENT",
  rag: "RAG",
  voice: "VOICE",
  memory: "MEMORY",
};
function kindLabel(k?: string): string {
  if (!k) return "URL";
  return KIND_LABEL[k] ?? k.replace(/_/g, " ").toUpperCase();
}
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

// Merge DAST scans with normalised repo (SAST) scans, newest first, so both
// kinds appear in the dashboard's recent-assessments list.
function mergeScans(
  dast: Scan[],
  repos: RepoScanRow[],
  targets: Array<{ id: string; repository_id?: string | null }>,
): Scan[] {
  const mapped = repos.map(
    (r) => mapRepoScanToScan(r, targets) as unknown as Scan,
  );
  return [...dast, ...mapped].sort(
    (a, b) =>
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  );
}

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEV_LABEL: Record<(typeof SEV_ORDER)[number], string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info.",
};
const SEV_COLOR: Record<(typeof SEV_ORDER)[number], string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const STATUS_LABEL: Record<string, string> = {
  queued: "Queued",
  running: "In progress",
  done: "Complete",
  failed: "Failed",
};

const TARGETS_PAGE_SIZE = 6;
const SCANS_PAGE_SIZE = 20;

function shortId(id: string) {
  return id.slice(0, 8).toUpperCase();
}

function formatDate(iso: string | null) {
  if (!iso) return "—";
  return iso.replace("T", " · ").slice(0, 22);
}

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

export default function DashboardPage() {
  const router = useRouter();
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [targetQuery, setTargetQuery] = useState("");
  const [targetPage, setTargetPage] = useState(1);
  const [scanQuery, setScanQuery] = useState("");
  const [scanPage, setScanPage] = useState(1);
  const [commissionFor, setCommissionFor] = useState<{
    id: string;
    name: string;
    kind?: SupportedKind;
    repository_id?: string | null;
    kind_config?: Record<string, unknown> | null;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      api<Target[]>("/targets").catch(() => [] as Target[]),
      api<Scan[]>("/scans").catch(() => [] as Scan[]),
      // Repository (SAST) scans live on a separate endpoint — merge them in
      // so repo assessments show in "Recent Assessments" alongside DAST scans.
      api<RepoScanRow[]>("/repos/scans").catch(() => [] as RepoScanRow[]),
    ])
      .then(([t, s, rs]) => {
        if (cancelled) return;
        setTargets(t);
        setScans(mergeScans(s, rs, t));
      })
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const inflight = scans.some(
      (s) => s.status === "queued" || s.status === "running",
    );
    if (!inflight) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const [next, rs] = await Promise.all([
          api<Scan[]>("/scans"),
          api<RepoScanRow[]>("/repos/scans").catch(() => [] as RepoScanRow[]),
        ]);
        if (!cancelled) setScans(mergeScans(next, rs, targets));
      } catch {}
    };
    const handle = window.setInterval(tick, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, [scans, targets]);

  const filteredTargets = useMemo(() => {
    const q = targetQuery.trim().toLowerCase();
    if (!q) return targets;
    return targets.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        t.base_url.toLowerCase().includes(q) ||
        (t.kind ?? "url").toLowerCase().includes(q),
    );
  }, [targets, targetQuery]);

  const targetPageCount = Math.max(
    1,
    Math.ceil(filteredTargets.length / TARGETS_PAGE_SIZE),
  );
  const safeTargetPage = Math.min(targetPage, targetPageCount);
  const visibleTargets = filteredTargets.slice(
    (safeTargetPage - 1) * TARGETS_PAGE_SIZE,
    safeTargetPage * TARGETS_PAGE_SIZE,
  );

  useEffect(() => {
    if (targetPage > targetPageCount) setTargetPage(1);
  }, [targetPageCount, targetPage]);

  const filteredScans = useMemo(() => {
    const q = scanQuery.trim().toLowerCase();
    if (!q) return scans;
    return scans.filter((s) => {
      const target = targets.find((t) => t.id === s.target_id);
      return (
        shortId(s.id).toLowerCase().includes(q) ||
        s.id.toLowerCase().includes(q) ||
        s.status.toLowerCase().includes(q) ||
        (s.grade ?? "").toLowerCase().includes(q) ||
        (target?.name ?? "").toLowerCase().includes(q)
      );
    });
  }, [scans, scanQuery, targets]);

  const scanPageCount = Math.max(
    1,
    Math.ceil(filteredScans.length / SCANS_PAGE_SIZE),
  );
  const safeScanPage = Math.min(scanPage, scanPageCount);
  const visibleScans = filteredScans.slice(
    (safeScanPage - 1) * SCANS_PAGE_SIZE,
    safeScanPage * SCANS_PAGE_SIZE,
  );

  useEffect(() => {
    if (scanPage > scanPageCount) setScanPage(1);
  }, [scanPageCount, scanPage]);

  function commissionScan(target: Target) {
    const isRepo = Boolean(target.repository_id);
    setCommissionFor({
      id: target.id,
      name: target.name,
      kind: isRepo ? "repo" : target.kind,
      repository_id: target.repository_id ?? null,
      kind_config: target.kind_config ?? null,
    });
  }

  async function deleteTarget(t: Target) {
    if (
      !window.confirm(
        `Delete target "${t.name}"?\n\nThis will also remove every assessment and finding recorded against it. This action cannot be undone.`,
      )
    )
      return;
    try {
      await api(`/targets/${t.id}`, { method: "DELETE" });
      setTargets((prev) => prev.filter((x) => x.id !== t.id));
      setScans((prev) => prev.filter((x) => x.target_id !== t.id));
    } catch (e: any) {
      alert(e?.message || "Unable to delete target.");
    }
  }

  async function deleteRepoTarget(t: Target) {
    if (
      !window.confirm(
        `Delete repository "${t.name}"?\n\nThis will also remove every scan and finding recorded against it. This action cannot be undone.`,
      )
    )
      return;
    if (!t.repository_id) {
      alert("Repository id missing on target row.");
      return;
    }
    try {
      await api(`/repos/${t.repository_id}`, { method: "DELETE" });
      setTargets((prev) => prev.filter((x) => x.id !== t.id));
      setScans((prev) => prev.filter((x) => x.target_id !== t.id));
    } catch (e: any) {
      alert(e?.message || "Unable to delete repository.");
    }
  }

  async function deleteScan(scanId: string) {
    if (
      !window.confirm(
        "Delete this assessment?\n\nFindings, evidence, and generated reports will be removed. This action cannot be undone.",
      )
    )
      return;
    try {
      await api(`/scans/${scanId}`, { method: "DELETE" });
      setScans((prev) => prev.filter((x) => x.id !== scanId));
    } catch (e: any) {
      alert(e?.message || "Unable to delete assessment.");
    }
  }

  // ── Derived stats ──
  const activeScans = scans.filter(
    (s) => s.status === "running" || s.status === "queued",
  ).length;
  const completedScans = scans.filter((s) => s.status === "done").length;

  const totalFindings = useMemo(
    () => ({
      critical: scans.reduce(
        (sum, s) => sum + (Number(s.summary?.critical) || 0),
        0,
      ),
      high: scans.reduce((sum, s) => sum + (Number(s.summary?.high) || 0), 0),
      medium: scans.reduce(
        (sum, s) => sum + (Number(s.summary?.medium) || 0),
        0,
      ),
      low: scans.reduce((sum, s) => sum + (Number(s.summary?.low) || 0), 0),
    }),
    [scans],
  );

  const bestGrade = useMemo(() => {
    const grades = scans
      .filter((s) => s.status === "done" && s.grade)
      .map((s) => s.grade!);
    if (!grades.length) return "—";
    return grades.sort(
      (a, b) => GRADE_ORDER.indexOf(a) - GRADE_ORDER.indexOf(b),
    )[0];
  }, [scans]);

  const gradeDistribution = useMemo(() => {
    const dist: Record<string, number> = {};
    for (const s of scans) {
      if (s.grade) dist[s.grade] = (dist[s.grade] || 0) + 1;
    }
    return Object.entries(dist)
      .sort((a, b) => GRADE_ORDER.indexOf(a[0]) - GRADE_ORDER.indexOf(b[0]))
      .slice(0, 5);
  }, [scans]);

  const urlTargets = targets.filter(
    (t) => !t.repository_id && t.kind !== "llm",
  ).length;
  const repoTargets = targets.filter((t) => Boolean(t.repository_id)).length;
  const llmTargets = targets.filter((t) => t.kind === "llm").length;

  if (loading) return <PageLoading title="Dashboard" cards={6} />;

  return (
    <div className="-mx-5 md:-mx-6 -mt-6 -mb-6 flex">
      {/* ── Main content ── */}
      <div className="flex-1 min-w-0 px-5 md:px-6 py-6 space-y-6">
        {/* Header */}
        <header>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-gilt">
            Overview — Dashboard
          </p>
          <div className="mt-3 flex items-end justify-between gap-4 flex-wrap">
            <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
              Dashboard.
            </h1>
            <Link href="/targets/new">
              <Button variant="pink">Register target</Button>
            </Link>
          </div>
          <p className="mt-2 font-body text-[14px] text-slate">
            Security posture overview for this workspace.
          </p>
        </header>

        {/* Stat bar */}
        <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
          <StatCard label="Security Grade" value={bestGrade} highlight="gilt" />
          <StatCard label="Total Targets" value={targets.length} />
          <StatCard
            label="Active Scans"
            value={activeScans}
            highlight={activeScans > 0 ? "green" : undefined}
          />
          <StatCard label="Completed" value={completedScans} />
          <StatCard
            label="Critical"
            value={totalFindings.critical}
            highlight={totalFindings.critical > 0 ? "red" : undefined}
          />
          <StatCard label="High" value={totalFindings.high} />
        </div>

        {/* ── Targets ── */}
        <section>
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
                Assets
              </p>
              <h2 className="font-display text-[22px] text-ink">
                Registered Targets
              </h2>
            </div>
            {targets.length > 0 && (
              <Link
                href="/targets"
                className="font-body text-[12px] text-slate hover:text-ink underline underline-offset-4 decoration-hairline"
              >
                View all →
              </Link>
            )}
          </div>

          {targets.length > 0 && (
            <div className="flex items-center justify-between gap-4 flex-wrap mb-4">
              <div className="w-full sm:w-[360px]">
                <Input
                  type="search"
                  value={targetQuery}
                  onChange={(e) => setTargetQuery(e.target.value)}
                  placeholder="Search targets…"
                  aria-label="Search targets"
                />
              </div>
              <Paginator
                page={safeTargetPage}
                pageCount={targetPageCount}
                onChange={setTargetPage}
              />
            </div>
          )}

          {targets.length === 0 ? (
            <div className="border border-hairline rounded-sm p-10 text-center bg-vellum/30">
              <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-gilt">
                No targets
              </p>
              <h3 className="mt-3 font-display text-[24px] text-ink">
                Register your first target.
              </h3>
              <p className="mt-2 font-body text-[14px] text-slate max-w-[48ch] mx-auto">
                Provide a URL and optionally credentials for authenticated
                coverage.
              </p>
              <div className="mt-5">
                <Link href="/targets/new">
                  <Button variant="pink">Register target</Button>
                </Link>
              </div>
            </div>
          ) : filteredTargets.length === 0 ? (
            <p className="font-body text-[14px] text-slate italic">
              No targets match &quot;{targetQuery}&quot;.
            </p>
          ) : (
            <div className="border border-hairline rounded-sm overflow-hidden">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-hairline bg-vellum">
                    <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
                      Name
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist hidden sm:table-cell">
                      URL / Path
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
                      Kind
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist text-right">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline">
                  {visibleTargets.map((t) => {
                    const isRepo = Boolean(t.repository_id);
                    const kind = isRepo ? "REPO" : kindLabel(t.kind);
                    return (
                      <tr
                        key={t.id}
                        className="hover:bg-vellum/40 transition-colors"
                      >
                        <td className="px-4 py-3">
                          <Link
                            href={
                              isRepo
                                ? `/repos/${t.repository_id}`
                                : `/targets/${t.id}`
                            }
                            className="font-body text-[14px] text-ink hover:underline underline-offset-4 decoration-gilt"
                          >
                            {t.name}
                          </Link>
                          {t.has_credentials && (
                            <span className="ml-2 inline-flex items-center gap-1 border border-hairline rounded-sm px-1.5 py-0.5 font-mono text-[9px] uppercase text-forest bg-vellum">
                              <span
                                className="w-1 h-1 rounded-full bg-forest"
                                aria-hidden
                              />{" "}
                              Auth
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3 hidden sm:table-cell">
                          <span className="font-mono text-[12px] text-slate break-all">
                            {t.base_url}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate">
                            {kind}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <Button
                              variant="pink"
                              className="text-[11px] px-2.5 py-1"
                              onClick={() => commissionScan(t)}
                            >
                              {isRepo ? "Scan" : "Commission"}
                            </Button>
                            <Button
                              variant="danger"
                              className="text-[11px] px-2.5 py-1"
                              onClick={() =>
                                isRepo ? deleteRepoTarget(t) : deleteTarget(t)
                              }
                            >
                              Delete
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* ── Assessments ── */}
        <section>
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
                Activity
              </p>
              <h2 className="font-display text-[22px] text-ink">
                Recent Assessments
              </h2>
            </div>
            {scans.length > 0 && (
              <Link
                href="/scans"
                className="font-body text-[12px] text-slate hover:text-ink underline underline-offset-4 decoration-hairline"
              >
                View all →
              </Link>
            )}
          </div>

          {scans.length > 0 && (
            <div className="flex items-center justify-between gap-4 flex-wrap mb-4">
              <div className="w-full sm:w-[400px]">
                <Input
                  type="search"
                  value={scanQuery}
                  onChange={(e) => setScanQuery(e.target.value)}
                  placeholder="Search assessments…"
                  aria-label="Search assessments"
                />
              </div>
              <Paginator
                page={safeScanPage}
                pageCount={scanPageCount}
                onChange={setScanPage}
              />
            </div>
          )}

          {scans.length === 0 ? (
            <p className="font-body text-[14px] text-slate italic">
              No assessments commissioned yet.
            </p>
          ) : filteredScans.length === 0 ? (
            <p className="font-body text-[14px] text-slate italic">
              No assessments match &quot;{scanQuery}&quot;.
            </p>
          ) : (
            <div className="border border-hairline rounded-sm overflow-hidden">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-hairline bg-vellum">
                    <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
                      Grade
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
                      Report №
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist hidden md:table-cell">
                      Target
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist hidden lg:table-cell">
                      Date
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
                      Status
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist hidden xl:table-cell">
                      Findings
                    </th>
                    <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist text-right">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline">
                  {visibleScans.map((s) => {
                    const target = targets.find((t) => t.id === s.target_id);
                    return (
                      <tr
                        key={s.id}
                        className="hover:bg-vellum/40 transition-colors"
                      >
                        <td className="px-4 py-3">
                          <GradeBadge
                            grade={s.grade || (s.status !== "done" ? "?" : "—")}
                            size="sm"
                          />
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-[12px] text-mist">
                            {shortId(s.id)}
                          </span>
                        </td>
                        <td className="px-4 py-3 hidden md:table-cell">
                          {target ? (
                            <Link
                              href={`/targets/${target.id}`}
                              className="font-body text-[13px] text-ink hover:underline underline-offset-4"
                            >
                              {target.name}
                            </Link>
                          ) : (
                            <span className="text-mist">—</span>
                          )}
                        </td>
                        <td className="px-4 py-3 hidden lg:table-cell">
                          <span className="font-mono text-[12px] text-slate">
                            {formatDate(s.created_at)}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="inline-flex items-center gap-1.5 font-body text-[11px] uppercase tracking-[0.14em] text-slate">
                            <span
                              className={`w-1.5 h-1.5 rounded-full ${s.status === "done" ? "bg-forest" : s.status === "failed" ? "bg-oxblood" : "bg-gilt animate-pulse"}`}
                              aria-hidden
                            />
                            {STATUS_LABEL[s.status] || s.status}
                            {s.status === "running" && ` · ${s.progress_pct}%`}
                          </span>
                        </td>
                        <td className="px-4 py-3 hidden xl:table-cell">
                          {s.profile === "load" ? (
                            <LoadMetricCell
                              summary={
                                s.summary as Record<string, unknown> | null
                              }
                            />
                          ) : s.summary ? (
                            <div className="flex items-center gap-3">
                              {(
                                ["critical", "high", "medium", "low"] as const
                              ).map((sev) => (
                                <span
                                  key={sev}
                                  className="flex items-center gap-1"
                                >
                                  <span
                                    className={`w-[3px] h-[10px] rounded-[1px] ${SEV_COLOR[sev]}`}
                                    aria-hidden
                                  />
                                  <span className="font-mono text-[11px] text-slate">
                                    {s.summary?.[sev] ?? 0}
                                  </span>
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-mist font-mono text-[12px]">
                              —
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <Link href={`/scans/${s.id}`}>
                              <Button
                                variant="lime"
                                className="text-[11px] px-2.5 py-1"
                              >
                                Review
                              </Button>
                            </Link>
                            <Button
                              variant="danger"
                              className="text-[11px] px-2.5 py-1"
                              onClick={() => deleteScan(s.id)}
                            >
                              Delete
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <CommissionScanModal
          targetId={commissionFor?.id ?? null}
          targetName={commissionFor?.name ?? null}
          targetKind={commissionFor?.kind}
          repositoryId={commissionFor?.repository_id ?? null}
          targetKindConfig={commissionFor?.kind_config ?? null}
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

      {/* ── Intelligence panel ── */}
      <aside className="w-[260px] shrink-0 border-l border-hairline px-5 py-6 space-y-5 hidden lg:block bg-vellum/20">
        <IntelPanel title="Posture Overview" eyebrow="Intelligence">
          <div className="space-y-3">
            <IntelRow label="Total targets" value={targets.length} />
            <IntelRow label="Assessments" value={scans.length} />
            <IntelRow label="Completed" value={completedScans} />
            <IntelRow label="In progress" value={activeScans} />
          </div>
        </IntelPanel>

        <IntelDivider label="Target Types" />
        <div className="space-y-2.5">
          {[
            { label: "Web / API", value: urlTargets },
            { label: "Repositories", value: repoTargets },
            { label: "LLM / AI", value: llmTargets },
          ].map(({ label, value }) => (
            <IntelRow
              key={label}
              label={label}
              value={value}
              bar={
                targets.length ? Math.round((value / targets.length) * 100) : 0
              }
            />
          ))}
        </div>

        <IntelDivider label="Severity Totals" />
        <div className="space-y-2.5">
          {(
            [
              {
                label: "Critical",
                value: totalFindings.critical,
                color: "bg-sev-critical",
              },
              {
                label: "High",
                value: totalFindings.high,
                color: "bg-sev-high",
              },
              {
                label: "Medium",
                value: totalFindings.medium,
                color: "bg-sev-medium",
              },
              { label: "Low", value: totalFindings.low, color: "bg-sev-low" },
            ] as const
          ).map(({ label, value, color }) => {
            const max = Math.max(totalFindings.critical, 1);
            return (
              <IntelRow
                key={label}
                label={label}
                value={value}
                bar={Math.round((value / max) * 100)}
                color={color}
              />
            );
          })}
        </div>

        {gradeDistribution.length > 0 && (
          <>
            <IntelDivider label="Grade Distribution" />
            <div className="space-y-2.5">
              {gradeDistribution.map(([grade, count]) => (
                <IntelRow
                  key={grade}
                  label={`Grade ${grade}`}
                  value={count}
                  bar={Math.round((count / scans.length) * 100)}
                />
              ))}
            </div>
          </>
        )}
      </aside>
    </div>
  );
}
