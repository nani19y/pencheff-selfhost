"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { Button, GradeBadge } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { CategoryBar } from "@/components/dashboard/CategoryBar";
import { CvssHistogram } from "@/components/dashboard/CvssHistogram";
import { EndpointTreemap } from "@/components/dashboard/EndpointTreemap";
import { OwaspCoverage } from "@/components/dashboard/OwaspCoverage";
import { SeverityDonut } from "@/components/dashboard/SeverityDonut";
import { TopRiskList } from "@/components/dashboard/TopRiskList";
import { VerificationPie } from "@/components/dashboard/VerificationPie";
import { JudgeConfidence } from "@/components/dashboard/llm/JudgeConfidence";
import { OwaspLlmHeatmap } from "@/components/dashboard/llm/OwaspLlmHeatmap";
import { StrategyBreakdown } from "@/components/dashboard/llm/StrategyBreakdown";
import { TokenProfile } from "@/components/dashboard/llm/TokenProfile";
import { TopFailuresList } from "@/components/dashboard/llm/TopFailuresList";
import { VerdictFunnel } from "@/components/dashboard/llm/VerdictFunnel";
import { api } from "@/lib/api";
import type { Severity } from "@/lib/sev";

type Scan = {
  id: string;
  target_id: string;
  status: string;
  grade: string | null;
  score: number | null;
  summary:
    | (Partial<Record<Severity, number | string>> & {
        llm_redteam_summary?: LlmRedteamSummary | null;
        llm_redteam_by_category?: Record<string, number> | null;
      })
    | null;
  started_at: string | null;
  finished_at: string | null;
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
  suppressed: boolean;
  risk_score: number | null;
  ssvc_decision: string | null;
  reachability: string | null;
  epss: number | null;
  kev: boolean;
};

type LlmRedteamSummary = {
  total_failures?: number;
  by_category?: Record<string, number>;
  by_technique?: Record<string, number>;
  by_strategy?: Record<string, number>;
  by_severity?: Record<string, number>;
  top_failures?: Array<{
    id: string;
    title: string;
    severity: string;
    owasp_category: string;
    technique: string;
    endpoint: string;
  }>;
};

type LlmTranscriptRecord = {
  verdict?: string | null;
  owasp_category?: string | null;
  technique?: string | null;
  judge?: { confidence?: number | null } | null;
  judge_confidence?: number | null;
  latency_ms?: number | null;
  tokens?: {
    prompt?: number;
    completion?: number;
    cached?: number;
    reasoning?: number;
  } | null;
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  cached_tokens?: number | null;
  reasoning_tokens?: number | null;
};

function shortId(id: string) {
  return id.slice(0, 8).toUpperCase();
}

function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function percentile(values: number[], p: number): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(
    sorted.length - 1,
    Math.floor((p / 100) * sorted.length),
  );
  return sorted[idx];
}

function classifyVerdict(
  v: string | null | undefined,
): "vulnerable" | "refused" | "ambiguous" {
  const s = (v || "").toLowerCase();
  if (s.includes("vulner") || s === "fail" || s === "failure")
    return "vulnerable";
  if (s.includes("refus") || s === "blocked" || s === "denied")
    return "refused";
  return "ambiguous";
}

export default function ScanDashboardPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const id = mounted ? pathSegment(pathname, 2) : "";
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [transcripts, setTranscripts] = useState<LlmTranscriptRecord[] | null>(
    null,
  );
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    let alive = true;
    setLoading(true);
    Promise.all([
      api<Scan>(`/scans/${id}`).catch(() => null),
      api<Finding[]>(`/findings?scan_id=${id}&include_suppressed=false`).catch(
        () => [] as Finding[],
      ),
    ])
      .then(async ([s, f]) => {
        if (!alive) return;
        setScan(s);
        setFindings(f || []);
        if (s?.target_kind === "llm") {
          // Best-effort: transcript file may have expired or never been
          // written. The dashboard renders summary-only when missing.
          try {
            const t = await api<{ records: LlmTranscriptRecord[] }>(
              `/scans/${id}/llm-transcripts?format=json`,
            );
            if (alive) setTranscripts(t.records || []);
          } catch {
            if (alive) setTranscripts([]);
          }
        }
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [id]);

  if (loading || !scan) {
    return (
      <div className="py-6">
        <InlineLoading label="Loading dashboard…" />
      </div>
    );
  }

  if (scan.status !== "done") {
    return <DashboardPending scan={scan} />;
  }

  const isLlm = scan.target_kind === "llm";
  return (
    <div className="space-y-8">
      <header className="flex items-start justify-between flex-wrap gap-6">
        <div>
          <p className="eyebrow-gilt">
            {isLlm ? "LLM red-team dashboard" : "Dashboard"}
          </p>
          <h1 className="mt-4 font-display text-[36px] md:text-[42px] leading-[1.05] tracking-[-0.015em] text-ink">
            Report № {shortId(scan.id)}
          </h1>
          <p className="mt-2 font-mono text-[12px] text-mist">
            {scan.finished_at
              ? `Completed ${scan.finished_at.replace("T", " · ").slice(0, 22)}`
              : "Completed"}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <GradeBadge grade={scan.grade || "—"} size="md" />
          <Link href={`/scans/${scan.id}`}>
            <Button variant="lime">← Findings register</Button>
          </Link>
        </div>
      </header>

      {isLlm ? (
        <LlmDashboard
          scan={scan}
          findings={findings}
          transcripts={transcripts}
          scanId={id}
        />
      ) : (
        <GenericDashboard scan={scan} findings={findings} scanId={id} />
      )}
    </div>
  );
}

function DashboardPending({ scan }: { scan: Scan }) {
  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between flex-wrap gap-6">
        <div>
          <p className="eyebrow-gilt">Dashboard</p>
          <h1 className="mt-4 font-display text-[32px] md:text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
            Report № {shortId(scan.id)}
          </h1>
        </div>
        <Link href={`/scans/${scan.id}`}>
          <Button variant="lime">← Back to assessment</Button>
        </Link>
      </header>
      <section className="formal-surface p-10 text-center">
        <p className="eyebrow-gilt">Assessment in progress</p>
        <h3 className="mt-4 font-display text-[24px] text-ink">
          Dashboard available once the assessment finishes.
        </h3>
        <p className="mt-3 text-[14px] text-slate max-w-[52ch] mx-auto">
          Charts depend on the full findings register. Track progress on the
          assessment page; the dashboard will populate automatically.
        </p>
        <div className="mt-6 flex justify-center">
          <Link href={`/scans/${scan.id}`}>
            <Button variant="pink">View assessment progress</Button>
          </Link>
        </div>
      </section>
    </div>
  );
}

function GenericDashboard({
  scan,
  findings,
  scanId,
}: {
  scan: Scan;
  findings: Finding[];
  scanId: string;
}) {
  const stats = useMemo(() => {
    const total = findings.length;
    const kev = findings.filter((f) => f.kev).length;
    const reachable = findings.filter(
      (f) => (f.reachability || "").toLowerCase() === "reachable",
    ).length;
    const epssValues = findings
      .map((f) => f.epss)
      .filter((v): v is number => typeof v === "number");
    const epssMedian = median(epssValues);
    return { total, kev, reachable, epssMedian };
  }, [findings]);

  return (
    <>
      <section>
        <p className="eyebrow mb-3">Severity · CVSS · Verification</p>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <SeverityDonut summary={scan.summary} />
          <CvssHistogram findings={findings} />
          <VerificationPie findings={findings} />
        </div>
      </section>

      <section>
        <p className="eyebrow mb-3">Categories · OWASP coverage</p>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <CategoryBar findings={findings} />
          <OwaspCoverage findings={findings} />
        </div>
      </section>

      <section>
        <p className="eyebrow mb-3">Top risk · Affected endpoints</p>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <TopRiskList findings={findings} scanId={scanId} />
          <EndpointTreemap findings={findings} />
        </div>
      </section>

      <section>
        <p className="eyebrow mb-3">Exposure indicators</p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Tile
            label="Total active"
            value={stats.total}
            hint="Suppressed FPs hidden"
          />
          <Tile
            label="KEV in scan"
            value={stats.kev}
            hint="Known exploited"
            accent={stats.kev > 0 ? "danger" : "neutral"}
          />
          <Tile
            label="Reachable"
            value={stats.reachable}
            hint="Code-path verified"
          />
          <Tile
            label="Median EPSS"
            value={
              stats.epssMedian == null
                ? "—"
                : `${(stats.epssMedian * 100).toFixed(1)}%`
            }
            hint="30-day exploit prob."
          />
        </div>
      </section>
    </>
  );
}

function LlmDashboard({
  scan,
  findings,
  transcripts,
  scanId,
}: {
  scan: Scan;
  findings: Finding[];
  transcripts: LlmTranscriptRecord[] | null;
  scanId: string;
}) {
  const summary: LlmRedteamSummary = scan.summary?.llm_redteam_summary || {};

  // Verdict counts: derived from transcripts when available; fall back
  // to the failure summary (which only tracks vulnerable verdicts) when
  // the transcript file expired or was never written.
  const verdictCounts = useMemo(() => {
    if (transcripts && transcripts.length > 0) {
      const c = {
        total: transcripts.length,
        vulnerable: 0,
        refused: 0,
        ambiguous: 0,
      };
      for (const r of transcripts) {
        const v = classifyVerdict(r.verdict);
        c[v] += 1;
      }
      return c;
    }
    return {
      total: summary.total_failures || 0,
      vulnerable: summary.total_failures || 0,
      refused: 0,
      ambiguous: 0,
    };
  }, [transcripts, summary.total_failures]);

  // Per-category probe totals (for success-rate column on heatmap).
  const totalsByCategory = useMemo(() => {
    if (!transcripts || transcripts.length === 0) return undefined;
    const out: Record<string, number> = {};
    for (const r of transcripts) {
      const c = r.owasp_category || "";
      if (c.startsWith("LLM")) out[c] = (out[c] || 0) + 1;
    }
    return out;
  }, [transcripts]);

  const judgeScores = useMemo(() => {
    if (!transcripts) return [];
    return transcripts
      .map((r) => r.judge?.confidence ?? r.judge_confidence ?? null)
      .filter((v): v is number => typeof v === "number" && v >= 0 && v <= 1);
  }, [transcripts]);

  const tokenAndLatency = useMemo(() => {
    if (!transcripts || transcripts.length === 0)
      return {
        tokens: { prompt: 0, completion: 0, cached: 0, reasoning: 0 },
        p50: null,
        p95: null,
      };
    let prompt = 0,
      completion = 0,
      cached = 0,
      reasoning = 0;
    const latencies: number[] = [];
    for (const r of transcripts) {
      prompt += r.tokens?.prompt ?? r.prompt_tokens ?? 0;
      completion += r.tokens?.completion ?? r.completion_tokens ?? 0;
      cached += r.tokens?.cached ?? r.cached_tokens ?? 0;
      reasoning += r.tokens?.reasoning ?? r.reasoning_tokens ?? 0;
      if (typeof r.latency_ms === "number") latencies.push(r.latency_ms);
    }
    return {
      tokens: { prompt, completion, cached, reasoning },
      p50: percentile(latencies, 50),
      p95: percentile(latencies, 95),
    };
  }, [transcripts]);

  const transcriptUnavailable =
    transcripts !== null && transcripts.length === 0;

  return (
    <>
      {/* Verdict funnel — the centerpiece */}
      <section>
        <p className="eyebrow mb-3">What actually happened</p>
        <VerdictFunnel counts={verdictCounts} />
        {transcriptUnavailable && (
          <p className="mt-2 font-mono text-[11px] text-mist italic">
            Transcript file unavailable — verdict counts derived from the
            failure summary (refused / ambiguous probe counts hidden).
          </p>
        )}
      </section>

      {/* OWASP-LLM Top-10 heatmap */}
      <section>
        <p className="eyebrow mb-3">OWASP LLM Top-10 outcomes</p>
        <OwaspLlmHeatmap
          byCategory={summary.by_category || {}}
          totalsByCategory={totalsByCategory}
        />
      </section>

      {/* Strategy + technique breakdown */}
      <section>
        <p className="eyebrow mb-3">Strategy · technique breakdown</p>
        <StrategyBreakdown
          byStrategy={summary.by_strategy || {}}
          byTechnique={summary.by_technique || {}}
        />
      </section>

      {/* Judge confidence + token profile */}
      <section>
        <p className="eyebrow mb-3">Judge confidence · token profile</p>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <JudgeConfidence scores={judgeScores} />
          <TokenProfile
            tokens={tokenAndLatency.tokens}
            latencyP50Ms={tokenAndLatency.p50}
            latencyP95Ms={tokenAndLatency.p95}
          />
        </div>
      </section>

      {/* Top 10 failures */}
      <section>
        <p className="eyebrow mb-3">Top failures</p>
        <TopFailuresList
          failures={summary.top_failures || []}
          scanId={scanId}
        />
      </section>

      {/* Severity tile row */}
      <section>
        <p className="eyebrow mb-3">Severity rollup</p>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {(["critical", "high", "medium", "low", "info"] as const).map(
            (sev) => (
              <Tile
                key={sev}
                label={sev}
                value={Number(
                  summary.by_severity?.[sev] ?? scan.summary?.[sev] ?? 0,
                )}
                hint="Failures"
                accent={sev === "critical" ? "danger" : "neutral"}
              />
            ),
          )}
        </div>
      </section>

      {/* Recommended guardrails CTA */}
      {findings.length > 0 && (
        <section className="formal-surface p-6">
          <p className="eyebrow-gilt mb-2">Next step</p>
          <p className="font-body text-[13px] text-slate max-w-[64ch]">
            Review the recommended Sentry guardrail configuration for this
            target, computed from the failure breakdown above.
          </p>
          <div className="mt-4">
            <Link
              href={`/scans/${scanId}/recommended-guardrails`}
              className="inline-block border border-graphite px-4 py-2 font-mono text-[12px] uppercase tracking-[0.08em] hover:bg-graphite hover:text-white"
            >
              View recommended guardrails →
            </Link>
          </div>
        </section>
      )}
    </>
  );
}

function Tile({
  label,
  value,
  hint,
  accent = "neutral",
}: {
  label: string;
  value: number | string;
  hint?: string;
  accent?: "neutral" | "danger";
}) {
  return (
    <div
      className={
        "formal-surface p-5 " +
        (accent === "danger" ? "border-sev-critical" : "")
      }
    >
      <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
        {label}
      </p>
      <p
        className={
          "mt-2 font-display text-[36px] leading-none " +
          (accent === "danger" ? "text-sev-critical" : "text-ink")
        }
      >
        {value}
      </p>
      {hint && <p className="mt-2 font-mono text-[10px] text-slate">{hint}</p>}
    </div>
  );
}
