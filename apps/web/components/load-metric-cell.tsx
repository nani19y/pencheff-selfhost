"use client";

type LoadReport = {
  breaking_point?: {
    vus?: number;
    p95_ms?: number;
    error_rate?: number;
    load_error_rate?: number;
  } | null;
  latency_ms?: Record<string, number>;
  stages?: Array<{ vus?: number }>;
  extra?: { load_error_rate?: number };
};

function fmtLoad(lr: LoadReport): string {
  const bp = lr.breaking_point;
  const p95 = Math.round(bp?.p95_ms ?? lr.latency_ms?.p95 ?? 0);
  if (bp) {
    const er =
      bp.load_error_rate ?? lr.extra?.load_error_rate ?? bp.error_rate ?? 0;
    const vus = bp.vus ?? "?";
    return `~${vus} VUs · ${(er * 100).toFixed(1)}% err · p95 ${p95}ms`;
  }
  const stages = lr.stages ?? [];
  const lastVus = stages.length ? stages[stages.length - 1]?.vus : undefined;
  return lastVus != null ? `held → ${lastVus} VUs` : "—";
}

/** Compact per-row summary for load-profile assessments (replaces the
 *  security severity pills, which are meaningless for a load test). */
export function LoadMetricCell({
  summary,
}: {
  summary: Record<string, unknown> | null;
}) {
  const lr = (summary?.load_report as LoadReport | undefined) ?? undefined;
  return (
    <span className="font-mono text-[11px] text-slate whitespace-nowrap">
      {lr ? fmtLoad(lr) : "—"}
    </span>
  );
}
