"use client";

/**
 * Executive risk dashboard.
 *
 * Renders the four aggregations the backend exposes at /dashboard/*:
 *   1. Severity × category heatmap
 *   2. 90-day new-vs-closed trend (sparkline-style SVG)
 *   3. Top-10 repos by open findings
 *   4. KEV exposure tile + fix-conversion tile
 *
 * Charts are inline SVG so we don't pull a new charting dep into the
 * web bundle just for this page. The visual language matches the rest
 * of the app — gilt accents, mono numerals, generous whitespace.
 *
 * Plan-tier gate: the backend returns 402 for plans without the
 * EXECUTIVE_DASHBOARD feature; we surface that as an upgrade nudge
 * rather than an error toast.
 */

import { useEffect, useState } from "react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, ApiError } from "@/lib/api";
import { PageLoading } from "@/components/loading";

type HeatmapCell = { severity: string; category: string; count: number };
type Heatmap = {
  cells: HeatmapCell[];
  severities: string[];
  categories: string[];
};

type TrendPoint = { date: string; new: number; closed: number };
type Trend = { points: TrendPoint[]; window_days: number };

type TopRepo = {
  repository_id: string;
  full_name: string;
  open_findings: number;
  critical: number;
  high: number;
};

type KevExposure = {
  total_kev_findings: number;
  open_kev_findings: number;
  suppressed_kev_findings: number;
  fixed_kev_findings: number;
  by_severity: Record<string, number>;
};

type FixConversion = {
  findings_total: number;
  findings_with_proposal: number;
  findings_with_applied_fix: number;
  proposal_coverage_pct: number;
  apply_coverage_pct: number;
};

const SEVERITY_HEX: Record<string, string> = {
  critical: "#C00000",
  high: "#E06666",
  medium: "#E69138",
  low: "#6FA8DC",
  info: "#B7B7B7",
};

export default function ExecutiveDashboardPage() {
  const [heatmap, setHeatmap] = useState<Heatmap | null>(null);
  const [trend, setTrend] = useState<Trend | null>(null);
  const [topRepos, setTopRepos] = useState<TopRepo[] | null>(null);
  const [kev, setKev] = useState<KevExposure | null>(null);
  const [fixConv, setFixConv] = useState<FixConversion | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    Promise.all([
      api<Heatmap>("/dashboard/heatmap"),
      api<Trend>("/dashboard/trend?days=90"),
      api<{ rows: TopRepo[] }>("/dashboard/top-repos?limit=10"),
      api<KevExposure>("/dashboard/kev-exposure"),
      api<FixConversion>("/dashboard/fix-conversion"),
    ])
      .then(([h, t, r, k, f]) => {
        if (!alive) return;
        setHeatmap(h);
        setTrend(t);
        setTopRepos(r.rows);
        setKev(k);
        setFixConv(f);
      })
      .catch((e: unknown) => {
        if (!alive) return;
        if (e instanceof ApiError && e.status === 402) {
          setError(
            "Executive dashboard is part of Pro / Team / Enterprise plans. " +
              "Upgrade to unlock CVSS heatmaps, trend lines, and risk reporting.",
          );
        } else {
          setError(e instanceof Error ? e.message : "Failed to load dashboard");
        }
      });
    return () => {
      alive = false;
    };
  }, []);

  if (error) {
    return (
      <div className="max-w-3xl mx-auto py-16 px-6">
        <h1 className="font-serif text-3xl mb-4">Executive risk dashboard</h1>
        <div className="advisory-warn font-body text-[14px] leading-[1.7]">
          {error}
        </div>
      </div>
    );
  }

  const loading =
    !heatmap || !trend || !topRepos || !kev || !fixConv;

  if (loading) {
    return <PageLoading title="Executive dashboard" cards={6} />;
  }

  return (
    <div className="space-y-6">
      <header>
        <p className="eyebrow-gilt">Executive risk dashboard</p>
        <h1 className="font-serif text-4xl mt-2">Risk at a glance</h1>
        <p className="font-body text-[14px] text-slate mt-2">
          Workspace-scoped roll-up of every open finding, KEV exposure,
          and fix-conversion rate. Refresh the page for live data.
        </p>
      </header>
      <section className="grid md:grid-cols-3 gap-px bg-hairline border border-hairline rounded-md overflow-hidden">
        <Tile
          label="KEV-exposed findings"
          big={kev!.open_kev_findings.toString()}
          caption={`${kev!.total_kev_findings} total · ${kev!.fixed_kev_findings} fixed · ${kev!.suppressed_kev_findings} suppressed`}
        />
        <Tile
          label="Fix-proposal coverage"
          big={`${fixConv!.proposal_coverage_pct}%`}
          caption={`${fixConv!.findings_with_proposal}/${fixConv!.findings_total} findings have a proposal`}
        />
        <Tile
          label="PR-applied coverage"
          big={`${fixConv!.apply_coverage_pct}%`}
          caption={`${fixConv!.findings_with_applied_fix} fixes shipped to PRs`}
        />
      </section>

      <section>
        <p className="eyebrow mb-3">Severity × category</p>
        <Heatmap data={heatmap!} />
      </section>

      <section>
        <p className="eyebrow mb-3">{trend!.window_days}-day trend</p>
        <TrendChart points={trend!.points} />
      </section>

      <section>
        <p className="eyebrow mb-3">Top repos by open findings</p>
        {topRepos!.length === 0 ? (
          <p className="font-body text-[13px] italic text-slate">
            No repo findings yet — attach a repository to start scanning.
          </p>
        ) : (
          <div className="formal-surface overflow-hidden">
            <table className="w-full font-mono text-[12px]">
              <thead className="text-mist border-b border-hairline">
                <tr>
                  <th className="text-left p-3">Repository</th>
                  <th className="text-right p-3">Open</th>
                  <th className="text-right p-3 text-sev-critical">Critical</th>
                  <th className="text-right p-3 text-sev-high">High</th>
                </tr>
              </thead>
              <tbody>
                {topRepos!.map((r) => (
                  <tr key={r.repository_id} className="border-b border-hairline last:border-b-0">
                    <td className="p-3">{r.full_name}</td>
                    <td className="p-3 text-right">{r.open_findings}</td>
                    <td className="p-3 text-right">{r.critical}</td>
                    <td className="p-3 text-right">{r.high}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function Tile({
  label,
  big,
  caption,
}: {
  label: string;
  big: string;
  caption: string;
}) {
  return (
    <div className="bg-paper p-6">
      <p className="eyebrow mb-3">{label}</p>
      <p className="font-serif text-5xl mb-2">{big}</p>
      <p className="font-body text-[12px] text-slate">{caption}</p>
    </div>
  );
}

function Heatmap({ data }: { data: Heatmap }) {
  // Build a map for O(1) cell lookup. Categories with > 12 columns
  // get truncated — auditors can see the rest in the per-finding view.
  const cellMap = new Map<string, number>();
  for (const c of data.cells) {
    cellMap.set(`${c.severity}|${c.category}`, c.count);
  }
  const cats = data.categories.slice(0, 12);
  const max = Math.max(1, ...data.cells.map((c) => c.count));
  return (
    <div className="formal-surface overflow-x-auto">
      <table className="w-full text-[11px] font-mono border-collapse">
        <thead>
          <tr>
            <th className="p-2 text-left text-mist"></th>
            {cats.map((c) => (
              <th key={c} className="p-2 text-left text-mist whitespace-nowrap">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.severities.map((s) => (
            <tr key={s}>
              <th className="p-2 text-left font-mono uppercase tracking-[0.1em] text-[10px]" style={{ color: SEVERITY_HEX[s] }}>
                {s}
              </th>
              {cats.map((c) => {
                const n = cellMap.get(`${s}|${c}`) ?? 0;
                const intensity = n / max;
                return (
                  <td
                    key={c}
                    className="p-2 text-right tabular-nums"
                    style={{
                      backgroundColor: n
                        ? `${SEVERITY_HEX[s]}${Math.round(intensity * 200 + 30)
                            .toString(16)
                            .padStart(2, "0")}`
                        : "transparent",
                      color: intensity > 0.5 ? "#fff" : undefined,
                    }}
                  >
                    {n || ""}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TrendChart({ points }: { points: TrendPoint[] }) {
  if (points.length === 0) {
    return (
      <p className="font-body text-[13px] italic text-slate">No data yet.</p>
    );
  }
  const data = points.map((p) => ({
    date: p.date.slice(5),
    New: p.new,
    Closed: p.closed,
  }));
  return (
    <div className="formal-surface p-4" style={{ height: 260 }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 16, right: 24, bottom: 12, left: 0 }}>
          <CartesianGrid stroke="#E5DFCE" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="date"
            stroke="#8C8273"
            tick={{ fontSize: 10, fontFamily: "ui-monospace" }}
            interval="preserveStartEnd"
            minTickGap={32}
          />
          <YAxis
            stroke="#8C8273"
            tick={{ fontSize: 10, fontFamily: "ui-monospace" }}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              background: "#FAF7F0",
              border: "1px solid #C7BFA8",
              borderRadius: "4px",
              fontFamily: "ui-monospace",
              fontSize: "12px",
            }}
          />
          <Legend
            wrapperStyle={{
              fontFamily: "ui-monospace",
              fontSize: "10px",
              textTransform: "uppercase",
              letterSpacing: "0.12em",
            }}
          />
          <Line
            type="monotone"
            dataKey="New"
            stroke="#C00000"
            strokeWidth={2}
            dot={false}
            isAnimationActive={false}
          />
          <Line
            type="monotone"
            dataKey="Closed"
            stroke="#6B8E23"
            strokeWidth={2}
            dot={false}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
