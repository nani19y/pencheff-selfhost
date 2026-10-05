"use client";

import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type ScanStat = {
  count?: number;
  error?: string;
  skipped?: string;
  duration_ms?: number;
};

const SCANNER_HEX: Record<string, string> = {
  semgrep: "#4F7CAC",
  bandit: "#7A6F46",
  gosec: "#3F8E4F",
  brakeman: "#A04545",
  eslint: "#B89B3F",
  gitleaks: "#C00000",
  ghsa: "#6B4FA1",
  yara: "#5B6E8F",
  trivy_iac: "#2E7D7B",
  checkov: "#A85B2F",
};

export function ScannerEffortBar({
  stats,
  height = 280,
}: {
  stats: Record<string, ScanStat> | null | undefined;
  height?: number;
}) {
  const data = Object.entries(stats || {})
    .map(([scanner, s]) => ({
      scanner,
      count: s.count ?? 0,
      duration_ms: s.duration_ms,
      error: s.error,
      skipped: s.skipped,
    }))
    .filter((d) => d.count > 0 || d.error || d.skipped)
    .sort((a, b) => b.count - a.count);

  if (data.length === 0) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        No scanner activity recorded.
      </div>
    );
  }

  return (
    <div className="formal-surface" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 12, right: 24, bottom: 12, left: 12 }}
        >
          <XAxis
            type="number"
            stroke="#8C8273"
            tick={{ fontSize: 11, fontFamily: "ui-monospace" }}
            allowDecimals={false}
          />
          <YAxis
            type="category"
            dataKey="scanner"
            stroke="#8C8273"
            tick={{ fontSize: 11, fontFamily: "ui-monospace" }}
            width={88}
          />
          <Tooltip
            cursor={{ fill: "rgba(199,191,168,0.15)" }}
            content={({ active, payload }) => {
              if (!active || !payload?.[0]?.payload) return null;
              const p = payload[0].payload as {
                scanner: string;
                count: number;
                duration_ms?: number;
                error?: string;
                skipped?: string;
              };
              return (
                <div className="bg-paper border border-hairline rounded-sm px-3 py-2 font-mono text-[11px] text-graphite">
                  <div className="font-bold">{p.scanner}</div>
                  <div>{p.count} findings</div>
                  {p.duration_ms != null && (
                    <div className="text-mist">
                      {(p.duration_ms / 1000).toFixed(1)}s
                    </div>
                  )}
                  {p.error && (
                    <div className="text-sev-critical">error: {p.error}</div>
                  )}
                  {p.skipped && (
                    <div className="text-mist">skipped: {p.skipped}</div>
                  )}
                </div>
              );
            }}
          />
          <Bar dataKey="count" isAnimationActive={false}>
            {data.map((d) => (
              <Cell
                key={d.scanner}
                fill={SCANNER_HEX[d.scanner] || "#8C8273"}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
