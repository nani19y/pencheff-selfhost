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
import { SEV_HEX } from "@/lib/sev";

type Finding = { cvss_score?: number | null };

const BUCKETS: { label: string; lo: number; hi: number; sev: keyof typeof SEV_HEX }[] = [
  { label: "0.0–2.0", lo: 0, hi: 2, sev: "info" },
  { label: "2.1–4.0", lo: 2.001, hi: 4, sev: "low" },
  { label: "4.1–6.0", lo: 4.001, hi: 6, sev: "medium" },
  { label: "6.1–8.0", lo: 6.001, hi: 8, sev: "high" },
  { label: "8.1–10.0", lo: 8.001, hi: 10, sev: "critical" },
];

export function CvssHistogram({
  findings,
  height = 240,
}: {
  findings: Finding[];
  height?: number;
}) {
  const counts = BUCKETS.map((b) => ({
    range: b.label,
    sev: b.sev,
    count: findings.filter((f) => {
      const v = f.cvss_score;
      if (v == null) return false;
      return v >= b.lo && v <= b.hi;
    }).length,
  }));

  const total = counts.reduce((s, d) => s + d.count, 0);
  if (total === 0) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        No CVSS scores in this scan.
      </div>
    );
  }

  return (
    <div className="formal-surface" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={counts}
          margin={{ top: 16, right: 16, bottom: 12, left: 0 }}
        >
          <XAxis
            dataKey="range"
            stroke="#8C8273"
            tick={{ fontSize: 10, fontFamily: "ui-monospace" }}
          />
          <YAxis
            stroke="#8C8273"
            tick={{ fontSize: 10, fontFamily: "ui-monospace" }}
            allowDecimals={false}
          />
          <Tooltip
            cursor={{ fill: "rgba(199,191,168,0.15)" }}
            contentStyle={{
              background: "#FAF7F0",
              border: "1px solid #C7BFA8",
              borderRadius: "4px",
              fontFamily: "ui-monospace",
              fontSize: "12px",
            }}
          />
          <Bar dataKey="count" isAnimationActive={false}>
            {counts.map((d) => (
              <Cell key={d.range} fill={SEV_HEX[d.sev]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
