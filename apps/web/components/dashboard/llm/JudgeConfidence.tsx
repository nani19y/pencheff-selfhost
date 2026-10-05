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

export function JudgeConfidence({
  scores,
  height = 220,
}: {
  scores: number[];
  height?: number;
}) {
  if (scores.length === 0) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        No judge-graded probes in this scan.
      </div>
    );
  }

  const buckets = Array.from({ length: 10 }, (_, i) => ({
    range: `${i / 10}–${(i + 1) / 10}`,
    lo: i / 10,
    hi: (i + 1) / 10,
    count: 0,
  }));
  for (const s of scores) {
    const idx = Math.min(9, Math.max(0, Math.floor(s * 10)));
    buckets[idx].count += 1;
  }

  const fillForBucket = (lo: number) => {
    if (lo < 0.3) return "#B7B7B7";
    if (lo < 0.6) return "#E69138";
    if (lo < 0.8) return "#E06666";
    return "#C00000";
  };

  return (
    <div className="formal-surface" style={{ height }}>
      <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist px-4 pt-3">
        Judge confidence ({scores.length} graded)
      </p>
      <ResponsiveContainer width="100%" height="85%">
        <BarChart
          data={buckets}
          margin={{ top: 8, right: 16, bottom: 12, left: 0 }}
        >
          <XAxis
            dataKey="range"
            stroke="#8C8273"
            tick={{ fontSize: 9, fontFamily: "ui-monospace" }}
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
            {buckets.map((b) => (
              <Cell key={b.range} fill={fillForBucket(b.lo)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
