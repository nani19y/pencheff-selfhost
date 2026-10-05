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
import { normalizeSeverity, SEV_HEX, SEV_RANK } from "@/lib/sev";

type Finding = {
  category?: string | null;
  severity?: string | null;
};

function prettyCategory(c: string) {
  return c.replace(/^llm_/, "").replace(/_/g, " ");
}

export function CategoryBar({
  findings,
  top = 8,
  height = 280,
}: {
  findings: Finding[];
  top?: number;
  height?: number;
}) {
  const buckets = new Map<
    string,
    { count: number; topSev: number; sevKey: string }
  >();
  for (const f of findings) {
    const cat = (f.category || "uncategorised").toLowerCase();
    const sev = normalizeSeverity(f.severity);
    const rank = SEV_RANK[sev];
    const cur = buckets.get(cat);
    if (!cur) {
      buckets.set(cat, { count: 1, topSev: rank, sevKey: sev });
    } else {
      cur.count += 1;
      if (rank > cur.topSev) {
        cur.topSev = rank;
        cur.sevKey = sev;
      }
    }
  }

  const data = Array.from(buckets.entries())
    .map(([category, v]) => ({
      category: prettyCategory(category),
      count: v.count,
      sevKey: v.sevKey,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, top);

  if (data.length === 0) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        No category data.
      </div>
    );
  }

  return (
    <div className="formal-surface" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 12, right: 24, bottom: 12, left: 24 }}
        >
          <XAxis
            type="number"
            stroke="#8C8273"
            tick={{ fontSize: 11, fontFamily: "ui-monospace" }}
            allowDecimals={false}
          />
          <YAxis
            type="category"
            dataKey="category"
            stroke="#8C8273"
            tick={{ fontSize: 11, fontFamily: "ui-sans-serif" }}
            width={120}
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
            {data.map((d) => (
              <Cell
                key={d.category}
                fill={SEV_HEX[d.sevKey as keyof typeof SEV_HEX]}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
