"use client";

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { SEV_HEX, SEV_LABEL, SEV_ORDER, type Severity } from "@/lib/sev";

type Summary = Partial<Record<Severity, number | string>> | null | undefined;

export function SeverityDonut({
  summary,
  height = 240,
}: {
  summary: Summary;
  height?: number;
}) {
  const data = SEV_ORDER.map((sev) => ({
    name: SEV_LABEL[sev],
    severity: sev,
    count: Number(summary?.[sev] ?? 0),
  }));
  const total = data.reduce((s, d) => s + d.count, 0);

  if (total === 0) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        No findings recorded.
      </div>
    );
  }

  return (
    <div className="formal-surface relative" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="count"
            nameKey="name"
            innerRadius={60}
            outerRadius={90}
            paddingAngle={1.5}
            stroke="none"
            isAnimationActive={false}
          >
            {data.map((d) => (
              <Cell key={d.severity} fill={SEV_HEX[d.severity]} />
            ))}
          </Pie>
          <Tooltip
            formatter={(value: number, name: string) => [`${value}`, name]}
            contentStyle={{
              background: "#FAF7F0",
              border: "1px solid #C7BFA8",
              borderRadius: "4px",
              fontFamily: "var(--font-mono, ui-monospace)",
              fontSize: "12px",
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="font-display text-[36px] leading-none text-ink">
          {total}
        </span>
        <span className="mt-1 font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
          findings
        </span>
      </div>
    </div>
  );
}
