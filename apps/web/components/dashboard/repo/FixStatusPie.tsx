"use client";

import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

type RepoFinding = { fix_status?: string | null };

const FIX_HEX: Record<string, string> = {
  none: "#B7B7B7",
  proposed: "#E69138",
  pr_open: "#6FA8DC",
  merged: "#5B8A6B",
};

const FIX_LABEL: Record<string, string> = {
  none: "Untouched",
  proposed: "Proposed",
  pr_open: "PR open",
  merged: "Merged",
};

export function FixStatusPie({
  findings,
  height = 240,
}: {
  findings: RepoFinding[];
  height?: number;
}) {
  const counts: Record<string, number> = {
    none: 0,
    proposed: 0,
    pr_open: 0,
    merged: 0,
  };
  for (const f of findings) {
    const k = f.fix_status || "none";
    counts[k] = (counts[k] || 0) + 1;
  }

  const data = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([status, count]) => ({
      name: FIX_LABEL[status] || status,
      status,
      count,
    }));

  if (data.length === 0) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        No findings to fix.
      </div>
    );
  }

  return (
    <div className="formal-surface" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="count"
            nameKey="name"
            innerRadius={50}
            outerRadius={80}
            paddingAngle={1.5}
            stroke="none"
            isAnimationActive={false}
          >
            {data.map((d) => (
              <Cell key={d.status} fill={FIX_HEX[d.status] || "#8C8273"} />
            ))}
          </Pie>
          <Tooltip
            formatter={(value: number, name: string) => [`${value}`, name]}
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
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
