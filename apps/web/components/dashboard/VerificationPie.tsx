"use client";

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip, Legend } from "recharts";

type Finding = { verification_status?: string | null };

const STATUS_COPY: Record<string, string> = {
  unverified: "Unverified",
  true_positive: "Confirmed",
  false_positive: "False positive",
  fixed: "Fixed",
};

const STATUS_HEX: Record<string, string> = {
  unverified: "#B7B7B7",
  true_positive: "#C00000",
  false_positive: "#8C8273",
  fixed: "#5B8A6B",
};

export function VerificationPie({
  findings,
  height = 240,
}: {
  findings: Finding[];
  height?: number;
}) {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    const k = f.verification_status || "unverified";
    counts[k] = (counts[k] || 0) + 1;
  }

  const data = Object.entries(counts)
    .map(([status, count]) => ({
      name: STATUS_COPY[status] || status,
      status,
      count,
    }))
    .sort((a, b) => b.count - a.count);

  if (data.length === 0 || data.every((d) => d.count === 0)) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        No findings to verify.
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
              <Cell key={d.status} fill={STATUS_HEX[d.status] || "#8C8273"} />
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
