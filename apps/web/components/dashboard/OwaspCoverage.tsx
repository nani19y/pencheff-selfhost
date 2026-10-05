"use client";

import {
  Bar,
  BarChart,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { normalizeSeverity, SEV_HEX, SEV_LABEL, SEV_ORDER } from "@/lib/sev";

type Finding = {
  owasp_category?: string | null;
  severity?: string | null;
};

export function OwaspCoverage({
  findings,
  top = 10,
  height = 320,
}: {
  findings: Finding[];
  top?: number;
  height?: number;
}) {
  type Row = {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  const map = new Map<string, Row>();
  for (const f of findings) {
    const owasp = (f.owasp_category || "—").toString();
    const sev = normalizeSeverity(f.severity);
    let row = map.get(owasp);
    if (!row) {
      row = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
      map.set(owasp, row);
    }
    row[sev] += 1;
    row.total += 1;
  }

  const data = Array.from(map.entries())
    .map(([owasp, row]) => ({ owasp, ...row }))
    .sort((a, b) => b.total - a.total)
    .slice(0, top);

  if (data.length === 0) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        No OWASP-mapped findings.
      </div>
    );
  }

  return (
    <div className="formal-surface" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 12, right: 16, bottom: 12, left: 16 }}
        >
          <XAxis
            type="number"
            stroke="#8C8273"
            tick={{ fontSize: 10, fontFamily: "ui-monospace" }}
            allowDecimals={false}
          />
          <YAxis
            type="category"
            dataKey="owasp"
            stroke="#8C8273"
            tick={{ fontSize: 11, fontFamily: "ui-monospace" }}
            width={110}
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
          <Legend
            wrapperStyle={{
              fontFamily: "ui-monospace",
              fontSize: "10px",
              textTransform: "uppercase",
              letterSpacing: "0.12em",
            }}
          />
          {SEV_ORDER.map((sev) => (
            <Bar
              key={sev}
              dataKey={sev}
              name={SEV_LABEL[sev]}
              stackId="a"
              fill={SEV_HEX[sev]}
              isAnimationActive={false}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
