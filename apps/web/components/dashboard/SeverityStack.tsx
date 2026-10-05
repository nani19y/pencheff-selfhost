"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { SEV_HEX, SEV_LABEL, SEV_ORDER, type Severity } from "@/lib/sev";

type SeriesPoint = {
  date: string;
  summary?: Partial<Record<Severity, number>> | null;
};

function fmtDate(iso: string) {
  return iso.slice(0, 10);
}

export function SeverityStack({
  series,
  height = 280,
}: {
  series: SeriesPoint[];
  height?: number;
}) {
  if (series.length < 2) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        Trends appear after the second completed assessment.
      </div>
    );
  }

  const data = series.map((p) => ({
    date: fmtDate(p.date),
    critical: Number(p.summary?.critical ?? 0),
    high: Number(p.summary?.high ?? 0),
    medium: Number(p.summary?.medium ?? 0),
    low: Number(p.summary?.low ?? 0),
    info: Number(p.summary?.info ?? 0),
  }));

  return (
    <div className="formal-surface" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 16, right: 24, bottom: 12, left: 0 }}>
          <CartesianGrid stroke="#E5DFCE" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="date"
            stroke="#8C8273"
            tick={{ fontSize: 10, fontFamily: "ui-monospace" }}
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
          {SEV_ORDER.map((sev) => (
            <Area
              key={sev}
              type="monotone"
              dataKey={sev}
              name={SEV_LABEL[sev]}
              stackId="1"
              stroke={SEV_HEX[sev]}
              fill={SEV_HEX[sev]}
              fillOpacity={0.85}
              isAnimationActive={false}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
