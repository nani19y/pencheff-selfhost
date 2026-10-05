"use client";

import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type Point = {
  date: string;
  value: number;
  label?: string | null;
};

function fmtDate(iso: string) {
  return iso.slice(0, 10);
}

export function TrendLine({
  points,
  yLabel = "Score",
  yDomain,
  height = 240,
  stroke = "#C7A861",
}: {
  points: Point[];
  yLabel?: string;
  yDomain?: [number, number];
  height?: number;
  stroke?: string;
}) {
  if (points.length === 0) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        Not enough data for a trend.
      </div>
    );
  }
  const data = points.map((p) => ({
    date: fmtDate(p.date),
    value: p.value,
    label: p.label,
  }));
  return (
    <div className="formal-surface" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 16, right: 24, bottom: 12, left: 0 }}>
          <CartesianGrid stroke="#E5DFCE" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="date"
            stroke="#8C8273"
            tick={{ fontSize: 10, fontFamily: "ui-monospace" }}
          />
          <YAxis
            stroke="#8C8273"
            tick={{ fontSize: 10, fontFamily: "ui-monospace" }}
            domain={yDomain || ["auto", "auto"]}
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
            formatter={(v: number) => [`${v}`, yLabel]}
          />
          <Line
            type="monotone"
            dataKey="value"
            stroke={stroke}
            strokeWidth={2}
            dot={{ r: 3, fill: stroke, stroke: "none" }}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
