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

const STRATEGY_HEX: Record<string, string> = {
  base: "#8C8273",
  jailbreak: "#C00000",
  dataset: "#6B4FA1",
  custom: "#E69138",
  guardrail: "#5B8A6B",
};

export function StrategyBreakdown({
  byStrategy,
  byTechnique,
  height = 240,
}: {
  byStrategy: Record<string, number>;
  byTechnique?: Record<string, number>;
  height?: number;
}) {
  const stratData = Object.entries(byStrategy)
    .map(([strategy, count]) => ({ strategy, count }))
    .sort((a, b) => b.count - a.count);

  const techData = byTechnique
    ? Object.entries(byTechnique)
        .map(([technique, count]) => ({ technique, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10)
    : [];

  if (stratData.length === 0 && techData.length === 0) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        No strategy data recorded.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
      <div className="formal-surface" style={{ height }}>
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist px-4 pt-3">
          Failures by strategy
        </p>
        <ResponsiveContainer width="100%" height="85%">
          <BarChart
            data={stratData}
            margin={{ top: 8, right: 16, bottom: 12, left: 0 }}
          >
            <XAxis
              dataKey="strategy"
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
              {stratData.map((d) => (
                <Cell
                  key={d.strategy}
                  fill={STRATEGY_HEX[d.strategy] || "#8C8273"}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="formal-surface" style={{ height }}>
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist px-4 pt-3">
          Top techniques (top 10)
        </p>
        {techData.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[12px] text-mist italic">
            No technique data.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="85%">
            <BarChart
              data={techData}
              layout="vertical"
              margin={{ top: 8, right: 16, bottom: 12, left: 12 }}
            >
              <XAxis
                type="number"
                stroke="#8C8273"
                tick={{ fontSize: 10, fontFamily: "ui-monospace" }}
                allowDecimals={false}
              />
              <YAxis
                type="category"
                dataKey="technique"
                stroke="#8C8273"
                tick={{ fontSize: 10, fontFamily: "ui-monospace" }}
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
              <Bar
                dataKey="count"
                fill="#A04545"
                isAnimationActive={false}
              />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
