"use client";

import { ResponsiveContainer, Tooltip, Treemap } from "recharts";
import { normalizeSeverity, SEV_HEX, SEV_RANK } from "@/lib/sev";

type Finding = {
  endpoint?: string | null;
  severity?: string | null;
};

export function EndpointTreemap({
  findings,
  top = 12,
  height = 320,
}: {
  findings: Finding[];
  top?: number;
  height?: number;
}) {
  const map = new Map<string, { count: number; topSev: number; sevKey: string }>();
  for (const f of findings) {
    const ep = f.endpoint;
    if (!ep) continue;
    const sev = normalizeSeverity(f.severity);
    const rank = SEV_RANK[sev];
    const cur = map.get(ep);
    if (!cur) {
      map.set(ep, { count: 1, topSev: rank, sevKey: sev });
    } else {
      cur.count += 1;
      if (rank > cur.topSev) {
        cur.topSev = rank;
        cur.sevKey = sev;
      }
    }
  }

  const data = Array.from(map.entries())
    .map(([endpoint, v]) => ({
      name: endpoint.length > 40 ? `…${endpoint.slice(-38)}` : endpoint,
      fullName: endpoint,
      size: v.count,
      sevKey: v.sevKey,
    }))
    .sort((a, b) => b.size - a.size)
    .slice(0, top);

  if (data.length === 0) {
    return (
      <div
        className="formal-surface flex items-center justify-center text-[12px] text-mist italic"
        style={{ height }}
      >
        No endpoint-scoped findings.
      </div>
    );
  }

  return (
    <div className="formal-surface" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <Treemap
          data={data}
          dataKey="size"
          nameKey="name"
          stroke="#FAF7F0"
          isAnimationActive={false}
          content={<CellContent />}
        >
          <Tooltip
            content={({ active, payload }) => {
              if (!active || !payload?.[0]?.payload) return null;
              const p = payload[0].payload as {
                fullName: string;
                size: number;
              };
              return (
                <div className="bg-paper border border-hairline rounded-sm px-3 py-2 font-mono text-[11px] text-graphite">
                  <div className="break-all max-w-[320px]">{p.fullName}</div>
                  <div className="mt-1 text-mist">{p.size} findings</div>
                </div>
              );
            }}
          />
        </Treemap>
      </ResponsiveContainer>
    </div>
  );
}

type CellProps = {
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  name?: string;
  sevKey?: string;
};

function CellContent(props: CellProps) {
  const { x = 0, y = 0, width = 0, height = 0, name, sevKey } = props;
  const fill = SEV_HEX[(sevKey as keyof typeof SEV_HEX) || "info"] || "#B7B7B7";
  const showLabel = width > 56 && height > 24;
  return (
    <g>
      <rect x={x} y={y} width={width} height={height} fill={fill} stroke="#FAF7F0" />
      {showLabel && (
        <text
          x={x + 6}
          y={y + 16}
          fill="#FAF7F0"
          fontFamily="ui-monospace"
          fontSize={10}
        >
          {(name || "").slice(0, Math.max(4, Math.floor(width / 6)))}
        </text>
      )}
    </g>
  );
}
