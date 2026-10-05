"use client";

import Link from "next/link";
import { SeverityPill } from "@/components/brutal";
import { PriorityStrip } from "@/components/priority-badges";

type Finding = {
  id: string;
  title: string;
  severity: string;
  endpoint: string | null;
  risk_score: number | null;
  ssvc_decision: string | null;
  reachability: string | null;
  epss: number | null;
  kev: boolean;
  cvss_score: number | null;
};

export function TopRiskList({
  findings,
  scanId,
  limit = 10,
}: {
  findings: Finding[];
  scanId: string;
  limit?: number;
}) {
  const sorted = [...findings]
    .sort((a, b) => {
      const ra = a.risk_score ?? -1;
      const rb = b.risk_score ?? -1;
      if (ra !== rb) return rb - ra;
      return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
    })
    .slice(0, limit);

  if (sorted.length === 0) {
    return (
      <div className="formal-surface p-6 text-center text-[12px] text-mist italic">
        No findings to prioritise.
      </div>
    );
  }

  return (
    <ol className="formal-surface divide-y divide-hairline">
      {sorted.map((f, i) => (
        <li key={f.id} className="p-4">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono text-[11px] text-mist tracking-[0.08em] w-5">
              {String(i + 1).padStart(2, "0")}
            </span>
            <SeverityPill severity={f.severity} />
            <Link
              href={`/scans/${scanId}/findings/${f.id}`}
              className="font-body text-[13px] font-medium text-ink hover:underline underline-offset-[4px] decoration-gilt decoration-1 flex-1 min-w-0 truncate"
            >
              {f.title}
            </Link>
            {f.cvss_score != null && (
              <span className="font-mono text-[12px] text-graphite">
                {f.cvss_score.toFixed(1)}
              </span>
            )}
          </div>
          <div className="mt-2 ml-8 flex items-center gap-3 flex-wrap">
            <PriorityStrip
              riskScore={f.risk_score}
              reachability={f.reachability}
              ssvc={f.ssvc_decision}
              epss={f.epss}
              kev={f.kev}
            />
            {f.endpoint && (
              <span className="font-mono text-[11px] text-mist break-all max-w-[40ch] truncate">
                {f.endpoint}
              </span>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}
