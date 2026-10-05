"use client";

import Link from "next/link";
import { SeverityPill } from "@/components/brutal";

type TopFailure = {
  id: string;
  title: string;
  severity: string;
  owasp_category: string;
  technique: string;
  endpoint: string;
};

export function TopFailuresList({
  failures,
  scanId,
}: {
  failures: TopFailure[];
  scanId: string;
}) {
  if (failures.length === 0) {
    return (
      <div className="formal-surface p-6 text-center text-[12px] text-mist italic">
        No red-team failures recorded.
      </div>
    );
  }

  return (
    <ol className="formal-surface divide-y divide-hairline">
      {failures.map((f, i) => (
        <li key={f.id || i} className="p-4">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono text-[11px] text-mist tracking-[0.08em] w-5">
              {String(i + 1).padStart(2, "0")}
            </span>
            <SeverityPill severity={f.severity} />
            {f.owasp_category && (
              <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-graphite border border-hairline rounded-sm px-2 py-0.5">
                {f.owasp_category}
              </span>
            )}
            {f.id ? (
              <Link
                href={`/scans/${scanId}/findings/${f.id}`}
                className="font-body text-[13px] font-medium text-ink hover:underline underline-offset-[4px] decoration-gilt decoration-1 flex-1 min-w-0 truncate"
              >
                {f.title}
              </Link>
            ) : (
              <span className="font-body text-[13px] font-medium text-ink flex-1 min-w-0 truncate">
                {f.title}
              </span>
            )}
          </div>
          <div className="mt-2 ml-8 flex items-center gap-3 flex-wrap font-mono text-[11px] text-slate">
            {f.technique && (
              <span className="text-graphite">technique: {f.technique}</span>
            )}
            {f.endpoint && (
              <span className="text-mist break-all">{f.endpoint}</span>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}
