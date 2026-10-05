"use client";

import { SeverityPill } from "@/components/brutal";

type RepoFinding = {
  id: string;
  severity?: string | null;
  cve?: string | null;
  package?: string | null;
  installed_version?: string | null;
  fixed_version?: string | null;
  fix_status?: string | null;
  fix_pr_url?: string | null;
};

const SEV_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const FIX_LABEL: Record<string, string> = {
  none: "—",
  proposed: "Proposed",
  pr_open: "PR open",
  merged: "Merged",
};

export function CveTable({
  findings,
  limit = 12,
}: {
  findings: RepoFinding[];
  limit?: number;
}) {
  const cves = findings
    .filter((f) => f.cve)
    .sort((a, b) => {
      const ra = SEV_RANK[(a.severity || "info").toLowerCase()] ?? 0;
      const rb = SEV_RANK[(b.severity || "info").toLowerCase()] ?? 0;
      return rb - ra;
    })
    .slice(0, limit);

  if (cves.length === 0) {
    return (
      <div className="formal-surface p-6 text-center text-[12px] text-mist italic">
        No CVE-tagged findings in this scan.
      </div>
    );
  }

  return (
    <div className="formal-surface overflow-hidden">
      <table className="w-full font-body text-[12px]">
        <thead>
          <tr className="border-b border-hairline">
            <th className="text-left p-3 font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
              Severity
            </th>
            <th className="text-left p-3 font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
              CVE
            </th>
            <th className="text-left p-3 font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
              Package
            </th>
            <th className="text-left p-3 font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
              Installed → Fix
            </th>
            <th className="text-left p-3 font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
              Fix
            </th>
          </tr>
        </thead>
        <tbody>
          {cves.map((f) => {
            const fixLabel = FIX_LABEL[f.fix_status || "none"] || f.fix_status;
            return (
              <tr key={f.id} className="border-b border-hairline last:border-b-0">
                <td className="p-3">
                  <SeverityPill severity={f.severity || "info"} />
                </td>
                <td className="p-3 font-mono text-[12px] text-ink">
                  {f.cve}
                </td>
                <td className="p-3 font-mono text-[12px] text-graphite break-all">
                  {f.package || "—"}
                </td>
                <td className="p-3 font-mono text-[11px] text-slate">
                  {f.installed_version || "—"}
                  {f.fixed_version && (
                    <>
                      <span className="text-mist mx-1">→</span>
                      <span className="text-forest">{f.fixed_version}</span>
                    </>
                  )}
                </td>
                <td className="p-3 font-mono text-[11px]">
                  {f.fix_pr_url ? (
                    <a
                      href={f.fix_pr_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-ink underline underline-offset-[4px] decoration-gilt decoration-1"
                    >
                      {fixLabel} ↗
                    </a>
                  ) : (
                    <span className="text-mist">{fixLabel}</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
