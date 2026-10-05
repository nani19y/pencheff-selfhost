"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { api } from "@/lib/api";

type SeverityBucket = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

type Control = {
  id: string;
  control: string;
  title: string;
  finding_count: number;
  severity_breakdown: SeverityBucket;
  finding_ids: string[];
};

type FrameworkSummary = {
  controls: Control[];
  covered: number;
  total: number;
};

type ComplianceFinding = {
  id: string;
  title: string;
  severity: string;
  category: string;
  owasp_category: string | null;
  scanner: string | null;
  compliance: Record<string, string[]>;
};

type ComplianceRollup = {
  scan_id: string;
  target_kind: "url" | "repo" | "llm";
  frameworks: string[];
  totals: { findings: number; controls_touched: number };
  frameworks_summary: Record<string, FrameworkSummary>;
  findings: ComplianceFinding[];
};

const SEV_BAR: Record<string, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export default function RepoScanCompliancePage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const scanId = mounted ? pathSegment(pathname, 3) : "";
  const [data, setData] = useState<ComplianceRollup | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeFramework, setActiveFramework] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    setError(null);
    api<ComplianceRollup>(`/repos/scans/${scanId}/compliance`)
      .then((d) => {
        setData(d);
        setActiveFramework(d.frameworks[0] ?? null);
      })
      .catch((e) => setError(String(e?.message || e)));
  }, [scanId]);

  if (error) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-10">
        <BackLink scanId={scanId} />
        <h1 className="mt-4 text-3xl font-bold">Compliance mapping</h1>
        <div className="mt-4 rounded border border-red-300 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      </main>
    );
  }

  if (!data) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-10">
        <BackLink scanId={scanId} />
        <h1 className="mt-4 text-3xl font-bold">Compliance mapping</h1>
        <div className="mt-4 text-sm text-neutral-500">Loading…</div>
      </main>
    );
  }

  const fw = activeFramework ?? data.frameworks[0];
  const summary = fw ? data.frameworks_summary[fw] : null;

  return (
    <main className="mx-auto max-w-6xl px-6 py-10">
      <BackLink scanId={scanId} />
      <div className="mt-4 flex items-baseline justify-between gap-4 flex-wrap">
        <h1 className="text-3xl font-bold">Compliance mapping</h1>
        <span className="font-mono text-xs uppercase text-neutral-500">
          Repository target
        </span>
      </div>

      <p className="mt-3 text-sm text-neutral-700 max-w-[72ch]">
        Every active SAST · SCA · IaC · secret-scan finding from this repo scan,
        fanned out across the same framework set used for URL DAST scans &mdash;
        so audit evidence is portable between the two surfaces.
      </p>

      <div className="mt-6 grid grid-cols-2 gap-3 md:grid-cols-4">
        <SummaryStat label="Findings" value={data.totals.findings} />
        <SummaryStat
          label="Controls touched"
          value={data.totals.controls_touched}
        />
        <SummaryStat label="Frameworks" value={data.frameworks.length} />
        <SummaryStat label="Target" value="REPO" />
      </div>

      <FrameworkTabs
        frameworks={data.frameworks}
        active={fw}
        summary={data.frameworks_summary}
        onChange={setActiveFramework}
      />

      {fw && summary ? (
        <FrameworkPanel framework={fw} summary={summary} />
      ) : (
        <p className="mt-6 text-sm text-neutral-500">
          No frameworks enabled for this scan.
        </p>
      )}

      <FindingsTable findings={data.findings} />
    </main>
  );
}

function BackLink({ scanId }: { scanId: string }) {
  return (
    <Link
      href={`/repos/scans/${scanId}`}
      className="text-xs uppercase tracking-wider text-neutral-500 hover:text-black"
    >
      ← back to repo scan
    </Link>
  );
}

function SummaryStat({
  label,
  value,
}: {
  label: string;
  value: string | number;
}) {
  return (
    <div className="border border-neutral-300 px-4 py-3">
      <p className="font-mono text-[10px] uppercase tracking-wider text-neutral-500">
        {label}
      </p>
      <p className="mt-1 font-mono text-2xl font-bold">{value}</p>
    </div>
  );
}

function FrameworkTabs({
  frameworks,
  active,
  summary,
  onChange,
}: {
  frameworks: string[];
  active: string | null;
  summary: Record<string, FrameworkSummary>;
  onChange: (f: string) => void;
}) {
  return (
    <nav className="mt-8 border-b border-neutral-300">
      <ul className="flex flex-wrap">
        {frameworks.map((f) => {
          const fs = summary[f];
          const ctrlCount = fs ? fs.covered : 0;
          const denom = fs ? fs.total : 0;
          const isActive = f === active;
          return (
            <li key={f}>
              <button
                type="button"
                onClick={() => onChange(f)}
                className={`px-4 py-2 text-sm border-b-2 transition-colors ${
                  isActive
                    ? "border-black font-bold"
                    : "border-transparent text-neutral-600 hover:text-black"
                }`}
              >
                {f}
                <span className="ml-2 font-mono text-[11px] text-neutral-500">
                  {denom > 0 && f.startsWith("OWASP")
                    ? `${ctrlCount}/${denom}`
                    : ctrlCount}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

function FrameworkPanel({
  framework,
  summary,
}: {
  framework: string;
  summary: FrameworkSummary;
}) {
  if (summary.controls.length === 0) {
    return (
      <div className="mt-6 rounded border border-neutral-300 bg-neutral-50 p-6 text-sm text-neutral-600">
        No findings on this scan map onto <strong>{framework}</strong> controls.
      </div>
    );
  }

  return (
    <section className="mt-6 overflow-x-auto rounded border border-neutral-300">
      <table className="w-full text-sm">
        <thead className="bg-neutral-50 text-left">
          <tr>
            <th className="px-3 py-2">Control</th>
            <th className="px-3 py-2 text-right">Findings</th>
            <th className="px-3 py-2">Severity</th>
          </tr>
        </thead>
        <tbody>
          {summary.controls.map((c) => (
            <tr key={c.id} className="border-t border-neutral-200 align-top">
              <td className="px-3 py-2">
                <p className="font-mono text-xs uppercase tracking-wider text-neutral-500">
                  {c.control}
                </p>
                <p className="mt-1">{c.title}</p>
              </td>
              <td className="px-3 py-2 text-right font-mono font-bold">
                {c.finding_count}
              </td>
              <td className="px-3 py-2">
                <SeverityRibbon breakdown={c.severity_breakdown} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function SeverityRibbon({ breakdown }: { breakdown: SeverityBucket }) {
  const order: (keyof SeverityBucket)[] = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
  ];
  const total = order.reduce((a, k) => a + (breakdown[k] || 0), 0);
  if (total === 0) {
    return <span className="text-xs text-neutral-500">—</span>;
  }
  return (
    <div className="flex w-full items-center gap-1">
      {order.map((sev) => {
        const n = breakdown[sev] || 0;
        if (n === 0) return null;
        return (
          <span
            key={sev}
            title={`${n} ${sev}`}
            className={`inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono uppercase ${SEV_BAR[sev]} text-white`}
          >
            {sev[0]}·{n}
          </span>
        );
      })}
    </div>
  );
}

function FindingsTable({ findings }: { findings: ComplianceFinding[] }) {
  if (findings.length === 0) return null;
  return (
    <section className="mt-12">
      <h2 className="text-xl font-bold">Per-finding mapping</h2>
      <p className="mt-1 text-sm text-neutral-600">
        Each row shows one repo finding plus the controls it triggers across
        every enabled framework.
      </p>
      <div className="mt-4 overflow-x-auto rounded border border-neutral-300">
        <table className="w-full text-sm">
          <thead className="bg-neutral-50 text-left">
            <tr>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">Finding</th>
              <th className="px-3 py-2">Category</th>
              <th className="px-3 py-2">Mapped controls</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => {
              const sev = (f.severity || "info").toLowerCase();
              return (
                <tr
                  key={f.id}
                  className="border-t border-neutral-200 align-top"
                >
                  <td className="px-3 py-2">
                    <span
                      className={`inline-block px-2 py-0.5 text-[10px] font-mono uppercase ${SEV_BAR[sev]} text-white`}
                    >
                      {sev}
                    </span>
                  </td>
                  <td className="px-3 py-2">{f.title}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {f.category}
                    {f.scanner ? (
                      <span className="ml-2 text-neutral-500">
                        ({f.scanner})
                      </span>
                    ) : null}
                  </td>
                  <td className="px-3 py-2">
                    {Object.keys(f.compliance).length === 0 ? (
                      <span className="text-xs text-neutral-500">—</span>
                    ) : (
                      <ul className="space-y-1">
                        {Object.entries(f.compliance).map(([fw, ctrls]) => (
                          <li key={fw} className="text-xs">
                            <span className="font-mono text-neutral-500">
                              {fw}:
                            </span>{" "}
                            {ctrls.join(", ")}
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
