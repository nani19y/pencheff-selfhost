"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { api } from "@/lib/api";

type StrideRow = {
  asset: string;
  category: string;
  threats: string[];
  mitigations: string[];
};

type DreadRow = {
  asset: string;
  category: string;
  threat: string;
  damage: number;
  reproducibility: number;
  exploitability: number;
  affected_users: number;
  discoverability: number;
  score: number;
  priority: "critical" | "high" | "medium" | "low";
  mitigations: string[];
};

type ThreatModel = {
  method: "STRIDE" | "DREAD";
  generated_at: string;
  method_summary?: string;
  assets?: { name: string; type: string }[];
  table?: StrideRow[];
  threats?: DreadRow[];
  category_scores?: Record<string, number>;
};

type ScanThreatModelOut = {
  scan_id: string;
  threat_model: ThreatModel;
  threat_model_updated_at: string | null;
};

const PRIORITY_RANK: Record<DreadRow["priority"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const PRIORITY_COLOR: Record<DreadRow["priority"], string> = {
  critical: "bg-sev-critical text-white",
  high: "bg-sev-high text-white",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
};

export default function ScanThreatModelPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const scanId = mounted ? pathSegment(pathname, 2) : "";
  const [data, setData] = useState<ScanThreatModelOut | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    setError(null);
    api<ScanThreatModelOut>(`/scans/${scanId}/threat-model`)
      .then(setData)
      .catch((e) => setError(String(e?.message || e)));
  }, [scanId]);

  if (error) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-10">
        <BackLink scanId={scanId} />
        <h1 className="mt-4 text-3xl font-bold">Threat model</h1>
        <div className="mt-4 rounded border border-red-300 bg-red-50 p-4 text-sm text-red-700">
          {error.includes("404") || error.includes("no persisted")
            ? "No threat model is attached to this scan. Run a deep-profile scan against the same target to generate one."
            : error}
        </div>
      </main>
    );
  }

  if (!data) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-10">
        <BackLink scanId={scanId} />
        <h1 className="mt-4 text-3xl font-bold">Threat model</h1>
        <div className="mt-4 text-sm text-neutral-500">Loading…</div>
      </main>
    );
  }

  const m = data.threat_model;

  return (
    <main className="mx-auto max-w-5xl px-6 py-10">
      <BackLink scanId={scanId} />
      <div className="mt-4 flex items-baseline justify-between">
        <h1 className="text-3xl font-bold">Threat model</h1>
        <span className="font-mono text-xs uppercase text-neutral-500">
          {m.method}
        </span>
      </div>
      {data.threat_model_updated_at ? (
        <div className="mt-1 text-xs text-neutral-500">
          generated {data.threat_model_updated_at.slice(0, 19)}
        </div>
      ) : null}
      {m.method_summary ? (
        <p className="mt-4 text-sm text-neutral-700">{m.method_summary}</p>
      ) : null}

      {m.method === "DREAD" ? (
        <DreadView model={m} />
      ) : (
        <StrideView model={m} />
      )}
    </main>
  );
}

function BackLink({ scanId }: { scanId: string }) {
  return (
    <Link
      href={`/scans/${scanId}`}
      className="text-xs uppercase tracking-wider text-neutral-500 hover:text-black"
    >
      ← back to assessment
    </Link>
  );
}

function DreadView({ model }: { model: ThreatModel }) {
  const ranked = (model.threats ?? [])
    .slice()
    .sort(
      (a, b) =>
        PRIORITY_RANK[b.priority] - PRIORITY_RANK[a.priority] ||
        b.score - a.score,
    );
  return (
    <>
      {model.category_scores ? (
        <div className="mt-6 rounded border border-neutral-300 p-4">
          <p className="mb-2 text-xs uppercase text-neutral-500">
            Category scores
          </p>
          <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
            {Object.entries(model.category_scores)
              .sort((a, b) => b[1] - a[1])
              .map(([cat, score]) => (
                <div
                  key={cat}
                  className="flex items-baseline justify-between border border-neutral-200 px-3 py-2"
                >
                  <span className="text-sm">{cat}</span>
                  <span className="font-mono font-bold">
                    {score.toFixed(1)}
                  </span>
                </div>
              ))}
          </div>
        </div>
      ) : null}

      <div className="mt-6 overflow-x-auto rounded border border-neutral-300">
        <table className="w-full text-sm">
          <thead className="bg-neutral-50 text-left">
            <tr>
              <th className="px-3 py-2">Asset</th>
              <th className="px-3 py-2">Category</th>
              <th className="px-3 py-2">Threat</th>
              <th className="px-3 py-2 text-right">D</th>
              <th className="px-3 py-2 text-right">R</th>
              <th className="px-3 py-2 text-right">E</th>
              <th className="px-3 py-2 text-right">A</th>
              <th className="px-3 py-2 text-right">D</th>
              <th className="px-3 py-2 text-right">Score</th>
              <th className="px-3 py-2">Priority</th>
            </tr>
          </thead>
          <tbody>
            {ranked.map((r, i) => (
              <tr key={i} className="border-t border-neutral-200 align-top">
                <td className="px-3 py-2 font-mono text-xs">{r.asset}</td>
                <td className="px-3 py-2 text-xs">{r.category}</td>
                <td className="px-3 py-2">{r.threat}</td>
                <td className="px-3 py-2 text-right font-mono">{r.damage}</td>
                <td className="px-3 py-2 text-right font-mono">
                  {r.reproducibility}
                </td>
                <td className="px-3 py-2 text-right font-mono">
                  {r.exploitability}
                </td>
                <td className="px-3 py-2 text-right font-mono">
                  {r.affected_users}
                </td>
                <td className="px-3 py-2 text-right font-mono">
                  {r.discoverability}
                </td>
                <td className="px-3 py-2 text-right font-mono font-bold">
                  {r.score.toFixed(1)}
                </td>
                <td className="px-3 py-2">
                  <span
                    className={`rounded px-2 py-0.5 text-xs uppercase ${PRIORITY_COLOR[r.priority]}`}
                  >
                    {r.priority}
                  </span>
                </td>
              </tr>
            ))}
            {ranked.length === 0 ? (
              <tr>
                <td
                  colSpan={10}
                  className="px-3 py-4 text-center text-sm text-neutral-500"
                >
                  No threats recorded.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </>
  );
}

function StrideView({ model }: { model: ThreatModel }) {
  const rows = model.table ?? [];
  return (
    <div className="mt-6 overflow-x-auto rounded border border-neutral-300">
      <table className="w-full text-sm">
        <thead className="bg-neutral-50 text-left">
          <tr>
            <th className="px-3 py-2">Asset</th>
            <th className="px-3 py-2">Category</th>
            <th className="px-3 py-2">Threats</th>
            <th className="px-3 py-2">Mitigations</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-t border-neutral-200 align-top">
              <td className="px-3 py-2 font-mono text-xs">{r.asset}</td>
              <td className="px-3 py-2 text-xs">{r.category}</td>
              <td className="px-3 py-2">
                <ul className="list-disc pl-4">
                  {r.threats.map((t, j) => (
                    <li key={j}>{t}</li>
                  ))}
                </ul>
              </td>
              <td className="px-3 py-2">
                <ul className="list-disc pl-4">
                  {r.mitigations.map((t, j) => (
                    <li key={j}>{t}</li>
                  ))}
                </ul>
              </td>
            </tr>
          ))}
          {rows.length === 0 ? (
            <tr>
              <td
                colSpan={4}
                className="px-3 py-4 text-center text-sm text-neutral-500"
              >
                No rows recorded.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}
