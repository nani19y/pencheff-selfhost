"use client";

// Phase 3.2 UI — API discovery from runtime traffic.
//
// Sits at /engagements/{id}/api-discovery as a sibling of the existing
// /engagements/{id}/threat-model page. Surfaces the synthesised
// OpenAPI spec + drift findings produced by the
// modules/api_discovery/synth.py + services/api_drift.py pair.

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import Link from "next/link";
import { api } from "@/lib/api";

type DriftRow = {
  drift_kind: "shadow" | "phantom" | "method-drift";
  severity: "high" | "medium" | "low" | "info" | "critical";
  title: string;
  path: string;
  method: string | null;
};

type ApiDiscoveryOut = {
  engagement_id: string;
  endpoints_seen: number;
  flows_processed: number;
  auth_schemes: string[];
  template_replacements: Record<string, number>;
  spec_url: string | null;
  drift: DriftRow[];
};

const KIND_LABEL: Record<DriftRow["drift_kind"], string> = {
  shadow: "Shadow endpoint (live, undocumented)",
  phantom: "Phantom endpoint (declared, no traffic)",
  "method-drift": "Method drift",
};

const SEV_TONE: Record<DriftRow["severity"], string> = {
  critical: "border-oxblood text-oxblood",
  high: "border-oxblood text-oxblood",
  medium: "border-gilt text-graphite",
  low: "border-hairline text-slate",
  info: "border-hairline text-slate",
};

export default function ApiDiscoveryPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const id = mounted ? pathSegment(pathname, 2) : "";
  const [data, setData] = useState<ApiDiscoveryOut | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    api<ApiDiscoveryOut>(`/engagements/${id}/api-discovery`)
      .then(setData)
      .catch((e) => setError(String(e?.message || e)));
  }, [id]);

  return (
    <main className="mx-auto max-w-5xl px-6 py-10 space-y-8">
      <header className="flex items-baseline justify-between gap-4">
        <div>
          <p className="eyebrow-gilt">API discovery</p>
          <h1 className="mt-3 font-display text-[36px] tracking-[-0.015em]">
            Runtime-discovered API
          </h1>
        </div>
        <Link
          href={`/engagements/${id}`}
          className="text-[12px] underline underline-offset-2"
        >
          ← back to engagement
        </Link>
      </header>

      {error && <p className="text-[13px] text-oxblood font-mono">{error}</p>}

      {!data && !error && <p className="text-[13px] text-mist">Loading…</p>}

      {data && (
        <>
          <section className="formal-surface p-6 grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
            <Stat label="Endpoints" value={data.endpoints_seen} />
            <Stat label="Flows" value={data.flows_processed} />
            <Stat label="Auth schemes" value={data.auth_schemes.length || 0} />
            <Stat label="Drift findings" value={data.drift.length} />
          </section>

          {data.auth_schemes.length > 0 && (
            <section>
              <p className="eyebrow mb-2">Auth schemes detected</p>
              <div className="flex flex-wrap gap-2 font-mono text-[12px]">
                {data.auth_schemes.map((s) => (
                  <span
                    key={s}
                    className="border border-hairline rounded-sm px-2 py-0.5 text-slate"
                  >
                    {s}
                  </span>
                ))}
              </div>
            </section>
          )}

          <section>
            <div className="flex items-baseline justify-between mb-3">
              <p className="eyebrow">Drift</p>
              {data.spec_url && (
                <a
                  href={data.spec_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[12px] underline underline-offset-2"
                >
                  Download synthesised OpenAPI 3.1 →
                </a>
              )}
            </div>
            {data.drift.length === 0 ? (
              <p className="text-[13px] text-mist">
                No drift detected — every endpoint observed in traffic is in the
                declared OpenAPI spec.
              </p>
            ) : (
              <table className="w-full text-[13px] border border-hairline">
                <thead className="bg-vellum">
                  <tr>
                    <th className="px-3 py-2 text-left">Severity</th>
                    <th className="px-3 py-2 text-left">Kind</th>
                    <th className="px-3 py-2 text-left">Method</th>
                    <th className="px-3 py-2 text-left">Path</th>
                  </tr>
                </thead>
                <tbody className="font-mono text-[12px]">
                  {data.drift.map((d, i) => (
                    <tr key={i} className="border-t border-hairline">
                      <td className="px-3 py-2">
                        <span
                          className={
                            "inline-block rounded-sm border px-1.5 py-0.5 text-[10px] uppercase " +
                            SEV_TONE[d.severity]
                          }
                        >
                          {d.severity}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        {KIND_LABEL[d.drift_kind] || d.drift_kind}
                      </td>
                      <td className="px-3 py-2">{d.method || "—"}</td>
                      <td className="px-3 py-2">{d.path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <p className="text-[11px] text-mist">
            Synthesised from captured proxy traffic. URL ids are templated
            automatically (UUID, integer, base36). Provenance recorded under{" "}
            <code>~/.pencheff/data/provenance/api_discovery/</code>.
          </p>
        </>
      )}
    </main>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <p className="font-mono text-[10px] uppercase text-mist tracking-wider">
        {label}
      </p>
      <p className="mt-1 font-display text-[28px] text-ink">{value}</p>
    </div>
  );
}
