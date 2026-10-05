"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { InlineLoading } from "@/components/loading";
import { api } from "@/lib/api";

type TraceSummary = {
  trace_id: string;
  name: string;
  kind: string;
  status: string;
  source: string;
  target_id: string | null;
  started_at: string;
  duration_ms: number | null;
  span_count: number;
  model: string | null;
};

const STATUS_STYLE: Record<string, string> = {
  ok: "text-forest border-forest/40",
  blocked: "text-oxblood border-oxblood/40",
  error: "text-rust border-rust/40",
};

function StatusPill({ status }: { status: string }) {
  return (
    <span
      className={`px-1.5 py-0.5 border rounded-sm font-mono text-[10px] uppercase tracking-[0.12em] ${
        STATUS_STYLE[status] ?? "text-slate border-hairline"
      }`}
    >
      {status}
    </span>
  );
}

export default function TracesPage() {
  const [traces, setTraces] = useState<TraceSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api<TraceSummary[]>("/traces?limit=100")
      .then((t) => alive && setTraces(t))
      .catch((e) => alive && setError(String((e as Error)?.message ?? e)));
    return () => {
      alive = false;
    };
  }, []);

  return (
    <div>
      <div className="mb-8">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">
          Runtime protection
        </p>
        <h1 className="mt-2 font-display text-[36px] leading-[1.05] tracking-[-0.015em] text-ink">
          Runtime traces.
        </h1>
        <p className="mt-2 text-[14px] text-slate max-w-[70ch]">
          Every request through the guardrail proxy and every trace your SDK
          sends lands here — the LLM call, the firewall decision, the detector
          verdict. Click a trace to see its spans.
        </p>
      </div>

      {error && (
        <div className="mb-6 advisory-warn font-body text-[13px]">{error}</div>
      )}

      {traces === null ? (
        <InlineLoading label="Loading traces…" />
      ) : traces.length === 0 ? (
        <div className="formal-surface p-10 text-center">
          <p className="eyebrow-gilt">No traces yet</p>
          <h3 className="mt-3 font-display text-[22px] text-ink">
            Nothing has flowed through the proxy yet.
          </h3>
          <p className="mt-2 text-[13px] text-slate max-w-[60ch] mx-auto">
            Point an app at your target&apos;s proxy URL (Targets → an LLM
            target → guardrails), or send spans to{" "}
            <code className="font-mono text-[12px]">POST /v1/traces</code>.
          </p>
        </div>
      ) : (
        <div className="formal-surface overflow-hidden">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-b border-hairline text-left font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
                <th className="px-4 py-3">Trace</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Model</th>
                <th className="px-4 py-3">Spans</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Duration</th>
                <th className="px-4 py-3">When</th>
              </tr>
            </thead>
            <tbody>
              {traces.map((t) => (
                <tr
                  key={t.trace_id}
                  className="border-b border-hairline/60 hover:bg-vellum/50"
                >
                  <td className="px-4 py-3">
                    <Link
                      href={`/traces/${t.trace_id}`}
                      className="text-ink hover:underline underline-offset-[5px] decoration-gilt"
                    >
                      <span className="font-display">{t.name}</span>{" "}
                      <span className="font-mono text-[11px] text-mist">
                        {t.trace_id.slice(0, 12)}
                      </span>
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill status={t.status} />
                  </td>
                  <td className="px-4 py-3 font-mono text-[12px] text-slate">
                    {t.model ?? "—"}
                  </td>
                  <td className="px-4 py-3 text-slate">{t.span_count}</td>
                  <td className="px-4 py-3 font-mono text-[11px] text-slate">
                    {t.source}
                  </td>
                  <td className="px-4 py-3 text-slate">
                    {t.duration_ms != null ? `${t.duration_ms}ms` : "—"}
                  </td>
                  <td className="px-4 py-3 text-slate">
                    {new Date(t.started_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
