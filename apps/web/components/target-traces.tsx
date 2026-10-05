"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type TraceSummary = {
  trace_id: string;
  name: string;
  status: string;
  source: string;
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

/** Recent runtime-protection traces for one LLM target (proxy requests:
 *  LLM call · firewall decision · detector verdict). Rendered on the target
 *  detail page. */
export function TargetTraces({ targetId }: { targetId: string }) {
  const [traces, setTraces] = useState<TraceSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api<TraceSummary[]>(`/traces?target_id=${targetId}&limit=25`)
      .then((t) => alive && setTraces(t))
      .catch((e) => alive && setError(String((e as Error)?.message ?? e)));
    return () => {
      alive = false;
    };
  }, [targetId]);

  if (error) {
    return <p className="text-[13px] text-slate">{error}</p>;
  }
  if (traces === null) {
    return <p className="text-[13px] text-slate italic">Loading traces…</p>;
  }
  if (traces.length === 0) {
    return (
      <p className="text-[13px] text-slate">
        No runtime traces yet. Send a request through this target&apos;s proxy
        URL and it&apos;ll appear here.
      </p>
    );
  }

  return (
    <div className="formal-surface overflow-hidden">
      <table className="w-full text-[13px]">
        <thead>
          <tr className="border-b border-hairline text-left font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
            <th className="px-4 py-2.5">Trace</th>
            <th className="px-4 py-2.5">Status</th>
            <th className="px-4 py-2.5">Spans</th>
            <th className="px-4 py-2.5">Duration</th>
            <th className="px-4 py-2.5">When</th>
          </tr>
        </thead>
        <tbody>
          {traces.map((t) => (
            <tr
              key={t.trace_id}
              className="border-b border-hairline/60 hover:bg-vellum/50"
            >
              <td className="px-4 py-2.5">
                <Link
                  href={`/traces/${t.trace_id}`}
                  className="text-ink hover:underline underline-offset-[5px] decoration-gilt font-mono text-[11px]"
                >
                  {t.name} · {t.trace_id.slice(0, 10)}
                </Link>
              </td>
              <td className="px-4 py-2.5">
                <span
                  className={`px-1.5 py-0.5 border rounded-sm font-mono text-[10px] uppercase tracking-[0.12em] ${
                    STATUS_STYLE[t.status] ?? "text-slate border-hairline"
                  }`}
                >
                  {t.status}
                </span>
              </td>
              <td className="px-4 py-2.5 text-slate">{t.span_count}</td>
              <td className="px-4 py-2.5 text-slate">
                {t.duration_ms != null ? `${t.duration_ms}ms` : "—"}
              </td>
              <td className="px-4 py-2.5 text-slate">
                {new Date(t.started_at).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
