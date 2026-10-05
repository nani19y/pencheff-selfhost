"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { pathSegment } from "@/lib/route-params";
import { InlineLoading } from "@/components/loading";
import { api } from "@/lib/api";

type Span = {
  span_id: string;
  trace_id: string;
  parent_span_id: string | null;
  name: string;
  kind: string;
  status: string;
  source: string;
  target_id: string | null;
  start_time: string;
  end_time: string | null;
  duration_ms: number | null;
  attributes: Record<string, unknown> | null;
};

type TraceDetail = { trace_id: string; spans: Span[] };

const KIND_STYLE: Record<string, string> = {
  request: "border-l-slate",
  llm: "border-l-gilt",
  tool: "border-l-cyan",
  firewall: "border-l-oxblood",
  detector: "border-l-rust",
  other: "border-l-hairline",
};

const STATUS_STYLE: Record<string, string> = {
  ok: "text-forest",
  blocked: "text-oxblood",
  error: "text-rust",
};

// Order spans into a parent→child tree, return flat rows with a depth.
function ordered(spans: Span[]): { span: Span; depth: number }[] {
  const byParent = new Map<string | null, Span[]>();
  for (const s of spans) {
    const k = s.parent_span_id;
    if (!byParent.has(k)) byParent.set(k, []);
    byParent.get(k)!.push(s);
  }
  const ids = new Set(spans.map((s) => s.span_id));
  const out: { span: Span; depth: number }[] = [];
  function walk(parent: string | null, depth: number) {
    for (const s of byParent.get(parent) ?? []) {
      out.push({ span: s, depth });
      walk(s.span_id, depth + 1);
    }
  }
  // Roots: null parent, or a parent not present in this trace.
  walk(null, 0);
  for (const s of spans) {
    if (s.parent_span_id && !ids.has(s.parent_span_id)) {
      out.push({ span: s, depth: 0 });
      walk(s.span_id, 1);
    }
  }
  return out;
}

export default function TraceDetailPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const traceId = mounted ? pathSegment(pathname, 2) : "";

  const [detail, setDetail] = useState<TraceDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!traceId) return;
    let alive = true;
    api<TraceDetail>(`/traces/${traceId}`)
      .then((d) => alive && setDetail(d))
      .catch((e) => alive && setError(String((e as Error)?.message ?? e)));
    return () => {
      alive = false;
    };
  }, [traceId]);

  return (
    <div>
      <div className="mb-4">
        <Link
          href="/traces"
          className="text-[13px] text-slate hover:text-ink underline underline-offset-[6px] decoration-gilt decoration-1"
        >
          ← All traces
        </Link>
      </div>

      <h1 className="font-display text-[30px] leading-[1.05] tracking-[-0.015em] text-ink">
        Trace
      </h1>
      <p className="mt-1 font-mono text-[12px] text-mist">{traceId}</p>

      {error && (
        <div className="mt-6 advisory-warn font-body text-[13px]">{error}</div>
      )}

      {!detail && !error ? (
        <div className="mt-6">
          <InlineLoading label="Loading trace…" />
        </div>
      ) : detail ? (
        <div className="mt-6 space-y-2">
          {ordered(detail.spans).map(({ span, depth }) => (
            <div
              key={span.span_id}
              className={`formal-surface border-l-2 ${KIND_STYLE[span.kind] ?? "border-l-hairline"} p-4`}
              style={{ marginLeft: depth * 24 }}
            >
              <div className="flex items-center gap-3 flex-wrap">
                <span className="font-display text-[15px] text-ink">
                  {span.name}
                </span>
                <span className="px-1.5 py-0.5 border border-hairline rounded-sm font-mono text-[10px] uppercase tracking-[0.12em] text-slate">
                  {span.kind}
                </span>
                <span
                  className={`font-mono text-[11px] uppercase ${STATUS_STYLE[span.status] ?? "text-slate"}`}
                >
                  {span.status}
                </span>
                {span.duration_ms != null && (
                  <span className="font-mono text-[11px] text-mist">
                    {span.duration_ms}ms
                  </span>
                )}
                <span className="font-mono text-[10px] text-mist">
                  {span.source}
                </span>
              </div>
              {span.attributes && Object.keys(span.attributes).length > 0 && (
                <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
                  {Object.entries(span.attributes).map(([k, v]) => (
                    <div key={k} className="contents">
                      <dt className="font-mono text-[11px] text-mist">{k}</dt>
                      <dd className="font-mono text-[11px] text-graphite break-all">
                        {typeof v === "object" ? JSON.stringify(v) : String(v)}
                      </dd>
                    </div>
                  ))}
                </dl>
              )}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
