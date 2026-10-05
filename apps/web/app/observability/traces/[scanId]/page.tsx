"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { api } from "@/lib/api";

type Span = {
  span_id: string;
  parent_span_id: string | null;
  trace_id: string;
  name: string;
  service_name: string;
  scope_name: string | null;
  kind: number;
  status_code: number | null;
  status_message: string | null;
  started_at: string;
  ended_at: string | null;
  duration_ns: number | null;
  attributes: Record<string, unknown> | null;
  children: Span[];
};

type TraceResp = {
  scan_id: string;
  span_count: number;
  tree: Span[];
};

function fmtMs(ns: number | null) {
  if (ns == null) return "—";
  return `${(ns / 1e6).toFixed(1)} ms`;
}

function SpanRow({
  span,
  depth,
  traceStart,
  traceWidth,
}: {
  span: Span;
  depth: number;
  traceStart: number;
  traceWidth: number;
}) {
  const start = new Date(span.started_at).getTime();
  const end = span.ended_at ? new Date(span.ended_at).getTime() : start;
  const offset = traceWidth > 0 ? ((start - traceStart) / traceWidth) * 100 : 0;
  const width =
    traceWidth > 0 ? Math.max(0.5, ((end - start) / traceWidth) * 100) : 1;
  const failed = span.status_code === 2;

  return (
    <>
      <div className="flex items-center gap-3 py-1.5 text-xs">
        <div className="w-72 truncate" style={{ paddingLeft: depth * 16 }}>
          <span className="font-mono">{span.name}</span>
          <span className="ml-2 text-neutral-400">{span.service_name}</span>
        </div>
        <div className="w-20 text-right text-neutral-600">
          {fmtMs(span.duration_ns)}
        </div>
        <div className="relative h-4 flex-1 rounded bg-neutral-100">
          <div
            className={`absolute h-4 rounded ${failed ? "bg-red-500" : "bg-blue-500"}`}
            style={{ left: `${offset}%`, width: `${width}%` }}
            title={`${span.name} • ${fmtMs(span.duration_ns)}`}
          />
        </div>
      </div>
      {span.children.map((c) => (
        <SpanRow
          key={c.span_id}
          span={c}
          depth={depth + 1}
          traceStart={traceStart}
          traceWidth={traceWidth}
        />
      ))}
    </>
  );
}

export default function TracePage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const scanId = mounted ? pathSegment(pathname, 3) : "";
  const [data, setData] = useState<TraceResp | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    api<TraceResp>(`/observability/scans/${scanId}/trace`)
      .then(setData)
      .catch((e) => setError(String(e?.message || e)));
  }, [scanId]);

  if (error) {
    return (
      <main className="mx-auto max-w-6xl px-6 py-10">
        <h1 className="mb-4 text-3xl font-bold">Trace</h1>
        <div className="rounded border border-red-300 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      </main>
    );
  }
  if (!data) {
    return (
      <main className="mx-auto max-w-6xl px-6 py-10">
        <h1 className="mb-4 text-3xl font-bold">Trace</h1>
        <div className="text-sm text-neutral-500">Loading…</div>
      </main>
    );
  }

  // Compute global trace window across all roots so the bars share an axis.
  const allStarts = collectStarts(data.tree);
  const allEnds = collectEnds(data.tree);
  const traceStart = allStarts.length ? Math.min(...allStarts) : 0;
  const traceEnd = allEnds.length ? Math.max(...allEnds) : traceStart;
  const traceWidth = traceEnd - traceStart || 1;

  return (
    <main className="mx-auto max-w-6xl px-6 py-10">
      <h1 className="mb-2 text-3xl font-bold">Trace</h1>
      <div className="mb-6 text-sm text-neutral-500">
        scan_id <span className="font-mono">{data.scan_id}</span> ·{" "}
        {data.span_count} spans · window {fmtMs(traceWidth * 1e6)}
      </div>
      <div className="rounded border border-neutral-300 bg-white p-2">
        {data.tree.map((root) => (
          <SpanRow
            key={root.span_id}
            span={root}
            depth={0}
            traceStart={traceStart}
            traceWidth={traceWidth}
          />
        ))}
        {data.tree.length === 0 ? (
          <div className="px-3 py-6 text-center text-sm text-neutral-500">
            No spans recorded for this scan_id.
          </div>
        ) : null}
      </div>
    </main>
  );
}

function collectStarts(spans: Span[]): number[] {
  const out: number[] = [];
  function walk(s: Span) {
    out.push(new Date(s.started_at).getTime());
    s.children.forEach(walk);
  }
  spans.forEach(walk);
  return out;
}

function collectEnds(spans: Span[]): number[] {
  const out: number[] = [];
  function walk(s: Span) {
    if (s.ended_at) out.push(new Date(s.ended_at).getTime());
    s.children.forEach(walk);
  }
  spans.forEach(walk);
  return out;
}
