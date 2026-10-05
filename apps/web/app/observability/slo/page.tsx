"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type SloSummary = {
  window_minutes: number;
  request_count: number;
  error_count: number;
  error_rate: number;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
  active_scans: number;
  queued_scans: number;
};

function Card({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded border border-neutral-300 p-4">
      <div className="text-xs uppercase text-neutral-500">{label}</div>
      <div className="mt-1 text-2xl font-bold">{value}</div>
      {sub ? <div className="mt-1 text-xs text-neutral-500">{sub}</div> : null}
    </div>
  );
}

export default function SloPage() {
  const [data, setData] = useState<SloSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [windowMin, setWindowMin] = useState(60);

  useEffect(() => {
    setError(null);
    api<SloSummary>(`/observability/slo?window_minutes=${windowMin}`)
      .then(setData)
      .catch((e) => setError(String(e?.message || e)));
  }, [windowMin]);

  if (error) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-10">
        <h1 className="mb-4 text-3xl font-bold">SLO dashboard</h1>
        <div className="rounded border border-red-300 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-5xl px-6 py-10">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-3xl font-bold">SLO dashboard</h1>
        <select
          className="rounded border border-neutral-300 px-3 py-1 text-sm"
          value={windowMin}
          onChange={(e) => setWindowMin(parseInt(e.target.value, 10))}
        >
          <option value={15}>last 15 min</option>
          <option value={60}>last 1 hour</option>
          <option value={360}>last 6 hours</option>
          <option value={1440}>last 24 hours</option>
        </select>
      </div>
      {data ? (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <Card label="Requests" value={data.request_count.toLocaleString()} />
          <Card
            label="Error rate"
            value={`${(data.error_rate * 100).toFixed(2)}%`}
            sub={`${data.error_count} errors`}
          />
          <Card label="p50 latency" value={`${data.p50_ms.toFixed(1)} ms`} />
          <Card label="p95 latency" value={`${data.p95_ms.toFixed(1)} ms`} />
          <Card label="p99 latency" value={`${data.p99_ms.toFixed(1)} ms`} />
          <Card label="Active scans" value={data.active_scans.toString()} />
          <Card label="Queued scans" value={data.queued_scans.toString()} />
        </div>
      ) : (
        <div className="text-sm text-neutral-500">Loading…</div>
      )}
    </main>
  );
}
