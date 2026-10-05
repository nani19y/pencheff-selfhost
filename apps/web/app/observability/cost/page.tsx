"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type CostRow = {
  model: string | null;
  input_tokens: number;
  output_tokens: number;
  calls: number;
};
type CostResp = { window_hours: number; by_model: CostRow[] };

export default function CostPage() {
  const [data, setData] = useState<CostResp | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [windowH, setWindowH] = useState(168);

  useEffect(() => {
    api<CostResp>(`/observability/cost?window_hours=${windowH}`)
      .then(setData)
      .catch((e) => setError(String(e?.message || e)));
  }, [windowH]);

  const totalInput = data ? data.by_model.reduce((s, r) => s + Number(r.input_tokens), 0) : 0;
  const totalOutput = data ? data.by_model.reduce((s, r) => s + Number(r.output_tokens), 0) : 0;
  const totalCalls = data ? data.by_model.reduce((s, r) => s + Number(r.calls), 0) : 0;

  return (
    <main className="mx-auto max-w-5xl px-6 py-10">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-3xl font-bold">LLM cost</h1>
        <select
          className="rounded border border-neutral-300 px-3 py-1 text-sm"
          value={windowH}
          onChange={(e) => setWindowH(parseInt(e.target.value, 10))}
        >
          <option value={24}>last 24 hours</option>
          <option value={168}>last 7 days</option>
          <option value={720}>last 30 days</option>
        </select>
      </div>

      {error ? (
        <div className="mb-4 rounded border border-red-300 bg-red-50 p-3 text-sm text-red-700">
          {error}
        </div>
      ) : null}

      {data ? (
        <>
          <div className="mb-6 grid grid-cols-3 gap-4">
            <div className="rounded border border-neutral-300 p-4">
              <div className="text-xs uppercase text-neutral-500">Input tokens</div>
              <div className="mt-1 text-2xl font-bold">
                {totalInput.toLocaleString()}
              </div>
            </div>
            <div className="rounded border border-neutral-300 p-4">
              <div className="text-xs uppercase text-neutral-500">Output tokens</div>
              <div className="mt-1 text-2xl font-bold">
                {totalOutput.toLocaleString()}
              </div>
            </div>
            <div className="rounded border border-neutral-300 p-4">
              <div className="text-xs uppercase text-neutral-500">LLM calls</div>
              <div className="mt-1 text-2xl font-bold">
                {totalCalls.toLocaleString()}
              </div>
            </div>
          </div>

          <table className="w-full text-sm">
            <thead className="bg-neutral-100 text-left">
              <tr>
                <th className="px-3 py-2">Model</th>
                <th className="px-3 py-2 text-right">Calls</th>
                <th className="px-3 py-2 text-right">Input tokens</th>
                <th className="px-3 py-2 text-right">Output tokens</th>
              </tr>
            </thead>
            <tbody>
              {data.by_model.map((r) => (
                <tr
                  key={r.model || "unknown"}
                  className="border-t border-neutral-200"
                >
                  <td className="px-3 py-2 font-mono text-xs">
                    {r.model || "unknown"}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {Number(r.calls).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {Number(r.input_tokens).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {Number(r.output_tokens).toLocaleString()}
                  </td>
                </tr>
              ))}
              {data.by_model.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-3 py-4 text-center text-sm text-neutral-500">
                    No LLM activity recorded in this window.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </>
      ) : (
        <div className="text-sm text-neutral-500">Loading…</div>
      )}
    </main>
  );
}
