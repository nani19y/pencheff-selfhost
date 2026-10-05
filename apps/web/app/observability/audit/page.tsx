"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type AuditRow = {
  id: string;
  user_id: string | null;
  org_id: string | null;
  workspace_id: string | null;
  action: string;
  entity_type: string | null;
  entity_id: string | null;
  meta: Record<string, unknown> | null;
  created_at: string;
  trace_id: string | null;
  request_ip: string | null;
  user_agent: string | null;
  hashed: boolean;
};

type AuditList = { items: AuditRow[]; limit: number; offset: number };
type VerifyResult = { ok: boolean; checked: number; broken_at: string | null };

export default function AuditPage() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => {
    api<AuditList>("/observability/audit?limit=200")
      .then((r) => setRows(r.items))
      .catch((e) => setError(String(e?.message || e)));
  }, []);

  async function runVerify() {
    setVerifying(true);
    setVerify(null);
    try {
      const r = await api<VerifyResult>("/observability/audit/verify");
      setVerify(r);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setVerify({ ok: false, checked: 0, broken_at: msg });
    }
    setVerifying(false);
  }

  return (
    <main className="mx-auto max-w-6xl px-6 py-10">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-3xl font-bold">Audit trail</h1>
        <button
          onClick={runVerify}
          disabled={verifying}
          className="rounded border border-black px-4 py-2 text-sm font-semibold hover:bg-black hover:text-white disabled:opacity-50"
        >
          {verifying ? "Verifying…" : "Verify hash chain"}
        </button>
      </div>

      {verify ? (
        <div
          className={`mb-4 rounded border p-3 text-sm ${
            verify.ok
              ? "border-green-300 bg-green-50 text-green-800"
              : "border-red-300 bg-red-50 text-red-800"
          }`}
        >
          {verify.ok
            ? `Chain intact. Verified ${verify.checked} rows.`
            : `Tamper detected at row ${verify.broken_at} (${verify.checked} rows valid before that).`}
        </div>
      ) : null}

      {error ? (
        <div className="mb-4 rounded border border-red-300 bg-red-50 p-3 text-sm text-red-700">
          {error}
        </div>
      ) : null}

      <div className="overflow-x-auto rounded border border-neutral-300">
        <table className="w-full text-sm">
          <thead className="bg-neutral-100 text-left">
            <tr>
              <th className="px-3 py-2">Time</th>
              <th className="px-3 py-2">Actor</th>
              <th className="px-3 py-2">Action</th>
              <th className="px-3 py-2">IP</th>
              <th className="px-3 py-2">Trace</th>
              <th className="px-3 py-2">Hashed</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-t border-neutral-200">
                <td className="px-3 py-2 font-mono text-xs">
                  {r.created_at.replace("T", " ").slice(0, 19)}
                </td>
                <td className="px-3 py-2 font-mono text-xs">
                  {r.user_id ? r.user_id.slice(0, 8) : "—"}
                </td>
                <td className="px-3 py-2">{r.action}</td>
                <td className="px-3 py-2 font-mono text-xs">
                  {r.request_ip || "—"}
                </td>
                <td className="px-3 py-2 font-mono text-xs">
                  {r.trace_id ? r.trace_id.slice(0, 12) : "—"}
                </td>
                <td className="px-3 py-2">
                  {r.hashed ? (
                    <span className="rounded bg-green-100 px-2 py-0.5 text-xs text-green-800">
                      yes
                    </span>
                  ) : (
                    <span className="rounded bg-neutral-100 px-2 py-0.5 text-xs text-neutral-600">
                      no
                    </span>
                  )}
                </td>
              </tr>
            ))}
            {rows.length === 0 && !error ? (
              <tr>
                <td colSpan={6} className="px-3 py-4 text-center text-sm text-neutral-500">
                  No audit rows yet.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </main>
  );
}
