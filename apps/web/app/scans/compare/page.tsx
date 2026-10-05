"use client";

import Link from "next/link";
import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Button, Input } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { api } from "@/lib/api";

type ComparedFinding = {
  id?: string;
  title?: string;
  severity?: string;
  category?: string;
  owasp_category?: string;
  endpoint?: string;
  parameter?: string;
  description?: string;
};

type ComparisonResult = {
  baseline: { name: string; summary: Record<string, unknown> };
  candidate: { name: string; summary: Record<string, unknown> };
  regressions: ComparedFinding[];
  fixes: ComparedFinding[];
  common_failures: ComparedFinding[];
  counts: { regressions: number; fixes: number; common_failures: number };
  scan_a: { id: string; profile: string; grade: string | null; created_at: string };
  scan_b: { id: string; profile: string; grade: string | null; created_at: string };
};

const SEV_COLOR: Record<string, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

function shortId(id: string) {
  return id.slice(0, 8).toUpperCase();
}

function FindingRow({ f }: { f: ComparedFinding }) {
  const sev = String(f.severity || "info").toLowerCase();
  return (
    <li className="border border-hairline rounded-sm bg-paper p-4">
      <div className="flex items-center gap-3 mb-1">
        <span className={`w-1.5 h-3 ${SEV_COLOR[sev] || "bg-sev-info"}`} aria-hidden />
        <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
          {sev}
        </span>
        <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-slate">
          {f.owasp_category || "—"}
        </span>
        <span className="font-mono text-[11px] text-mist">
          {f.category ? f.category.replace(/^llm_/, "") : "—"}
        </span>
      </div>
      <div className="font-display text-[15px] text-ink">{f.title || "Untitled"}</div>
      {f.description && (
        <p className="mt-1 text-[12px] text-slate line-clamp-2">{f.description}</p>
      )}
    </li>
  );
}

function CompareInner() {
  const sp = useSearchParams();
  const [scanA, setScanA] = useState(sp.get("a") || "");
  const [scanB, setScanB] = useState(sp.get("b") || "");
  const [result, setResult] = useState<ComparisonResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanA || !scanB) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    api<ComparisonResult>(`/scans/${scanA}/compare/${scanB}`)
      .then((r) => !cancelled && setResult(r))
      .catch((e) => !cancelled && setError(e?.message || "Comparison failed."))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [scanA, scanB]);

  const regressions = result?.regressions ?? [];
  const fixes = result?.fixes ?? [];
  const common = result?.common_failures ?? [];

  const downloadJunitDiff = useMemo(() => {
    if (!result) return null;
    const lines = [
      `<?xml version="1.0" encoding="UTF-8"?>`,
      `<testsuite name="pencheff-llm-redteam-diff" tests="${regressions.length}" failures="${regressions.length}">`,
      ...regressions.map((f) => {
        const name = `${f.owasp_category || "LLM"} ${f.category || "?"} ${f.title || ""}`;
        return [
          `  <testcase classname="llm.redteam.regression" name="${name.replace(/[<&>]/g, "")}">`,
          `    <failure type="${(f.severity || "info").toLowerCase()}">regression vs baseline</failure>`,
          `  </testcase>`,
        ].join("\n");
      }),
      `</testsuite>`,
    ];
    const blob = new Blob([lines.join("\n")], { type: "application/xml" });
    return URL.createObjectURL(blob);
  }, [result, regressions]);

  return (
    <div className="space-y-6">
      <header>
        <p className="eyebrow-gilt">Comparison</p>
        <h1 className="mt-3 font-display text-[36px] tracking-[-0.015em] text-ink">
          Scan diff
        </h1>
        <p className="mt-2 text-[13px] text-slate max-w-[58ch]">
          Compare two LLM red-team scans. Regressions are findings only in the
          candidate; fixes are only in the baseline; common failures are present
          in both.
        </p>
      </header>

      <section className="formal-surface p-6 space-y-4">
        <div className="grid sm:grid-cols-2 gap-4">
          <div>
            <label className="font-mono text-[11px] uppercase tracking-[0.18em] text-slate">
              Baseline scan ID (a)
            </label>
            <Input
              value={scanA}
              onChange={(e) => setScanA(e.target.value)}
              placeholder="paste full scan UUID"
              className="font-mono text-[12px] mt-1"
            />
          </div>
          <div>
            <label className="font-mono text-[11px] uppercase tracking-[0.18em] text-slate">
              Candidate scan ID (b)
            </label>
            <Input
              value={scanB}
              onChange={(e) => setScanB(e.target.value)}
              placeholder="paste full scan UUID"
              className="font-mono text-[12px] mt-1"
            />
          </div>
        </div>
      </section>

      {loading && <p className="text-[13px] text-slate italic">Comparing…</p>}
      {error && (
        <div className="advisory-warn font-body text-[13px]">{error}</div>
      )}

      {result && (
        <>
          <section className="grid sm:grid-cols-2 gap-4">
            {(["scan_a", "scan_b"] as const).map((side) => {
              const meta = result[side];
              const summary = side === "scan_a" ? result.baseline.summary : result.candidate.summary;
              return (
                <div key={side} className="formal-surface p-5">
                  <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">
                    {side === "scan_a" ? "Baseline" : "Candidate"} · {shortId(meta.id)}
                  </p>
                  <p className="mt-1 font-mono text-[12px] text-slate">
                    profile {meta.profile} · grade {meta.grade ?? "—"}
                  </p>
                  <p className="mt-1 font-mono text-[11px] text-mist">
                    {meta.created_at.replace("T", " · ").slice(0, 22)}
                  </p>
                  <dl className="mt-3 grid grid-cols-2 gap-y-1 text-[12px]">
                    <dt className="text-slate">Total LLM failures</dt>
                    <dd className="font-mono">{Number(summary["total_failures"] ?? 0)}</dd>
                  </dl>
                </div>
              );
            })}
          </section>

          <section>
            <div className="grid grid-cols-3 gap-4 mb-6">
              {([
                ["regressions", "Regressions", "text-sev-critical"],
                ["fixes", "Fixes", "text-forest"],
                ["common_failures", "Common", "text-mist"],
              ] as const).map(([key, label, color]) => (
                <div key={key} className="formal-surface p-5">
                  <p className={`font-mono text-[10px] uppercase tracking-[0.18em] ${color}`}>
                    {label}
                  </p>
                  <p className="mt-1 font-display text-[28px] text-ink">
                    {result.counts[key]}
                  </p>
                </div>
              ))}
            </div>
            {downloadJunitDiff && regressions.length > 0 && (
              <div className="mb-4">
                <a
                  href={downloadJunitDiff}
                  download={`pencheff-redteam-diff-${shortId(result.scan_a.id)}-vs-${shortId(result.scan_b.id)}.xml`}
                  className="font-mono text-[11px] uppercase tracking-[0.16em] text-ink underline underline-offset-[4px] decoration-gilt"
                >
                  Download regressions as JUnit XML
                </a>
              </div>
            )}
            <div className="grid lg:grid-cols-3 gap-6">
              <div>
                <h3 className="font-display text-[16px] text-ink mb-3">Regressions</h3>
                <ul className="space-y-2">
                  {regressions.length === 0 ? (
                    <li className="text-[13px] text-slate italic">No regressions.</li>
                  ) : (
                    regressions.map((f, i) => <FindingRow key={i} f={f} />)
                  )}
                </ul>
              </div>
              <div>
                <h3 className="font-display text-[16px] text-ink mb-3">Fixes</h3>
                <ul className="space-y-2">
                  {fixes.length === 0 ? (
                    <li className="text-[13px] text-slate italic">No fixes.</li>
                  ) : (
                    fixes.map((f, i) => <FindingRow key={i} f={f} />)
                  )}
                </ul>
              </div>
              <div>
                <h3 className="font-display text-[16px] text-ink mb-3">Common failures</h3>
                <ul className="space-y-2">
                  {common.length === 0 ? (
                    <li className="text-[13px] text-slate italic">No common failures.</li>
                  ) : (
                    common.slice(0, 20).map((f, i) => <FindingRow key={i} f={f} />)
                  )}
                </ul>
              </div>
            </div>
          </section>
        </>
      )}

      <p className="font-mono text-[11px] text-mist">
        <Link href="/dashboard" className="hover:text-ink underline-offset-[4px] hover:underline decoration-gilt decoration-1">
          ← Dashboard
        </Link>
      </p>
    </div>
  );
}

export default function CompareScansPage() {
  return (
    <Suspense
      fallback={
        <div className="py-6">
          <InlineLoading label="Loading…" />
        </div>
      }
    >
      <CompareInner />
    </Suspense>
  );
}
