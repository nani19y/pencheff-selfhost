"use client";

// Recommended Guardrails — sibling of /scans/[id]/threat-model.
//
// Computes which Sentry detectors to enable based on the LLM red-team
// scan's per-OWASP-LLM-category failure breakdown. One-click "Apply"
// writes the suggested config onto the underlying target's
// llm_config.guardrails — the proxy picks it up immediately.

import Link from "next/link";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { Button } from "@/components/brutal";
import { api } from "@/lib/api";

type Recommendation = {
  category: string; // "LLM01" .. "LLM10"
  side: "input" | "output";
  detector: string;
  value: unknown;
  rationale: string;
  failure_count: number;
};

type RecommendedGuardrailsOut = {
  target_id: string;
  scan_id: string;
  target_name: string | null;
  summary: Record<string, number>;
  recommendations: Recommendation[];
  suggested_config: Record<string, unknown>;
};

const CATEGORY_LABEL: Record<string, string> = {
  LLM01: "Prompt Injection",
  LLM02: "Sensitive Information Disclosure",
  LLM03: "Supply Chain",
  LLM04: "Data and Model Poisoning",
  LLM05: "Improper Output Handling",
  LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage",
  LLM08: "Vector and Embedding Weaknesses",
  LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
};

export default function RecommendedGuardrailsPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const scanId = mounted ? pathSegment(pathname, 2) : "";
  const [data, setData] = useState<RecommendedGuardrailsOut | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  const [applyMsg, setApplyMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    setError(null);
    api<RecommendedGuardrailsOut>(`/scans/${scanId}/recommended-guardrails`)
      .then(setData)
      .catch((e: unknown) =>
        setError(String((e as { message?: unknown })?.message ?? e)),
      );
  }, [scanId]);

  async function applyAll() {
    setApplying(true);
    setApplyMsg(null);
    try {
      const r = await api<{
        ok: boolean;
        target_id: string;
        applied_recommendations: number;
      }>(`/scans/${scanId}/recommended-guardrails/apply`, { method: "POST" });
      setApplyMsg(
        r.ok
          ? `Applied ${r.applied_recommendations} recommendation${
              r.applied_recommendations === 1 ? "" : "s"
            }. Open the target's Guardrails section to fine-tune.`
          : "Apply failed; see server logs.",
      );
    } catch (e: unknown) {
      setApplyMsg(String((e as { message?: unknown })?.message ?? e));
    } finally {
      setApplying(false);
    }
  }

  if (error) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-10">
        <BackLink scanId={scanId} />
        <h1 className="mt-4 text-3xl font-bold">Recommended guardrails</h1>
        <div className="mt-4 rounded border border-red-300 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      </main>
    );
  }
  if (!data) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-10">
        <BackLink scanId={scanId} />
        <h1 className="mt-4 text-3xl font-bold">Recommended guardrails</h1>
        <p className="mt-4 text-sm text-mist">Loading…</p>
      </main>
    );
  }

  const grouped = groupByCategory(data.recommendations);
  const noFailures = data.recommendations.length === 0;

  return (
    <main className="mx-auto max-w-5xl px-6 py-10 space-y-8">
      <BackLink scanId={scanId} />
      <header>
        <p className="eyebrow-gilt">Recommended guardrails</p>
        <h1 className="mt-3 font-display text-[36px] tracking-[-0.015em]">
          {data.target_name ?? "LLM target"}
        </h1>
        <p className="mt-2 max-w-[64ch] text-[14px] text-graphite">
          Computed from the OWASP-LLM-Top-10 failure breakdown of this red-team
          scan. Each row maps a category that produced VULNERABLE verdicts onto
          the Sentry detector that catches its primary attack shape.
        </p>
      </header>

      <section className="formal-surface p-6 grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
        <Stat
          label="OWASP-LLM categories failed"
          value={Object.keys(data.summary).length}
        />
        <Stat
          label="Total VULNERABLE"
          value={Object.values(data.summary).reduce((a, b) => a + b, 0)}
        />
        <Stat label="Recommendations" value={data.recommendations.length} />
        <Stat
          label="Distinct detectors"
          value={
            new Set(data.recommendations.map((r) => `${r.side}.${r.detector}`))
              .size
          }
        />
      </section>

      {noFailures ? (
        <section className="formal-surface p-6">
          <p className="eyebrow-gilt">Clean</p>
          <h3 className="mt-3 font-display text-[24px] text-ink">
            No recommendations — the scan recorded zero failures.
          </h3>
          <p className="mt-2 text-[13px] text-graphite">
            The default guardrail config (block prompt-injection / PII / unsafe
            HTML) is already a safe baseline. Configure it under{" "}
            <Link
              href={`/targets/${data.target_id}`}
              className="underline underline-offset-2"
            >
              the target&rsquo;s Guardrails section
            </Link>
            .
          </p>
        </section>
      ) : (
        <>
          <section className="space-y-4">
            {Object.keys(grouped)
              .sort()
              .map((category) => (
                <CategoryCard
                  key={category}
                  category={category}
                  recommendations={grouped[category]}
                />
              ))}
          </section>

          <section className="formal-surface p-6 space-y-3">
            <p className="eyebrow-gilt text-[10px]">Apply</p>
            <p className="text-[14px] text-graphite max-w-[60ch]">
              Apply the suggested configuration above to{" "}
              <strong>{data.target_name}</strong>&rsquo;s guardrails. This
              writes the toggles onto the target&rsquo;s{" "}
              <code>llm_config.guardrails</code>; the Pencheff proxy picks up
              the change on the next request.
            </p>
            <div className="flex items-center gap-3">
              <Button variant="pink" disabled={applying} onClick={applyAll}>
                {applying
                  ? "Applying…"
                  : `Apply ${data.recommendations.length} recommendation${
                      data.recommendations.length === 1 ? "" : "s"
                    } →`}
              </Button>
              <Link
                href={`/targets/${data.target_id}`}
                className="text-[12px] underline underline-offset-2"
              >
                Open target Guardrails →
              </Link>
            </div>
            {applyMsg && <p className="text-[12px] text-forest">{applyMsg}</p>}
          </section>
        </>
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

function groupByCategory(
  recs: Recommendation[],
): Record<string, Recommendation[]> {
  const out: Record<string, Recommendation[]> = {};
  for (const r of recs) {
    (out[r.category] ??= []).push(r);
  }
  return out;
}

function CategoryCard({
  category,
  recommendations,
}: {
  category: string;
  recommendations: Recommendation[];
}) {
  const rationale = recommendations[0]?.rationale;
  const count = recommendations[0]?.failure_count ?? 0;
  return (
    <div className="formal-surface p-6 space-y-3">
      <div className="flex items-baseline justify-between gap-4 flex-wrap">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-wider text-mist">
            {category}
          </p>
          <h3 className="mt-1 font-display text-[20px] text-ink">
            {CATEGORY_LABEL[category] ?? category}
          </h3>
        </div>
        <span className="font-mono text-[12px] text-oxblood border border-oxblood rounded-sm px-2 py-0.5">
          {count} VULNERABLE
        </span>
      </div>
      {rationale && (
        <p className="text-[13px] text-graphite max-w-[64ch]">{rationale}</p>
      )}
      <ul className="space-y-1.5">
        {recommendations.map((r, i) => (
          <li
            key={`${r.side}-${r.detector}-${i}`}
            className="flex items-center gap-3 text-[12px] font-mono"
          >
            <span className="border border-hairline rounded-sm px-2 py-0.5 uppercase text-slate">
              {r.side}
            </span>
            <span className="text-graphite">{r.detector}</span>
            <span className="text-mist">→</span>
            <span className="text-graphite">{String(r.value)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
