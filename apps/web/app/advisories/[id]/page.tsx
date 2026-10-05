"use client";

// Phase 1.1c UI — advisory detail page.
//
// Surfaces:
//   * Cached OSV/RustSec/GoVulnDB advisory body
//   * NVD enrichment (CWE / CPE / NVD-CVSS)
//   * EPSS / KEV labels
//   * AI-enriched exploit walkthrough + fix recipe (cached server-side)
//   * Per-output provenance trail (model, prompt version, source URLs/licenses)

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import Link from "next/link";
import { api } from "@/lib/api";
import { Markdown } from "@/components/markdown";

type Source = {
  url: string | null;
  license: string | null;
  retrieved_at: string | null;
};

type AiEnrichment = {
  exploit_walkthrough: string;
  fix_recipe: string;
  reachability_signals: string[];
  references: string[];
  model: string | null;
  prompt_version: string;
  cached: boolean;
};

type AdvisoryOut = {
  id: string;
  ecosystem: string | null;
  package: string | null;
  summary: string | null;
  severity: string | null;
  license: string | null;
  advisory: Record<string, unknown>;
  nvd: {
    cwe_ids: string[];
    cpe_uris: string[];
    nvd_cvss_score: number | null;
    nvd_cvss_severity: string | null;
    primary_url: string | null;
    description: string | null;
  } | null;
  epss: number | null;
  epss_percentile: number | null;
  kev: boolean;
  ai: AiEnrichment | null;
  provenance: Array<{
    advisory_id: string;
    generated_at: string;
    model: string | null;
    prompt_version: string;
    input_hash: string;
    output_hash: string;
    sources: Source[];
  }>;
  sources: Source[];
};

export default function AdvisoryDetailPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const id = mounted ? pathSegment(pathname, 2) : "";
  const [data, setData] = useState<AdvisoryOut | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    api<AdvisoryOut>(`/advisories/${encodeURIComponent(id)}`)
      .then(setData)
      .catch((e) => setError(String(e?.message || e)));
  }, [id]);

  if (error) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-10">
        <h1 className="text-2xl font-bold">Advisory {id}</h1>
        <p className="mt-4 text-sm text-oxblood">{error}</p>
      </main>
    );
  }
  if (!data) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-10">
        <h1 className="text-2xl font-bold">Advisory {id}</h1>
        <p className="mt-4 text-sm text-mist">Loading…</p>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-5xl px-6 py-10 space-y-8">
      <header>
        <p className="eyebrow-gilt">Advisory</p>
        <h1 className="mt-3 font-display text-[36px] tracking-[-0.015em]">
          {data.id}
        </h1>
        {data.summary && (
          <p className="mt-2 text-[15px] text-graphite">{data.summary}</p>
        )}
        <div className="mt-4 flex flex-wrap gap-2 text-[12px] font-mono">
          {data.ecosystem && <Pill label={`ecosystem: ${data.ecosystem}`} />}
          {data.package && <Pill label={`package: ${data.package}`} />}
          {data.severity && <Pill label={`severity: ${data.severity}`} />}
          {data.kev && <Pill label="CISA KEV" tone="oxblood" />}
          {data.epss != null && (
            <Pill
              label={`EPSS ${(data.epss * 100).toFixed(1)}%`}
              tone={data.epss > 0.5 ? "oxblood" : "default"}
            />
          )}
          {data.nvd?.nvd_cvss_score != null && (
            <Pill label={`CVSS ${data.nvd.nvd_cvss_score.toFixed(1)}`} />
          )}
          {data.license && <Pill label={`upstream license: ${data.license}`} />}
        </div>
      </header>

      {data.ai && (
        <section className="formal-surface p-6 space-y-4">
          <div className="flex items-baseline justify-between">
            <p className="eyebrow">AI Walkthrough</p>
            <span className="text-[11px] font-mono text-mist">
              {data.ai.cached ? "cached" : "fresh"} · {data.ai.model || "n/a"} ·
              v{data.ai.prompt_version}
            </span>
          </div>
          <div>
            <p className="eyebrow-gilt mb-2 text-[10px]">Exploit walkthrough</p>
            <Markdown>{data.ai.exploit_walkthrough}</Markdown>
          </div>
          <div>
            <p className="eyebrow-gilt mb-2 text-[10px]">Fix recipe</p>
            <Markdown>{data.ai.fix_recipe}</Markdown>
          </div>
          {data.ai.reachability_signals.length > 0 && (
            <div>
              <p className="eyebrow-gilt mb-2 text-[10px]">
                Reachability signals
              </p>
              <ul className="font-mono text-[12px] text-graphite space-y-1">
                {data.ai.reachability_signals.map((s, i) => (
                  <li key={i}>· {s}</li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      {data.nvd && (
        <section className="formal-surface p-6 space-y-3">
          <p className="eyebrow">NVD enrichment</p>
          {data.nvd.description && (
            <p className="text-[14px] text-graphite">{data.nvd.description}</p>
          )}
          <div className="flex flex-wrap gap-2 font-mono text-[12px]">
            {data.nvd.cwe_ids.map((cwe) => (
              <Pill key={cwe} label={cwe} />
            ))}
            {data.nvd.nvd_cvss_severity && (
              <Pill label={`NVD ${data.nvd.nvd_cvss_severity}`} />
            )}
          </div>
          {data.nvd.primary_url && (
            <a
              href={data.nvd.primary_url}
              className="text-[12px] underline underline-offset-4"
              target="_blank"
              rel="noopener noreferrer"
            >
              {data.nvd.primary_url}
            </a>
          )}
        </section>
      )}

      <section className="formal-surface p-6">
        <p className="eyebrow mb-4">Provenance</p>
        {data.provenance.length === 0 ? (
          <p className="text-[13px] text-mist">
            No AI enrichment runs recorded yet.
          </p>
        ) : (
          <ul className="space-y-3 font-mono text-[12px]">
            {data.provenance.map((p, i) => (
              <li key={i} className="border-l-2 border-hairline pl-3">
                <p className="text-graphite">
                  {p.generated_at} · model={p.model || "n/a"} · v
                  {p.prompt_version}
                </p>
                <p className="text-mist">
                  input_hash={p.input_hash.slice(0, 16)}… output_hash=
                  {p.output_hash.slice(0, 16)}…
                </p>
                {p.sources.length > 0 && (
                  <ul className="mt-1 ml-4 list-disc text-mist">
                    {p.sources.map((s, j) => (
                      <li key={j}>
                        {s.url} ({s.license})
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <p className="text-[11px] text-mist">
        AI walkthrough trained only on permissively-licensed inputs. Every row
        in <code>~/.pencheff/data/provenance/</code> records the model, prompt
        version, and source URLs the output was derived from.{" "}
        <Link href="/dashboard" className="underline underline-offset-2">
          ← Dashboard
        </Link>
      </p>
    </main>
  );
}

function Pill({
  label,
  tone = "default",
}: {
  label: string;
  tone?: "default" | "oxblood";
}) {
  return (
    <span
      className={
        "inline-flex items-center rounded-sm border px-2 py-0.5 text-[11px] " +
        (tone === "oxblood"
          ? "border-oxblood text-oxblood"
          : "border-hairline text-slate")
      }
    >
      {label}
    </span>
  );
}
