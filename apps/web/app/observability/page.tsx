import Link from "next/link";

export default function ObservabilityIndex() {
  const cards = [
    {
      href: "/observability/slo",
      title: "SLO dashboard",
      desc: "Error rate, p50/p95/p99 latency, queued + active scans.",
    },
    {
      href: "/observability/audit",
      title: "Audit trail",
      desc: "Append-only mutation log with sha256 hash chain. Verify chain integrity.",
    },
    {
      href: "/observability/cost",
      title: "LLM cost",
      desc: "Token spend by model across the last 7 days. Drill into a single scan.",
    },
    {
      href: "/observability",
      title: "Trace viewer",
      desc: "Open from a scan detail page. Waterfall of spans for a single scan_id.",
    },
  ];
  return (
    <main className="mx-auto max-w-5xl px-6 py-10">
      <h1 className="mb-2 text-3xl font-bold">Observability</h1>
      <p className="mb-8 text-sm text-neutral-500">
        End-to-end trace, log, metric, and audit pipeline. 7-day retention by
        default. Toggle with PENCHEFF_OBSERVABILITY_ENABLED.
      </p>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {cards.map((c) => (
          <Link
            key={c.title}
            href={c.href}
            className="block rounded border border-neutral-300 p-6 transition hover:border-black hover:shadow"
          >
            <div className="mb-2 text-lg font-semibold">{c.title}</div>
            <div className="text-sm text-neutral-600">{c.desc}</div>
          </Link>
        ))}
      </div>
    </main>
  );
}
