"use client";

const LLM_CATEGORIES: { code: string; label: string }[] = [
  { code: "LLM01", label: "Prompt Injection" },
  { code: "LLM02", label: "Sensitive Info Disclosure" },
  { code: "LLM03", label: "Supply Chain" },
  { code: "LLM04", label: "Data + Model Poisoning" },
  { code: "LLM05", label: "Improper Output Handling" },
  { code: "LLM06", label: "Excessive Agency" },
  { code: "LLM07", label: "System Prompt Leakage" },
  { code: "LLM08", label: "Vector + Embedding Weak." },
  { code: "LLM09", label: "Misinformation" },
  { code: "LLM10", label: "Unbounded Consumption" },
];

export function OwaspLlmHeatmap({
  byCategory,
  totalsByCategory,
}: {
  byCategory: Record<string, number>;
  totalsByCategory?: Record<string, number>;
}) {
  const max = Math.max(1, ...Object.values(byCategory));

  return (
    <div className="formal-surface p-4">
      <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist mb-3">
        OWASP LLM Top-10 — attack outcomes
      </p>
      <ul className="space-y-1.5">
        {LLM_CATEGORIES.map((c) => {
          const failures = byCategory[c.code] || 0;
          const total = totalsByCategory?.[c.code];
          const intensity = failures / max;
          const successRatePct =
            total != null && total > 0
              ? ((failures / total) * 100).toFixed(0)
              : null;
          return (
            <li
              key={c.code}
              className="flex items-center gap-3 font-mono text-[12px]"
            >
              <span className="w-14 text-graphite">{c.code}</span>
              <span className="w-44 text-slate truncate">{c.label}</span>
              <div className="flex-1 h-3 bg-vellum rounded-sm overflow-hidden">
                <div
                  className="h-full bg-sev-critical"
                  style={{ width: `${Math.max(intensity * 100, failures > 0 ? 4 : 0)}%` }}
                  aria-hidden
                />
              </div>
              <span className="w-10 text-right text-ink">{failures}</span>
              {successRatePct != null && (
                <span className="w-12 text-right text-mist">
                  {successRatePct}%
                </span>
              )}
            </li>
          );
        })}
      </ul>
      {totalsByCategory && (
        <p className="mt-3 font-mono text-[10px] text-mist">
          Bar = absolute failures · right column = success rate vs. probes in category
        </p>
      )}
    </div>
  );
}
