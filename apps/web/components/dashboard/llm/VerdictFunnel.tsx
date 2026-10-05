"use client";

type VerdictCounts = {
  total: number;
  vulnerable: number;
  refused: number;
  ambiguous: number;
};

const SEGMENT_HEX = {
  vulnerable: "#C00000",
  refused: "#5B8A6B",
  ambiguous: "#B7B7B7",
};

const SEGMENT_LABEL = {
  vulnerable: "Vulnerable",
  refused: "Refused",
  ambiguous: "Ambiguous",
};

export function VerdictFunnel({ counts }: { counts: VerdictCounts }) {
  const { total, vulnerable, refused, ambiguous } = counts;
  if (total === 0) {
    return (
      <div className="formal-surface p-10 text-center">
        <p className="eyebrow-gilt">No probes recorded</p>
        <p className="mt-2 font-mono text-[12px] text-mist">
          The transcript file is missing or empty — the scan may not have
          run the LLM red-team stage, or the worker tmpdir expired.
        </p>
      </div>
    );
  }
  const pct = (n: number) => (total === 0 ? 0 : (n / total) * 100);

  return (
    <div className="formal-surface p-6">
      <div className="flex items-baseline justify-between mb-3">
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
          Verdict funnel
        </p>
        <p className="font-mono text-[12px] text-graphite">
          {total} probes
        </p>
      </div>

      <div className="flex h-8 rounded-sm overflow-hidden border border-hairline">
        {(["vulnerable", "refused", "ambiguous"] as const).map((k) => {
          const n = k === "vulnerable" ? vulnerable : k === "refused" ? refused : ambiguous;
          if (n === 0) return null;
          return (
            <div
              key={k}
              style={{
                width: `${pct(n)}%`,
                backgroundColor: SEGMENT_HEX[k],
              }}
              title={`${SEGMENT_LABEL[k]}: ${n} (${pct(n).toFixed(1)}%)`}
            />
          );
        })}
      </div>

      <div className="mt-4 grid grid-cols-3 gap-4">
        {(["vulnerable", "refused", "ambiguous"] as const).map((k) => {
          const n = k === "vulnerable" ? vulnerable : k === "refused" ? refused : ambiguous;
          return (
            <div key={k}>
              <div className="flex items-center gap-2">
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: SEGMENT_HEX[k] }}
                  aria-hidden
                />
                <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
                  {SEGMENT_LABEL[k]}
                </span>
              </div>
              <p className="mt-1 font-display text-[28px] leading-none text-ink">
                {n}
              </p>
              <p className="font-mono text-[11px] text-slate">
                {pct(n).toFixed(1)}% of probes
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
