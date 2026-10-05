"use client";

type Tokens = {
  prompt: number;
  completion: number;
  cached: number;
  reasoning: number;
};

const SEGMENT_HEX = {
  prompt: "#6FA8DC",
  completion: "#E69138",
  cached: "#5B8A6B",
  reasoning: "#6B4FA1",
};

const SEGMENT_LABEL = {
  prompt: "Prompt",
  completion: "Completion",
  cached: "Cached",
  reasoning: "Reasoning",
};

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

export function TokenProfile({
  tokens,
  latencyP50Ms,
  latencyP95Ms,
}: {
  tokens: Tokens;
  latencyP50Ms?: number | null;
  latencyP95Ms?: number | null;
}) {
  const total = tokens.prompt + tokens.completion + tokens.cached + tokens.reasoning;
  if (total === 0) {
    return (
      <div className="formal-surface p-6 text-[12px] text-mist italic text-center">
        No token usage recorded for this scan.
      </div>
    );
  }
  const pct = (n: number) => (n / total) * 100;

  return (
    <div className="formal-surface p-6">
      <div className="flex items-baseline justify-between mb-3">
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
          Token + latency profile
        </p>
        <p className="font-mono text-[12px] text-graphite">
          {fmt(total)} tokens
        </p>
      </div>

      <div className="flex h-6 rounded-sm overflow-hidden border border-hairline">
        {(["prompt", "completion", "cached", "reasoning"] as const).map((k) => {
          if (tokens[k] === 0) return null;
          return (
            <div
              key={k}
              style={{
                width: `${pct(tokens[k])}%`,
                backgroundColor: SEGMENT_HEX[k],
              }}
              title={`${SEGMENT_LABEL[k]}: ${fmt(tokens[k])} (${pct(tokens[k]).toFixed(1)}%)`}
            />
          );
        })}
      </div>

      <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4">
        {(["prompt", "completion", "cached", "reasoning"] as const).map((k) => (
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
            <p className="mt-1 font-display text-[20px] leading-none text-ink">
              {fmt(tokens[k])}
            </p>
            <p className="font-mono text-[10px] text-slate">
              {pct(tokens[k]).toFixed(1)}%
            </p>
          </div>
        ))}
      </div>

      {(latencyP50Ms != null || latencyP95Ms != null) && (
        <div className="mt-5 pt-4 border-t border-hairline grid grid-cols-2 gap-4">
          {latencyP50Ms != null && (
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
                p50 latency
              </p>
              <p className="mt-1 font-display text-[20px] leading-none text-ink">
                {(latencyP50Ms / 1000).toFixed(2)}s
              </p>
            </div>
          )}
          {latencyP95Ms != null && (
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
                p95 latency
              </p>
              <p className="mt-1 font-display text-[20px] leading-none text-ink">
                {(latencyP95Ms / 1000).toFixed(2)}s
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
