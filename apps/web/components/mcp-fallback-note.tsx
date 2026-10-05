"use client";

/**
 * Shown when a plan's AI quota is exhausted or its credits are used up: you can
 * still drive Pencheff from your IDE over MCP, where the IDE's OWN model does the
 * work — so no Pencheff AI quota / credits are consumed. Results still sync to
 * the dashboard.
 */
export function McpFallbackNote({ kind }: { kind: "quota" | "credits" }) {
  const noun = kind === "credits" ? "credits" : "AI quota";
  const verb = kind === "credits" ? "fix findings" : "run this scan";
  return (
    <div className="mt-3 border-2 border-hairline bg-vellum p-3">
      <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-slate">
        Out of {noun}? Use Pencheff from your IDE
      </p>
      <p className="mt-1 text-[12px] text-graphite">
        Connect Pencheff&apos;s MCP server to Claude Code, Cursor, or Codex and{" "}
        {verb} with your IDE&apos;s{" "}
        <span className="font-medium text-ink">own model</span> — no Pencheff{" "}
        {noun} is consumed, and results still sync to this dashboard.
      </p>
      <a
        href="https://docs.pencheff.com/features/mcp"
        target="_blank"
        rel="noreferrer"
        className="mt-1.5 inline-block font-mono text-[11px] text-ink underline underline-offset-2"
      >
        Set up MCP &rarr;
      </a>
    </div>
  );
}
