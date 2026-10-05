"use client";

import { useState } from "react";
import { Button } from "@/components/brutal";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";

/**
 * Triage panel — exploitability walkthrough.
 *
 * Lazy by design: we don't auto-fire the upstream call when the page
 * loads because triage is expensive and the user may not need it.
 * Instead we render the cached result if the finding already has one
 * and a "Generate" button otherwise.
 */

export type TriagePayload = {
  walkthrough: string | null;
  blast_radius: string | null;
  exploit_scenario: string | null;
  fix_outline: string | null;
  confidence: string | null;
  model: string | null;
};

const CONF_TONE: Record<string, string> = {
  high: "bg-forest/15 text-forest",
  medium: "bg-sev-medium/15 text-sev-medium",
  low: "bg-sev-high/15 text-sev-high",
};

export function AiTriagePanel({
  findingId,
  initial,
  aiEnabled,
  onUpdated,
}: {
  findingId: string;
  initial: TriagePayload | null;
  aiEnabled: boolean;
  onUpdated?: (next: { ai_triage: TriagePayload | null }) => void;
}) {
  const [data, setData] = useState<TriagePayload | null>(initial);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function generate(force = false) {
    setErr(null);
    setBusy(true);
    try {
      // ``direct: true`` bypasses the Next.js rewrite proxy so the
      // upstream call doesn't get torn down at the 30s socket-idle timeout.
      const res = await api<{ ai_triage: TriagePayload | null }>(
        `/findings/${findingId}/triage${force ? "?force=true" : ""}`,
        { method: "POST", direct: true }
      );
      setData(res.ai_triage);
      onUpdated?.(res);
    } catch (e: any) {
      const msg =
        e instanceof ApiError && e.status === 402
          ? "Triage requires Pro. Upgrade to enable per-finding walkthroughs."
          : e?.message || "Triage call failed.";
      setErr(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <div className="flex items-baseline justify-between mb-3">
        <p className="eyebrow">Triage</p>
        <span className="font-mono text-[11px] text-mist">
          Exploitability walkthrough
        </span>
      </div>
      <div className="formal-surface p-6 space-y-5">
        {!data && !err && !busy && (
          <div className="space-y-3">
            <p className="text-[14px] leading-[1.6] text-graphite">
              Generate a structured walkthrough — exploit scenario, blast
              radius, and remediation outline — using the live evidence on
              this finding.
            </p>
            <Button
              variant="cyan"
              onClick={() => generate(false)}
              disabled={!aiEnabled}
            >
              {aiEnabled ? "Run triage" : "Pro · Run triage"}
            </Button>
            {!aiEnabled && (
              <p className="font-mono text-[11px] text-mist">
                Triage is a Pro-tier feature. The deterministic evidence
                and remediation guidance below remain free.
              </p>
            )}
          </div>
        )}

        {busy && (
          <p className="font-body text-[13px] text-slate italic">
            Generating walkthrough for this finding…
          </p>
        )}

        {err && (
          <div className="space-y-2">
            <p className="font-body text-[13px] text-oxblood">{err}</p>
            <Button variant="pink" onClick={() => generate(false)}>
              Retry
            </Button>
          </div>
        )}

        {data && (
          <div className="space-y-5">
            {data.confidence && (
              <div className="flex items-center gap-2">
                <span
                  className={cn(
                    "inline-flex items-center rounded-sm px-2 py-0.5",
                    "font-body text-[11px] font-medium uppercase tracking-[0.16em]",
                    CONF_TONE[data.confidence] || "bg-paper text-mist"
                  )}
                >
                  Confidence · {data.confidence}
                </span>
              </div>
            )}

            {data.walkthrough && (
              <Block label="Walkthrough" body={data.walkthrough} />
            )}
            {data.exploit_scenario && (
              <Block
                label="Exploit scenario"
                body={data.exploit_scenario}
                tone="warn"
              />
            )}
            {data.blast_radius && (
              <Block label="Blast radius" body={data.blast_radius} />
            )}
            {data.fix_outline && (
              <Block label="Fix outline" body={data.fix_outline} tone="ok" />
            )}

            <Button
              variant="lime"
              onClick={() => generate(true)}
              disabled={busy || !aiEnabled}
            >
              Regenerate
            </Button>
          </div>
        )}
      </div>
    </section>
  );
}

function Block({
  label,
  body,
  tone,
}: {
  label: string;
  body: string;
  tone?: "warn" | "ok";
}) {
  return (
    <div>
      <p
        className={cn(
          "eyebrow mb-2",
          tone === "warn" && "text-oxblood",
          tone === "ok" && "text-forest"
        )}
      >
        {label}
      </p>
      <p className="whitespace-pre-wrap text-[14px] leading-[1.7] text-graphite">
        {body}
      </p>
    </div>
  );
}
