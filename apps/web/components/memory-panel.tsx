"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/brutal";
import { api } from "@/lib/api";

type Finding = {
  item_id: string;
  category: string;
  detector: string;
  severity: string;
  reason: string;
  matched_text: string;
  risk_score: number;
};

type ScanOut = {
  items_scanned: number;
  clean: boolean;
  severity_counts: Record<string, number>;
  findings: Finding[];
};

type MemoryItem = string | Record<string, unknown>;

const SEV_STYLE: Record<string, string> = {
  critical: "text-oxblood border-oxblood/40",
  high: "text-rust border-rust/40",
  medium: "text-gilt2 border-gilt/40",
};

function itemToLine(item: MemoryItem): string {
  if (typeof item === "string") return item;
  if (typeof item.text === "string") return JSON.stringify(item);
  return JSON.stringify({ text: JSON.stringify(item) });
}

function lineToItem(line: string): MemoryItem | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  try {
    const parsed = JSON.parse(trimmed);
    if (
      parsed &&
      !Array.isArray(parsed) &&
      typeof parsed === "object" &&
      typeof parsed.text === "string"
    ) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // Plain memory rows stay plain.
  }
  return trimmed;
}

/** View/edit a memory target's stored items and scan them on demand.
 *  Memory targets are scanned here (POST /v1/memory/scan), not via the
 *  Celery assessment pipeline — so this panel is the target's main surface. */
export function MemoryPanel({
  targetId,
  initialConfig,
  initialItems,
}: {
  targetId: string;
  initialConfig?: Record<string, unknown>;
  initialItems: MemoryItem[];
}) {
  const initialText = initialItems.map(itemToLine).join("\n");
  const [text, setText] = useState(initialText);
  const [savedText, setSavedText] = useState(initialText);
  const [result, setResult] = useState<ScanOut | null>(null);
  const [busy, setBusy] = useState<"" | "save" | "scan">("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // /v1/memory/scan is stateless (no server persistence), so cache the last
  // result per target in localStorage — findings then survive navigating away
  // and back without re-running the scan. Loaded after mount to avoid an SSR
  // hydration mismatch.
  const cacheKey = `memory-scan-result:${targetId}`;
  useEffect(() => {
    try {
      const cached = window.localStorage.getItem(cacheKey);
      if (cached) setResult(JSON.parse(cached) as ScanOut);
    } catch {
      /* private mode / corrupt cache — ignore */
    }
  }, [cacheKey]);

  const items = () =>
    text
      .split("\n")
      .map(lineToItem)
      .filter((item): item is MemoryItem => item !== null);
  const dirty = text !== savedText;

  async function save() {
    setBusy("save");
    setMsg(null);
    try {
      await api(`/targets/${targetId}`, {
        method: "PATCH",
        json: {
          kind_config: {
            ...(initialConfig ?? {}),
            kind: "memory",
            items: items(),
          },
        },
      });
      setSavedText(text);
      setMsg({ ok: true, text: "Memory items saved." });
    } catch (e) {
      setMsg({ ok: false, text: String((e as Error)?.message ?? e) });
    } finally {
      setBusy("");
    }
  }

  async function scan() {
    const its = items();
    if (its.length === 0) {
      setMsg({
        ok: false,
        text: "Add at least one memory item (one per line).",
      });
      return;
    }
    setBusy("scan");
    setMsg(null);
    setResult(null);
    try {
      const out = await api<ScanOut>("/v1/memory/scan", {
        method: "POST",
        json: { items: its },
      });
      setResult(out);
      try {
        window.localStorage.setItem(cacheKey, JSON.stringify(out));
      } catch {
        /* storage full / private mode — result still shows this session */
      }
    } catch (e) {
      setMsg({ ok: false, text: String((e as Error)?.message ?? e) });
    } finally {
      setBusy("");
    }
  }

  return (
    <section>
      <div className="mb-3">
        <p className="eyebrow">Runtime protection — Memory</p>
        <h2 className="mt-2 font-display text-[24px] text-ink">
          Stored memory items
        </h2>
        <p className="mt-1 text-[13px] text-slate max-w-[70ch]">
          One item per line (long-term memory rows, RAG chunks, retrieved docs).
          Scanning checks for secrets / PII at rest and memory poisoning. Save
          to persist on this target; scan runs on demand.
        </p>
      </div>

      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={8}
        placeholder="One memory item per line…"
        className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
      />
      <div className="mt-3 flex items-center gap-3">
        <Button
          variant="pink"
          onClick={scan}
          disabled={busy !== ""}
          type="button"
        >
          {busy === "scan" ? "Scanning…" : "Scan memory"}
        </Button>
        <Button
          variant="lime"
          onClick={save}
          disabled={busy !== "" || !dirty}
          type="button"
        >
          {busy === "save" ? "Saving…" : dirty ? "Save items" : "Saved"}
        </Button>
      </div>

      {msg && (
        <div
          className={
            msg.ok
              ? "mt-4 formal-surface p-3 font-body text-[13px] text-graphite"
              : "mt-4 advisory-warn font-body text-[13px]"
          }
        >
          {msg.text}
        </div>
      )}

      {result && (
        <div className="mt-6">
          <div className="flex items-center gap-3 mb-3 flex-wrap">
            <span className="font-display text-[16px] text-ink">
              {result.clean
                ? "Clean — no issues found"
                : `${result.findings.length} finding${result.findings.length === 1 ? "" : "s"}`}
            </span>
            {Object.entries(result.severity_counts).map(([sev, n]) => (
              <span
                key={sev}
                className={`px-1.5 py-0.5 border rounded-sm font-mono text-[10px] uppercase tracking-[0.12em] ${SEV_STYLE[sev] ?? "text-slate border-hairline"}`}
              >
                {n} {sev}
              </span>
            ))}
          </div>
          {!result.clean && (
            <div className="formal-surface overflow-hidden">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="border-b border-hairline text-left font-mono text-[10px] uppercase tracking-[0.14em] text-mist">
                    <th className="px-4 py-2.5">Item</th>
                    <th className="px-4 py-2.5">Severity</th>
                    <th className="px-4 py-2.5">Risk</th>
                    <th className="px-4 py-2.5">Category</th>
                    <th className="px-4 py-2.5">Detector</th>
                    <th className="px-4 py-2.5">Matched</th>
                    <th className="px-4 py-2.5">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {result.findings.map((f, i) => (
                    <tr key={i} className="border-b border-hairline/60">
                      <td className="px-4 py-2.5 font-mono text-[12px] text-slate">
                        {f.item_id}
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={`px-1.5 py-0.5 border rounded-sm font-mono text-[10px] uppercase ${SEV_STYLE[f.severity] ?? "text-slate border-hairline"}`}
                        >
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[12px] text-slate tabular-nums">
                        {f.risk_score.toFixed(2)}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[12px] text-slate">
                        {f.category}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[12px] text-slate">
                        {f.detector}
                      </td>
                      <td
                        className="px-4 py-2.5 font-mono text-[11px] text-slate max-w-[18ch] truncate"
                        title={f.matched_text}
                      >
                        {f.matched_text}
                      </td>
                      <td className="px-4 py-2.5 text-graphite">{f.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
