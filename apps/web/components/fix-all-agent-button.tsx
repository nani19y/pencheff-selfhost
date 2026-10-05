"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/brutal";
import { McpFallbackNote } from "@/components/mcp-fallback-note";
import { api, ApiError } from "@/lib/api";

/**
 * "Fix all findings (Agent)" CTA — drives the new agentic flow.
 *
 * Spec: docs/superpowers/specs/2026-05-23-agentic-fixer-design.md
 *
 * Backend contract:
 *   POST /fix-tasks/agentic                  → start a run (preflight billing check)
 *   GET  /fix-tasks/agentic/{id}             → poll detail + recent steps
 *   GET  /fix-tasks/agentic/{id}/stream      → SSE: per-step + status events
 *   POST /fix-tasks/agentic/{id}/cancel
 *   GET  /fix-tasks/agentic/latest?…         → re-attach to in-flight run
 *   GET  /fix-tasks/agentic/usage            → MTD spend snapshot
 *
 * The component itself is a button + an inline status card that
 * appears once a run is in flight. The polling fallback (3s) covers
 * environments where the SSE proxy strips streaming responses.
 */

type AgenticUsage = {
  plan: string;
  in_flight_runs: number;
  max_concurrent_runs: number;
  can_start: boolean;
  block_reason: string | null;
};

type AgenticStep = {
  iteration: number;
  step_index: number;
  tool_name: string;
  tool_input: Record<string, unknown> | null;
  tool_error: string | null;
  duration_ms: number;
  created_at: string;
};

type AgenticRun = {
  id: string;
  runtime: string;
  status:
    | "queued"
    | "cloning"
    | "running"
    | "committing"
    | "pushing"
    | "done"
    | "failed"
    | "canceled";
  findings_count: number;
  iterations: number;
  current_step: string | null;
  branch_name: string | null;
  pr_url: string | null;
  error: string | null;
  model: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  cancel_requested: boolean;
};

type AgenticRunDetail = AgenticRun & {
  recent_steps: AgenticStep[];
  usage_total_input_tokens: number;
  usage_total_output_tokens: number;
  usage_total_cost_cents: number;
};

const POLL_INTERVAL_MS = 3000;
const TERMINAL = new Set(["done", "failed", "canceled"]);

export function FixAllAgentButton({
  scope,
  id,
  linkedRepos = [],
  allowNoRepo = false,
  className,
}: {
  scope: "scan" | "repo";
  id: string;
  linkedRepos?: Array<{
    repository_id: string;
    full_name: string;
    provider: string | null;
  }>;
  // Upload-source targets have no git repo — the run returns a downloadable
  // .zip instead of a PR, so don't gate the button on an attached repository.
  allowNoRepo?: boolean;
  className?: string;
}) {
  const [usage, setUsage] = useState<AgenticUsage | null>(null);
  const [run, setRun] = useState<AgenticRunDetail | null>(null);
  const [steps, setSteps] = useState<AgenticStep[]>([]);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedRepositoryId, setSelectedRepositoryId] = useState("");
  const [downloading, setDownloading] = useState(false);

  async function downloadFixedZip() {
    if (!run) return;
    setDownloading(true);
    setError(null);
    try {
      const { url } = await api<{ url: string }>(
        `/fix-tasks/agentic/${run.id}/download`,
        { direct: true },
      );
      window.open(url, "_blank", "noopener");
    } catch (e) {
      setError(extractMessage(e));
    } finally {
      setDownloading(false);
    }
  }

  const aliveRef = useRef(true);
  useEffect(() => {
    aliveRef.current = true;
    return () => {
      aliveRef.current = false;
    };
  }, []);

  // On mount: pull usage + check if there's an in-flight run.
  useEffect(() => {
    let canceled = false;
    (async () => {
      try {
        const u = await api<AgenticUsage>("/fix-tasks/agentic/usage", {
          direct: true,
        });
        if (canceled) return;
        setUsage(u);
      } catch {
        // usage call failures are non-fatal — button still works
      }
      try {
        const param = scope === "scan" ? `scan_id=${id}` : `repo_scan_id=${id}`;
        const latest = await api<AgenticRun | null>(
          `/fix-tasks/agentic/latest?${param}`,
          { direct: true },
        );
        if (canceled || !latest) return;
        const detail = await api<AgenticRunDetail>(
          `/fix-tasks/agentic/${latest.id}`,
          { direct: true },
        );
        if (canceled) return;
        setRun(detail);
        setSteps(detail.recent_steps);
        if (!TERMINAL.has(detail.status)) {
          startStream(detail.id);
        }
      } catch {
        // no prior run — fine
      }
    })();
    return () => {
      canceled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, id]);

  useEffect(() => {
    if (scope !== "scan") return;
    if (linkedRepos.length === 1) {
      setSelectedRepositoryId(linkedRepos[0].repository_id);
    }
  }, [scope, linkedRepos]);

  // ── Start a new run ───────────────────────────────────────────
  const startRun = useCallback(async () => {
    setStarting(true);
    setError(null);
    setSteps([]);
    try {
      const body =
        scope === "scan"
          ? {
              scan_id: id,
              ...(selectedRepositoryId
                ? { repository_id: selectedRepositoryId }
                : {}),
            }
          : { repo_scan_id: id };
      const accepted = await api<AgenticRun>("/fix-tasks/agentic", {
        method: "POST",
        body: JSON.stringify(body),
        direct: true,
      });
      const detail: AgenticRunDetail = {
        ...accepted,
        recent_steps: [],
        usage_total_input_tokens: 0,
        usage_total_output_tokens: 0,
        usage_total_cost_cents: 0,
      };
      setRun(detail);
      startStream(accepted.id);
    } catch (e) {
      setError(extractMessage(e));
    } finally {
      setStarting(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, id, selectedRepositoryId]);

  // ── Cancel ────────────────────────────────────────────────────
  const cancelRun = useCallback(async () => {
    if (!run || TERMINAL.has(run.status)) return;
    try {
      const next = await api<AgenticRun>(
        `/fix-tasks/agentic/${run.id}/cancel`,
        { method: "POST", direct: true },
      );
      if (!aliveRef.current) return;
      setRun((prev) => (prev ? { ...prev, ...next } : null));
    } catch (e) {
      setError(extractMessage(e));
    }
  }, [run]);

  // ── SSE stream + polling fallback ─────────────────────────────
  function startStream(runId: string) {
    let eventSource: EventSource | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let usingSSE = false;

    // Try SSE first. Use raw EventSource — the API's
    // /fix-tasks/agentic/{id}/stream endpoint requires auth via the
    // same Bearer token cookies CSR API calls use. EventSource sends
    // credentials when withCredentials=true and the API rewrite is
    // same-origin via Next's /api/* proxy.
    try {
      const url = `/api/fix-tasks/agentic/${runId}/stream`;
      eventSource = new EventSource(url, { withCredentials: true });
      eventSource.addEventListener("step", (ev) => {
        if (!aliveRef.current) return;
        try {
          const payload = JSON.parse((ev as MessageEvent).data);
          setSteps((prev) => [
            ...prev,
            {
              iteration: payload.iteration,
              step_index: payload.step_index,
              tool_name: payload.tool_name,
              tool_input: payload.tool_input ?? null,
              tool_error: payload.is_error
                ? "(see audit log for details)"
                : null,
              duration_ms: payload.duration_ms,
              created_at: new Date().toISOString(),
            },
          ]);
        } catch {
          // ignore malformed event
        }
      });
      eventSource.addEventListener("status", (ev) => {
        if (!aliveRef.current) return;
        try {
          const payload = JSON.parse((ev as MessageEvent).data);
          setRun((prev) =>
            prev
              ? {
                  ...prev,
                  status: payload.status,
                  pr_url: payload.pr_url ?? prev.pr_url,
                }
              : prev,
          );
        } catch {
          // ignore
        }
      });
      eventSource.addEventListener("terminal", (ev) => {
        try {
          const payload = JSON.parse((ev as MessageEvent).data);
          setRun((prev) =>
            prev
              ? {
                  ...prev,
                  status: payload.status,
                  pr_url: payload.pr_url ?? prev.pr_url,
                  error: payload.error ?? prev.error,
                }
              : prev,
          );
        } catch {
          // ignore
        }
        eventSource?.close();
        if (pollTimer) clearInterval(pollTimer);
      });
      eventSource.onerror = () => {
        eventSource?.close();
        eventSource = null;
        // Fall back to polling.
        if (!pollTimer) startPolling();
      };
      usingSSE = true;
    } catch {
      // EventSource construction failed — go straight to polling.
    }

    function startPolling() {
      pollTimer = setInterval(async () => {
        if (!aliveRef.current) {
          if (pollTimer) clearInterval(pollTimer);
          return;
        }
        try {
          const detail = await api<AgenticRunDetail>(
            `/fix-tasks/agentic/${runId}`,
            { direct: true },
          );
          if (!aliveRef.current) return;
          setRun(detail);
          setSteps(detail.recent_steps);
          if (TERMINAL.has(detail.status)) {
            if (pollTimer) clearInterval(pollTimer);
          }
        } catch {
          // transient — keep trying
        }
      }, POLL_INTERVAL_MS);
    }

    if (!usingSSE) startPolling();
  }

  const isRunning = run !== null && !TERMINAL.has(run.status);
  const usageBar = usage ? renderUsageBar(usage) : null;
  const blockedByUsage = usage && !usage.can_start && !isRunning;
  const needsRepository =
    scope === "scan" && linkedRepos.length > 0 && !selectedRepositoryId;
  const noAttachedRepository =
    scope === "scan" && linkedRepos.length === 0 && !allowNoRepo;

  return (
    <div className={className}>
      {scope === "scan" && linkedRepos.length > 1 && (
        <div className="mb-3 max-w-md">
          <label className="block font-mono text-[11px] uppercase tracking-[0.18em] text-mist mb-1">
            Source repo
          </label>
          <select
            value={selectedRepositoryId}
            onChange={(e) => setSelectedRepositoryId(e.target.value)}
            className="w-full border border-hairline bg-paper px-3 py-2 font-body text-[13px] text-ink rounded-sm"
          >
            <option value="">Select attached repo…</option>
            {linkedRepos.map((repo) => (
              <option key={repo.repository_id} value={repo.repository_id}>
                {repo.full_name}
              </option>
            ))}
          </select>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <Button
          variant="pink"
          onClick={startRun}
          disabled={
            starting ||
            isRunning ||
            blockedByUsage === true ||
            needsRepository ||
            noAttachedRepository
          }
        >
          {starting
            ? "Starting…"
            : isRunning
              ? labelForStatus(run.status)
              : run && TERMINAL.has(run.status)
                ? "Run Agent again"
                : "Fix all findings (Agent)"}
        </Button>
        {isRunning && (
          <Button variant="ink" onClick={cancelRun}>
            Stop
          </Button>
        )}
        <span className="font-body text-[12px] text-slate italic">
          Pencheff Agent reads + edits files, runs your linters, and opens one
          PR with all fixes. <span className="font-mono text-[10px]">beta</span>
        </span>
      </div>
      {noAttachedRepository && (
        <p className="mt-2 font-body text-[12px] text-slate italic">
          Attach a source repository to this target before running Agent fix.
        </p>
      )}

      {usageBar}

      {error && (
        <div className="mt-3 border border-rust/40 bg-rust/[0.04] rounded-sm p-3">
          <span className="font-mono text-[10px] text-rust uppercase tracking-[0.12em]">
            Error
          </span>
          <p className="mt-1 font-body text-[13px] text-graphite leading-[1.55] break-words">
            {error}
          </p>
        </div>
      )}

      {(blockedByUsage || (error != null && /credit/i.test(error))) && (
        <McpFallbackNote kind="credits" />
      )}

      {run && (
        <div className="mt-4 formal-surface p-4 space-y-3">
          <div className="flex flex-wrap items-center gap-3 font-mono text-[11px]">
            <span className="text-mist uppercase tracking-[0.12em]">
              {labelForStatus(run.status)}
            </span>
            <span className="text-slate">
              · {run.findings_count} finding
              {run.findings_count !== 1 ? "s" : ""}
            </span>
            <span className="text-slate">· iter {run.iterations}</span>
            {run.pr_url && (
              <a
                href={run.pr_url}
                target="_blank"
                rel="noopener noreferrer"
                className="underline underline-offset-[4px] decoration-gilt decoration-1 hover:text-ink"
              >
                PR ↗
              </a>
            )}
            {allowNoRepo && run.status === "done" && (
              <button
                type="button"
                onClick={downloadFixedZip}
                disabled={downloading}
                className="underline underline-offset-[4px] decoration-gilt decoration-1 hover:text-ink disabled:opacity-50"
              >
                {downloading ? "Preparing…" : "Download fixed .zip ↓"}
              </button>
            )}
          </div>

          {run.current_step && (
            <p className="font-mono text-[11px] text-slate">
              {run.current_step}
            </p>
          )}

          {steps.length > 0 && <ToolTranscript steps={steps} />}

          {run.error && (
            <div className="mt-2 border border-rust/40 bg-rust/[0.04] rounded-sm p-3">
              <p className="font-body text-[12px] text-rust break-words">
                {run.error}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Tool transcript ────────────────────────────────────────────────

function ToolTranscript({ steps }: { steps: AgenticStep[] }) {
  // Cap to the last 50 rows so the DOM doesn't bloat on long runs.
  const tail = steps.slice(-50);
  return (
    <div className="mt-2 max-h-56 overflow-y-auto border border-hairline rounded-sm bg-paper/50 p-2 font-mono text-[11px] leading-[1.6]">
      {tail.map((s) => (
        <div
          key={`${s.iteration}-${s.step_index}-${s.created_at}`}
          className="flex flex-wrap gap-2"
        >
          <span className="text-mist">
            #{s.iteration}.{s.step_index}
          </span>
          <span className="text-graphite">{toolGlyph(s.tool_name)}</span>
          <span className={s.tool_error ? "text-rust" : "text-graphite"}>
            {s.tool_name}
          </span>
          <span className="text-mist break-all">
            {summarizeInput(s.tool_name, s.tool_input)}
          </span>
          <span className="text-mist ml-auto">{s.duration_ms}ms</span>
        </div>
      ))}
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────

function renderUsageBar(u: AgenticUsage) {
  return (
    <div className="mt-3 flex flex-wrap items-center gap-3 font-mono text-[11px]">
      <span className="text-mist uppercase tracking-[0.12em]">{u.plan}</span>
      <span className="text-slate">
        · {u.in_flight_runs}/
        {u.max_concurrent_runs < 0 ? "∞" : u.max_concurrent_runs} in-flight
      </span>
      {!u.can_start && (
        <span className="text-rust">
          ·{" "}
          {u.block_reason === "concurrency_exceeded"
            ? "concurrency cap reached"
            : "blocked"}
        </span>
      )}
    </div>
  );
}

function labelForStatus(s: AgenticRun["status"]): string {
  switch (s) {
    case "queued":
      return "Queued";
    case "cloning":
      return "Cloning repo";
    case "running":
      return "Agent running";
    case "committing":
      return "Committing changes";
    case "pushing":
      return "Opening PR";
    case "done":
      return "Done";
    case "failed":
      return "Failed";
    case "canceled":
      return "Canceled";
    default:
      return s;
  }
}

function toolGlyph(name: string): string {
  switch (name) {
    case "read_file":
      return "📖";
    case "write_file":
      return "📝";
    case "edit_file":
      return "✏️";
    case "grep":
      return "🔎";
    case "glob":
      return "🗂️";
    case "bash":
      return "⚡";
    default:
      return "·";
  }
}

function summarizeInput(
  name: string,
  input: Record<string, unknown> | null,
): string {
  if (!input) return "";
  switch (name) {
    case "read_file":
    case "write_file":
    case "edit_file":
      return String(input.path ?? "");
    case "grep":
      return `/${String(input.pattern ?? "")}/${input.glob ? ` ${input.glob}` : ""}`;
    case "glob":
      return String(input.pattern ?? "");
    case "bash":
      return String(input.command ?? "").slice(0, 80);
    default:
      return Object.keys(input).slice(0, 3).join(",");
  }
}

function extractMessage(e: unknown): string {
  if (e instanceof ApiError) {
    const detail = e.body?.detail;
    if (typeof detail === "string") return detail;
    if (
      typeof detail === "object" &&
      detail !== null &&
      typeof (detail as { message?: unknown }).message === "string"
    ) {
      return (detail as { message: string }).message;
    }
    return e.message;
  }
  if (e instanceof Error) return e.message;
  return "Agentic fix failed.";
}
