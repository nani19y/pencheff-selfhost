"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/brutal";
import { api, ApiError } from "@/lib/api";

type FixProposalKind = "sast" | "dast";
type ProposalStatus = "draft" | "applied" | "failed" | "superseded";
type ProposalSource = "scanner" | "llm";

type FixProposalOut = {
  id: string;
  finding_kind: FixProposalKind;
  finding_id: string;
  repository_id: string | null;
  status: ProposalStatus;
  source: ProposalSource;
  diff: string;
  target_files: string[];
  provenance_confidence: number | null;
  provenance_reasoning: string | null;
  llm_input_tokens: number | null;
  llm_output_tokens: number | null;
  cost_usd: number | null;
  branch_name: string | null;
  pr_url: string | null;
  commit_sha: string | null;
  error: string | null;
  /** One-shot info message set when the proposal is generated (e.g. the
   * deterministic-fallback notice when the org is over its AI allotment). */
  notice: string | null;
  created_at: string;
  applied_at: string | null;
};

type ErrorPayload = { reason: string | null; message: string };

function unpackError(e: unknown, fallback: string): ErrorPayload {
  if (e instanceof ApiError) {
    const detail = e.body?.detail as
      | string
      | { reason?: unknown; message?: unknown }
      | undefined;
    if (detail && typeof detail === "object") {
      const reason = typeof detail.reason === "string" ? detail.reason : null;
      const message =
        typeof detail.message === "string" ? detail.message : e.message || fallback;
      return { reason, message };
    }
    if (typeof detail === "string") {
      return { reason: null, message: detail };
    }
    return { reason: null, message: e.message || fallback };
  }
  if (e instanceof Error && e.message) {
    return { reason: null, message: e.message };
  }
  return { reason: null, message: fallback };
}

export function FixProposalCard({
  findingKind,
  findingId,
  scanId,
}: {
  findingKind: FixProposalKind;
  findingId: string;
  scanId?: string;
}) {
  const [proposal, setProposal] = useState<FixProposalOut | null>(null);
  const [busy, setBusy] = useState(false);
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState<ErrorPayload | null>(null);

  useEffect(() => {
    api<FixProposalOut | null>(
      `/findings/${findingKind}/${findingId}/fix_proposal`
    )
      .then(setProposal)
      .catch(() => setProposal(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingId, scanId]);

  async function propose() {
    setBusy(true);
    setError(null);
    try {
      const p = await api<FixProposalOut>(
        `/findings/${findingKind}/${findingId}/propose_fix`,
        {
          method: "POST",
          json: { allow_payg: false },
          direct: true,
        }
      );
      setProposal(p);
    } catch (e: unknown) {
      setError(unpackError(e, "Could not generate a fix."));
    } finally {
      setBusy(false);
    }
  }

  async function apply() {
    if (!proposal) return;
    setApplying(true);
    setError(null);
    try {
      const result = await api<{
        status: ProposalStatus;
        branch_name: string | null;
        pr_url: string | null;
        error: string | null;
      }>(`/fix-proposals/${proposal.id}/apply`, {
        method: "POST",
        direct: true,
      });
      const next = { ...proposal, ...result };
      setProposal(next as FixProposalOut);
    } catch (e: unknown) {
      setError(unpackError(e, "Apply failed."));
    } finally {
      setApplying(false);
    }
  }

  async function discard() {
    if (!proposal) return;
    try {
      await api(`/fix-proposals/${proposal.id}`, { method: "DELETE" });
      setProposal(null);
      setError(null);
    } catch (e: unknown) {
      setError(unpackError(e, "Could not discard."));
    }
  }

  async function discardAndRepropose() {
    if (!proposal) return;
    setApplying(true);
    setError(null);
    try {
      // Close the PR + delete the branch upstream, then mark superseded.
      await api(`/fix-proposals/${proposal.id}/revert`, {
        method: "POST",
        direct: true,
      });
      setProposal(null);
      // Kick off a fresh proposal.
      await propose();
    } catch (e: unknown) {
      setError(unpackError(e, "Could not revert + re-propose."));
    } finally {
      setApplying(false);
    }
  }

  // ── render ────────────────────────────────────────────────────

  return (
    <section>
      <p className="eyebrow-gilt mb-3">Auto-fix</p>
      <div className="formal-surface p-6 space-y-4">
        {/* Deterministic-fallback notice (AI allotment spent) */}
        {proposal?.notice && (
          <div className="flex items-start gap-2 border border-gilt/40 bg-gilt/8 rounded-sm px-3 py-2">
            <span className="text-gilt mt-0.5" aria-hidden>•</span>
            <p className="font-body text-[12.5px] text-graphite leading-[1.5]">
              {proposal.notice}
            </p>
          </div>
        )}

        {/* Existing proposal */}
        {proposal && (
          <ProposalView
            proposal={proposal}
            applying={applying}
            onApply={apply}
            onDiscard={discard}
            onDiscardAndRepropose={discardAndRepropose}
          />
        )}

        {/* Errors */}
        {error && <ErrorBlock error={error} />}

        {/* Initial CTA */}
        {!proposal && (
          <div className="flex flex-wrap items-center gap-3">
            <Button
              variant="pink"
              onClick={() => propose()}
              disabled={busy}
            >
              {busy ? "Proposing fix…" : "Propose fix"}
            </Button>
            <span className="font-body text-[12px] text-slate italic">
              {findingKind === "sast"
                ? "Patches the file in the attached repo and opens a PR."
                : "Locates the source handler in attached repos and opens a PR."}
            </span>
          </div>
        )}
      </div>
    </section>
  );
}

function ProposalView({
  proposal,
  applying,
  onApply,
  onDiscard,
  onDiscardAndRepropose,
}: {
  proposal: FixProposalOut;
  applying: boolean;
  onApply: () => void;
  onDiscard: () => void;
  onDiscardAndRepropose: () => void;
}) {
  const isApplied = proposal.status === "applied";
  const isFailed = proposal.status === "failed";
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-baseline gap-x-5 gap-y-1 font-mono text-[11px] text-mist">
        <span>
          Source ·{" "}
          <span className="text-graphite">
            {proposal.source === "scanner" ? "scanner autofix" : "LLM-generated"}
          </span>
        </span>
        <span>
          Status ·{" "}
          <span
            className={
              isApplied
                ? "text-lime"
                : isFailed
                ? "text-rust"
                : "text-graphite"
            }
          >
            {proposal.status}
          </span>
        </span>
        {proposal.provenance_confidence != null && (
          <span>
            Provenance ·{" "}
            <span className="text-graphite">
              {(proposal.provenance_confidence * 100).toFixed(0)}%
            </span>
          </span>
        )}
        {proposal.cost_usd != null && proposal.cost_usd > 0 && (
          <span>
            Cost · <span className="text-graphite">${proposal.cost_usd.toFixed(4)}</span>
          </span>
        )}
      </div>

      {proposal.provenance_reasoning && (
        <p className="font-body text-[12px] text-slate italic">
          {proposal.provenance_reasoning}
        </p>
      )}

      {proposal.target_files.length > 0 && (
        <p className="font-mono text-[11px] text-mist">
          Target ·{" "}
          <span className="text-graphite">
            {proposal.target_files.join(", ")}
          </span>
        </p>
      )}

      <pre className="formal-surface bg-paper border border-hairline rounded-sm p-4 max-h-[420px] overflow-auto font-mono text-[11px] leading-[1.5] text-graphite">
        {proposal.diff || "(empty diff)"}
      </pre>

      {proposal.error && (
        <p className="font-mono text-[12px] text-rust break-words">
          {proposal.error}
        </p>
      )}

      {isApplied ? (
        <div className="flex flex-wrap items-center gap-3 font-body text-[13px] text-graphite">
          {proposal.pr_url ? (
            <a
              className="underline underline-offset-[4px] decoration-gilt decoration-1 hover:text-ink"
              href={proposal.pr_url}
              target="_blank"
              rel="noopener noreferrer"
            >
              View PR ↗
            </a>
          ) : (
            <span>
              Branch <code className="font-mono">{proposal.branch_name}</code>{" "}
              committed locally — push it to open a PR.
            </span>
          )}
          {proposal.commit_sha && (
            <span className="font-mono text-[11px] text-mist">
              {proposal.commit_sha.slice(0, 12)}
            </span>
          )}
          <Button
            variant="cyan"
            onClick={onDiscardAndRepropose}
            disabled={applying}
            title="Closes the PR, deletes the branch, then asks the LLM for another fix."
          >
            {applying ? "Reverting…" : "Discard PR & propose another"}
          </Button>
        </div>
      ) : (
        <div className="flex flex-wrap gap-2">
          <Button variant="pink" onClick={onApply} disabled={applying}>
            {applying ? "Opening PR…" : "Open PR"}
          </Button>
          <Button variant="cyan" onClick={onDiscard} disabled={applying}>
            Discard
          </Button>
        </div>
      )}
    </div>
  );
}


function ErrorBlock({ error }: { error: ErrorPayload }) {
  return (
    <div className="border border-rust/40 bg-rust/[0.04] rounded-sm p-3 space-y-1">
      <div className="flex items-baseline gap-3">
        <span className="font-mono text-[10px] text-rust uppercase tracking-[0.12em]">
          Error
        </span>
        {error.reason && (
          <span className="font-mono text-[10px] text-mist">{error.reason}</span>
        )}
      </div>
      <p className="font-body text-[13px] text-graphite leading-[1.55] break-words">
        {error.message}
      </p>
    </div>
  );
}
