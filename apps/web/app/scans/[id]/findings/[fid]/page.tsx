"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { Button, SeverityPill } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { FixProposalCard } from "@/components/fix-proposal-card";
import { PriorityStrip } from "@/components/priority-badges";
import { AiTriagePanel, TriagePayload } from "@/components/ai-triage-panel";
import { Markdown } from "@/components/markdown";
import { VerifyWithHumansButton } from "@/components/verify-with-humans-button";
import { api } from "@/lib/api";
import { useWorkspace } from "@/lib/workspace-context";

type Finding = {
  id: string;
  scan_id: string;
  title: string;
  severity: string;
  category: string;
  owasp_category: string | null;
  cwe_id: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  endpoint: string | null;
  parameter: string | null;
  description: string | null;
  remediation: string | null;
  evidence: any[] | null;
  references: string[] | null;
  verification_status: string;
  hackable: boolean | null;
  suppressed: boolean;
  suppress_reason: string | null;
  last_rechecked_at: string | null;
  recheck_status: string | null;
  // Phase 1.3 + 2.5 + 2.6 fields — prioritisation surface and AI triage.
  risk_score: number | null;
  ssvc_decision: string | null;
  reachability: string | null;
  epss: number | null;
  kev: boolean;
  ai_triage: TriagePayload | null;
};

const SEV_BAR: Record<string, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const VERIF_COPY: Record<string, string> = {
  unverified: "Unverified",
  true_positive: "Verified",
  false_positive: "False positive",
  fixed: "Fixed",
};

export default function FindingDetailPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const id = mounted ? pathSegment(pathname, 2) : "";
  const fid = mounted ? pathSegment(pathname, 4) : "";
  const { activeOrg } = useWorkspace();
  // Prefer the API-resolved ai_enabled flag (respects AI_FREE_TIER_ENABLED).
  // Fall back to plan-based check for older API versions that don't return
  // the field.
  const aiEnabled = activeOrg
    ? (activeOrg.ai_enabled ?? activeOrg.plan !== "free")
    : false;
  const [f, setF] = useState<Finding | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function load() {
    const data = await api<Finding>(`/findings/${fid}`);
    setF(data);
    return data;
  }

  useEffect(() => {
    if (!fid) return;
    load().catch(() => {});
  }, [fid]);

  async function recheck() {
    setBusy(true);
    setMsg("Re-examination queued…");
    try {
      await api<Finding>(`/findings/${fid}/recheck`, { method: "POST" });
      const interval = setInterval(async () => {
        const updated = await api<Finding>(`/findings/${fid}`);
        setF(updated);
        if (updated.recheck_status && updated.recheck_status !== "queued") {
          clearInterval(interval);
          setMsg(`Re-examination complete — ${updated.recheck_status}.`);
          setBusy(false);
        }
      }, 2500);
    } catch (e: any) {
      setMsg(e?.message || "Re-examination failed.");
      setBusy(false);
    }
  }

  async function setStatus(status: string) {
    const updated = await api<Finding>(`/findings/${fid}/status`, {
      method: "POST",
      json: { verification_status: status },
    });
    setF(updated);
  }

  async function suppress(reason: string) {
    const updated = await api<Finding>(`/findings/${fid}/suppress`, {
      method: "POST",
      json: { reason },
    });
    setF(updated);
  }

  async function unsuppress() {
    const updated = await api<Finding>(`/findings/${fid}/unsuppress`, {
      method: "POST",
    });
    setF(updated);
  }

  if (!f) {
    return (
      <div className="py-6">
        <InlineLoading label="Loading finding…" />
      </div>
    );
  }

  const sev = (f.severity || "info").toLowerCase();
  const bar = SEV_BAR[sev] || SEV_BAR.info;

  return (
    <div className="space-y-10">
      <Link
        href={`/scans/${id}`}
        className="inline-flex items-center gap-2 font-body text-[13px] text-slate hover:text-ink underline-offset-[6px] hover:underline decoration-gilt decoration-1"
      >
        ← Return to assessment
      </Link>

      {/* --- Title ---------------------------------------------- */}
      <header className="relative pl-6">
        <span
          className={`absolute left-0 top-1 bottom-1 w-[3px] rounded-[1px] ${bar}`}
          aria-hidden
        />
        <div className="flex items-center gap-3 mb-3">
          <SeverityPill severity={f.severity} />
          <span className="font-mono text-[11px] text-mist tracking-[0.08em]">
            Finding № {f.id.slice(0, 8).toUpperCase()}
          </span>
        </div>
        <h1 className="font-display text-[32px] md:text-[40px] leading-[1.1] tracking-[-0.015em] text-ink max-w-[52ch]">
          {f.title}
        </h1>
        {/* Priority surface — risk_score / SSVC / reachability / EPSS / KEV.
            Renders nothing when all five are null (legacy findings predating
            the prioritisation engine). */}
        <div className="mt-4">
          <PriorityStrip
            riskScore={f.risk_score}
            reachability={f.reachability}
            ssvc={f.ssvc_decision}
            epss={f.epss}
            kev={f.kev}
          />
        </div>
        <dl className="mt-5 flex flex-wrap gap-x-8 gap-y-2 font-mono text-[12px] text-slate">
          <div>
            <dt className="inline text-mist">Category · </dt>
            <dd className="inline text-graphite">{f.category}</dd>
          </div>
          {f.owasp_category && (
            <div>
              <dt className="inline text-mist">OWASP · </dt>
              <dd className="inline text-graphite">{f.owasp_category}</dd>
            </div>
          )}
          {f.cwe_id && (
            <div>
              <dt className="inline text-mist">CWE · </dt>
              <dd className="inline text-graphite">{f.cwe_id}</dd>
            </div>
          )}
          {f.cvss_score != null && (
            <div>
              <dt className="inline text-mist">CVSS · </dt>
              <dd className="inline text-graphite">
                {f.cvss_score.toFixed(1)}
              </dd>
            </div>
          )}
          {f.cvss_vector && (
            <div className="break-all">
              <dt className="inline text-mist">Vector · </dt>
              <dd className="inline text-graphite">{f.cvss_vector}</dd>
            </div>
          )}
        </dl>
      </header>

      {/* --- Actions -------------------------------------------- */}
      <section>
        <div className="flex items-baseline justify-between mb-4">
          <p className="eyebrow">Disposition</p>
          <span className="font-mono text-[11px] text-mist">
            Status ·{" "}
            <span className="text-graphite">
              {VERIF_COPY[f.verification_status] || f.verification_status}
            </span>
            {f.hackable === true && (
              <span
                title="AI agent verified this finding is exploitable"
                className="ml-2 inline-flex items-center border border-oxblood rounded-sm px-2 py-0.5 font-body text-[10px] font-semibold uppercase tracking-[0.16em] text-paper bg-oxblood"
              >
                Hackable
              </span>
            )}
            {f.hackable === false && (
              <span
                title="AI agent verified this finding is not exploitable"
                className="ml-2 inline-flex items-center border border-hairline rounded-sm px-2 py-0.5 font-body text-[10px] font-medium uppercase tracking-[0.16em] text-mist"
              >
                Not exploitable
              </span>
            )}
            {f.last_rechecked_at && (
              <>
                {" "}
                · last re-examined{" "}
                <span className="text-graphite">
                  {f.last_rechecked_at.slice(0, 19).replace("T", " · ")}
                </span>
              </>
            )}
          </span>
        </div>

        <div className="formal-surface p-6">
          {msg && (
            <p className="mb-4 font-body text-[13px] text-slate italic">
              {msg}
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <Button variant="pink" onClick={recheck} disabled={busy}>
              {busy ? "Re-examining…" : "Re-examine finding"}
            </Button>
            <Button variant="lime" onClick={() => setStatus("fixed")}>
              Mark fixed
            </Button>
            <Button variant="lime" onClick={() => setStatus("true_positive")}>
              Confirm
            </Button>
            <Button variant="lime" onClick={() => setStatus("false_positive")}>
              Mark false positive
            </Button>
            {f.suppressed ? (
              <Button variant="danger" onClick={unsuppress}>
                Unsuppress
              </Button>
            ) : (
              <>
                <Button
                  variant="cyan"
                  onClick={() => suppress("accepted_risk")}
                >
                  Accept risk
                </Button>
                <Button variant="cyan" onClick={() => suppress("wont_fix")}>
                  Won&rsquo;t fix
                </Button>
              </>
            )}
          </div>
          {/* Phase 4.2 — submit this finding to a partner pentest
              platform (HackerOne / Bugcrowd / Cobalt) for human triage.
              Only renders when the workspace has at least one partner
              integration configured; the ack handles "no integration
              configured" cleanly. */}
          <div className="mt-4 pt-4 border-t border-hairline">
            <p className="eyebrow-gilt mb-2 text-[10px]">Human triage</p>
            <VerifyWithHumansButton findingId={fid} />
          </div>
        </div>
      </section>

      {/* --- Where ---------------------------------------------- */}
      <section>
        <p className="eyebrow mb-3">Locus</p>
        <div className="formal-surface p-6 space-y-2 font-mono text-[13px]">
          <p className="break-all">
            <span className="text-mist">Endpoint · </span>
            <span className="text-graphite">{f.endpoint || "—"}</span>
          </p>
          <p>
            <span className="text-mist">Parameter · </span>
            <span className="text-graphite">{f.parameter || "—"}</span>
          </p>
        </div>
      </section>

      {/* --- Description ---------------------------------------- */}
      <section>
        <p className="eyebrow mb-3">Description</p>
        <div className="formal-surface p-6">
          {f.description ? (
            <Markdown>{f.description}</Markdown>
          ) : (
            <p className="text-[14px] leading-[1.7] text-graphite">—</p>
          )}
        </div>
      </section>

      {/* --- Triage panel ---------------------------------------- */}
      <AiTriagePanel
        findingId={f.id}
        initial={f.ai_triage}
        aiEnabled={aiEnabled}
        onUpdated={(next) =>
          setF((cur) => (cur ? { ...cur, ai_triage: next.ai_triage } : cur))
        }
      />

      {/* --- Remediation ---------------------------------------- */}
      <section>
        <p className="eyebrow-gilt mb-3">Remediation</p>
        <div className="advisory">
          <p className="eyebrow-gilt mb-3 text-[10px]">Advisory note</p>
          {f.remediation ? (
            <Markdown>{f.remediation}</Markdown>
          ) : (
            <p className="text-[14px] leading-[1.7] text-graphite">—</p>
          )}
        </div>
      </section>

      {/* --- Auto-fix proposal (PR flow) ------------------------- */}
      <FixProposalCard
        findingKind={f.category === "sast" ? "sast" : "dast"}
        findingId={f.id}
        scanId={f.scan_id}
      />

      {/* --- Evidence ------------------------------------------- */}
      {f.evidence && f.evidence.length > 0 && (
        <section>
          <p className="eyebrow mb-3">Evidence</p>
          <div className="space-y-6">
            {f.evidence.map((ev, i) => (
              <article key={i} className="formal-surface p-6">
                <div className="flex items-baseline justify-between mb-4">
                  <span className="eyebrow-gilt">
                    Evidence № {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className="font-mono text-[11px] text-mist">
                    {ev.request_method || "—"} · {ev.response_status || "—"}
                  </span>
                </div>
                <p className="font-mono text-[12px] text-graphite break-all">
                  <span className="text-ink font-medium">
                    {ev.request_method}
                  </span>{" "}
                  {ev.request_url}
                </p>
                {ev.description && (
                  <p className="mt-3 text-[13px] text-slate italic">
                    {ev.description}
                  </p>
                )}
                {ev.response_body_snippet && (
                  <pre className="mt-4 bg-vellum border border-hairline rounded-sm p-4 font-mono text-[12px] text-graphite whitespace-pre-wrap overflow-auto leading-[1.6]">
                    {ev.response_body_snippet}
                  </pre>
                )}
              </article>
            ))}
          </div>
        </section>
      )}

      {/* --- References ----------------------------------------- */}
      {f.references && f.references.length > 0 && (
        <section>
          <p className="eyebrow mb-3">References</p>
          <div className="formal-surface p-6">
            <ul className="space-y-2 font-mono text-[12px]">
              {f.references.map((r) => (
                <li key={r} className="break-all">
                  <span className="text-mist">↪ </span>
                  <a
                    href={r}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-ink underline underline-offset-[4px] decoration-gilt decoration-1 hover:decoration-2"
                  >
                    {r}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </section>
      )}
    </div>
  );
}
