"use client";

import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useRouter } from "next/navigation";
import { Button } from "@/components/brutal";
import { EmailRecipientsInput } from "@/components/email-recipients-input";
import { McpFallbackNote } from "@/components/mcp-fallback-note";
import { api, AUTHORIZATION_STATEMENT_STORAGE_KEY } from "@/lib/api";
import {
  DISCLOSED_ACTIONS,
  getKindDisclosures,
  type KindConfigForDisclosures,
} from "@/lib/consent-disclosures";
import type { SupportedKind } from "@/components/register-target/target-types";
import { useWorkspace } from "@/lib/workspace-context";

const PROFILES: { value: string; label: string; hint: string }[] = [
  {
    value: "quick",
    label: "Quick",
    hint:
      "5–10 min · top-severity probes only · CI/CD-friendly fail-fast on " +
      "critical and high.",
  },
  {
    value: "standard",
    label: "Standard",
    hint:
      "20–40 min · OWASP Top 10 + active scanner · REST/GraphQL/API surface · " +
      "ASM/SCA/IaC checks · deterministic bug-bounty pipeline · " +
      "CVE correlation.",
  },
  {
    value: "deep",
    label: "Deep",
    hint:
      "60+ min · every module + Pulse + attack chains · full swarm (Tier 2 · " +
      "all 7 phases · top-1000 ports · subdomain fan-out ≤100) · deterministic " +
      "orchestrator · MITRE ATT&CK narrative · PCI/SOC 2/ISO 27001/HIPAA mappings.",
  },
];

const LLM_PROFILES: { value: string; label: string; hint: string }[] = [
  {
    value: "quick",
    label: "Quick",
    hint: "10 probes · ~2 min · top-priority subset across LLM01/02/05/07/10",
  },
  {
    value: "standard",
    label: "Standard",
    hint: "Full v1 library · ~5 min · every technique class",
  },
  {
    value: "deep",
    label: "Deep",
    hint: "Same as standard for v1 · multi-turn variants ship in v1.1",
  },
];

type Scan = {
  id: string;
};

type ScanAiQuota = {
  plan: string;
  monthly_cap: number | null;
  monthly_used: number;
  monthly_remaining: number | null;
  credit_metered?: boolean;
  has_ai_access: boolean;
  quota_exhausted: boolean;
  ai_available: boolean;
  period_resets_at: string;
  beta: boolean;
};

export function CommissionScanModal({
  targetId,
  targetName,
  targetKind,
  repositoryId,
  targetKindConfig,
  priorAuthorizationText,
  onClose,
}: {
  targetId: string | null;
  targetName: string | null;
  /** "repo" / "source_code" routes through POST /repos/{id}/scan when a
   * repository_id is attached; "url" + all new DAST/artifact/hybrid kinds use
   * POST /scans; "llm" uses /scans with the LLM red-team branch. Feature 001
   * widened this from the legacy 3-value union to the full SupportedKind. */
  targetKind?: SupportedKind;
  /** Required when targetKind === "repo" / "source_code" with a backing Repository. */
  repositoryId?: string | null;
  /** Feature 001 — when supplied, the modal computes Phase B disclosures
   * for hybrid kinds (cicd_pipeline live_api_enabled, k8s_cluster live_cluster).
   * Optional — base required-actions set is sent when omitted. */
  targetKindConfig?: KindConfigForDisclosures | Record<string, unknown> | null;
  /** Authorization statement from this target's most recent scan, if any.
   * Wins over the localStorage fallback so re-scanning a previously-scanned
   * target prefills its own engagement-letter text instead of whatever was
   * last typed on a different target. */
  priorAuthorizationText?: string | null;
  onClose: () => void;
}) {
  const router = useRouter();
  const { activeWorkspace } = useWorkspace();
  // Repo-style routing covers legacy "repo" mirror AND new "source_code" Targets
  // when they carry a repository_id (created via /repos/github). API-only
  // source_code Targets without a repository_id post to /scans like other kinds.
  const isRepo =
    targetKind === "repo" ||
    (targetKind === "source_code" && Boolean(repositoryId));
  const isLlm = targetKind === "llm";
  // Live kinds that can be load-tested (static/artifact kinds can't).
  const supportsLoad = new Set([
    "web_app",
    "url",
    "rest_api",
    "graphql",
    "websocket",
    "grpc",
    "voice",
    "llm",
  ]).has(targetKind ?? "");
  const [profile, setProfile] = useState("standard");
  const [loadCfg, setLoadCfg] = useState({
    mode: "agentic",
    profile_shape: "ramp",
    duration_s: 30,
    concurrency: 20,
    target_rps: "" as number | "",
    ramp_s: 5,
    thresholds: {
      p95_ms: 1000 as number | "",
      error_rate: 0.05 as number | "",
    },
    max_stages: 6,
    stage_duration_s: 25,
    total_budget_s: 240,
  });
  const [submitting, setSubmitting] = useState(false);
  const [sbomSubmitting, setSbomSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // Consent state. Prefill priority: this target's most recent scan
  // → last statement entered on this device → empty. Operators can edit
  // or clear before submitting. We only persist on successful submit so
  // abandoned edits don't bleed into the next scan.
  const [authorizationText, setAuthorizationText] = useState<string>(() => {
    if (priorAuthorizationText && priorAuthorizationText.trim().length > 0) {
      return priorAuthorizationText;
    }
    if (typeof window === "undefined") return "";
    try {
      return (
        window.localStorage.getItem(AUTHORIZATION_STATEMENT_STORAGE_KEY) ?? ""
      );
    } catch {
      return "";
    }
  });
  const [consentChecked, setConsentChecked] = useState(false);
  // Render into document.body so the fixed backdrop escapes the page-content
  // stacking context and covers the whole viewport — including the sticky app
  // header (z-40, its own backdrop-blur context), which otherwise stays
  // un-dimmed and reads as a gap at the top of the modal.
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const [actionsExpanded, setActionsExpanded] = useState(false);
  // Scan-complete email state
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [notifyEmails, setNotifyEmails] = useState<string[]>([]);
  // AI toggle — shown for DAST scans (not repo/LLM, which don't use the
  // agent/triage pipeline). Forced off + disabled when the org's monthly
  // AI quota is spent or its plan has no AI access (driven by aiQuota).
  const [useAi, setUseAi] = useState(true);
  const [aiQuota, setAiQuota] = useState<ScanAiQuota | null>(null);
  // The toggle only governs the AI pipeline for DAST scans. Repo scans run
  // the SAST pipeline via a different endpoint; LLM scans use a deterministic
  // rule-based engine (no LLM-as-judge), so an AI toggle is meaningless there.
  const showAiToggle = !isRepo && !isLlm;
  const aiBlocked = aiQuota !== null && !aiQuota.ai_available;

  const authTextTrimmed = authorizationText.trim();
  const consentValid = consentChecked && authTextTrimmed.length >= 50;

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    if (targetId) document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [targetId, onClose]);

  // Reset the textarea each time the modal opens — the parent keeps this
  // component mounted across targets (targetId just flips), so the lazy
  // useState initializer alone would freeze the prefill on whatever the
  // *first* target's value was. Only fires on the closed→open transition;
  // mid-edit prop changes do not clobber what the operator has typed.
  const wasOpenRef = useRef(false);
  useEffect(() => {
    const isOpen = Boolean(targetId);
    if (isOpen && !wasOpenRef.current) {
      let initial = "";
      if (priorAuthorizationText && priorAuthorizationText.trim().length > 0) {
        initial = priorAuthorizationText;
      } else if (typeof window !== "undefined") {
        try {
          initial =
            window.localStorage.getItem(AUTHORIZATION_STATEMENT_STORAGE_KEY) ??
            "";
        } catch {
          initial = "";
        }
      }
      setAuthorizationText(initial);
      setConsentChecked(false);
    }
    wasOpenRef.current = isOpen;
  }, [targetId, priorAuthorizationText]);

  // Fetch the org's pre-flight scan-AI allowance whenever the modal opens
  // for a DAST target. Force the toggle off when AI isn't available (quota
  // spent or no plan access); otherwise default it on.
  useEffect(() => {
    if (!targetId || !showAiToggle) return;
    let cancelled = false;
    setAiQuota(null);
    setUseAi(true);
    api<ScanAiQuota>("/scans/ai-quota")
      .then((q) => {
        if (cancelled) return;
        setAiQuota(q);
        if (!q.ai_available) setUseAi(false);
      })
      .catch(() => {
        // Non-fatal: leave the toggle enabled and let the runner apply its
        // own quota fallback. The user can still commission the scan.
      });
    return () => {
      cancelled = true;
    };
  }, [targetId, showAiToggle]);

  if (!targetId) return null;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!isRepo && !consentValid) return;
    setSubmitting(true);
    setErr(null);
    try {
      // Repo-mirror Targets get their own scan endpoint — the DAST
      // pipeline can't make sense of github.com URLs.
      if (isRepo) {
        if (!repositoryId) {
          setErr("Missing repository_id on this target.");
          setSubmitting(false);
          return;
        }
        const scan = await api<{ id: string }>(`/repos/${repositoryId}/scan`, {
          method: "POST",
        });
        router.push(`/repos/scans/${scan.id}`);
        return;
      }
      // Feature 001 — kind-aware disclosed_actions. The backend's
      // KIND_REQUIRED_DISCLOSED_ACTIONS map enforces a per-kind required set
      // at routers/scans.py::start_scan; sending the wrong vocabulary returns
      // 400. ``getKindDisclosures`` returns IDs that match the router's
      // required set + Phase B extensions when kind_config implies them.
      const { ids: kindActionIds } = getKindDisclosures(
        targetKind,
        targetKindConfig,
      );
      const consentPayload = {
        version: 1,
        acknowledged: true,
        authorization_text: authTextTrimmed,
        // Load mode requires the extra "load_testing" disclosed action.
        disclosed_actions:
          profile === "load"
            ? [...kindActionIds, "load_testing"]
            : kindActionIds,
        consent_given_at: new Date().toISOString(),
      };
      const scan = await api<Scan>("/scans", {
        method: "POST",
        json: {
          target_id: targetId,
          profile,
          consent_payload: consentPayload,
          ...(profile === "load"
            ? {
                load_test: {
                  mode: loadCfg.mode,
                  profile_shape: loadCfg.profile_shape,
                  duration_s: loadCfg.duration_s,
                  concurrency: loadCfg.concurrency,
                  ramp_s: loadCfg.ramp_s,
                  ...(loadCfg.target_rps !== ""
                    ? { target_rps: Number(loadCfg.target_rps) }
                    : {}),
                  thresholds: {
                    ...(loadCfg.thresholds.p95_ms !== ""
                      ? { p95_ms: Number(loadCfg.thresholds.p95_ms) }
                      : {}),
                    ...(loadCfg.thresholds.error_rate !== ""
                      ? { error_rate: Number(loadCfg.thresholds.error_rate) }
                      : {}),
                  },
                  max_stages: loadCfg.max_stages,
                  stage_duration_s: loadCfg.stage_duration_s,
                  total_budget_s: loadCfg.total_budget_s,
                },
              }
            : {}),
          notify_emails:
            emailEnabled && notifyEmails.length > 0 ? notifyEmails : undefined,
          // Honour the AI toggle. When blocked (quota/plan) it's already
          // forced off; otherwise send the operator's choice.
          use_ai: showAiToggle ? useAi && !aiBlocked : true,
        },
      });
      try {
        window.localStorage.setItem(
          AUTHORIZATION_STATEMENT_STORAGE_KEY,
          authTextTrimmed,
        );
      } catch {
        /* Private-mode / quota — non-fatal; the scan was already commissioned. */
      }
      router.push(`/scans/${scan.id}`);
    } catch (e: any) {
      setErr(e?.message || "Unable to commission assessment.");
      setSubmitting(false);
    }
  }

  async function generateSbom() {
    if (!repositoryId) {
      setErr("Missing repository_id on this target.");
      return;
    }
    setSbomSubmitting(true);
    setErr(null);
    try {
      await api(`/repos/${repositoryId}/sbom`, {
        method: "POST",
        json: { format: "cyclonedx" },
      });
      router.push(`/repos/${repositoryId}?sbom=1`);
    } catch (e: any) {
      setErr(e?.message || "Unable to generate SBOM.");
    } finally {
      setSbomSubmitting(false);
    }
  }

  if (!mounted) return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 bg-ink/40 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <form
        onClick={(e) => e.stopPropagation()}
        onSubmit={submit}
        className="bg-paper border-2 border-ink shadow-[8px_8px_0_#000] max-w-lg w-full max-h-[90vh] overflow-y-auto p-6 space-y-5"
      >
        <header>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-slate">
            Commission scan
          </p>
          <h2 className="mt-1 font-display text-[26px] text-ink leading-tight">
            {targetName || "Target"}
          </h2>
        </header>

        {isRepo ? (
          <div className="border-2 border-hairline bg-vellum px-4 py-3 text-[13px]">
            <p className="font-bold text-ink">Repository scan</p>
            <p className="mt-1 text-slate">
              This target mirrors a repository — Pencheff will run the SAST/SCA
              pipeline (CodeQL · Semgrep · OSV · secret scanning · IaC) over the
              latest commit. Profile selection doesn't apply.
            </p>
          </div>
        ) : (
          <fieldset>
            <legend className="block font-mono text-[11px] uppercase tracking-[0.18em] text-slate mb-2">
              {isLlm ? "LLM red-team profile" : "Profile"}
            </legend>
            <div
              className={
                isLlm ? "grid grid-cols-1 gap-2" : "grid grid-cols-2 gap-2"
              }
            >
              {[
                ...(isLlm ? LLM_PROFILES : PROFILES),
                ...(supportsLoad
                  ? [
                      {
                        value: "load",
                        label: "Load test",
                        hint: "Performance under concurrent load (not a security scan)",
                      },
                    ]
                  : []),
              ].map((p) => (
                <label
                  key={p.value}
                  className={`border-2 px-3 py-2 cursor-pointer text-[13px] ${
                    profile === p.value
                      ? "border-ink bg-gilt"
                      : "border-hairline bg-vellum hover:border-ink"
                  }`}
                >
                  <input
                    type="radio"
                    name="profile"
                    value={p.value}
                    checked={profile === p.value}
                    onChange={() => setProfile(p.value)}
                    className="sr-only"
                  />
                  <span className="font-bold block">{p.label}</span>
                  <span className="text-[11px] text-slate">{p.hint}</span>
                </label>
              ))}
            </div>

            {profile === "load" && (
              <div className="mt-3 border-2 border-hairline bg-vellum px-4 py-3">
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate mb-2">
                  Load parameters
                </p>
                <label className="text-[12px] text-slate mb-3 block">
                  Mode
                  <select
                    value={loadCfg.mode}
                    onChange={(e) =>
                      setLoadCfg({ ...loadCfg, mode: e.target.value })
                    }
                    className="mt-1 block w-full border border-hairline bg-paper px-2 py-1 text-[13px] text-ink"
                  >
                    <option value="agentic">
                      Agentic (agent finds the breaking point)
                    </option>
                    <option value="simple">Simple (fixed load)</option>
                  </select>
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <label className="text-[12px] text-slate">
                    Duration (s)
                    <input
                      type="number"
                      min={5}
                      max={300}
                      value={loadCfg.duration_s}
                      onChange={(e) =>
                        setLoadCfg({
                          ...loadCfg,
                          duration_s: Number(e.target.value),
                        })
                      }
                      className="mt-1 block w-full border border-hairline bg-paper px-2 py-1 text-[13px] text-ink"
                    />
                  </label>
                  <label className="text-[12px] text-slate">
                    Concurrency (VUs)
                    <input
                      type="number"
                      min={1}
                      max={200}
                      value={loadCfg.concurrency}
                      onChange={(e) =>
                        setLoadCfg({
                          ...loadCfg,
                          concurrency: Number(e.target.value),
                        })
                      }
                      className="mt-1 block w-full border border-hairline bg-paper px-2 py-1 text-[13px] text-ink"
                    />
                  </label>
                  <label className="text-[12px] text-slate">
                    Target RPS (optional)
                    <input
                      type="number"
                      min={1}
                      max={2000}
                      value={loadCfg.target_rps}
                      onChange={(e) =>
                        setLoadCfg({
                          ...loadCfg,
                          target_rps:
                            e.target.value === "" ? "" : Number(e.target.value),
                        })
                      }
                      placeholder="max"
                      className="mt-1 block w-full border border-hairline bg-paper px-2 py-1 text-[13px] text-ink"
                    />
                  </label>
                  <label className="text-[12px] text-slate">
                    Ramp-up (s)
                    <input
                      type="number"
                      min={0}
                      max={60}
                      value={loadCfg.ramp_s}
                      onChange={(e) =>
                        setLoadCfg({
                          ...loadCfg,
                          ramp_s: Number(e.target.value),
                        })
                      }
                      className="mt-1 block w-full border border-hairline bg-paper px-2 py-1 text-[13px] text-ink"
                    />
                  </label>
                </div>
                {loadCfg.mode === "agentic" && (
                  <div className="mt-3 grid grid-cols-2 gap-3">
                    <label className="text-[12px] text-slate">
                      Profile
                      <select
                        value={loadCfg.profile_shape}
                        onChange={(e) =>
                          setLoadCfg({
                            ...loadCfg,
                            profile_shape: e.target.value,
                          })
                        }
                        className="mt-1 block w-full border border-hairline bg-paper px-2 py-1 text-[13px] text-ink"
                      >
                        <option value="ramp">Ramp</option>
                        <option value="steady">Steady</option>
                        <option value="spike">Spike</option>
                        <option value="soak">Soak</option>
                        <option value="arrival_rate">
                          Arrival rate (open model)
                        </option>
                      </select>
                    </label>
                    <label className="text-[12px] text-slate">
                      SLA p95 (ms)
                      <input
                        type="number"
                        value={loadCfg.thresholds.p95_ms}
                        onChange={(e) =>
                          setLoadCfg({
                            ...loadCfg,
                            thresholds: {
                              ...loadCfg.thresholds,
                              p95_ms:
                                e.target.value === ""
                                  ? ""
                                  : Number(e.target.value),
                            },
                          })
                        }
                        className="mt-1 block w-full border border-hairline bg-paper px-2 py-1 text-[13px] text-ink"
                      />
                    </label>
                    <label className="text-[12px] text-slate">
                      Max error rate (0-1)
                      <input
                        type="number"
                        step="0.01"
                        value={loadCfg.thresholds.error_rate}
                        onChange={(e) =>
                          setLoadCfg({
                            ...loadCfg,
                            thresholds: {
                              ...loadCfg.thresholds,
                              error_rate:
                                e.target.value === ""
                                  ? ""
                                  : Number(e.target.value),
                            },
                          })
                        }
                        className="mt-1 block w-full border border-hairline bg-paper px-2 py-1 text-[13px] text-ink"
                      />
                    </label>
                    <label className="text-[12px] text-slate">
                      Max stages
                      <input
                        type="number"
                        min={1}
                        max={10}
                        value={loadCfg.max_stages}
                        onChange={(e) =>
                          setLoadCfg({
                            ...loadCfg,
                            max_stages: Number(e.target.value),
                          })
                        }
                        className="mt-1 block w-full border border-hairline bg-paper px-2 py-1 text-[13px] text-ink"
                      />
                    </label>
                    <label className="text-[12px] text-slate">
                      Stage duration (s)
                      <input
                        type="number"
                        min={5}
                        max={120}
                        value={loadCfg.stage_duration_s}
                        onChange={(e) =>
                          setLoadCfg({
                            ...loadCfg,
                            stage_duration_s: Number(e.target.value),
                          })
                        }
                        className="mt-1 block w-full border border-hairline bg-paper px-2 py-1 text-[13px] text-ink"
                      />
                    </label>
                    <label className="text-[12px] text-slate">
                      Total budget (s)
                      <input
                        type="number"
                        min={10}
                        max={600}
                        value={loadCfg.total_budget_s}
                        onChange={(e) =>
                          setLoadCfg({
                            ...loadCfg,
                            total_budget_s: Number(e.target.value),
                          })
                        }
                        className="mt-1 block w-full border border-hairline bg-paper px-2 py-1 text-[13px] text-ink"
                      />
                    </label>
                  </div>
                )}
                <p className="mt-2 text-[11px] text-slate italic">
                  Read-only requests only, capped at 300s / 200 VUs / 2000 rps.
                  You&rsquo;re authorising a load test on this target.
                </p>
              </div>
            )}
            {isLlm && (
              <p className="mt-3 text-[11px] text-slate italic">
                Probes the OWASP LLM Top 10 (LLM01 prompt injection, LLM02 info
                disclosure, LLM05 output handling, LLM07 system prompt leak,
                LLM10 unbounded consumption) using a deterministic rule-based
                engine — no LLM-as-judge.
              </p>
            )}
          </fieldset>
        )}

        {/* Host list — shown when the target is a host kind with configured hosts */}
        {targetKind === "host" &&
          Array.isArray(targetKindConfig?.hosts) &&
          (targetKindConfig?.hosts?.length ?? 0) > 0 && (
            <div className="border-2 border-hairline bg-vellum px-4 py-3 text-[13px]">
              <p className="font-bold text-ink">
                You are authorizing exploitation of these hosts:
              </p>
              <ul className="mt-2 list-disc pl-5 font-mono text-[11px]">
                {targetKindConfig!.hosts!.map((h) => (
                  <li key={h}>{h}</li>
                ))}
              </ul>
            </div>
          )}

        {/* Consent section — only for DAST (non-repo) scans */}
        {!isRepo && (
          <div className="border-2 border-ink bg-vellum p-4 space-y-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-slate">
              Operator consent required
            </p>

            {/* Disclosed actions toggle */}
            <div>
              <button
                type="button"
                onClick={() => setActionsExpanded((v) => !v)}
                className="flex items-center gap-2 text-[13px] font-bold text-ink hover:underline underline-offset-4"
              >
                <span>{actionsExpanded ? "▾" : "▸"}</span>
                AI-driven actions this scan will perform (
                {
                  getKindDisclosures(targetKind, targetKindConfig).actions
                    .length
                }
                )
              </button>
              {actionsExpanded && (
                <ul className="mt-2 space-y-2 pl-4">
                  {getKindDisclosures(targetKind, targetKindConfig).actions.map(
                    (action) => (
                      <li key={action.id} className="text-[12px]">
                        <span className="font-bold text-ink">
                          {action.displayName}
                          {action.upcoming && (
                            <span className="ml-1 font-mono text-[10px] text-slate">
                              (upcoming)
                            </span>
                          )}
                        </span>
                        <span className="text-slate">
                          {" "}
                          — {action.description}
                        </span>
                      </li>
                    ),
                  )}
                </ul>
              )}
            </div>

            {/* Authorization text */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label
                  htmlFor="authorization_text"
                  className="block font-mono text-[11px] uppercase tracking-[0.18em] text-slate"
                >
                  Written authorization statement
                </label>
                {authorizationText.length > 0 && (
                  <button
                    type="button"
                    onClick={() => {
                      setAuthorizationText("");
                      try {
                        window.localStorage.removeItem(
                          AUTHORIZATION_STATEMENT_STORAGE_KEY,
                        );
                      } catch {}
                    }}
                    className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate hover:text-ink underline underline-offset-4"
                  >
                    Clear
                  </button>
                )}
              </div>
              <textarea
                id="authorization_text"
                rows={4}
                value={authorizationText}
                onChange={(e) => setAuthorizationText(e.target.value)}
                placeholder={
                  "Paste the authorization statement from your engagement letter, e.g. " +
                  "'I confirm I have written authorization from <customer> to perform an " +
                  "AI-assisted security assessment of <target>.'"
                }
                className="w-full border-2 border-hairline bg-paper px-3 py-2 text-[13px] text-ink resize-none focus:outline-none focus:border-ink"
                required
              />
              <p className="mt-1 text-[11px] text-slate">
                {authTextTrimmed.length < 50
                  ? `${50 - authTextTrimmed.length} more characters required`
                  : `${authTextTrimmed.length} characters — minimum met. Saved on submit for next time.`}
              </p>
            </div>

            {/* Confirmation checkbox */}
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={consentChecked}
                onChange={(e) => setConsentChecked(e.target.checked)}
                className="mt-0.5 h-4 w-4 border-2 border-ink accent-ink"
              />
              <span className="text-[13px] text-ink">
                I confirm I have read each disclosed action above and have
                written authorisation to perform this scan against the target.
              </span>
            </label>
          </div>
        )}

        {/* AI toggle — DAST scans only. Force-disabled when the org's
            monthly AI quota is spent or its plan has no AI access. */}
        {showAiToggle && (
          <div className="border-2 border-hairline bg-paper p-4 space-y-3">
            <label
              className={`flex items-start gap-3 ${
                aiBlocked ? "cursor-not-allowed opacity-70" : "cursor-pointer"
              }`}
            >
              <input
                type="checkbox"
                checked={useAi && !aiBlocked}
                disabled={aiBlocked}
                onChange={(e) => setUseAi(e.target.checked)}
                className="mt-0.5 h-4 w-4 border-2 border-ink accent-ink disabled:cursor-not-allowed"
              />
              <span>
                <span className="block font-mono text-[11px] uppercase tracking-[0.18em] text-slate">
                  Use AI for this scan
                </span>
                <span className="block text-[12px] text-graphite mt-0.5">
                  Runs the autonomous agent, AI false-positive triage, and
                  AI-graded executive summary. Turn off to run a fully
                  deterministic scan.
                </span>
              </span>
            </label>
            {aiBlocked && aiQuota && (
              <p className="text-[11px] text-sev-high font-medium">
                {aiQuota.has_ai_access
                  ? aiQuota.credit_metered
                    ? `AI credits exhausted. Top up credits or wait for your monthly grant to continue using AI.`
                    : `AI usage limit reached for this month (${aiQuota.monthly_used}/${aiQuota.monthly_cap}). ` +
                      `Resets ${new Date(aiQuota.period_resets_at).toLocaleDateString()}, ` +
                      `or upgrade your plan to continue using AI.`
                  : "AI-assisted scanning requires a Pro plan or higher. This scan will run deterministic-only."}
              </p>
            )}
            {aiBlocked && <McpFallbackNote kind="quota" />}
          </div>
        )}

        {/* Scan-completion email — DAST + LLM only. Repo scans run a
            different pipeline; we'll wire repo notifications separately. */}
        {!isRepo && (
          <div className="border-2 border-hairline bg-paper p-4 space-y-3">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={emailEnabled}
                onChange={(e) => setEmailEnabled(e.target.checked)}
                className="mt-0.5 h-4 w-4 border-2 border-ink accent-ink"
              />
              <span>
                <span className="block font-mono text-[11px] uppercase tracking-[0.18em] text-slate">
                  Email when complete
                </span>
                <span className="block text-[12px] text-graphite mt-0.5">
                  Send the dashboard link to one or more recipients when the
                  scan finishes.
                </span>
              </span>
            </label>
            {emailEnabled && (
              <EmailRecipientsInput
                value={notifyEmails}
                onChange={setNotifyEmails}
                workspaceId={activeWorkspace?.id ?? null}
                label="Recipients"
                hint="Pick a workspace member from the dropdown or type any email and press Add."
              />
            )}
          </div>
        )}

        {err && (
          <p className="text-sev-critical font-bold text-[13px]">{err}</p>
        )}

        <div className="flex items-center justify-end gap-3 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="text-[13px] underline underline-offset-4 text-slate hover:text-ink"
          >
            Cancel
          </button>
          {isRepo && (
            <Button
              type="button"
              variant="ink"
              onClick={generateSbom}
              disabled={sbomSubmitting || submitting}
            >
              {sbomSubmitting ? "Generating…" : "Generate SBOM"}
            </Button>
          )}
          <Button
            type="submit"
            variant="pink"
            disabled={
              submitting || sbomSubmitting || (!isRepo && !consentValid)
            }
          >
            {submitting ? "Queuing…" : isRepo ? "Run repo scan" : "Commission"}
          </Button>
        </div>
      </form>
    </div>,
    document.body,
  );
}
