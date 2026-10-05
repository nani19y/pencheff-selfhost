"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { Button, GradeBadge, Input } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { Paginator } from "@/components/paginator";
import { api } from "@/lib/api";
import { CommissionScanModal } from "@/components/commission-scan-modal";
import { TargetTraces } from "@/components/target-traces";
import { MemoryPanel } from "@/components/memory-panel";
import { SeverityStack } from "@/components/dashboard/SeverityStack";
import { TrendLine } from "@/components/dashboard/TrendLine";
import type { Severity } from "@/lib/sev";

const SCANS_PAGE_SIZE = 20;

type TrendScan = {
  id: string;
  created_at: string | null;
  finished_at: string | null;
  status: string;
  grade: string | null;
  score: number | null;
  summary: Record<Severity, number>;
};
type TrendDelta = {
  scan_id: string;
  vs_prior_scan_id: string;
  new: number;
  fixed: number;
  regressed: number;
};
type TargetTrend = {
  target: { id: string; name: string | null; base_url: string | null };
  scans: TrendScan[];
  deltas: TrendDelta[];
  mttr_days: number | null;
  open_total: number;
  fixed_total: number;
};

type LlmConfigOut = {
  provider: "openai-chat" | "custom";
  model?: string | null;
  system_prompt?: string | null;
  request_template?: string | null;
  response_path?: string | null;
  timeout_s?: number;
  concurrency?: number;
};
// Feature 001 — wire kind expanded from 3 to 15. The detail page accepts the
// full SupportedKind list and renders kind-specific config blocks via
// <KindConfigView> below. ``kind_config`` is the typed JSONB payload returned
// by the API (TargetOut.kind_config in apps/api/pencheff_api/schemas/targets.py).
import type { SupportedKind } from "@/components/register-target/target-types";

type KindConfigPayload = { kind: SupportedKind } & Record<string, unknown>;

type Target = {
  id: string;
  name: string;
  base_url: string;
  has_credentials: boolean;
  has_kind_credentials?: boolean;
  kind?: SupportedKind;
  repository_id?: string | null;
  llm_config?: LlmConfigOut | null;
  kind_config?: KindConfigPayload | null;
  created_at?: string;
};
type Scan = {
  id: string;
  target_id: string;
  status: string;
  progress_pct: number;
  grade: string | null;
  score: number | null;
  summary: Record<string, number | string> | null;
  consent_payload: { authorization_text?: string } | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
};

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEV_LABEL: Record<(typeof SEV_ORDER)[number], string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info.",
};
const SEV_COLOR: Record<(typeof SEV_ORDER)[number], string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};
const STATUS_LABEL: Record<string, string> = {
  queued: "Queued",
  running: "In progress",
  done: "Complete",
  failed: "Failed",
};

function shortId(id: string) {
  return id.slice(0, 8).toUpperCase();
}
function formatDate(iso: string | null) {
  if (!iso) return "—";
  return iso.replace("T", " · ").slice(0, 22);
}

// ============================================================================
// Feature 001 — per-kind detail-page renderer.
// Renders the most informative subset of Target.kind_config as a small <dl>.
// Operators who need the full payload can hit GET /targets/{id} directly.
// ============================================================================

function Dt({ children }: { children: React.ReactNode }) {
  return (
    <dt className="font-mono uppercase tracking-[0.16em] text-[10px] text-mist">
      {children}
    </dt>
  );
}
function Dd({
  children,
  mono = false,
}: {
  children: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <dd
      className={mono ? "text-graphite font-mono text-[12px]" : "text-graphite"}
    >
      {children}
    </dd>
  );
}
function Field({
  label,
  value,
  mono = false,
  span = 1,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  span?: 1 | 2;
}) {
  if (
    value === null ||
    value === undefined ||
    value === "" ||
    (Array.isArray(value) && value.length === 0)
  ) {
    return null;
  }
  return (
    <div className={span === 2 ? "sm:col-span-2" : undefined}>
      <Dt>{label}</Dt>
      <Dd mono={mono}>{value}</Dd>
    </div>
  );
}

function KindConfigView({
  kind,
  config,
}: {
  kind: SupportedKind;
  config: Record<string, unknown>;
}) {
  const cfg = config as Record<string, unknown>;
  return (
    <dl className="mt-4 grid sm:grid-cols-2 gap-x-8 gap-y-2 text-[13px]">
      {kind === "web_app" && (
        <>
          <Field label="Crawl depth" value={cfg.crawl_depth as number} />
          <Field label="Max pages" value={cfg.max_pages as number} />
          <Field
            label="Browser render"
            value={cfg.browser_render ? "yes" : "no"}
          />
          <Field
            label="API spec URL"
            value={cfg.api_spec_url as string}
            mono
            span={2}
          />
        </>
      )}
      {kind === "rest_api" && (
        <>
          <Field
            label="Spec format"
            value={cfg.api_spec_format as string}
            mono
          />
          <Field label="Auth in spec" value={cfg.auth_in_spec ? "yes" : "no"} />
          <Field
            label="Spec URL"
            value={cfg.api_spec_url as string}
            mono
            span={2}
          />
        </>
      )}
      {kind === "graphql" && (
        <>
          <Field
            label="Introspection"
            value={cfg.introspection_enabled ? "enabled" : "disabled"}
          />
          <Field
            label="Max query depth"
            value={cfg.max_query_depth as number}
          />
          <Field
            label="Operations tested"
            value={(cfg.operations_to_test as string[] | undefined)?.join(", ")}
            mono
          />
          {!cfg.introspection_enabled && cfg.schema_sdl ? (
            <Field
              label="Schema SDL (excerpt)"
              value={
                (cfg.schema_sdl as string).slice(0, 240) +
                ((cfg.schema_sdl as string).length > 240 ? "…" : "")
              }
              mono
              span={2}
            />
          ) : null}
        </>
      )}
      {kind === "websocket" && (
        <>
          <Field
            label="Subprotocols"
            value={
              (cfg.subprotocols as string[] | undefined)?.join(", ") || "(none)"
            }
            mono
          />
          <Field
            label="Origin header"
            value={cfg.origin_header as string}
            mono
          />
          <Field
            label="Auth token in query"
            value={cfg.auth_token_in_query ? "yes" : "no"}
          />
        </>
      )}
      {kind === "grpc" && (
        <>
          <Field
            label="Reflection"
            value={cfg.reflection_enabled ? "enabled" : "disabled"}
          />
          <Field label="TLS verify" value={cfg.tls_verify ? "yes" : "no"} />
          {!cfg.reflection_enabled && Array.isArray(cfg.proto_files) ? (
            <Field
              label="Operator-supplied .proto"
              value={`${(cfg.proto_files as unknown[]).length} file(s)`}
              span={2}
            />
          ) : null}
        </>
      )}
      {kind === "source_code" && (
        <>
          <Field label="Source" value={cfg.source as string} mono />
          <Field label="Git ref" value={cfg.git_ref as string} mono />
          <Field
            label="Repo URL"
            value={cfg.repo_url as string}
            mono
            span={2}
          />
          <Field
            label="Languages hint"
            value={(cfg.languages_hint as string[] | undefined)?.join(", ")}
            mono
          />
          <Field
            label="Scanners disabled"
            value={(cfg.scanners_disabled as string[] | undefined)?.join(", ")}
            mono
          />
        </>
      )}
      {kind === "cicd_pipeline" && (
        <>
          <Field label="Provider" value={cfg.provider as string} mono />
          <Field
            label="Live API"
            value={
              cfg.live_api_enabled
                ? "enabled (Phase A + B)"
                : "disabled (Phase A only)"
            }
          />
          <Field
            label="Repo URL"
            value={cfg.repo_url as string}
            mono
            span={2}
          />
          <Field
            label="Config paths"
            value={(cfg.config_paths as string[] | undefined)?.join(", ")}
            mono
            span={2}
          />
        </>
      )}
      {kind === "iac" && (
        <>
          <Field
            label="Frameworks"
            value={(cfg.frameworks as string[] | undefined)?.join(", ")}
            mono
          />
          <Field label="Source" value={cfg.source as string} mono />
          <Field
            label="Repo URL"
            value={cfg.repo_url as string}
            mono
            span={2}
          />
        </>
      )}
      {kind === "container_image" && (
        <>
          <Field
            label="Image ref"
            value={cfg.image_ref as string}
            mono
            span={2}
          />
          <Field label="Registry" value={cfg.registry as string} mono />
          <Field label="Scan layers" value={cfg.scan_layers ? "yes" : "no"} />
          <Field label="Scan secrets" value={cfg.scan_secrets ? "yes" : "no"} />
          <Field
            label="Scan misconfigs"
            value={cfg.scan_misconfigs ? "yes" : "no"}
          />
        </>
      )}
      {kind === "k8s_cluster" && (
        <>
          <Field label="Target mode" value={cfg.target as string} mono />
          <Field
            label="RBAC enumeration"
            value={cfg.rbac_enum ? "enabled" : "disabled"}
          />
          <Field
            label="Network policy audit"
            value={cfg.network_policy_audit ? "enabled" : "disabled"}
          />
          {cfg.target === "manifests_only" ? (
            <Field
              label="Manifests archive URL"
              value={cfg.manifests_archive_url as string}
              mono
              span={2}
            />
          ) : null}
          <Field
            label="Namespaces"
            value={(cfg.namespaces as string[] | undefined)?.join(", ")}
            mono
            span={2}
          />
        </>
      )}
      {[
        "cloud_account",
        "serverless_function",
        "cloud_storage",
        "load_balancer_cdn",
        "cloud_database",
        "secrets_manager",
      ].includes(kind) && (
        <>
          <Field label="Provider" value={cfg.provider as string} mono />
          <Field
            label="Scope"
            value={
              (cfg.account_id as string) ||
              (cfg.subscription_id as string) ||
              (cfg.project_id as string)
            }
            mono
          />
          <Field
            label="Regions"
            value={(cfg.regions as string[] | undefined)?.join(", ")}
            mono
            span={2}
          />
          <Field
            label="Resources"
            value={(
              (cfg.resource_names as string[] | undefined) ||
              (cfg.function_names as string[] | undefined)
            )?.join(", ")}
            mono
            span={2}
          />
          <Field
            label="Inventory"
            value={
              cfg.inventory ? "offline metadata attached" : "provider metadata"
            }
          />
          <Field
            label="Read-only"
            value={cfg.read_only === false ? "no" : "yes"}
          />
          {kind === "secrets_manager" ? (
            <Field label="Secret values" value="never read" />
          ) : null}
        </>
      )}
      {kind === "package_registry" && (
        <>
          <Field label="Ecosystem" value={cfg.ecosystem as string} mono />
          <Field
            label="Packages"
            value={`${(cfg.package_list as unknown[] | undefined)?.length ?? 0} package(s)`}
          />
          <Field
            label="Include dev deps"
            value={cfg.include_dev ? "yes" : "no"}
          />
        </>
      )}
      {kind === "sbom" && (
        <>
          <Field label="Format" value={cfg.format as string} mono />
          <Field
            label="Source"
            value={
              cfg.content
                ? "inline content"
                : (cfg.url as string)
                  ? "remote URL"
                  : "(unset)"
            }
          />
          {cfg.url ? (
            <Field label="URL" value={cfg.url as string} mono span={2} />
          ) : null}
          <Field
            label="License checks"
            value={cfg.check_licenses ? "enabled" : "disabled"}
          />
          <Field
            label="Supplier checks"
            value={cfg.check_suppliers ? "enabled" : "disabled"}
          />
        </>
      )}
      {kind === "mcp" && (
        <>
          <Field label="Source" value={cfg.source_type as string} mono />
          {cfg.url ? (
            <Field label="URL" value={cfg.url as string} mono span={2} />
          ) : null}
          {cfg.transport ? (
            <Field label="Transport" value={cfg.transport as string} mono />
          ) : null}
          {cfg.command ? (
            <Field
              label="Command"
              value={(cfg.command as string[]).join(" ")}
              mono
              span={2}
            />
          ) : null}
          {cfg.provider ? (
            <Field label="Provider" value={cfg.provider as string} mono />
          ) : null}
          {cfg.model ? (
            <Field label="Model" value={cfg.model as string} mono />
          ) : null}
          <Field
            label="Dynamic"
            value={cfg.dynamic_invocation ? "enabled" : "static only"}
            mono
          />
          {cfg.destructive_opt_in ? (
            <Field label="Destructive" value="opted in" mono />
          ) : null}
        </>
      )}
      {kind === "rag" && (
        <>
          <Field label="Source" value={cfg.source_type as string} mono />
          {cfg.provider ? (
            <Field label="Provider" value={cfg.provider as string} mono />
          ) : null}
          {cfg.url ? (
            <Field label="URL" value={cfg.url as string} mono span={2} />
          ) : null}
          {cfg.index_name ? (
            <Field label="Index" value={cfg.index_name as string} mono />
          ) : null}
          {cfg.namespace ? (
            <Field label="Namespace" value={cfg.namespace as string} mono />
          ) : null}
          {cfg.provider_llm ? (
            <Field
              label="LLM provider"
              value={cfg.provider_llm as string}
              mono
            />
          ) : null}
          <Field
            label="Query probes"
            value={cfg.query_probes ? "enabled" : "static only"}
            mono
          />
          {cfg.poison_injection_opt_in ? (
            <Field label="Poison injection" value="opted in" mono />
          ) : null}
        </>
      )}
      {kind === "ml_model" && (
        <>
          <Field label="Source" value={cfg.source_type as string} mono />
          {cfg.url ? (
            <Field label="URL" value={cfg.url as string} mono span={2} />
          ) : null}
          {cfg.hf_repo ? (
            <Field label="HF repo" value={cfg.hf_repo as string} mono />
          ) : null}
          {cfg.hf_revision ? (
            <Field label="Revision" value={cfg.hf_revision as string} mono />
          ) : null}
          {cfg.local_path ? (
            <Field
              label="Local path"
              value={cfg.local_path as string}
              mono
              span={2}
            />
          ) : null}
          {cfg.format_hint ? (
            <Field label="Format hint" value={cfg.format_hint as string} mono />
          ) : null}
        </>
      )}
      {kind === "voice" && (
        <>
          <Field label="Source" value={cfg.source_type as string} mono />
          {cfg.url ? (
            <Field label="URL" value={cfg.url as string} mono span={2} />
          ) : null}
          {cfg.audio_format ? (
            <Field
              label="Audio format"
              value={cfg.audio_format as string}
              mono
            />
          ) : null}
          {cfg.response_path ? (
            <Field
              label="Response path"
              value={cfg.response_path as string}
              mono
            />
          ) : null}
          {cfg.injection_phrase ? (
            <Field
              label="Injection phrase"
              value={cfg.injection_phrase as string}
              mono
              span={2}
            />
          ) : null}
          <Field
            label="Audio probes"
            value={cfg.audio_probes ? "enabled" : "transport only"}
            mono
          />
        </>
      )}
      {kind === "memory" && (
        <>
          <Field label="Source" value={cfg.source_type as string} mono />
          {cfg.url ? (
            <Field
              label="Provider URL"
              value={cfg.url as string}
              mono
              span={2}
            />
          ) : null}
          {cfg.user_id ? (
            <Field label="User ID" value={cfg.user_id as string} mono />
          ) : null}
          {cfg.session_id ? (
            <Field label="Session ID" value={cfg.session_id as string} mono />
          ) : null}
          {cfg.collection ? (
            <Field label="Collection" value={cfg.collection as string} mono />
          ) : null}
          {cfg.namespace ? (
            <Field label="Namespace" value={cfg.namespace as string} mono />
          ) : null}
          {cfg.index_name ? (
            <Field label="Index" value={cfg.index_name as string} mono />
          ) : null}
          {cfg.file_name ? (
            <Field label="File" value={cfg.file_name as string} mono />
          ) : null}
          <Field
            label="Stored rows"
            value={`${(cfg.items as unknown[] | undefined)?.length ?? 0} item(s)`}
          />
        </>
      )}
    </dl>
  );
}

function TargetDetailPageContent() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const id = mounted ? pathSegment(pathname, 2) : "";
  const router = useRouter();
  const searchParams = useSearchParams();

  const [target, setTarget] = useState<Target | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [trend, setTrend] = useState<TargetTrend | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCommissionModal, setShowCommissionModal] = useState(false);
  const [scanQuery, setScanQuery] = useState("");
  const [scanPage, setScanPage] = useState(1);

  // Only legacy GitHub-mirror targets (kind="repo" / a set repository_id)
  // produce RepoScan rows at /repos/scans/{id}. Every other kind — including
  // the kind-aware ones (source_code, iac, cicd_pipeline, container_image,
  // k8s_cluster, sbom, package_registry) — runs through the /scans pipeline and
  // stores a Scan row at /scans/{id}. Routing those to /repos/scans/ 404s.
  const isRepoTarget = !!target?.repository_id || target?.kind === "repo";
  const scanHref = (sid: string) =>
    isRepoTarget ? `/repos/scans/${sid}` : `/scans/${sid}`;

  // Auto-open the commission modal when the user lands here after
  // "Register & commission" on the new-target form (targets/new passes ?commission=1).
  // Memory targets have no Celery assessment pipeline — they're scanned from the
  // Memory panel — so never auto-open the commission modal for them.
  useEffect(() => {
    if (
      searchParams.get("commission") === "1" &&
      target &&
      target.kind !== "memory"
    ) {
      setShowCommissionModal(true);
    }
  }, [searchParams, target]);

  const filteredScans = useMemo(() => {
    const q = scanQuery.trim().toLowerCase();
    if (!q) return scans;
    return scans.filter(
      (s) =>
        shortId(s.id).toLowerCase().includes(q) ||
        s.id.toLowerCase().includes(q) ||
        s.status.toLowerCase().includes(q) ||
        (s.grade ?? "").toLowerCase().includes(q),
    );
  }, [scans, scanQuery]);

  const scanPageCount = Math.max(
    1,
    Math.ceil(filteredScans.length / SCANS_PAGE_SIZE),
  );
  const safeScanPage = Math.min(scanPage, scanPageCount);
  const visibleScans = filteredScans.slice(
    (safeScanPage - 1) * SCANS_PAGE_SIZE,
    safeScanPage * SCANS_PAGE_SIZE,
  );
  useEffect(() => {
    if (scanPage > scanPageCount) setScanPage(1);
  }, [scanPageCount, scanPage]);

  useEffect(() => {
    if (!id) return;
    let alive = true;
    api<Target>(`/targets/${id}`)
      .then(async (t) => {
        if (!alive) return;
        // Repo-mirror Targets live under /repos. Hop the user there so
        // they see the SAST/SCA scan history (RepoScan), not an empty
        // DAST view that can't be commissioned anyway.
        if (t.repository_id) {
          router.replace(`/repos/${t.repository_id}`);
          return;
        }
        const s = await api<Scan[]>(`/scans?target_id=${id}`);
        if (!alive) return;
        setTarget(t);
        setScans(s);
        // Trend data is best-effort — older API deployments may 404 on
        // this endpoint. Render the page even if it fails.
        api<TargetTrend>(`/dashboard/target/${id}/trend`)
          .then((tr) => {
            if (alive) setTrend(tr);
          })
          .catch(() => {});
      })
      .catch((e: unknown) => {
        if (!alive) return;
        const msg = e instanceof Error ? e.message : "Target not found.";
        setError(msg);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [id, router]);

  function startScan() {
    setShowCommissionModal(true);
  }

  async function deleteTarget() {
    if (!target) return;
    if (
      !window.confirm(
        `Delete target "${target.name}"?\n\nThis will also remove every assessment and finding recorded against it. This action cannot be undone.`,
      )
    ) {
      return;
    }
    try {
      await api(`/targets/${target.id}`, { method: "DELETE" });
      router.push("/dashboard");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unable to delete target.";
      alert(msg);
    }
  }

  async function deleteScan(scanId: string) {
    if (
      !window.confirm(
        "Delete this assessment?\n\nFindings, evidence, and generated reports will be removed. This action cannot be undone.",
      )
    ) {
      return;
    }
    try {
      await api(`/scans/${scanId}`, { method: "DELETE" });
      setScans((prev) => prev.filter((x) => x.id !== scanId));
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : "Unable to delete assessment.";
      alert(msg);
    }
  }

  if (loading) {
    return (
      <div className="py-6">
        <InlineLoading label="Loading…" />
      </div>
    );
  }

  if (error || !target) {
    return (
      <div className="formal-surface p-10">
        <p className="eyebrow-gilt">Target not found</p>
        <h2 className="mt-3 font-display text-[24px] text-ink">
          {error ?? "We couldn't load this target."}
        </h2>
        <div className="mt-6">
          <Link href="/dashboard">
            <Button variant="lime">Back to dashboard</Button>
          </Link>
        </div>
      </div>
    );
  }

  // remove in sub-project B (OSExploitAgent)
  const isHostKindUntilB = target.kind === "host";

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <p className="font-mono text-[11px] text-slate uppercase tracking-[0.18em]">
        <Link
          href="/dashboard"
          className="hover:text-ink underline-offset-[4px] hover:underline decoration-gilt decoration-1"
        >
          ← Dashboard
        </Link>
      </p>

      {/* Header */}
      <header className="flex items-end justify-between flex-wrap gap-6">
        <div className="min-w-0">
          <p className="eyebrow-gilt">Target</p>
          <div className="mt-4 flex items-center gap-4 flex-wrap">
            <h1 className="font-display text-[40px] md:text-[48px] leading-[1.05] tracking-[-0.015em] text-ink">
              {target.name}
            </h1>
            {target.has_credentials && (
              <span className="inline-flex items-center gap-1.5 border border-hairline rounded-sm px-2 py-1 font-body text-[10px] font-medium uppercase tracking-[0.16em] text-forest bg-vellum whitespace-nowrap">
                <span className="w-1 h-1 rounded-full bg-forest" aria-hidden />
                Credentials on file
              </span>
            )}
          </div>
          <p className="mt-3 font-mono text-[13px] text-slate break-all">
            {target.base_url}
          </p>
          {target.kind === "llm" && target.llm_config && (
            <dl className="mt-4 grid sm:grid-cols-2 gap-x-8 gap-y-2 text-[13px]">
              <div>
                <dt className="font-mono uppercase tracking-[0.16em] text-[10px] text-mist">
                  Provider
                </dt>
                <dd className="text-graphite">{target.llm_config.provider}</dd>
              </div>
              {target.llm_config.model && (
                <div>
                  <dt className="font-mono uppercase tracking-[0.16em] text-[10px] text-mist">
                    Model
                  </dt>
                  <dd className="text-graphite font-mono text-[12px]">
                    {target.llm_config.model}
                  </dd>
                </div>
              )}
              {target.llm_config.system_prompt && (
                <div className="sm:col-span-2">
                  <dt className="font-mono uppercase tracking-[0.16em] text-[10px] text-mist">
                    System prompt baseline
                  </dt>
                  <dd className="text-graphite italic">
                    “{target.llm_config.system_prompt.slice(0, 240)}
                    {target.llm_config.system_prompt.length > 240 ? "…" : ""}”
                  </dd>
                </div>
              )}
            </dl>
          )}
          {/* Feature 001 — per-kind config dl for the 11 new non-llm kinds.
              Each renderer picks the fields worth surfacing; everything else
              is available via the API. */}
          {target.kind && target.kind_config && (
            <KindConfigView kind={target.kind} config={target.kind_config} />
          )}
          {target.has_kind_credentials && (
            <span className="inline-flex items-center gap-1.5 mt-3 border border-hairline rounded-sm px-2 py-1 font-body text-[10px] font-medium uppercase tracking-[0.16em] text-forest bg-vellum whitespace-nowrap">
              <span className="w-1 h-1 rounded-full bg-forest" aria-hidden />
              Kind credentials on file
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {/* Memory targets are scanned from the Memory panel below
              (POST /v1/memory/scan), not the Celery assessment pipeline,
              and their items are edited there too — so no Commission / Edit. */}
          {target.kind !== "memory" && (
            <>
              <Button
                variant="pink"
                onClick={startScan}
                disabled={isHostKindUntilB}
                title={
                  isHostKindUntilB
                    ? "Host-target scanning ships in OSExploitAgent v2 (coming soon)."
                    : undefined
                }
              >
                Commission scan
              </Button>
              <Link href={`/targets/${target.id}/edit`}>
                <Button variant="lime">Edit</Button>
              </Link>
            </>
          )}
          <Button variant="danger" onClick={deleteTarget}>
            Delete
          </Button>
        </div>
      </header>

      {/* Recommended Guardrails — LLM targets only. Computed per-scan
          from the OWASP-LLM-Top-10 failure breakdown; this card just
          points at the latest scan's report. The full editor lives on
          the target's New / Edit pages. */}
      {target.kind === "llm" && (
        <RecommendedGuardrailsCard
          targetId={target.id}
          targetName={target.name}
          scans={scans}
        />
      )}

      {trend && trend.scans.filter((s) => s.status === "done").length >= 2 && (
        <TargetTrendSection trend={trend} isRepoTarget={isRepoTarget} />
      )}

      {/* Memory target — view/edit stored items + scan on demand. */}
      {target.kind === "memory" && (
        <MemoryPanel
          targetId={target.id}
          initialConfig={target.kind_config as Record<string, unknown>}
          initialItems={
            (target.kind_config?.items as
              (string | Record<string, unknown>)[] | undefined) ?? []
          }
        />
      )}

      {/* Runtime traces — LLM targets. Every request through this target's
          guardrail proxy (LLM call · firewall decision · detector verdict). */}
      {target.kind === "llm" && (
        <section>
          <div className="mb-4">
            <p className="eyebrow">Runtime protection — Traces</p>
            <h2 className="mt-2 font-display text-[24px] text-ink">
              Runtime traces
            </h2>
          </div>
          <TargetTraces targetId={target.id} />
        </section>
      )}

      {/* Assessments for this target */}
      <section>
        <div className="flex items-end justify-between mb-6">
          <div>
            <p className="eyebrow">Register — Assessments</p>
            <h2 className="mt-2 font-display text-[24px] text-ink">
              Assessments for {target.name}
            </h2>
          </div>
          <span className="font-mono text-[12px] text-mist">
            {filteredScans.length}
            {scanQuery ? ` matching · ${scans.length} total` : " on record"}
          </span>
        </div>

        {scans.length > 0 && (
          <div className="flex items-center justify-between gap-4 flex-wrap mb-6">
            <div className="w-full sm:w-[480px] max-w-full">
              <Input
                type="search"
                value={scanQuery}
                onChange={(e) => setScanQuery(e.target.value)}
                placeholder="Search by report №, status, or grade…"
                aria-label="Search assessments"
              />
            </div>
            <Paginator
              page={safeScanPage}
              pageCount={scanPageCount}
              onChange={setScanPage}
            />
          </div>
        )}

        {scans.length === 0 ? (
          target.kind === "memory" ? (
            // Memory targets are scanned in place from the Memory panel below
            // (POST /v1/memory/scan) — never through the assessment pipeline,
            // so no Commission button here.
            <div className="formal-surface p-10 text-center">
              <p className="eyebrow-gilt">Memory target</p>
              <h3 className="mt-4 font-display text-[24px] text-ink">
                Scan this memory from the panel below.
              </h3>
              <p className="mt-3 text-[14px] text-slate max-w-[52ch] mx-auto">
                Memory items are scanned in place for secrets and poisoning;
                results appear inline. There is no assessment-pipeline scan for
                memory targets.
              </p>
            </div>
          ) : (
            <div className="formal-surface p-10 text-center">
              <p className="eyebrow-gilt">No assessments yet</p>
              <h3 className="mt-4 font-display text-[24px] text-ink">
                Commission your first assessment for this target.
              </h3>
              <p className="mt-3 text-[14px] text-slate max-w-[52ch] mx-auto">
                A standard assessment completes in 10–25 minutes and yields a
                formal report with letter grade, evidence, and remediation
                guidance.
              </p>
              <div className="mt-6 flex justify-center">
                <Button variant="pink" onClick={startScan}>
                  Commission scan
                </Button>
              </div>
            </div>
          )
        ) : filteredScans.length === 0 ? (
          <p className="text-[14px] text-slate italic">
            No assessments match “{scanQuery}”.
          </p>
        ) : (
          <ul className="grid gap-5">
            {visibleScans.map((s) => (
              <li
                key={s.id}
                className="bg-paper border border-hairline rounded-md shadow-subtle p-6 hover:border-ink transition-colors duration-150"
              >
                <div className="flex items-start gap-6">
                  <GradeBadge
                    grade={s.grade || (s.status !== "done" ? "?" : "—")}
                    size="sm"
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="font-mono text-[11px] text-mist tracking-[0.04em]">
                        Report № {shortId(s.id)}
                      </span>
                      <span className="inline-flex items-center gap-1.5 font-body text-[11px] font-medium uppercase tracking-[0.16em] text-slate">
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            s.status === "done"
                              ? "bg-forest"
                              : s.status === "failed"
                                ? "bg-oxblood"
                                : "bg-gilt"
                          }`}
                          aria-hidden
                        />
                        {STATUS_LABEL[s.status] || s.status}
                        {s.status === "running" && ` · ${s.progress_pct}%`}
                      </span>
                    </div>
                    <p className="mt-2 font-mono text-[12px] text-slate">
                      {formatDate(s.created_at)}
                    </p>
                    {s.summary && (
                      <dl className="mt-4 flex gap-5 flex-wrap">
                        {SEV_ORDER.map((sev) => (
                          <div key={sev} className="flex items-center gap-2">
                            <span
                              className={`w-[3px] h-[12px] rounded-[1px] ${SEV_COLOR[sev]}`}
                              aria-hidden
                            />
                            <dt className="sr-only">{SEV_LABEL[sev]}</dt>
                            <dd className="font-body text-[11px] text-slate tracking-[0.04em]">
                              <span className="font-mono text-graphite">
                                {s.summary?.[sev] ?? 0}
                              </span>{" "}
                              {SEV_LABEL[sev]}
                            </dd>
                          </div>
                        ))}
                      </dl>
                    )}
                  </div>
                  <div className="shrink-0 flex flex-col items-end gap-2">
                    <Link href={scanHref(s.id)}>
                      <Button variant="lime" className="text-[12px]">
                        Review
                      </Button>
                    </Link>
                    <Button
                      variant="danger"
                      className="text-[11px] px-2.5 py-1"
                      onClick={() => deleteScan(s.id)}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Commission scan modal — carries the consent screen */}
      <CommissionScanModal
        targetId={showCommissionModal && target ? target.id : null}
        targetName={target?.name ?? null}
        targetKind={target?.kind}
        repositoryId={target?.repository_id}
        // Feature 001 — pass kind_config so the modal can extend Phase B
        // disclosures (cicd_pipeline live_api_enabled, k8s_cluster live_cluster).
        // Pass the raw kind_config straight through so every conditional
        // disclosure flag is present (mcp dynamic_invocation/destructive_opt_in,
        // rag query_probes, voice audio_probes, …), not just cicd/k8s/host.
        targetKindConfig={
          (target?.kind_config as Record<string, unknown> | undefined) ?? null
        }
        priorAuthorizationText={
          scans
            .filter((s) => s.consent_payload?.authorization_text)
            .sort(
              (a, b) =>
                new Date(b.created_at).getTime() -
                new Date(a.created_at).getTime(),
            )[0]?.consent_payload?.authorization_text ?? null
        }
        onClose={() => setShowCommissionModal(false)}
      />
    </div>
  );
}

function TargetTrendSection({
  trend,
  isRepoTarget,
}: {
  trend: TargetTrend;
  isRepoTarget: boolean;
}) {
  // Repo scans live at /repos/scans/{id}; route per-scan links accordingly.
  const scanHref = (sid: string) =>
    isRepoTarget ? `/repos/scans/${sid}` : `/scans/${sid}`;
  const completed = trend.scans.filter((s) => s.status === "done");

  const gradePoints = completed
    .filter((s) => s.score != null && s.created_at)
    .map((s) => ({
      date: s.created_at as string,
      value: Math.round(s.score as number),
      label: s.grade,
    }));

  const stackPoints = completed
    .filter((s) => s.created_at)
    .map((s) => ({
      date: s.created_at as string,
      summary: s.summary,
    }));

  return (
    <section>
      <div className="flex items-end justify-between mb-6 flex-wrap gap-3">
        <div>
          <p className="eyebrow-gilt">Trend</p>
          <h2 className="mt-2 font-display text-[24px] text-ink">
            Posture over time
          </h2>
          <p className="mt-1 text-[13px] text-graphite max-w-[64ch]">
            Grade trajectory and severity drift across every completed
            assessment of this target. Snapshots taken at scan-completion time.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist mb-2">
            Grade score (0–100)
          </p>
          <TrendLine points={gradePoints} yLabel="Score" yDomain={[0, 100]} />
        </div>
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist mb-2">
            Severity counts per scan
          </p>
          <SeverityStack series={stackPoints} />
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-5">
        <div className="formal-surface p-5">
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
            Open findings
          </p>
          <p className="mt-2 font-display text-[36px] leading-none text-ink">
            {trend.open_total}
          </p>
          <p className="mt-2 font-mono text-[10px] text-slate">
            Active across this target
          </p>
        </div>
        <div className="formal-surface p-5">
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
            Fixed findings
          </p>
          <p className="mt-2 font-display text-[36px] leading-none text-forest">
            {trend.fixed_total}
          </p>
          <p className="mt-2 font-mono text-[10px] text-slate">
            Verified resolved
          </p>
        </div>
        <div className="formal-surface p-5">
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
            Mean time to resolve
          </p>
          <p className="mt-2 font-display text-[36px] leading-none text-ink">
            {trend.mttr_days == null ? "—" : `${trend.mttr_days}d`}
          </p>
          <p className="mt-2 font-mono text-[10px] text-slate">
            Avg. days created → fixed
          </p>
        </div>
      </div>

      {trend.deltas.length > 0 && (
        <div className="formal-surface p-5">
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist mb-3">
            Scan-pair deltas
          </p>
          <ul className="divide-y divide-hairline">
            {trend.deltas.map((d) => {
              const target = completed.find((s) => s.id === d.scan_id);
              return (
                <li
                  key={d.scan_id}
                  className="py-2 flex items-center gap-4 flex-wrap font-mono text-[12px]"
                >
                  <span className="text-mist">
                    {(target?.created_at || "").slice(0, 10)}
                  </span>
                  <Link
                    href={scanHref(d.scan_id)}
                    className="text-ink hover:underline underline-offset-[4px] decoration-gilt decoration-1"
                  >
                    {shortId(d.scan_id)}
                  </Link>
                  <span className="text-mist">vs</span>
                  <Link
                    href={scanHref(d.vs_prior_scan_id)}
                    className="text-slate hover:underline underline-offset-[4px] decoration-gilt decoration-1"
                  >
                    {shortId(d.vs_prior_scan_id)}
                  </Link>
                  <span className="flex-1" />
                  <span className="text-sev-critical">+{d.new} new</span>
                  <span className="text-forest">−{d.fixed} fixed</span>
                  {d.regressed > 0 && (
                    <span className="text-sev-high">
                      ±{d.regressed} regressed
                    </span>
                  )}
                  {!isRepoTarget && (
                    <Link
                      href={`/scans/compare?a=${d.vs_prior_scan_id}&b=${d.scan_id}`}
                      className="text-ink underline underline-offset-[4px] decoration-gilt decoration-1"
                    >
                      Diff →
                    </Link>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </section>
  );
}

function RecommendedGuardrailsCard({
  targetId,
  targetName,
  scans,
}: {
  targetId: string;
  targetName: string;
  scans: Scan[];
}) {
  // Recommendations are computed per-scan from the OWASP-LLM-Top-10
  // failure breakdown, so we need *some* completed scan to have data
  // to recommend from. Pick the most recent finished one.
  const latestDone = useMemo(
    () =>
      scans
        .filter((s) => s.status === "done")
        .sort((a, b) => (b.created_at > a.created_at ? 1 : -1))[0],
    [scans],
  );

  return (
    <section>
      <div className="flex items-end justify-between mb-6">
        <div>
          <p className="eyebrow">Pencheff Sentry</p>
          <h2 className="mt-2 font-display text-[24px] text-ink">
            Recommended guardrails
          </h2>
          <p className="mt-1 text-[13px] text-graphite max-w-[64ch]">
            Computed from the OWASP-LLM-Top-10 failure breakdown of the most
            recent red-team scan. Configure these on the target&rsquo;s Edit
            page.
          </p>
        </div>
        <Link href={`/targets/${targetId}/edit`}>
          <Button variant="lime">Edit guardrails</Button>
        </Link>
      </div>

      {latestDone ? (
        <div className="formal-surface p-6 flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-wider text-mist">
              Latest scan
            </p>
            <p className="mt-1 font-display text-[18px] text-ink">
              {shortId(latestDone.id)} ·{" "}
              {latestDone.grade ? `Grade ${latestDone.grade}` : "Ungraded"}
            </p>
            <p className="text-[12px] text-graphite">
              Finished {formatDate(latestDone.finished_at)}
            </p>
          </div>
          <Link href={`/scans/${latestDone.id}/recommended-guardrails`}>
            <Button variant="pink">View recommendations →</Button>
          </Link>
        </div>
      ) : (
        <div className="formal-surface p-6">
          <p className="text-[13px] text-graphite">
            No completed red-team scans for <strong>{targetName}</strong> yet.
            Commission a scan above; once it finishes, recommendations will
            appear here.
          </p>
        </div>
      )}
    </section>
  );
}

export default function TargetDetailPage() {
  return (
    <Suspense fallback={null}>
      <TargetDetailPageContent />
    </Suspense>
  );
}

