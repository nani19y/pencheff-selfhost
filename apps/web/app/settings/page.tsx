"use client";

import { useState, useEffect, useCallback } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useWorkspace } from "@/lib/workspace-context";
import {
  listProviders,
  getCatalog,
  createProvider,
  updateProvider,
  deleteProvider,
  activateProvider,
  deactivateProvider,
  testProvider,
  type LlmProvider,
  type LlmProviderKind,
  type LlmProviderInput,
} from "@/lib/llm-providers";

// ─── Small helpers ───────────────────────────────────────────────────────────

const KIND_LABELS: Record<LlmProviderKind, string> = {
  openai: "OpenAI",
  anthropic: "Anthropic",
  google: "Google",
  azure_openai: "Azure OpenAI",
  openai_compatible: "OpenAI-Compatible",
  bedrock: "AWS Bedrock",
  vertex: "Google Vertex AI",
};

function ProviderBadge({ kind }: { kind: LlmProviderKind }) {
  return (
    <span className="inline-block px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] border border-hairline rounded-sm text-slate">
      {KIND_LABELS[kind] ?? kind}
    </span>
  );
}

function CloseIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      className="w-4 h-4"
    >
      <path d="M4 4l8 8M12 4l-8 8" strokeLinecap="round" />
    </svg>
  );
}

// ─── Add / Edit modal ────────────────────────────────────────────────────────

type ModalMode = { type: "add" } | { type: "edit"; provider: LlmProvider };

type FormState = {
  label: string;
  provider: LlmProviderKind;
  model: string;
  base_url: string;
  api_key: string;
  azure_deployment: string;
  azure_api_version: string;
};

const EMPTY_FORM: FormState = {
  label: "",
  provider: "openai",
  model: "",
  base_url: "",
  api_key: "",
  azure_deployment: "",
  azure_api_version: "",
};

function providerToForm(p: LlmProvider): FormState {
  return {
    label: p.label,
    provider: p.provider,
    model: p.model,
    base_url: p.base_url ?? "",
    api_key: "", // never pre-fill; blank = keep unchanged on PATCH
    azure_deployment: p.azure_deployment ?? "",
    azure_api_version: p.azure_api_version ?? "",
  };
}

interface ProviderModalProps {
  mode: ModalMode;
  catalog: {
    kinds: LlmProviderKind[];
    models: Record<string, { id: string; label: string }[]>;
  };
  onClose: () => void;
  onSaved: () => void;
}

function ProviderModal({
  mode,
  catalog,
  onClose,
  onSaved,
}: ProviderModalProps) {
  const [form, setForm] = useState<FormState>(
    mode.type === "edit" ? providerToForm(mode.provider) : EMPTY_FORM,
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEdit = mode.type === "edit";
  const editTarget = isEdit ? mode.provider : null;
  const needsBaseUrl =
    form.provider === "openai_compatible" || form.provider === "azure_openai";
  const needsAzure = form.provider === "azure_openai";

  const modelSuggestions = catalog.models[form.provider] ?? [];

  function set<K extends keyof FormState>(key: K, val: FormState[K]) {
    setForm((f) => ({ ...f, [key]: val }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      if (isEdit && editTarget) {
        const body: Partial<LlmProviderInput> = {
          label: form.label,
          provider: form.provider,
          model: form.model,
        };
        if (needsBaseUrl) body.base_url = form.base_url;
        if (needsAzure) {
          body.azure_deployment = form.azure_deployment;
          body.azure_api_version = form.azure_api_version;
        }
        // Only include api_key if user typed something (blank = keep unchanged)
        if (form.api_key !== "") body.api_key = form.api_key;
        await updateProvider(editTarget.id, body);
      } else {
        const body: LlmProviderInput = {
          label: form.label,
          provider: form.provider,
          model: form.model,
        };
        if (needsBaseUrl) body.base_url = form.base_url;
        if (needsAzure) {
          body.azure_deployment = form.azure_deployment;
          body.azure_api_version = form.azure_api_version;
        }
        if (form.api_key !== "") body.api_key = form.api_key;
        await createProvider(body);
      }
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save provider");
    } finally {
      setSaving(false);
    }
  }

  const keyPlaceholder =
    isEdit && editTarget
      ? editTarget.key_set
        ? `•••• ${editTarget.key_hint ?? ""}`.trim()
        : "Not set — enter key to set one"
      : "";

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-ink/40 backdrop-blur-sm">
      <div
        className="w-full max-w-[520px] bg-paper border border-hairline rounded-sm shadow-elev"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="border-b border-hairline px-6 py-4 flex items-start justify-between">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
              {isEdit ? "Edit provider" : "Add provider"}
            </p>
            <h2 className="font-display text-[22px] text-ink mt-1">
              {isEdit ? "Edit LLM Provider" : "Add LLM Provider"}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-1.5 -m-1.5 text-mist hover:text-ink hover:bg-vellum rounded-sm"
          >
            <CloseIcon />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit}>
          <div className="px-6 py-5 space-y-4">
            {/* Label */}
            <label className="block">
              <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-slate">
                Label
              </span>
              <input
                type="text"
                required
                value={form.label}
                onChange={(e) => set("label", e.target.value)}
                placeholder="e.g. Production GPT-4o"
                className="mt-1 w-full bg-paper border border-hairline rounded-sm px-3 py-2 font-body text-[13px] text-ink placeholder:text-mist focus:outline-none focus:border-ink transition-colors"
              />
            </label>

            {/* Provider */}
            <label className="block">
              <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-slate">
                Provider
              </span>
              <select
                value={form.provider}
                onChange={(e) =>
                  set("provider", e.target.value as LlmProviderKind)
                }
                className="mt-1 w-full bg-paper border border-hairline rounded-sm px-3 py-2 font-body text-[13px] text-ink focus:outline-none focus:border-ink transition-colors"
              >
                {catalog.kinds.map((k) => (
                  <option key={k} value={k}>
                    {KIND_LABELS[k] ?? k}
                  </option>
                ))}
              </select>
            </label>

            {/* Model */}
            <label className="block">
              <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-slate">
                Model
              </span>
              <input
                type="text"
                list="model-suggestions"
                required
                value={form.model}
                onChange={(e) => set("model", e.target.value)}
                placeholder="e.g. gpt-4o"
                className="mt-1 w-full bg-paper border border-hairline rounded-sm px-3 py-2 font-body text-[13px] text-ink placeholder:text-mist focus:outline-none focus:border-ink transition-colors"
              />
              <datalist id="model-suggestions">
                {modelSuggestions.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.label}
                  </option>
                ))}
              </datalist>
            </label>

            {/* Base URL (openai_compatible + azure_openai) */}
            {needsBaseUrl && (
              <label className="block">
                <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-slate">
                  Base URL
                </span>
                <input
                  type="url"
                  required
                  value={form.base_url}
                  onChange={(e) => set("base_url", e.target.value)}
                  placeholder="https://…"
                  className="mt-1 w-full bg-paper border border-hairline rounded-sm px-3 py-2 font-body text-[13px] text-ink placeholder:text-mist focus:outline-none focus:border-ink transition-colors"
                />
              </label>
            )}

            {/* Azure-specific fields */}
            {needsAzure && (
              <>
                <label className="block">
                  <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-slate">
                    Azure Deployment
                  </span>
                  <input
                    type="text"
                    required
                    value={form.azure_deployment}
                    onChange={(e) => set("azure_deployment", e.target.value)}
                    placeholder="my-gpt4o-deployment"
                    className="mt-1 w-full bg-paper border border-hairline rounded-sm px-3 py-2 font-body text-[13px] text-ink placeholder:text-mist focus:outline-none focus:border-ink transition-colors"
                  />
                </label>
                <label className="block">
                  <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-slate">
                    Azure API Version
                  </span>
                  <input
                    type="text"
                    required
                    value={form.azure_api_version}
                    onChange={(e) => set("azure_api_version", e.target.value)}
                    placeholder="2024-02-01"
                    className="mt-1 w-full bg-paper border border-hairline rounded-sm px-3 py-2 font-body text-[13px] text-ink placeholder:text-mist focus:outline-none focus:border-ink transition-colors"
                  />
                </label>
              </>
            )}

            {/* API Key */}
            <label className="block">
              <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-slate">
                API Key
                {isEdit && (
                  <span className="ml-1 normal-case text-mist">
                    (leave blank to keep unchanged)
                  </span>
                )}
              </span>
              <input
                type="password"
                value={form.api_key}
                onChange={(e) => set("api_key", e.target.value)}
                placeholder={keyPlaceholder}
                autoComplete="new-password"
                className="mt-1 w-full bg-paper border border-hairline rounded-sm px-3 py-2 font-body text-[13px] text-ink placeholder:text-mist focus:outline-none focus:border-ink transition-colors"
              />
            </label>

            {error && (
              <p className="font-mono text-[12px] text-sev-critical">{error}</p>
            )}
          </div>

          {/* Footer */}
          <div className="border-t border-hairline px-6 py-4 flex items-center justify-end gap-3">
            <button
              type="button"
              disabled={saving}
              onClick={onClose}
              className="px-3 py-1.5 font-body text-[13px] border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-3 py-1.5 font-body text-[13px] bg-ink text-paper rounded-sm hover:bg-graphite transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving ? "Saving…" : isEdit ? "Save changes" : "Add provider"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Delete confirm modal ────────────────────────────────────────────────────

interface DeleteModalProps {
  provider: LlmProvider;
  onClose: () => void;
  onDeleted: () => void;
}

function DeleteModal({ provider, onClose, onDeleted }: DeleteModalProps) {
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleDelete() {
    setDeleting(true);
    setError(null);
    try {
      await deleteProvider(provider.id);
      onDeleted();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to delete provider",
      );
      setDeleting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-ink/40 backdrop-blur-sm">
      <div
        className="w-full max-w-[480px] bg-paper border border-hairline rounded-sm shadow-elev"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="border-b border-hairline px-6 py-4 flex items-start justify-between">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
              Confirm action
            </p>
            <h2 className="font-display text-[22px] text-ink mt-1">
              Delete provider?
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-1.5 -m-1.5 text-mist hover:text-ink hover:bg-vellum rounded-sm"
          >
            <CloseIcon />
          </button>
        </div>
        <div className="px-6 py-5">
          <p className="font-body text-[13px] text-graphite leading-relaxed">
            Remove <strong className="text-ink">{provider.label}</strong>? This
            cannot be undone. If this provider is currently active, scans will
            fall back to Pencheff defaults.
          </p>
          {error && (
            <p className="font-mono text-[12px] text-sev-critical mt-3">
              {error}
            </p>
          )}
        </div>
        <div className="border-t border-hairline px-6 py-4 flex items-center justify-end gap-3">
          <button
            type="button"
            disabled={deleting}
            onClick={onClose}
            className="px-3 py-1.5 font-body text-[13px] border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={deleting}
            onClick={() => handleDelete().catch(() => {})}
            className="px-3 py-1.5 font-body text-[13px] bg-ink text-paper rounded-sm hover:bg-graphite transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {deleting ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main page ───────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const { activeOrg, refresh } = useWorkspace();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showDisableModal, setShowDisableModal] = useState(false);
  const enabled = activeOrg?.security_lake_enabled ?? false;
  const canManage = activeOrg?.role === "owner" || activeOrg?.role === "admin";

  // ── LLM providers state ──────────────────────────────────────────────────
  const [providers, setProviders] = useState<LlmProvider[]>([]);
  const [catalog, setCatalog] = useState<{
    kinds: LlmProviderKind[];
    models: Record<string, { id: string; label: string }[]>;
  } | null>(null);
  const [providersLoading, setProvidersLoading] = useState(true);
  const [providersError, setProvidersError] = useState<string | null>(null);
  const [modalMode, setModalMode] = useState<ModalMode | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<LlmProvider | null>(null);
  const [activating, setActivating] = useState<string | null>(null); // provider id being activated
  const [deactivating, setDeactivating] = useState(false);
  const [testing, setTesting] = useState<string | null>(null); // provider id being tested
  const [testResults, setTestResults] = useState<
    Record<
      string,
      { ok: boolean; latency_ms: number; error: string | null; sample?: string }
    >
  >({});

  const fetchProviders = useCallback(async () => {
    setProvidersLoading(true);
    setProvidersError(null);
    try {
      const [ps, cat] = await Promise.all([listProviders(), getCatalog()]);
      setProviders(ps);
      setCatalog(cat);
    } catch (err) {
      setProvidersError(
        err instanceof Error ? err.message : "Failed to load providers",
      );
    } finally {
      setProvidersLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeOrg) fetchProviders();
  }, [activeOrg, fetchProviders]);

  async function handleActivate(id: string) {
    setActivating(id);
    try {
      await activateProvider(id);
      await fetchProviders();
    } catch (err) {
      setProvidersError(
        err instanceof Error ? err.message : "Failed to activate provider",
      );
    } finally {
      setActivating(null);
    }
  }

  async function handleDeactivate() {
    setDeactivating(true);
    try {
      await deactivateProvider();
      await fetchProviders();
    } catch (err) {
      setProvidersError(
        err instanceof Error ? err.message : "Failed to deactivate provider",
      );
    } finally {
      setDeactivating(false);
    }
  }

  async function handleTest(id: string) {
    setTesting(id);
    try {
      const result = await testProvider(id);
      setTestResults((prev) => ({ ...prev, [id]: result }));
    } catch (err) {
      setTestResults((prev) => ({
        ...prev,
        [id]: {
          ok: false,
          latency_ms: 0,
          error: err instanceof Error ? err.message : "Test failed",
        },
      }));
    } finally {
      setTesting(null);
    }
  }

  // ── Security Lake toggle ─────────────────────────────────────────────────

  async function setLakeEnabled(next: boolean) {
    if (!activeOrg) return;
    setSaving(true);
    setError(null);
    try {
      await api(`/orgs/${activeOrg.id}`, {
        method: "PATCH",
        json: { security_lake_enabled: next },
      });
      await refresh();
      setShowDisableModal(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to update setting");
    } finally {
      setSaving(false);
    }
  }

  if (!activeOrg)
    return (
      <p className="font-body text-[14px] text-slate">
        Select an organisation first.
      </p>
    );

  const hasActive = providers.some((p) => p.is_active);

  return (
    <div className="mx-auto max-w-3xl">
      <header className="mb-6">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">
          Organisation Settings
        </p>
        <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink mt-2">
          Settings.
        </h1>
        <p className="mt-1 font-body text-[14px] text-slate">
          Org-level feature flags and integrations.
        </p>
      </header>

      {/* ── Security Lake section ─────────────────────────────────────────── */}
      <section className="border border-hairline rounded-sm p-5">
        <div className="flex items-start gap-4">
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            disabled={saving || !canManage}
            onClick={() => {
              if (enabled) {
                setShowDisableModal(true);
              } else {
                setLakeEnabled(true).catch(() => {});
              }
            }}
            className={cn(
              "relative inline-flex shrink-0 h-5 w-9 rounded-full border transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-ink/20 disabled:opacity-50 disabled:cursor-not-allowed",
              enabled ? "bg-ink border-ink" : "bg-paper border-hairline",
            )}
          >
            <span
              className={cn(
                "inline-block h-3.5 w-3.5 rounded-full bg-paper border border-hairline shadow-subtle transform transition-transform duration-200 mt-[2px]",
                enabled ? "translate-x-4" : "translate-x-[2px]",
              )}
            />
          </button>
          <div className="min-w-0">
            <p className="font-body text-[13px] font-semibold text-ink">
              Security Lake
            </p>
            <p className="font-body text-[12px] text-slate mt-0.5 max-w-xl">
              Normalize every finding (SAST, SCA, secrets, IaC, DAST, runtime)
              into OCSF and store it in your queryable, exportable Security
              Lake. Disabled by default.{" "}
              <strong>
                Disabling stops ingestion and queries, and deletes your lake
                data after 7 days.
              </strong>
            </p>
          </div>
        </div>
        {!canManage && (
          <p className="font-mono text-[10px] text-mist mt-3">
            Only org owners/admins can change this.
          </p>
        )}
        {error && (
          <p className="font-mono text-[12px] text-sev-critical mt-3">
            {error}
          </p>
        )}
      </section>

      {/* ── AI / LLM Providers section ────────────────────────────────────── */}
      <section className="border border-hairline rounded-sm mt-6">
        {/* Section header */}
        <div className="px-5 py-4 border-b border-hairline flex items-center justify-between gap-4">
          <div>
            <p className="font-body text-[13px] font-semibold text-ink">
              AI / LLM Provider
            </p>
            <p className="font-body text-[12px] text-slate mt-0.5 max-w-xl">
              Override the default AI model used by Pencheff scans. At most one
              provider can be active at a time. Leave unset to use Pencheff
              defaults.
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {hasActive && canManage && (
              <button
                type="button"
                disabled={deactivating}
                onClick={() => handleDeactivate().catch(() => {})}
                className="px-3 py-1.5 font-body text-[12px] border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors disabled:opacity-50 whitespace-nowrap"
              >
                {deactivating ? "Resetting…" : "Use Pencheff defaults"}
              </button>
            )}
            {canManage && (
              <button
                type="button"
                onClick={() => setModalMode({ type: "add" })}
                className="px-3 py-1.5 font-body text-[12px] bg-ink text-paper rounded-sm hover:bg-graphite transition-colors whitespace-nowrap"
              >
                Add provider
              </button>
            )}
          </div>
        </div>

        {/* Body */}
        <div className="px-5 py-4">
          {providersLoading ? (
            <p className="font-mono text-[12px] text-mist py-2">Loading…</p>
          ) : providersError ? (
            <p className="font-mono text-[12px] text-sev-critical py-2">
              {providersError}
            </p>
          ) : providers.length === 0 ? (
            <p className="font-body text-[13px] text-slate py-2">
              No custom providers configured. Scans use Pencheff defaults.
            </p>
          ) : (
            <div className="divide-y divide-hairline">
              {providers.map((p) => (
                <div
                  key={p.id}
                  className="py-3 flex items-center gap-3 min-w-0"
                >
                  {/* Active indicator */}
                  <div
                    className={cn(
                      "shrink-0 w-1.5 h-1.5 rounded-full",
                      p.is_active ? "bg-ink" : "bg-transparent",
                    )}
                    title={p.is_active ? "Active" : undefined}
                  />

                  {/* Main info */}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-body text-[13px] font-medium text-ink truncate">
                        {p.label}
                      </span>
                      <ProviderBadge kind={p.provider} />
                      {p.is_active && (
                        <span className="inline-block px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.1em] bg-ink text-paper rounded-sm">
                          Active
                        </span>
                      )}
                    </div>
                    <p className="font-mono text-[11px] text-slate mt-0.5 truncate">
                      {p.model}
                      {p.key_set && p.key_hint && (
                        <span className="ml-2 text-mist">
                          key: •••• {p.key_hint}
                        </span>
                      )}
                      {testResults[p.id] && (
                        <span
                          className={cn(
                            "ml-2",
                            testResults[p.id].ok
                              ? "text-ink"
                              : "text-sev-critical",
                          )}
                        >
                          {testResults[p.id].ok
                            ? `✓ ok (${testResults[p.id].latency_ms}ms)`
                            : testResults[p.id].error}
                        </span>
                      )}
                    </p>
                  </div>

                  {/* Actions */}
                  {canManage && (
                    <div className="flex items-center gap-2 shrink-0">
                      {!p.is_active ? (
                        <button
                          type="button"
                          disabled={activating === p.id}
                          onClick={() => handleActivate(p.id).catch(() => {})}
                          className="px-2.5 py-1 font-body text-[12px] border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors disabled:opacity-50"
                        >
                          {activating === p.id ? "…" : "Activate"}
                        </button>
                      ) : (
                        <button
                          type="button"
                          disabled={deactivating}
                          onClick={() => handleDeactivate().catch(() => {})}
                          title="Stop using this provider; Pencheff's default AI is used instead"
                          className="px-2.5 py-1 font-body text-[12px] border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors disabled:opacity-50"
                        >
                          {deactivating ? "…" : "Deactivate"}
                        </button>
                      )}
                      <button
                        type="button"
                        disabled={testing === p.id}
                        onClick={() => handleTest(p.id).catch(() => {})}
                        className="px-2.5 py-1 font-body text-[12px] border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors disabled:opacity-50"
                      >
                        {testing === p.id ? "…" : "Test"}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setModalMode({ type: "edit", provider: p })
                        }
                        className="px-2.5 py-1 font-body text-[12px] border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors"
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => setDeleteTarget(p)}
                        className="px-2.5 py-1 font-body text-[12px] border border-hairline rounded-sm text-slate hover:border-sev-critical hover:text-sev-critical transition-colors"
                      >
                        Delete
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
          {!canManage && providers.length > 0 && (
            <p className="font-mono text-[10px] text-mist mt-3">
              Only org owners/admins can add or change providers.
            </p>
          )}
        </div>
      </section>

      {/* ── Security Lake disable modal ───────────────────────────────────── */}
      {showDisableModal && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-ink/40 backdrop-blur-sm">
          <div
            className="w-full max-w-[480px] bg-paper border border-hairline rounded-sm shadow-elev"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="border-b border-hairline px-6 py-4 flex items-start justify-between">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
                  Confirm action
                </p>
                <h2 className="font-display text-[22px] text-ink mt-1">
                  Disable Security Lake?
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setShowDisableModal(false)}
                aria-label="Close"
                className="p-1.5 -m-1.5 text-mist hover:text-ink hover:bg-vellum rounded-sm"
              >
                <CloseIcon />
              </button>
            </div>
            <div className="px-6 py-5">
              <p className="font-body text-[13px] text-graphite leading-relaxed">
                New findings will stop ingesting and the Security Lake API will
                be turned off for your org. Your existing lake data will be{" "}
                <strong>permanently deleted 7 days</strong> from now unless you
                re-enable before then.
              </p>
            </div>
            <div className="border-t border-hairline px-6 py-4 flex items-center justify-end gap-3">
              <button
                type="button"
                disabled={saving}
                onClick={() => setShowDisableModal(false)}
                className="px-3 py-1.5 font-body text-[13px] border border-hairline rounded-sm text-slate hover:border-ink hover:text-ink transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => setLakeEnabled(false).catch(() => {})}
                className="px-3 py-1.5 font-body text-[13px] bg-ink text-paper rounded-sm hover:bg-graphite transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {saving ? "Disabling…" : "Disable"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Add/Edit modal ────────────────────────────────────────────────── */}
      {modalMode && catalog && (
        <ProviderModal
          mode={modalMode}
          catalog={catalog}
          onClose={() => setModalMode(null)}
          onSaved={() => {
            setModalMode(null);
            fetchProviders().catch(() => {});
          }}
        />
      )}

      {/* ── Delete confirm modal ──────────────────────────────────────────── */}
      {deleteTarget && (
        <DeleteModal
          provider={deleteTarget}
          onClose={() => setDeleteTarget(null)}
          onDeleted={() => {
            setDeleteTarget(null);
            fetchProviders().catch(() => {});
          }}
        />
      )}
    </div>
  );
}
