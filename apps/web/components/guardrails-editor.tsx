"use client";

// Per-target LLM guardrail editor.
//
// Renders all 10 OWASP-LLM-Top-10 categories on each side (input +
// output). Each row carries an enforcement-status pill so the user
// understands what each toggle actually does:
//
//   inline           — runs on every request, cheap regex
//   needs_baseline   — needs system_prompt_baseline configured below
//   needs_judge      — needs an external LLM judge call (latency / $)
//   side_na          — this side doesn't apply (e.g. LLM01-output)
//   scan_only        — only detectable at scan time, not at proxy
//
// Categories tagged ``side_na`` or ``scan_only`` are visually disabled
// — flipping them on would silently no-op, so we don't let the user
// shoot themselves in the foot.
//
// Four preset buttons (Strict / Balanced / Minimal / All) load the
// canonical configs from the backend.

import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/brutal";
import { api } from "@/lib/api";

type Status =
  | "inline"
  | "inline+judge"
  | "needs_baseline"
  | "needs_judge"
  | "side_na"
  | "scan_only";

type SideConfig = Record<string, unknown> & {
  LLM01: boolean;
  LLM02: boolean;
  LLM03: boolean;
  LLM04: boolean;
  LLM05: boolean;
  LLM06: boolean;
  LLM07: boolean;
  LLM08: boolean;
  LLM09: boolean;
  LLM10: boolean;
  extra_patterns: Array<{ name: string; regex: string; category: string }>;
};

export type Guardrails = {
  input: SideConfig & { max_prompt_tokens: number | null };
  output: SideConfig & {
    max_output_tokens: number | null;
    system_prompt_baseline: string | null;
  };
};

type CategoryMeta = {
  id: string;
  name: string;
  input_status: Status;
  output_status: Status;
  /** Optional — present on tier-4 categories that map to a regulatory frame. */
  compliance?: string[];
};

type Enforcement = {
  categories: CategoryMeta[];
  presets: string[];
};

type GuardrailsOut = {
  target_id: string;
  proxy_url: string | null;
  guardrails: Guardrails;
  enforcement: Enforcement;
  presets: Record<string, Guardrails>;
};

// Target-less metadata returned by GET /guardrails/metadata. Used by
// the controlled-mode editor on the new-target form (no Target row
// exists yet, so we can't fetch from /targets/{id}/guardrails).
type GuardrailsMeta = {
  defaults: Guardrails;
  enforcement: Enforcement;
  presets: Record<string, Guardrails>;
};

const STATUS_LABEL: Record<Status, string> = {
  inline: "inline",
  "inline+judge": "inline + judge fallback",
  needs_baseline: "needs baseline",
  needs_judge: "judge call",
  side_na: "n/a on this side",
  scan_only: "scan-time only",
};

const STATUS_TONE: Record<Status, string> = {
  inline: "border-forest/40 text-forest",
  "inline+judge": "border-forest/40 text-forest",
  needs_baseline: "border-gilt text-gilt",
  needs_judge: "border-oxblood/60 text-oxblood",
  side_na: "border-mist text-mist",
  scan_only: "border-mist text-mist",
};

function isEnforceable(status: Status): boolean {
  return (
    status === "inline" ||
    status === "inline+judge" ||
    status === "needs_baseline" ||
    status === "needs_judge"
  );
}

const PRESET_LABEL: Record<string, string> = {
  strict: "Strict",
  balanced: "Balanced",
  minimal: "Minimal",
  all: "All (LLM01–LLM10 + tier-4)",
  "gdpr-aligned": "GDPR-aligned",
  "iso-42001-aligned": "ISO/IEC 42001-aligned",
  "ai-act-high-risk": "EU AI Act — high-risk",
  "bias-aware-production": "Bias-aware (production)",
};

const FALLBACK_CATEGORY_NAMES: Record<string, string> = {
  LLM01: "Prompt Injection",
  LLM02: "Sensitive Information Disclosure",
  LLM03: "Supply Chain",
  LLM04: "Data and Model Poisoning",
  LLM05: "Improper Output Handling",
  LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage",
  LLM08: "Vector and Embedding Weaknesses",
  LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
  BIAS: "Bias / Stereotype Affirmation (LLM09 + GDPR Art. 22)",
  RAG: "RAG Retrieval-Context Leak (LLM02 + GDPR Art. 32)",
  MCP: "MCP Tool-Description Injection (LLM06 + ISO 42001 A.10.3)",
  CODING_AGENT: "Coding-Agent Hazard (LLM02 / LLM05 / LLM06)",
};

const FALLBACK_COMPLIANCE: Record<string, string[]> = {
  LLM01: ["OWASP LLM01", "ISO 42001 A.6.2.4"],
  LLM02: ["OWASP LLM02", "GDPR Art. 32", "ISO 42001 A.7.5"],
  LLM03: ["OWASP LLM03", "ISO 42001 A.10.3"],
  LLM04: ["OWASP LLM04", "GDPR Art. 5(1)(d)", "ISO 42001 A.7.3"],
  LLM05: ["OWASP LLM05", "GDPR Art. 32"],
  LLM06: ["OWASP LLM06", "EU AI Act Art. 14"],
  LLM07: ["OWASP LLM07", "ISO 42001 A.6.2.7"],
  LLM08: ["OWASP LLM08", "ISO 42001 A.7.2"],
  LLM09: ["OWASP LLM09", "EU AI Act Art. 13", "ISO 42001 A.7.2"],
  LLM10: ["OWASP LLM10", "ISO 42001 A.6.2.6"],
  BIAS: ["OWASP LLM09", "GDPR Art. 22", "EU AI Act Art. 5"],
  RAG: ["OWASP LLM02", "GDPR Art. 32", "ISO 42001 A.7.5"],
  MCP: ["OWASP LLM06", "ISO 42001 A.10.3"],
  CODING_AGENT: ["OWASP LLM02/05/06", "ISO 42001 A.6.2.4"],
};

const FALLBACK_ENFORCEMENT: Record<string, { input: Status; output: Status }> =
  {
    LLM01: { input: "inline", output: "side_na" },
    LLM02: { input: "inline", output: "inline" },
    LLM03: { input: "scan_only", output: "scan_only" },
    LLM04: { input: "scan_only", output: "scan_only" },
    LLM05: { input: "side_na", output: "inline" },
    LLM06: { input: "inline", output: "inline" },
    LLM07: { input: "inline", output: "needs_baseline" },
    LLM08: { input: "scan_only", output: "scan_only" },
    LLM09: { input: "side_na", output: "needs_judge" },
    LLM10: { input: "inline", output: "inline" },
    BIAS: { input: "side_na", output: "inline+judge" },
    RAG: { input: "side_na", output: "inline+judge" },
    MCP: { input: "inline", output: "side_na" },
    CODING_AGENT: { input: "side_na", output: "inline" },
  };

const FALLBACK_CATEGORIES = Object.keys(FALLBACK_CATEGORY_NAMES);

function emptySide(side: "input" | "output") {
  const out: Record<string, unknown> = {};
  for (const cat of FALLBACK_CATEGORIES) out[cat] = false;
  out.extra_patterns = [];
  if (side === "input") out.max_prompt_tokens = null;
  else {
    out.max_output_tokens = null;
    out.system_prompt_baseline = null;
  }
  return out;
}

function fallbackBalanced(): Guardrails {
  const input = emptySide("input") as Guardrails["input"];
  const output = emptySide("output") as Guardrails["output"];
  input.LLM01 = true;
  input.LLM02 = true;
  input.LLM07 = true;
  output.LLM02 = true;
  output.LLM05 = true;
  output.LLM10 = true;
  return { input, output };
}

function fallbackStrict(): Guardrails {
  const cfg = fallbackBalanced();
  cfg.input.LLM06 = true;
  cfg.input.LLM10 = true;
  cfg.output.LLM06 = true;
  cfg.output.LLM07 = true;
  return cfg;
}

function fallbackMinimal(): Guardrails {
  const input = emptySide("input") as Guardrails["input"];
  const output = emptySide("output") as Guardrails["output"];
  input.LLM02 = true;
  output.LLM02 = true;
  output.LLM05 = true;
  return { input, output };
}

function fallbackAll(): Guardrails {
  const input = emptySide("input") as Guardrails["input"];
  const output = emptySide("output") as Guardrails["output"];
  for (const cat of FALLBACK_CATEGORIES) {
    const profile = FALLBACK_ENFORCEMENT[cat];
    if (isEnforceable(profile.input)) input[cat] = true;
    if (isEnforceable(profile.output)) output[cat] = true;
  }
  return { input, output };
}

function fallbackGdprAligned(): Guardrails {
  const cfg = fallbackBalanced();
  cfg.input.LLM10 = true;
  cfg.output.BIAS = true;
  cfg.output.RAG = true;
  return cfg;
}

function fallbackIsoAligned(): Guardrails {
  const cfg = fallbackStrict();
  cfg.input.MCP = true;
  cfg.output.BIAS = true;
  cfg.output.RAG = true;
  cfg.output.CODING_AGENT = true;
  cfg.output.LLM09 = true;
  return cfg;
}

function fallbackAiActHighRisk(): Guardrails {
  const cfg = fallbackBalanced();
  cfg.input.LLM06 = true;
  cfg.input.MCP = true;
  cfg.output.LLM06 = true;
  cfg.output.LLM07 = true;
  cfg.output.LLM09 = true;
  cfg.output.RAG = true;
  cfg.output.CODING_AGENT = true;
  return cfg;
}

function fallbackBiasAware(): Guardrails {
  const cfg = fallbackBalanced();
  cfg.output.BIAS = true;
  cfg.output.RAG = true;
  cfg.output.LLM09 = true;
  return cfg;
}

function buildFallbackMeta(): GuardrailsMeta {
  const presets: Record<string, Guardrails> = {
    balanced: fallbackBalanced(),
    strict: fallbackStrict(),
    minimal: fallbackMinimal(),
    all: fallbackAll(),
    "gdpr-aligned": fallbackGdprAligned(),
    "iso-42001-aligned": fallbackIsoAligned(),
    "ai-act-high-risk": fallbackAiActHighRisk(),
    "bias-aware-production": fallbackBiasAware(),
  };
  return {
    defaults: fallbackBalanced(),
    enforcement: {
      categories: FALLBACK_CATEGORIES.map((cat) => ({
        id: cat,
        name: FALLBACK_CATEGORY_NAMES[cat],
        input_status: FALLBACK_ENFORCEMENT[cat].input,
        output_status: FALLBACK_ENFORCEMENT[cat].output,
        compliance: FALLBACK_COMPLIANCE[cat] ?? [],
      })),
      presets: Object.keys(presets),
    },
    presets,
  };
}

type HostedProps = {
  targetId: string;
  // Controlled-mode props are absent; component owns its draft + saves
  // via PUT /targets/{id}/guardrails.
  value?: undefined;
  onChange?: undefined;
};

type ControlledProps = {
  // Controlled mode for the new-target form: parent owns the value
  // and submits it inside its own create-target POST. No save button
  // here, no Target row required.
  targetId?: undefined;
  value: Guardrails | null;
  onChange: (next: Guardrails) => void;
  // Optional. When omitted, the editor fetches /guardrails/metadata.
  // Pre-fetching avoids a flicker when multiple editors share a page.
  meta?: GuardrailsMeta | null;
};

export function GuardrailsEditor(props: HostedProps | ControlledProps) {
  if ("targetId" in props && props.targetId !== undefined) {
    return <HostedEditor targetId={props.targetId} />;
  }
  return (
    <ControlledEditor
      value={props.value}
      onChange={props.onChange!}
      meta={props.meta ?? null}
    />
  );
}

function HostedEditor({ targetId }: { targetId: string }) {
  const [data, setData] = useState<GuardrailsOut | null>(null);
  const [draft, setDraft] = useState<Guardrails | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function reload() {
    setError(null);
    try {
      const d = await api<GuardrailsOut>(`/targets/${targetId}/guardrails`);
      setData(d);
      setDraft(structuredClone(d.guardrails));
    } catch (e: unknown) {
      setError(String((e as { message?: unknown })?.message ?? e));
    }
  }

  useEffect(() => {
    reload();
  }, [targetId]);

  async function save() {
    if (!draft) return;
    setBusy(true);
    setMsg(null);
    try {
      const out = await api<GuardrailsOut>(`/targets/${targetId}/guardrails`, {
        method: "PUT",
        json: { guardrails: draft },
      });
      setData(out);
      setDraft(structuredClone(out.guardrails));
      setMsg({ ok: true, text: "Guardrails saved." });
    } catch (e: unknown) {
      setMsg({
        ok: false,
        text: String((e as { message?: unknown })?.message ?? e),
      });
    } finally {
      setBusy(false);
    }
  }

  function reset() {
    if (data) setDraft(structuredClone(data.guardrails));
    setMsg(null);
  }

  function loadPreset(name: string) {
    if (!data?.presets?.[name]) return;
    setDraft(structuredClone(data.presets[name]));
    setMsg({
      ok: true,
      text: `${PRESET_LABEL[name] ?? name} preset loaded — review and click Save.`,
    });
  }

  const dirty = useMemo(
    () =>
      draft && data
        ? JSON.stringify(draft) !== JSON.stringify(data.guardrails)
        : false,
    [draft, data],
  );

  if (error) {
    return (
      <div className="formal-surface p-6 text-[13px] text-oxblood">{error}</div>
    );
  }
  if (!data || !draft) {
    return (
      <div className="formal-surface p-6 text-[13px] text-mist">
        Loading guardrails…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <ProxyHelloBlock proxyUrl={data.proxy_url} />
      <PresetBar presets={data.enforcement.presets} onPick={loadPreset} />
      <SidesGrid
        draft={draft}
        enforcement={data.enforcement}
        onChange={(next) =>
          setDraft((prev) =>
            typeof next === "function" ? (prev ? next(prev) : prev) : next,
          )
        }
      />
      <div className="flex items-center gap-3">
        <Button
          variant={dirty ? "pink" : "lime"}
          disabled={busy || !dirty}
          onClick={save}
        >
          {busy ? "Saving…" : dirty ? "Save guardrails" : "No changes"}
        </Button>
        <Button variant="cyan" disabled={busy || !dirty} onClick={reset}>
          Reset
        </Button>
        {msg && (
          <span
            className={
              "text-[12px] " + (msg.ok ? "text-forest" : "text-oxblood")
            }
          >
            {msg.text}
          </span>
        )}
      </div>
    </div>
  );
}

function ControlledEditor({
  value,
  onChange,
  meta: metaProp,
}: {
  value: Guardrails | null;
  onChange: (next: Guardrails) => void;
  meta: GuardrailsMeta | null;
}) {
  const [meta, setMeta] = useState<GuardrailsMeta | null>(metaProp);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (metaProp) {
      setMeta(metaProp);
      return;
    }
    let cancelled = false;
    api<GuardrailsMeta>("/guardrails/metadata")
      .then((m) => {
        if (cancelled) return;
        setError(null);
        setMeta(m);
        // Seed the parent with the canonical defaults the first time
        // the editor mounts — avoids the form starting with `null` and
        // submitting an empty guardrail block.
        if (!value) onChange(structuredClone(m.defaults));
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        const fallback = buildFallbackMeta();
        setMeta(fallback);
        if (!value) onChange(structuredClone(fallback.defaults));
        setError(
          `Using built-in guardrail defaults because API metadata could not load: ${String(
            (e as { message?: unknown })?.message ?? e,
          )}`,
        );
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [metaProp]);

  if (!meta || !value) {
    return (
      <div className="formal-surface p-6 text-[13px] text-mist">
        Loading guardrails…
      </div>
    );
  }

  function loadPreset(name: string) {
    const cfg = meta?.presets?.[name];
    if (!cfg) return;
    onChange(structuredClone(cfg));
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="formal-surface p-4 text-[12px] leading-5 text-gilt">
          {error}
        </div>
      )}
      <div className="formal-surface p-6 space-y-3">
        <p className="eyebrow-gilt text-[10px]">
          Pencheff Sentry — runtime guardrail
        </p>
        <p className="text-[13px] text-graphite max-w-[64ch]">
          Pick which OWASP-LLM-Top-10 categories the hosted Sentry proxy should
          enforce on every chat-completions request to this target. You can
          change these later from the target&rsquo;s Edit page.
        </p>
        <p className="text-[11px] text-mist">
          The proxy URL becomes{" "}
          <code>
            POST
            &lt;pencheff-base&gt;/proxy/&lt;target-id&gt;/v1/chat/completions
          </code>{" "}
          once this target is created. Authenticate with your{" "}
          <code>PENCHEFF_API_KEY</code>.
        </p>
      </div>
      <PresetBar presets={meta.enforcement.presets} onPick={loadPreset} />
      <SidesGrid
        draft={value}
        enforcement={meta.enforcement}
        onChange={(next) =>
          onChange(typeof next === "function" ? next(value) : next)
        }
      />
    </div>
  );
}

function ProxyHelloBlock({ proxyUrl }: { proxyUrl: string | null }) {
  return (
    <div className="formal-surface p-6 space-y-3">
      <p className="eyebrow-gilt text-[10px]">Pencheff guardrail proxy</p>
      <p className="text-[13px] text-graphite max-w-[64ch]">
        Point your application at the URL below and authenticate with your
        <code className="mx-1">PENCHEFF_API_KEY</code>. Pencheff applies the
        guardrails configured here on every chat-completions request, then
        forwards to the upstream LLM using the credentials stored on this
        target.
      </p>
      <pre className="bg-vellum border border-hairline rounded-sm p-3 text-[12px] overflow-x-auto whitespace-pre-wrap">
        <code>
          {`POST ${proxyUrl ?? "<proxy-url-unavailable>"}/v1/chat/completions
Authorization: Bearer <PENCHEFF_API_KEY>
Content-Type: application/json

{ "model": "...", "messages": [...] }`}
        </code>
      </pre>
      <p className="text-[11px] text-mist">
        Requests blocked by an input guardrail return{" "}
        <code>403 sentry_blocked</code>; blocked responses return{" "}
        <code>403 sentry_blocked_response</code>. Both bodies include the
        OWASP-LLM category and the detector that fired.
      </p>
    </div>
  );
}

function PresetBar({
  presets,
  onPick,
}: {
  presets: string[];
  onPick: (name: string) => void;
}) {
  return (
    <div className="formal-surface p-4 flex flex-wrap gap-2 items-center">
      <span className="font-mono text-[11px] uppercase tracking-wider text-mist mr-2">
        Presets:
      </span>
      {presets.map((name) => (
        <Button
          key={name}
          variant="cyan"
          onClick={() => onPick(name)}
          className="text-[11px] px-3 py-1"
        >
          {PRESET_LABEL[name] ?? name}
        </Button>
      ))}
      <span className="ml-auto text-[11px] text-mist max-w-[40ch] text-right">
        Strict / Balanced / Minimal toggle the inline-enforceable detectors
        only. <em>All</em> turns on every detector that has *any* enforcement
        path (skips scan-only / side-N/A).
      </span>
    </div>
  );
}

function SidesGrid({
  draft,
  enforcement,
  onChange,
}: {
  draft: Guardrails;
  enforcement: Enforcement;
  onChange: (next: Guardrails | ((prev: Guardrails) => Guardrails)) => void;
}) {
  function toggle(side: "input" | "output", category: string) {
    const next = structuredClone(draft);
    const sideObj = next[side] as unknown as Record<string, unknown>;
    sideObj[category] = !sideObj[category];
    onChange(next);
  }
  return (
    <div className="grid md:grid-cols-2 gap-6">
      <SidePanel
        title="Input — prompt-side"
        subtitle="Run before the request reaches the upstream model."
        numericLabel="Max prompt tokens (LLM10)"
        numericValue={draft.input.max_prompt_tokens}
        onNumeric={(v) =>
          onChange({
            ...draft,
            input: { ...draft.input, max_prompt_tokens: v },
          })
        }
      >
        {enforcement.categories.map((cat) => (
          <CategoryRow
            key={cat.id}
            cat={cat}
            side="input"
            status={cat.input_status}
            checked={draft.input[cat.id] as boolean}
            onToggle={() => toggle("input", cat.id)}
          />
        ))}
      </SidePanel>

      <SidePanel
        title="Output — response-side"
        subtitle="Run on the assistant's reply before it reaches your app."
        numericLabel="Max output tokens (LLM10)"
        numericValue={draft.output.max_output_tokens}
        onNumeric={(v) =>
          onChange({
            ...draft,
            output: { ...draft.output, max_output_tokens: v },
          })
        }
      >
        {enforcement.categories.map((cat) => (
          <CategoryRow
            key={cat.id}
            cat={cat}
            side="output"
            status={cat.output_status}
            checked={draft.output[cat.id] as boolean}
            onToggle={() => toggle("output", cat.id)}
          />
        ))}
        {draft.output.LLM07 && (
          <div className="border-t border-hairline pt-3 space-y-2">
            <p className="font-mono text-[11px] uppercase tracking-wider text-mist">
              LLM07 — system prompt baseline
            </p>
            <p className="text-[11px] text-mist">
              The response-side LLM07 detector blocks any reply that contains a
              40-char window from this baseline. Paste the deployed
              system-prompt verbatim.
            </p>
            <textarea
              rows={4}
              placeholder="(no baseline configured — LLM07 output detector won't fire)"
              value={draft.output.system_prompt_baseline ?? ""}
              onChange={(e) =>
                onChange({
                  ...draft,
                  output: {
                    ...draft.output,
                    system_prompt_baseline:
                      e.target.value === "" ? null : e.target.value,
                  },
                })
              }
              className="w-full bg-paper border border-hairline rounded-sm px-3 py-2 font-mono text-[12px]"
            />
          </div>
        )}
      </SidePanel>
    </div>
  );
}

function SidePanel({
  title,
  subtitle,
  numericLabel,
  numericValue,
  onNumeric,
  children,
}: {
  title: string;
  subtitle: string;
  numericLabel: string;
  numericValue: number | null;
  onNumeric: (v: number | null) => void;
  children: React.ReactNode;
}) {
  return (
    <div className="formal-surface p-6 space-y-3">
      <div>
        <p className="eyebrow-gilt text-[10px]">{title}</p>
        <p className="mt-1 text-[12px] text-mist">{subtitle}</p>
      </div>
      <div className="space-y-2">{children}</div>
      <div className="border-t border-hairline pt-3">
        <p className="font-mono text-[11px] uppercase tracking-wider text-mist mb-2">
          {numericLabel}
        </p>
        <input
          type="number"
          min={0}
          step={100}
          placeholder="(no cap)"
          value={numericValue ?? ""}
          onChange={(e) => {
            const v = e.target.value === "" ? null : Number(e.target.value);
            onNumeric(v);
          }}
          className="w-32 bg-paper border border-hairline rounded-sm px-3 py-1.5 font-mono text-[13px]"
        />
      </div>
    </div>
  );
}

function CategoryRow({
  cat,
  side,
  status,
  checked,
  onToggle,
}: {
  cat: CategoryMeta;
  side: "input" | "output";
  status: Status;
  checked: boolean;
  onToggle: () => void;
}) {
  const enforceable = isEnforceable(status);
  return (
    <label
      className={
        "flex items-start gap-3 cursor-pointer select-none py-1 " +
        (enforceable ? "" : "opacity-50 cursor-not-allowed")
      }
      title={
        enforceable
          ? undefined
          : `Not enforceable on the ${side} side at proxy level (${STATUS_LABEL[status]}).`
      }
    >
      <input
        type="checkbox"
        checked={enforceable && checked}
        disabled={!enforceable}
        onChange={onToggle}
        className="mt-1 accent-ink"
      />
      <span className="flex-1">
        <span className="flex items-baseline gap-2 flex-wrap">
          <span className="font-mono text-[11px] uppercase tracking-wider text-graphite">
            {cat.id}
          </span>
          <span className="text-[13px] text-graphite">{cat.name}</span>
          {cat.compliance && cat.compliance.length > 0 && (
            <span className="text-[10px] text-mist font-mono">
              {cat.compliance.join(" · ")}
            </span>
          )}
          <span
            className={
              "ml-auto inline-flex items-center border rounded-sm px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider " +
              STATUS_TONE[status]
            }
          >
            {STATUS_LABEL[status]}
          </span>
        </span>
      </span>
    </label>
  );
}
