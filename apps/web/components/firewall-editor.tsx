"use client";

import { useEffect, useState } from "react";
import { Button, Input, Label } from "@/components/brutal";
import { api } from "@/lib/api";

// Mirrors pencheff_sentry.firewall + services.agent_firewall config shape.
type FwRule = {
  id: string;
  action: string;
  tools: string[];
  arg_patterns: string[];
  reason: string;
};

type FwConfig = {
  enabled: boolean;
  default_action: string;
  rules: FwRule[];
};

type FwMeta = {
  actions: string[];
  default_rules: { id: string; action: string; reason: string }[];
};

type FirewallOut = {
  target_id: string;
  proxy_url: string | null;
  firewall: FwConfig;
  metadata: FwMeta;
};

const ACTION_LABEL: Record<string, string> = {
  allow: "Allow",
  block: "Block",
  require_approval: "Require approval",
  redact_args: "Redact args",
};

function csv(value: string): string[] {
  return value
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function FirewallEditor({ targetId }: { targetId: string }) {
  const [data, setData] = useState<FirewallOut | null>(null);
  const [draft, setDraft] = useState<FwConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function reload() {
    setError(null);
    try {
      const d = await api<FirewallOut>(`/targets/${targetId}/firewall`);
      setData(d);
      setDraft(structuredClone(d.firewall));
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
      const out = await api<FirewallOut>(`/targets/${targetId}/firewall`, {
        method: "PUT",
        json: { firewall: draft },
      });
      setData(out);
      setDraft(structuredClone(out.firewall));
      setMsg({ ok: true, text: "Firewall saved." });
    } catch (e: unknown) {
      setMsg({
        ok: false,
        text: String((e as { message?: unknown })?.message ?? e),
      });
    } finally {
      setBusy(false);
    }
  }

  function patch(next: Partial<FwConfig>) {
    setDraft((d) => (d ? { ...d, ...next } : d));
  }

  function patchRule(idx: number, next: Partial<FwRule>) {
    setDraft((d) =>
      d
        ? {
            ...d,
            rules: d.rules.map((r, i) => (i === idx ? { ...r, ...next } : r)),
          }
        : d,
    );
  }

  function addRule() {
    setDraft((d) =>
      d
        ? {
            ...d,
            rules: [
              ...d.rules,
              {
                id: "",
                action: "block",
                tools: [],
                arg_patterns: [],
                reason: "",
              },
            ],
          }
        : d,
    );
  }

  function removeRule(idx: number) {
    setDraft((d) =>
      d ? { ...d, rules: d.rules.filter((_, i) => i !== idx) } : d,
    );
  }

  if (error) {
    return <p className="text-[13px] text-oxblood">{error}</p>;
  }
  if (!draft || !data) {
    return <p className="text-[13px] text-slate italic">Loading firewall…</p>;
  }

  const actions = data.metadata.actions;

  return (
    <div className="space-y-6">
      <p className="text-[13px] text-slate max-w-[70ch]">
        The agent firewall inspects the tool calls the model returns through the
        proxy. Dangerous or approval-gated calls are refused before your app
        receives them; credential-shaped arguments are masked. Live
        execution-time blocking is handled by the SDK (coming next).
      </p>

      {/* Enable + default action */}
      <div className="flex flex-wrap items-end gap-6">
        <label className="flex items-center gap-3 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => patch({ enabled: e.target.checked })}
            className="w-[18px] h-[18px] border border-hairline rounded-sm accent-ink"
          />
          <span className="font-body text-[14px] text-graphite">
            Enable agent firewall on this target
          </span>
        </label>
        <div>
          <Label>Default action (unmatched calls)</Label>
          <select
            value={draft.default_action}
            onChange={(e) => patch({ default_action: e.target.value })}
            className="block border border-hairline bg-paper px-3 py-2 text-[13px] text-graphite focus:outline-none focus:border-ink"
          >
            {actions.map((a) => (
              <option key={a} value={a}>
                {ACTION_LABEL[a] ?? a}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Always-on baseline */}
      <div>
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist mb-2">
          Built-in rules (always on)
        </p>
        <ul className="space-y-1">
          {data.metadata.default_rules.map((r) => (
            <li
              key={r.id}
              className="flex items-center gap-3 text-[12px] text-slate"
            >
              <span className="font-mono text-ink">{r.id}</span>
              <span className="px-1.5 py-0.5 border border-hairline rounded-sm font-mono text-[10px] uppercase">
                {ACTION_LABEL[r.action] ?? r.action}
              </span>
              <span>{r.reason}</span>
            </li>
          ))}
        </ul>
        <p className="mt-2 text-[11px] text-slate italic">
          A custom rule with action “Allow” placed above these can whitelist a
          specific case (first match wins).
        </p>
      </div>

      {/* Custom rules */}
      <div>
        <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist mb-2">
          Custom rules
        </p>
        <div className="space-y-4">
          {draft.rules.map((r, idx) => (
            <div
              key={idx}
              className="border border-hairline rounded-sm p-4 space-y-3"
            >
              <div className="grid sm:grid-cols-[1fr_180px_auto] gap-3 items-end">
                <div>
                  <Label>Rule id</Label>
                  <Input
                    value={r.id}
                    placeholder="no-prod-deletes"
                    onChange={(e) => patchRule(idx, { id: e.target.value })}
                    className="font-mono text-[12px]"
                  />
                </div>
                <div>
                  <Label>Action</Label>
                  <select
                    value={r.action}
                    onChange={(e) => patchRule(idx, { action: e.target.value })}
                    className="block w-full border border-hairline bg-paper px-3 py-2 text-[13px] text-graphite focus:outline-none focus:border-ink"
                  >
                    {actions.map((a) => (
                      <option key={a} value={a}>
                        {ACTION_LABEL[a] ?? a}
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  type="button"
                  onClick={() => removeRule(idx)}
                  className="border border-hairline rounded-sm px-3 py-2 font-mono text-[11px] text-slate hover:border-ink hover:text-ink"
                  aria-label={`Remove rule ${idx + 1}`}
                >
                  ✕
                </button>
              </div>
              <div className="grid sm:grid-cols-2 gap-3">
                <div>
                  <Label>Tool name globs (comma-separated)</Label>
                  <Input
                    value={r.tools.join(", ")}
                    placeholder="delete_*, drop_*"
                    onChange={(e) =>
                      patchRule(idx, { tools: csv(e.target.value) })
                    }
                    className="font-mono text-[12px]"
                  />
                </div>
                <div>
                  <Label>Arg regex patterns (comma-separated)</Label>
                  <Input
                    value={r.arg_patterns.join(", ")}
                    placeholder="prod, 169\.254\.169\.254"
                    onChange={(e) =>
                      patchRule(idx, { arg_patterns: csv(e.target.value) })
                    }
                    className="font-mono text-[12px]"
                  />
                </div>
              </div>
              <div>
                <Label>Reason (shown in the block message)</Label>
                <Input
                  value={r.reason}
                  onChange={(e) => patchRule(idx, { reason: e.target.value })}
                />
              </div>
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={addRule}
          className="mt-3 border border-dashed border-hairline rounded-sm px-4 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-slate hover:border-ink hover:text-ink"
        >
          + Add rule
        </button>
        <p className="mt-2 text-[11px] text-slate italic">
          Each rule needs at least one tool glob or arg pattern. Invalid regexes
          are rejected on save.
        </p>
      </div>

      {msg && (
        <div
          className={
            msg.ok
              ? "formal-surface p-3 font-body text-[13px] text-graphite"
              : "advisory-warn font-body text-[13px]"
          }
        >
          {msg.text}
        </div>
      )}

      <div className="flex items-center gap-3">
        <Button variant="pink" onClick={save} disabled={busy} type="button">
          {busy ? "Saving…" : "Save firewall"}
        </Button>
        <Button
          variant="cyan"
          type="button"
          onClick={() => {
            setDraft(structuredClone(data.firewall));
            setMsg(null);
          }}
        >
          Reset
        </Button>
      </div>
    </div>
  );
}
