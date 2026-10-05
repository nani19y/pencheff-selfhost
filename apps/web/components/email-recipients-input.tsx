"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";

type WorkspaceMember = {
  user_id: string;
  email: string;
  name: string | null;
  role: string;
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function EmailRecipientsInput({
  value,
  onChange,
  workspaceId,
  label = "Recipients",
  hint,
  max = 10,
}: {
  value: string[];
  onChange: (next: string[]) => void;
  /** Pass to fetch workspace members. Omit to skip the dropdown. */
  workspaceId?: string | null;
  label?: string;
  hint?: string;
  max?: number;
}) {
  const [members, setMembers] = useState<WorkspaceMember[]>([]);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!workspaceId) return;
    let alive = true;
    api<WorkspaceMember[]>(`/workspaces/${workspaceId}/members`)
      .then((rows) => {
        if (alive) setMembers(rows);
      })
      .catch(() => {
        // Endpoint may not exist on older API deployments; just hide the
        // dropdown rather than error.
        if (alive) setMembers([]);
      });
    return () => {
      alive = false;
    };
  }, [workspaceId]);

  const memberOptions = useMemo(
    () => members.filter((m) => !value.includes(m.email)),
    [members, value]
  );

  function add(email: string) {
    const e = email.trim();
    if (!e) return;
    if (!EMAIL_RE.test(e)) {
      setError(`"${e}" is not a valid email`);
      return;
    }
    if (value.includes(e)) {
      setError(`${e} is already on the list`);
      return;
    }
    if (value.length >= max) {
      setError(`Maximum ${max} recipients`);
      return;
    }
    onChange([...value, e]);
    setDraft("");
    setError(null);
  }

  function remove(email: string) {
    onChange(value.filter((e) => e !== email));
    setError(null);
  }

  return (
    <div>
      <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-slate mb-2">
        {label}
      </p>

      {/* Chip list of selected recipients */}
      {value.length > 0 && (
        <ul className="flex flex-wrap gap-2 mb-3">
          {value.map((email) => (
            <li
              key={email}
              className="inline-flex items-center gap-2 border border-hairline rounded-sm px-2 py-1 font-mono text-[11px] bg-paper"
            >
              <span className="text-graphite">{email}</span>
              <button
                type="button"
                onClick={() => remove(email)}
                aria-label={`Remove ${email}`}
                className="text-mist hover:text-sev-critical"
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}

      {/* Member dropdown + free-text input on one row */}
      <div className="flex gap-2 flex-wrap">
        {memberOptions.length > 0 && (
          <select
            className="border-2 border-hairline bg-paper px-2 py-1.5 text-[12px] text-graphite focus:outline-none focus:border-ink min-w-[200px]"
            defaultValue=""
            onChange={(e) => {
              if (e.target.value) {
                add(e.target.value);
                e.currentTarget.value = "";
              }
            }}
            disabled={value.length >= max}
          >
            <option value="">+ Add workspace member…</option>
            {memberOptions.map((m) => (
              <option key={m.user_id} value={m.email}>
                {m.email}
                {m.name ? ` — ${m.name}` : ""}
              </option>
            ))}
          </select>
        )}
        <div className="flex-1 flex gap-2 min-w-[200px]">
          <input
            type="email"
            placeholder="any@email.address"
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value);
              if (error) setError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                add(draft);
              }
            }}
            className="flex-1 border-2 border-hairline bg-paper px-2 py-1.5 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
            disabled={value.length >= max}
          />
          <button
            type="button"
            onClick={() => add(draft)}
            disabled={value.length >= max || !draft.trim()}
            className="border-2 border-ink bg-vellum px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.08em] hover:bg-gilt disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Add
          </button>
        </div>
      </div>

      {error && (
        <p className="mt-2 font-mono text-[11px] text-sev-critical">{error}</p>
      )}
      {hint && !error && (
        <p className="mt-2 font-mono text-[11px] text-mist">{hint}</p>
      )}
      {value.length >= max && !error && (
        <p className="mt-2 font-mono text-[11px] text-mist">
          Recipient cap reached ({max}).
        </p>
      )}
    </div>
  );
}
