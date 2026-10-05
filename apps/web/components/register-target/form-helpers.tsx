"use client";

import type { ReactNode } from "react";
import { Input, Label } from "@/components/brutal";

type HeaderRow = { key: string; value: string };

export function SectionIntro({
  eyebrow,
  title,
  description,
}: {
  eyebrow?: string;
  title: string;
  description?: ReactNode;
}) {
  return (
    <div className="mb-5">
      {eyebrow && <p className="eyebrow-gilt">{eyebrow}</p>}
      <h2 className="mt-2 font-display text-[20px] text-ink">{title}</h2>
      {description && (
        <p className="mt-1 max-w-[72ch] text-[13px] leading-5 text-slate">
          {description}
        </p>
      )}
    </div>
  );
}

export function FieldHint({ children }: { children: ReactNode }) {
  return <p className="mt-1 text-[12px] leading-5 text-slate">{children}</p>;
}

export function AdvancedSection({
  title = "Advanced settings",
  description,
  children,
}: {
  title?: string;
  description?: ReactNode;
  children: ReactNode;
}) {
  return (
    <details className="border border-hairline bg-paper p-5">
      <summary className="cursor-pointer select-none font-display text-[16px] text-ink">
        {title}
      </summary>
      {description && (
        <p className="mt-2 max-w-[72ch] text-[13px] leading-5 text-slate">
          {description}
        </p>
      )}
      <div className="mt-5 grid gap-5">{children}</div>
    </details>
  );
}

export function HeaderRowsEditor({
  rows,
  setRows,
  emptyLabel = "No headers yet. Add one if this target needs a token or API key.",
  newRowKey = "Authorization",
  keyPlaceholder = "Authorization",
  valuePlaceholder = "Bearer sk-...",
}: {
  rows: HeaderRow[];
  setRows: (rows: HeaderRow[]) => void;
  emptyLabel?: string;
  newRowKey?: string;
  keyPlaceholder?: string;
  valuePlaceholder?: string;
}) {
  return (
    <div className="space-y-3">
      {rows.length === 0 && <FieldHint>{emptyLabel}</FieldHint>}
      {rows.map((row, idx) => (
        <div
          key={idx}
          className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto] sm:items-end"
        >
          <div>
            {idx === 0 && <Label>Header name</Label>}
            <Input
              value={row.key}
              placeholder={keyPlaceholder}
              onChange={(e) => {
                const next = [...rows];
                next[idx] = { ...next[idx], key: e.target.value };
                setRows(next);
              }}
              className="font-mono text-[12px]"
              autoComplete="off"
            />
          </div>
          <div>
            {idx === 0 && <Label>Value</Label>}
            <Input
              type="password"
              value={row.value}
              placeholder={valuePlaceholder}
              onChange={(e) => {
                const next = [...rows];
                next[idx] = { ...next[idx], value: e.target.value };
                setRows(next);
              }}
              className="font-mono text-[12px]"
              autoComplete="off"
            />
          </div>
          <button
            type="button"
            onClick={() => setRows(rows.filter((_, i) => i !== idx))}
            className="border border-hairline px-3 py-2 font-mono text-[11px] text-slate hover:border-ink hover:text-ink"
            aria-label={`Remove header ${row.key || idx + 1}`}
          >
            x
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={() => setRows([...rows, { key: newRowKey, value: "" }])}
        className="border border-dashed border-hairline px-4 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-slate hover:border-ink hover:text-ink"
      >
        + Add header
      </button>
    </div>
  );
}
