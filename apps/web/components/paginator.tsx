"use client";

import { Button } from "@/components/brutal";

/**
 * Editorial-style paginator. Renders an inline-flex pill so it can sit on
 * the right edge of a search row without needing its own line. Always
 * renders — including for single-page result sets, where Prev/Next are
 * disabled and only one page button is shown.
 *
 * Callers should still skip rendering this when there is *no* data at all
 * (e.g. `data.length === 0`) — a paginator over an empty list is noise.
 */
export function Paginator({
  page,
  pageCount,
  onChange,
}: {
  page: number;
  pageCount: number;
  onChange: (n: number) => void;
}) {
  const window = pageWindow(page, pageCount);
  return (
    <nav
      aria-label="Pagination"
      className="inline-flex items-center gap-2 flex-wrap"
    >
      <span className="font-mono text-[11px] text-mist tracking-[0.04em] mr-1">
        Page {page} of {pageCount}
      </span>
      <Button
        variant="lime"
        className="text-[12px] px-3 py-1.5 disabled:opacity-40"
        onClick={() => onChange(Math.max(1, page - 1))}
        disabled={page === 1}
      >
        ‹ Prev
      </Button>
      {window.map((n, i) =>
        n === "…" ? (
          <span
            key={`gap-${i}`}
            className="font-mono text-[12px] text-mist px-1"
            aria-hidden
          >
            …
          </span>
        ) : (
          <button
            key={n}
            type="button"
            onClick={() => onChange(n)}
            aria-current={n === page ? "page" : undefined}
            className={
              "min-w-[34px] h-[32px] rounded-sm font-mono text-[12px] tracking-[0.04em] transition-colors " +
              (n === page
                ? "bg-ink text-paper border border-ink"
                : "bg-paper text-graphite border border-hairline hover:border-ink hover:text-ink")
            }
          >
            {n}
          </button>
        )
      )}
      <Button
        variant="lime"
        className="text-[12px] px-3 py-1.5 disabled:opacity-40"
        onClick={() => onChange(Math.min(pageCount, page + 1))}
        disabled={page === pageCount}
      >
        Next ›
      </Button>
    </nav>
  );
}

/**
 * Build a compact page-number window with ellipses for large totals.
 * - ≤7 pages: every number.
 * - >7: 1 … (page-1, page, page+1) … N, with edges clamped.
 */
export function pageWindow(page: number, total: number): (number | "…")[] {
  if (total <= 7) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }
  const out: (number | "…")[] = [1];
  const start = Math.max(2, page - 1);
  const end = Math.min(total - 1, page + 1);
  if (start > 2) out.push("…");
  for (let i = start; i <= end; i++) out.push(i);
  if (end < total - 1) out.push("…");
  out.push(total);
  return out;
}
