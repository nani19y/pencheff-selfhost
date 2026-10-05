"use client";

/**
 * Reusable Markdown viewer.
 *
 * - GFM tables / strikethrough / task lists via remark-gfm
 * - Syntax highlighting on fenced code blocks via rehype-highlight
 * - Mermaid diagrams: ` ```mermaid ` blocks render as SVG via mermaid.js
 *   on the client (the library is dynamic-imported so it never enters
 *   the SSR bundle)
 *
 * Used to fix the "literal `##` and pipe characters in the UI" bug
 * where finding descriptions, executive summaries, and report bodies
 * were being rendered inside a plain `<p>`.
 */

import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeHighlight from "rehype-highlight";
import { cn } from "@/lib/cn";

import "highlight.js/styles/atom-one-light.css";

type Props = {
  /** Raw markdown source. */
  children: string;
  /** Wrapping class — useful for prose width / max-w constraints. */
  className?: string;
  /** When false, suppress mermaid rendering (e.g. inside a tiny preview). */
  enableMermaid?: boolean;
};

export function Markdown({
  children,
  className,
  enableMermaid = true,
}: Props): ReactNode {
  const text = (children ?? "").trim();
  if (!text) return null;

  return (
    <div
      className={cn(
        // Editorial typography close to the rest of the app — Tailwind's
        // ``prose`` plugin isn't installed here, so this hand-rolls the
        // bits we actually use (headings, lists, tables, code, blockquote).
        // Colors use CSS vars (--ink/--vellum/--hairline/--graphite/--slate)
        // rather than baked palette classes: these arbitrary-variant selectors
        // compile to escaped selectors the globals dark overrides can't reach,
        // so var-backed values are what make dark mode adapt here.
        "max-w-[72ch] text-[14px] leading-[1.7] text-[color:var(--graphite)]",
        "[&>h1]:text-[22px] [&>h1]:font-bold [&>h1]:mt-6 [&>h1]:mb-3 [&>h1]:text-[color:var(--ink)]",
        "[&>h2]:text-[18px] [&>h2]:font-bold [&>h2]:mt-5 [&>h2]:mb-2 [&>h2]:text-[color:var(--ink)]",
        "[&>h3]:text-[15px] [&>h3]:font-bold [&>h3]:mt-4 [&>h3]:mb-2 [&>h3]:text-[color:var(--ink)]",
        "[&>p]:my-3",
        "[&>ul]:my-3 [&>ul]:pl-6 [&>ul>li]:list-disc",
        "[&>ol]:my-3 [&>ol]:pl-6 [&>ol>li]:list-decimal",
        "[&_li]:my-1",
        "[&_a]:text-[color:var(--ink)] [&_a]:underline [&_a:hover]:text-[color:var(--graphite)]",
        "[&_blockquote]:border-l-4 [&_blockquote]:border-[color:var(--hairline)] [&_blockquote]:pl-3 [&_blockquote]:italic [&_blockquote]:text-[color:var(--slate)]",
        "[&_table]:my-3 [&_table]:w-full [&_table]:border-collapse [&_table]:text-[13px]",
        "[&_th]:border [&_th]:border-[color:var(--hairline)] [&_th]:bg-[var(--vellum)] [&_th]:px-2 [&_th]:py-1 [&_th]:text-left",
        "[&_td]:border [&_td]:border-[color:var(--hairline)] [&_td]:px-2 [&_td]:py-1",
        "[&_code]:bg-[var(--vellum)] [&_code]:px-1 [&_code]:py-[1px] [&_code]:rounded [&_code]:font-mono [&_code]:text-[12.5px]",
        "[&_pre]:bg-[var(--vellum)] [&_pre]:border [&_pre]:border-[color:var(--hairline)] [&_pre]:rounded [&_pre]:p-3 [&_pre]:my-3 [&_pre]:overflow-x-auto",
        "[&_pre_code]:bg-transparent [&_pre_code]:p-0",
        "[&_hr]:my-5 [&_hr]:border-[color:var(--hairline)]",
        className,
      )}
    >
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeHighlight]}
        components={{
          // Hijack fenced code blocks: ```mermaid renders as an SVG
          // diagram, everything else falls through to rehype-highlight.
          // The cast keeps the signature compatible with react-markdown's
          // generated component types without forcing us to import them.
          code(props: {
            className?: string;
            children?: ReactNode;
            inline?: boolean;
          }) {
            const {
              className: codeClass,
              children: codeChildren,
              inline,
            } = props;
            const match = /language-(\w+)/.exec(codeClass || "");
            if (!inline && enableMermaid && match && match[1] === "mermaid") {
              return <Mermaid chart={String(codeChildren ?? "").trim()} />;
            }
            return <code className={codeClass}>{codeChildren}</code>;
          },
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}

/**
 * Mermaid diagram renderer. Loads the library on the client only and
 * regenerates the SVG when the chart source changes.
 */
function Mermaid({ chart }: { chart: string }): ReactNode {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [error, setError] = useState<string | null>(null);
  const reactId = useId();
  // mermaid requires DOM ids that match a strict CSS-class regex; the
  // ``useId`` colons trip its parser, so we sanitize.
  const id = `mermaid-${reactId.replace(/[^a-zA-Z0-9_-]/g, "")}`;

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const mermaid = (await import("mermaid")).default;
        mermaid.initialize({
          startOnLoad: false,
          securityLevel: "strict",
          theme: "neutral",
          fontFamily: "inherit",
        });
        const { svg } = await mermaid.render(id, chart);
        if (cancelled) return;
        if (containerRef.current) {
          containerRef.current.innerHTML = svg;
        }
        setError(null);
      } catch (e: unknown) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [chart, id]);

  if (error) {
    return (
      <div className="my-3 border border-hairline bg-vellum p-3 font-mono text-[12px] text-graphite">
        <p className="font-bold mb-1">Diagram failed to render</p>
        <pre className="whitespace-pre-wrap text-[11px]">{error}</pre>
        <details className="mt-2">
          <summary className="cursor-pointer">Source</summary>
          <pre className="whitespace-pre-wrap text-[11px] mt-1">{chart}</pre>
        </details>
      </div>
    );
  }
  return <div ref={containerRef} className="my-3 overflow-x-auto" />;
}
