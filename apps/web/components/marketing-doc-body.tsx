"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

// This body is authored docs content (apps/docs/pages/**); its root-relative
// links (/features/*, /reference/*, /tutorials/*, …) resolve on the docs site,
// not on the marketing host — left as-is they 404. Rewrite them to the docs
// origin so they behave like the page's "Documentation" links.
const DOCS_BASE =
  process.env.NEXT_PUBLIC_DOCS_URL ?? "https://docs.pencheff.com";

function resolveDocHref(href?: string): string | undefined {
  if (!href) return href;
  // Leave anchors, external links, and mailto/tel untouched.
  if (!href.startsWith("/")) return href;
  return `${DOCS_BASE}${href}`;
}

// The docs source is Nextra MDX, but this page renders it with plain
// react-markdown (no MDX runtime). MDX-only constructs — `import` lines and
// capitalised component tags like <Tabs>/<Tabs.Tab>/<Callout> — aren't valid
// Markdown, so react-markdown prints them verbatim. Down-convert them to plain
// Markdown so nothing JSX-shaped leaks onto the page.
function mdxToMarkdown(src: string): string {
  let s = src;
  // Drop MDX `import { … } from "…"` / `export …` statement lines.
  s = s.replace(/^[ \t]*(?:import|export)\s.*$/gm, "");
  // <Tabs items={["A","B"]}> … <Tabs.Tab>…</Tabs.Tab> … </Tabs>
  // → each tab body under a bold label taken from the items array.
  s = s.replace(
    /<Tabs\b[^>]*items=\{\[([^\]]*)\]\}[^>]*>([\s\S]*?)<\/Tabs>/g,
    (_m, itemsRaw: string, inner: string) => {
      const labels = Array.from(
        itemsRaw.matchAll(/"([^"]*)"|'([^']*)'/g),
        (m) => m[1] ?? m[2],
      );
      let i = 0;
      return inner
        .replace(/<Tabs\.Tab>/g, () => `\n\n**${labels[i++] ?? ""}**\n\n`)
        .replace(/<\/Tabs\.Tab>/g, "\n");
    },
  );
  // <Callout …>…</Callout> → keep the inner content, drop the wrapper.
  s = s.replace(/<Callout\b[^>]*>/g, "\n").replace(/<\/Callout>/g, "\n");
  // Strip any remaining capitalised (component) JSX tags — paired or
  // self-closing — while leaving normal lowercase HTML and content intact.
  s = s.replace(/<\/?[A-Z][A-Za-z0-9.]*(?:\s[^>]*?)?\/?>/g, "");
  return s;
}

export function MarketingDocBody({ markdown }: { markdown: string }) {
  return (
    <div className="detail-doc-prose">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: () => null,
          a: ({ href, children, ...props }) => {
            const resolved = resolveDocHref(href);
            const external = resolved !== href || /^https?:/.test(href ?? "");
            return (
              <a
                href={resolved}
                {...(external
                  ? { target: "_blank", rel: "noopener noreferrer" }
                  : {})}
                {...props}
              >
                {children}
              </a>
            );
          },
        }}
      >
        {mdxToMarkdown(markdown)}
      </ReactMarkdown>
    </div>
  );
}
