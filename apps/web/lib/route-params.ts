"use client";

/**
 * Read a single path segment from a pathname produced by usePathname().
 * Under static export, dynamic pages are pre-rendered as a "_" placeholder
 * shell and served for the real URL via a Cloudflare 200-rewrite, so the
 * identifier must be read from the live URL at runtime — never from the
 * build-time `params` prop (which is "_").
 *
 * Index is the position in "/a/b/c".split("/") === ["", "a", "b", "c"].
 */
export function pathSegment(pathname: string, index: number): string {
  return pathname.split("/")[index] ?? "";
}
