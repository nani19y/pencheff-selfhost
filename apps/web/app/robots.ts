import type { MetadataRoute } from "next";
import { SITE_URL, absoluteUrl } from "@/lib/seo";

const PRIVATE_PREFIXES = [
  // NOTE: no "/api/" — the API moved to api.pencheff.com; there is no /api on
  // these Pages hosts. Listing it here only advertised a phantom path to
  // crawlers/DAST scanners (which probe robots Disallow entries).
  "/advisories/",
  "/assets/",
  "/billing/",
  "/dashboard/",
  "/dependencies/",
  "/engagements/",
  "/findings/",
  "/integrations/",
  "/invite/",
  "/observability/",
  "/onboarding/",
  "/org/",
  "/repos/",
  "/sbom/",
  "/scans/",
  "/schedules/",
  "/search/",
  "/settings/",
  "/targets/",
  "/workspaces/",
];

const AI_CRAWLERS = [
  "GPTBot",
  "ChatGPT-User",
  "ClaudeBot",
  "Claude-Web",
  "anthropic-ai",
  "Amazonbot",
  "PerplexityBot",
  "Applebot-Extended",
  "Bytespider",
  "cohere-ai",
  "GoogleOther",
  "Google-Extended",
  "CCBot",
];

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      // Explicitly allow AI crawlers to index marketing content for GEO/AEO
      ...AI_CRAWLERS.map((userAgent) => ({
        userAgent,
        allow: "/",
        disallow: PRIVATE_PREFIXES,
      })),
      {
        userAgent: "*",
        allow: "/",
        disallow: PRIVATE_PREFIXES,
      },
    ],
    sitemap: absoluteUrl("/sitemap.xml"),
    host: SITE_URL.origin,
  };
}

export const dynamic = "force-static";
