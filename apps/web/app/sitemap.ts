import type { MetadataRoute } from "next";
import { getMarketingTopics, isAliasTopic } from "@/lib/marketing-nav";
import { absoluteUrl } from "@/lib/seo";

// Paths that redirect to a canonical URL — exclude from sitemap to avoid
// duplicate content signals. See next.config.js for the redirect rules.
const REDIRECT_PATHS = new Set([
  "/support/case-studies",
  "/company/contact-us",
]);

// Placeholder pages with no real content yet — exclude until content ships.
const PLACEHOLDER_PATHS = new Set([
  "/company/careers",
  "/company/case-studies",
  "/company/newsroom",
  "/company/brand-press",
  "/support/overview",
]);

function daysAgo(n: number): Date {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
}

const STATIC_PUBLIC_ROUTES = [
  {
    path: "/",
    priority: 1,
    changeFrequency: "weekly" as const,
    lastModified: daysAgo(0),
  },
  {
    path: "/privacy",
    priority: 0.4,
    changeFrequency: "yearly" as const,
    lastModified: new Date("2025-06-01"),
  },
  {
    path: "/terms",
    priority: 0.4,
    changeFrequency: "yearly" as const,
    lastModified: new Date("2025-06-01"),
  },
  {
    path: "/company/contact",
    priority: 0.7,
    changeFrequency: "monthly" as const,
    lastModified: daysAgo(0),
  },
  {
    path: "/company/leadership",
    priority: 0.6,
    changeFrequency: "yearly" as const,
    lastModified: daysAgo(0),
  },
];

export default function sitemap(): MetadataRoute.Sitemap {
  const marketingRoutes = getMarketingTopics()
    .filter(
      (topic) =>
        // Skip alias topics — their auto-built path 301-redirects to the
        // canonical destination, so listing them here would re-introduce
        // the "Alternate page with proper canonical tag" indexing signal.
        !isAliasTopic(topic) &&
        !REDIRECT_PATHS.has(topic.href) &&
        !PLACEHOLDER_PATHS.has(topic.href) &&
        // The entire /support/* section duplicates content from other menus.
        !topic.href.startsWith("/support/"),
    )
    .map((topic) => ({
      path: topic.href,
      priority: topic.slug === "overview" ? 0.85 : 0.7,
      changeFrequency: "monthly" as const,
      lastModified: topic.slug === "overview" ? daysAgo(7) : daysAgo(21),
    }));

  const routes = [...STATIC_PUBLIC_ROUTES, ...marketingRoutes];
  const uniqueRoutes = Array.from(
    new Map(routes.map((route) => [route.path, route])).values(),
  );

  return uniqueRoutes.map((route) => ({
    url: absoluteUrl(route.path),
    lastModified: route.lastModified,
    changeFrequency: route.changeFrequency,
    priority: route.priority,
  }));
}

export const dynamic = "force-static";
