import type { Metadata } from "next";

export const SITE_NAME = "Pencheff";
export const DEFAULT_SITE_URL = "https://pencheff.com";
export const DEFAULT_TITLE =
  "Pencheff — The open-source, all-in-one security platform";
export const DEFAULT_DESCRIPTION =
  "The open-source, all-in-one security platform. DAST, SAST, VAPT, API security, CNAPP " +
  "(KSPM/KIEM/CWPP/ASPM), AI red teaming + AI-SPM, SBOM, IaC, and compliance " +
  "(OWASP / PCI-DSS / SOC 2 / ISO 27001 / NIST / HIPAA) — one workflow, " +
  "audit-grade evidence. Free, forever, and self-hostable under the GNU AGPL-3.0 licence.";

export const SEO_KEYWORDS = [
  "Pencheff",
  "open source security platform",
  "free security platform",
  "open source DAST",
  "open source SAST",
  "self-hosted security platform",
  "AGPL-3.0 licensed security tool",
  "all-in-one security platform",
  "unified security platform",
  "DAST",
  "SAST",
  "VAPT",
  "penetration testing",
  "application security",
  "API security testing",
  "CNAPP",
  "KSPM",
  "ASPM",
  "AI-SPM",
  "LLM red team",
  "AI security testing",
  "SCA",
  "SBOM",
  "IaC scanning",
  "OWASP Top 10",
  "SOC 2 security evidence",
  "security compliance reports",
];

export const DEFAULT_OG_IMAGE = {
  url: "/opengraph-image",
  width: 1200,
  height: 630,
  alt: "Pencheff — the all-in-one security platform",
};

function normalizeSiteUrl(value: string | undefined) {
  const raw = (value || DEFAULT_SITE_URL).replace(/\/+$/, "");
  try {
    return new URL(raw);
  } catch {
    return new URL(DEFAULT_SITE_URL);
  }
}

export const SITE_URL = normalizeSiteUrl(process.env.NEXT_PUBLIC_SITE_URL);

export function absoluteUrl(path = "/") {
  return new URL(path, SITE_URL).toString();
}

export function fullTitle(title?: string) {
  if (!title || title === DEFAULT_TITLE) return DEFAULT_TITLE;
  return title.includes(SITE_NAME) ? title : `${title} | ${SITE_NAME}`;
}

export const indexableRobots: Metadata["robots"] = {
  index: true,
  follow: true,
  googleBot: {
    index: true,
    follow: true,
    "max-video-preview": -1,
    "max-image-preview": "large",
    "max-snippet": -1,
  },
};

export const noIndexRobots: Metadata["robots"] = {
  index: false,
  follow: false,
  googleBot: {
    index: false,
    follow: false,
    noimageindex: true,
  },
};

type CreateMetadataOptions = {
  title?: string;
  description?: string;
  path?: string;
  noIndex?: boolean;
  image?: typeof DEFAULT_OG_IMAGE;
  keywords?: string[];
};

export function createMetadata({
  title = DEFAULT_TITLE,
  description = DEFAULT_DESCRIPTION,
  path = "/",
  noIndex = false,
  image = DEFAULT_OG_IMAGE,
  keywords = SEO_KEYWORDS,
}: CreateMetadataOptions = {}): Metadata {
  const resolvedTitle = fullTitle(title);

  return {
    title,
    description,
    keywords,
    alternates: {
      canonical: path,
    },
    robots: noIndex ? noIndexRobots : indexableRobots,
    openGraph: {
      type: "website",
      siteName: SITE_NAME,
      locale: "en_US",
      title: resolvedTitle,
      description,
      url: path,
      images: [image],
    },
    twitter: {
      card: "summary_large_image",
      title: resolvedTitle,
      description,
      images: [image.url],
    },
  };
}

export const privateRouteMetadata: Metadata = {
  robots: noIndexRobots,
};

export const authRouteMetadata = (
  title: string,
  description: string,
  path: string,
) =>
  createMetadata({
    title,
    description,
    path,
    noIndex: true,
  });
