import {
  DEFAULT_DESCRIPTION,
  DEFAULT_TITLE,
  SITE_NAME,
  absoluteUrl,
} from "@/lib/seo";

export type JsonLdValue =
  | string
  | number
  | boolean
  | null
  | JsonLdObject
  | JsonLdValue[];

export type JsonLdObject = {
  [key: string]: JsonLdValue;
};

export type BreadcrumbItem = {
  name: string;
  path: string;
};

export function organizationJsonLd(): JsonLdObject {
  return {
    "@type": "Organization",
    "@id": absoluteUrl("/#organization"),
    name: SITE_NAME,
    url: absoluteUrl("/"),
    logo: {
      "@type": "ImageObject",
      url: absoluteUrl("/logo.png"),
      width: 512,
      height: 512,
    },
    description:
      "Adversarial application security assessments with audit-grade evidence — DAST, SAST, SCA, IaC, and LLM red team in a single platform.",
    foundingDate: "2025",
    areaServed: "Worldwide",
    knowsAbout: [
      "Penetration Testing",
      "Application Security",
      "DAST",
      "SAST",
      "Software Composition Analysis",
      "LLM Red Teaming",
      "AI Security",
      "OWASP Top 10",
      "SOC 2 Compliance",
      "Vulnerability Management",
      "Open Source Software",
    ],
    sameAs: [
      "https://github.com/Magadha-IG/pencheff-ce",
      "https://github.com/Magadha-IG",
    ],
    contactPoint: [
      {
        "@type": "ContactPoint",
        contactType: "customer support",
        email: "hello@pencheff.com",
        url: absoluteUrl("/company/contact"),
        availableLanguage: "English",
        areaServed: "Worldwide",
      },
      {
        "@type": "ContactPoint",
        contactType: "technical support",
        email: "security@pencheff.com",
        url: absoluteUrl("/company/contact"),
        availableLanguage: "English",
        areaServed: "Worldwide",
      },
    ],
  };
}

export function websiteJsonLd(): JsonLdObject {
  return {
    "@type": "WebSite",
    "@id": absoluteUrl("/#website"),
    name: SITE_NAME,
    url: absoluteUrl("/"),
    description: DEFAULT_DESCRIPTION,
    publisher: { "@id": absoluteUrl("/#organization") },
  };
}

// Declares the primary site sections for crawlers. NOTE: Google generates
// sitelinks algorithmically (authority + brand-search volume + time) and does
// NOT take them from markup — this is a clean structure signal, not a control.
export function siteNavigationJsonLd(): JsonLdObject {
  const items: { name: string; path: string }[] = [
    { name: "Platform", path: "/platform/overview" },
    { name: "Capabilities", path: "/capabilities/injection-coverage" },
    { name: "AI Security", path: "/ai-security/owasp-llm-top-10" },
    { name: "Methodology", path: "/platform/methodology-v4-2" },
    { name: "Documentation", path: "/resources/user-documentation" },
    { name: "Repository (AGPL-3.0)", path: "/resources/repository" },
    { name: "Company", path: "/company/our-discipline" },
    { name: "Enquiries", path: "/enquiries" },
  ];
  return {
    "@type": "ItemList",
    "@id": absoluteUrl("/#site-navigation"),
    name: `${SITE_NAME} primary navigation`,
    itemListElement: items.map((it, i) => ({
      "@type": "SiteNavigationElement",
      position: i + 1,
      name: it.name,
      url: absoluteUrl(it.path),
    })),
  };
}

export function softwareApplicationJsonLd(): JsonLdObject {
  return {
    "@type": "SoftwareApplication",
    "@id": absoluteUrl("/#software"),
    name: SITE_NAME,
    applicationCategory: "SecurityApplication",
    operatingSystem: "Web",
    url: absoluteUrl("/"),
    description: DEFAULT_DESCRIPTION,
    isAccessibleForFree: true,
    license: "https://opensource.org/licenses/MIT",
    keywords:
      "DAST, SAST, VAPT, penetration testing, API security testing, " +
      "LLM red teaming, AI security, AI runtime security, LLM guardrails, " +
      "AI agent firewall, prompt injection detection, AI gateway, " +
      "LLM observability, agent memory scanner, CNAPP, SCA, SBOM, IaC scanning, " +
      "open source security platform, vulnerability scanning, compliance",
    featureList: [
      "Dynamic Application Security Testing (DAST)",
      "Static Application Security Testing (SAST)",
      "Penetration testing (VAPT)",
      "API security testing (REST, GraphQL, WebSockets)",
      "LLM / AI red teaming (OWASP LLM Top 10)",
      "AI runtime protection: guardrail proxy, agent firewall, prompt-injection detection",
      "LLM runtime traces (observability for live AI traffic)",
      "Agent memory / vector-store scanner (secrets at rest, memory poisoning)",
      "Cloud security posture (CNAPP: KSPM, KIEM, CWPP, ASPM)",
      "Software composition analysis (SCA) and SBOM",
      "Infrastructure-as-Code and container scanning",
      "Compliance mapping (OWASP, PCI-DSS, SOC 2, NIST, ISO 27001, HIPAA)",
    ],
    offers: {
      "@type": "Offer",
      price: "0",
      priceCurrency: "USD",
      availability: "https://schema.org/InStock",
      description: "Free and open source under the GNU AGPL-3.0 licence.",
    },
    publisher: { "@id": absoluteUrl("/#organization") },
  };
}

export function webPageJsonLd({
  name = DEFAULT_TITLE,
  description = DEFAULT_DESCRIPTION,
  path = "/",
  speakableSelectors,
}: {
  name?: string;
  description?: string;
  path?: string;
  speakableSelectors?: string[];
} = {}): JsonLdObject {
  const base: JsonLdObject = {
    "@type": "WebPage",
    "@id": absoluteUrl(`${path}#webpage`),
    name,
    description,
    url: absoluteUrl(path),
    isPartOf: { "@id": absoluteUrl("/#website") },
    publisher: { "@id": absoluteUrl("/#organization") },
  };
  if (speakableSelectors?.length) {
    base.speakable = {
      "@type": "SpeakableSpecification",
      cssSelector: speakableSelectors,
    };
  }
  return base;
}

export function breadcrumbJsonLd(items: BreadcrumbItem[]): JsonLdObject {
  return {
    "@type": "BreadcrumbList",
    itemListElement: items.map((item, index) => ({
      "@type": "ListItem",
      position: index + 1,
      name: item.name,
      item: absoluteUrl(item.path),
    })),
  };
}

export function faqJsonLd(
  items: Array<{ q: string; a: string }>,
): JsonLdObject {
  return {
    "@type": "FAQPage",
    mainEntity: items.map((item) => ({
      "@type": "Question",
      name: item.q,
      acceptedAnswer: {
        "@type": "Answer",
        text: item.a,
      },
    })),
  };
}

export function techArticleJsonLd({
  headline,
  description,
  path,
  datePublished,
  dateModified,
  about = [],
}: {
  headline: string;
  description: string;
  path: string;
  datePublished: string;
  dateModified?: string;
  about?: string[];
}): JsonLdObject {
  const article: JsonLdObject = {
    "@type": "TechArticle",
    "@id": absoluteUrl(`${path}#article`),
    headline,
    description,
    url: absoluteUrl(path),
    datePublished,
    dateModified: dateModified ?? datePublished,
    author: { "@id": absoluteUrl("/#founder") },
    publisher: { "@id": absoluteUrl("/#organization") },
    isPartOf: { "@id": absoluteUrl(`${path}#webpage`) },
  };
  if (about.length) {
    article.about = about.map((name) => ({ "@type": "Thing", name }));
  }
  return article;
}

export function graphJsonLd(items: JsonLdObject[]): JsonLdObject {
  return {
    "@context": "https://schema.org",
    "@graph": items,
  };
}
