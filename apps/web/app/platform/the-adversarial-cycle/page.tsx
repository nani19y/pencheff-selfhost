import Link from "next/link";
import { LandingNav } from "@/components/landing-nav";
import { JsonLd } from "@/components/json-ld";
import "@/styles/landing.css";
import { createMetadata } from "@/lib/seo";
import {
  breadcrumbJsonLd,
  graphJsonLd,
  webPageJsonLd,
} from "@/lib/structured-data";
import { absoluteUrl } from "@/lib/seo";

const DESCRIPTION =
  "The Adversarial Cycle is Pencheff's five-phase assessment methodology: Reconnaissance, Surface Mapping, Probing, Verification, and Exploit Chaining — each phase building on the last to produce reproducible, evidence-backed findings.";

export const metadata = createMetadata({
  title: "The Adversarial Cycle",
  description: DESCRIPTION,
  path: "/platform/the-adversarial-cycle",
});

const PHASES = [
  {
    position: 1,
    name: "Reconnaissance",
    text: "Passive enumeration of the target's attack surface: subdomains, DNS records, certificate transparency logs, public artefacts, and technology fingerprinting — before a single active probe is sent.",
  },
  {
    position: 2,
    name: "Surface Mapping",
    text: "Authenticated and unauthenticated crawls expand the recon baseline into a full endpoint inventory — API routes, parameters, authentication flows, session tokens, and application-specific logic paths.",
  },
  {
    position: 3,
    name: "Probing",
    text: "Forty-nine instruments are fired against the mapped surface covering injection classes, access control, OAuth and JWT abuse, cloud metadata exposure, business-logic flaws, and client-side vulnerabilities.",
  },
  {
    position: 4,
    name: "Verification",
    text: "Every candidate finding is re-fired with crafted payloads. HTTP request and response evidence is captured and preserved. False positives are discarded before a finding is promoted to the results stream.",
  },
  {
    position: 5,
    name: "Exploit Chaining",
    text: "Individual verified findings are composed into multi-step attack paths — SSRF into cloud metadata credential theft, XSS into session hijacking, IDOR into privilege escalation — to demonstrate real-world blast radius.",
  },
];

const howToJsonLd = {
  "@type": "HowTo",
  "@id": absoluteUrl("/platform/the-adversarial-cycle#howto"),
  name: "The Adversarial Cycle",
  description: DESCRIPTION,
  totalTime: "PT2H",
  step: PHASES.map((phase) => ({
    "@type": "HowToStep",
    position: phase.position,
    name: phase.name,
    text: phase.text,
  })),
};

export default function AdversarialCyclePage() {
  return (
    <div className="landing-root">
      <LandingNav />
      <JsonLd
        data={graphJsonLd([
          webPageJsonLd({
            name: "The Adversarial Cycle | Pencheff",
            description: DESCRIPTION,
            path: "/platform/the-adversarial-cycle",
          }),
          breadcrumbJsonLd([
            { name: "Home", path: "/" },
            { name: "Platform", path: "/platform/overview" },
            { name: "The Adversarial Cycle", path: "/platform/the-adversarial-cycle" },
          ]),
          howToJsonLd,
        ])}
      />

      <main className="lp-article">
        <div className="lp-container">
          <header className="lp-article-head lp-article-grid">
            <div className="lp-article-copy">
              <p className="lp-eyebrow">Platform · Methodology</p>
              <h1>The Adversarial Cycle</h1>
              <p>
                Every Pencheff engagement follows five ordered phases —
                Reconnaissance, Surface Mapping, Probing, Verification, and
                Exploit Chaining — building from passive enumeration to
                evidence-backed findings and demonstrated attack chains.
              </p>
              <div className="lp-article-cta">
                <Link href="/signup" className="lp-btn lp-btn-arrow">
                  Run a free assessment
                </Link>
                <Link href="/platform/methodology-v4-2" className="lp-btn lp-btn-ghost">
                  Read the full methodology
                </Link>
              </div>
            </div>
          </header>

          <div className="lp-article-body">
            <div className="lp-article-sections">
              {PHASES.map((phase) => (
                <div className="lp-article-section" key={phase.position}>
                  <h2>
                    {phase.position}. {phase.name}
                  </h2>
                  <div className="lp-article-section-body">
                    <p>{phase.text}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
