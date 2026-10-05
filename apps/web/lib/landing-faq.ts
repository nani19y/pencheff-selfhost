export type FaqItem = { q: string; a: string };

export const LANDING_FAQ: FaqItem[] = [
  {
    q: "Is Pencheff open source and free?",
    a: "Yes. Pencheff is free to use and fully open source under the GNU AGPL-3.0 licence. The entire platform is on GitHub and self-hostable as a Docker Compose stack - run it inside your own boundary with no licence fee, no seat limits, and no feature gating. There is nothing to pay and nothing locked behind a tier.",
  },
  {
    q: "Is this authorised?",
    a: "Pencheff is for applications you own or have been granted written permission to assess. It is an instrument of assurance, not a means of unauthorised access. Please direct it only at systems within your mandate.",
  },
  {
    q: "What constitutes a single assessment?",
    a: "One complete engagement against a target: reconnaissance, infrastructure, injection, client-side, authentication, authorisation, advanced web, API, business logic, cloud, file handling, websocket, subdomain takeover, and exploit chaining. Re-examination of individual findings is unlimited.",
  },
  {
    q: "How long does an assessment take?",
    a: "Quick profile: 2-5 minutes. Standard: 10-25 minutes. Deep: 30-90 minutes, contingent on application breadth.",
  },
  {
    q: "May these reports be used for SOC 2, PCI, or ISO audits?",
    a: "Yes. DOCX and PDF reports include evidence-backed mapping to OWASP Top 10 (2021), PCI-DSS 4.0, NIST 800-53, SOC 2 (CC6/CC7), ISO 27001:2022, and HIPAA Security Rule - accepted by auditors as evidentiary material.",
  },
  {
    q: "Is self-hosting supported?",
    a: "Yes. Pencheff is distributed as a Docker Compose stack under the GNU AGPL-3.0 licence. Refer to the repository documentation for installation.",
  },
  {
    q: "How are credentials handled?",
    a: "Credentials are encrypted at rest with Fernet (AES-128 in CBC mode with HMAC-SHA256). Removing a target removes its credentials immediately.",
  },
];
