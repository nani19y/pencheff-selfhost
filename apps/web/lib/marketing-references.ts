export type ExternalRef = { name: string; url: string };

// Outbound links to authoritative sources, keyed by "menuSlug:pageSlug".
// Rendered as a "References" section in MarketingDetailPage to signal
// source citation to AI engines and auditors.
export const MARKETING_REFERENCES: Record<string, ExternalRef[]> = {
  "capabilities:android-app-security-testing": [
    {
      name: "OWASP MASVS (Mobile App Security Verification Standard)",
      url: "https://mas.owasp.org/MASVS/",
    },
    {
      name: "OWASP MASTG (Mobile App Security Testing Guide)",
      url: "https://mas.owasp.org/MASTG/",
    },
    {
      name: "OWASP Mobile Top 10",
      url: "https://owasp.org/www-project-mobile-top-10/",
    },
    {
      name: "MobSF (Mobile Security Framework)",
      url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
    },
  ],
  "capabilities:ios-app-security-testing": [
    {
      name: "OWASP MASVS (Mobile App Security Verification Standard)",
      url: "https://mas.owasp.org/MASVS/",
    },
    {
      name: "OWASP MASTG (Mobile App Security Testing Guide)",
      url: "https://mas.owasp.org/MASTG/",
    },
    {
      name: "Apple App Transport Security",
      url: "https://developer.apple.com/documentation/security/preventing-insecure-network-connections",
    },
    {
      name: "OWASP Mobile Top 10",
      url: "https://owasp.org/www-project-mobile-top-10/",
    },
  ],
  "capabilities:browser-extension-security-testing": [
    {
      name: "Chrome Extensions — Permissions reference",
      url: "https://developer.chrome.com/docs/extensions/reference/permissions-list",
    },
    {
      name: "Mozilla addons-linter",
      url: "https://github.com/mozilla/addons-linter",
    },
    {
      name: "Chrome Manifest V3 migration",
      url: "https://developer.chrome.com/docs/extensions/develop/migrate",
    },
    { name: "OWASP Top 10 (2021)", url: "https://owasp.org/Top10/" },
  ],
  "capabilities:desktop-app-security-testing": [
    {
      name: "Electron Security Checklist",
      url: "https://www.electronjs.org/docs/latest/tutorial/security",
    },
    {
      name: "Electron Fuses",
      url: "https://www.electronjs.org/docs/latest/tutorial/fuses",
    },
    {
      name: "OWASP Dependency-Check",
      url: "https://owasp.org/www-project-dependency-check/",
    },
    { name: "OWASP Top 10 (2021)", url: "https://owasp.org/Top10/" },
  ],
  "capabilities:firmware-security-testing": [
    {
      name: "OWASP Firmware Security Testing Methodology (FSTM)",
      url: "https://github.com/scriptingxss/owasp-fstm",
    },
    { name: "binwalk", url: "https://github.com/ReFirmLabs/binwalk" },
    {
      name: "OWASP IoT Top 10",
      url: "https://owasp.org/www-project-internet-of-things/",
    },
    {
      name: "CWE-798: Use of Hard-coded Credentials",
      url: "https://cwe.mitre.org/data/definitions/798.html",
    },
  ],
  "capabilities:iot-device-security-testing": [
    {
      name: "OWASP IoT Top 10",
      url: "https://owasp.org/www-project-internet-of-things/",
    },
    {
      name: "OWASP Firmware Security Testing Methodology (FSTM)",
      url: "https://github.com/scriptingxss/owasp-fstm",
    },
    {
      name: "NIST IR 8259 (IoT device cybersecurity)",
      url: "https://csrc.nist.gov/pubs/ir/8259/final",
    },
    {
      name: "ENISA Baseline Security Recommendations for IoT",
      url: "https://www.enisa.europa.eu/publications/baseline-security-recommendations-for-iot",
    },
  ],
  "capabilities:ot-ics-scada-security-testing": [
    {
      name: "NIST SP 800-82 (Guide to OT Security)",
      url: "https://csrc.nist.gov/pubs/sp/800/82/r3/final",
    },
    {
      name: "MITRE ATT&CK for ICS",
      url: "https://attack.mitre.org/matrices/ics/",
    },
    {
      name: "OWASP Firmware Security Testing Methodology (FSTM)",
      url: "https://github.com/scriptingxss/owasp-fstm",
    },
    {
      name: "ISA/IEC 62443",
      url: "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards",
    },
  ],

  "platform:methodology-v4-2": [
    { name: "OWASP Top 10 (2021)", url: "https://owasp.org/Top10/" },
    {
      name: "NIST SP 800-53 Rev 5",
      url: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    },
    { name: "MITRE ATT&CK", url: "https://attack.mitre.org/" },
    {
      name: "ISO/IEC 27001:2022",
      url: "https://www.iso.org/standard/82875.html",
    },
    {
      name: "PCI DSS 4.0",
      url: "https://www.pcisecuritystandards.org/document_library/?category=pcidss&document=pci_dss",
    },
  ],

  "ai-security:owasp-llm-top-10": [
    {
      name: "OWASP LLM Top 10 (2025)",
      url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    { name: "MITRE ATLAS", url: "https://atlas.mitre.org/" },
    {
      name: "NIST AI Risk Management Framework",
      url: "https://www.nist.gov/artificial-intelligence/nist-ai-rmf",
    },
    { name: "EU AI Act", url: "https://artificialintelligenceact.eu/" },
  ],

  "platform:letter-grade": [
    { name: "OWASP Top 10 (2021)", url: "https://owasp.org/Top10/" },
    {
      name: "NIST SP 800-53 Rev 5",
      url: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    },
    {
      name: "ISO/IEC 27001:2022",
      url: "https://www.iso.org/standard/82875.html",
    },
  ],

  "platform:sca-and-sbom": [
    {
      name: "OSV.dev (Open Source Vulnerability database)",
      url: "https://osv.dev/",
    },
    {
      name: "NVD (National Vulnerability Database)",
      url: "https://nvd.nist.gov/",
    },
    {
      name: "CISA Known Exploited Vulnerabilities (KEV)",
      url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    },
    { name: "GitHub Advisory Database", url: "https://github.com/advisories" },
  ],

  "platform:web-dast": [
    { name: "OWASP Top 10 (2021)", url: "https://owasp.org/Top10/" },
    {
      name: "CWE/SANS Top 25 Most Dangerous Software Weaknesses",
      url: "https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html",
    },
    {
      name: "OWASP Testing Guide v4.2",
      url: "https://owasp.org/www-project-web-security-testing-guide/",
    },
  ],

  "company:trust-and-compliance": [
    {
      name: "SOC 2 Trust Services Criteria",
      url: "https://www.aicpa.org/resources/article/soc-2-reporting-on-an-examination-of-controls-at-a-service-organization-relevant-to-security",
    },
    {
      name: "ISO/IEC 27001:2022",
      url: "https://www.iso.org/standard/82875.html",
    },
    {
      name: "GDPR (General Data Protection Regulation)",
      url: "https://gdpr.eu/",
    },
  ],

  "platform:llm-red-team": [
    {
      name: "OWASP LLM Top 10 (2025)",
      url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    { name: "MITRE ATLAS", url: "https://atlas.mitre.org/" },
    {
      name: "NIST AI Risk Management Framework",
      url: "https://www.nist.gov/artificial-intelligence/nist-ai-rmf",
    },
  ],

  "platform:sast-and-secrets": [
    {
      name: "CWE/SANS Top 25 Most Dangerous Software Weaknesses",
      url: "https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html",
    },
    {
      name: "NIST SP 800-53 Rev 5",
      url: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    },
    { name: "GitHub Advisory Database", url: "https://github.com/advisories" },
  ],

  "platform:iac-and-containers": [
    {
      name: "CIS Benchmarks",
      url: "https://www.cisecurity.org/cis-benchmarks",
    },
    {
      name: "NIST SP 800-190 (Container Security)",
      url: "https://csrc.nist.gov/publications/detail/sp/800-190/final",
    },
    { name: "OWASP Top 10 (2021)", url: "https://owasp.org/Top10/" },
  ],

  "platform:audit-and-compliance": [
    { name: "OWASP Top 10 (2021)", url: "https://owasp.org/Top10/" },
    {
      name: "NIST SP 800-53 Rev 5",
      url: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    },
    {
      name: "ISO/IEC 27001:2022",
      url: "https://www.iso.org/standard/82875.html",
    },
    {
      name: "PCI DSS 4.0",
      url: "https://www.pcisecuritystandards.org/document_library/?category=pcidss&document=pci_dss",
    },
  ],

  "capabilities:injection-coverage": [
    {
      name: "OWASP Top 10 A03:2021 — Injection",
      url: "https://owasp.org/Top10/A03_2021-Injection/",
    },
    {
      name: "CWE-89: SQL Injection",
      url: "https://cwe.mitre.org/data/definitions/89.html",
    },
    {
      name: "PortSwigger Web Security Academy — Injection",
      url: "https://portswigger.net/web-security/injection",
    },
  ],

  "ai-security:sentry-runtime-guardrail": [
    {
      name: "OWASP LLM Top 10 (2025)",
      url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    {
      name: "NIST AI Risk Management Framework",
      url: "https://www.nist.gov/artificial-intelligence/nist-ai-rmf",
    },
    { name: "MITRE ATLAS", url: "https://atlas.mitre.org/" },
  ],

  "ai-security:llm-red-team": [
    {
      name: "OWASP LLM Top 10 (2025)",
      url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    { name: "MITRE ATLAS", url: "https://atlas.mitre.org/" },
    {
      name: "NIST AI Risk Management Framework",
      url: "https://www.nist.gov/artificial-intelligence/nist-ai-rmf",
    },
    { name: "EU AI Act", url: "https://artificialintelligenceact.eu/" },
  ],

  "ai-security:ai-agents": [
    {
      name: "OWASP LLM Top 10 (2025)",
      url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    { name: "MITRE ATLAS", url: "https://atlas.mitre.org/" },
    {
      name: "NIST AI Risk Management Framework",
      url: "https://www.nist.gov/artificial-intelligence/nist-ai-rmf",
    },
  ],

  "solutions:ci-cd-gates": [
    { name: "OWASP Top 10 (2021)", url: "https://owasp.org/Top10/" },
    {
      name: "NIST SP 800-53 Rev 5 — SA-11 (Developer Testing)",
      url: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    },
    {
      name: "CIS Software Supply Chain Security Guide",
      url: "https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide",
    },
  ],
};
