export type FaqItem = { q: string; a: string };

// FAQs keyed by "menuSlug:pageSlug". These are injected into the
// MarketingDetailPage template as both visible HTML accordions and
// FAQPage JSON-LD for featured-snippet eligibility.
export const MARKETING_FAQS: Record<string, FaqItem[]> = {
  "capabilities:android-app-security-testing": [
    {
      q: "What is the best tool for Android APK security testing?",
      a: "Pencheff is an open-source security platform that performs static security analysis of Android APK and AAB files. You upload a build (by URL plus a SHA-256) and Pencheff decompiles it with apktool and jadx, then inspects the AndroidManifest, exported components, hardcoded secrets, weak cryptography, debuggable/allowBackup flags, and cleartext traffic — mapping every finding to OWASP MASVS and CWE. No device or emulator is required.",
    },
    {
      q: "Can Pencheff scan an APK without the source code?",
      a: "Yes. Pencheff analyzes the compiled APK directly — it decompiles the DEX bytecode, parses the manifest and resources, and sweeps the decompiled output for secrets and insecure patterns. You only provide the .apk or .aab artifact; source code is never needed.",
    },
    {
      q: "Does Android app testing with Pencheff need a device, emulator, or root?",
      a: "No. Pencheff's Android scanning is fully static. The uploaded app is analyzed as data inside an isolated container and is never installed or executed, so there is no device farm, emulator, or rooting requirement.",
    },
    {
      q: "Which Android vulnerabilities does Pencheff detect?",
      a: "Hardcoded secrets (AWS/Google/Firebase keys, tokens, private keys), weak crypto (DES/RC4/ECB, MD5/SHA-1, hardcoded keys), cleartext traffic and insecure network-security config, exported components missing permissions, debuggable and allowBackup misconfigurations, and outdated dependencies — aligned to the OWASP Mobile Application Security Verification Standard (MASVS) and OWASP Mobile Top 10.",
    },
  ],
  "capabilities:ios-app-security-testing": [
    {
      q: "What is the best tool for iOS app (IPA) security testing?",
      a: "Pencheff is an open-source security platform that statically analyzes iOS IPA files. Upload an .ipa and Pencheff parses Info.plist (App Transport Security), enumerates custom URL schemes, checks Mach-O binary protections (PIE, stack canary, encryption state), and sweeps for embedded secrets and vulnerable third-party SDKs — mapped to OWASP MASVS. It runs on Linux with no macOS or jailbroken device required.",
    },
    {
      q: "Can Pencheff test an iOS app without a Mac or a jailbroken iPhone?",
      a: "Yes. Pencheff's iOS analysis is static and runs entirely in a Linux container. It inspects the IPA's plists, resources, and Mach-O headers without booting iOS, so no macOS host, physical device, or jailbreak is needed.",
    },
    {
      q: "What are the limits of static iOS analysis?",
      a: "App Store IPAs are FairPlay-encrypted (cryptid=1), which hides the compiled code section from static analysis. Pencheff flags this in every report and still extracts everything from the unencrypted plists, resources, entitlements, and binary headers. For full code-level depth, submit a development/enterprise build.",
    },
    {
      q: "Which iOS issues does Pencheff detect?",
      a: "Insecure App Transport Security (NSAllowsArbitraryLoads/cleartext), deeplink-hijackable URL schemes, missing Mach-O hardening (no PIE/canary), embedded secrets, excessive privacy permissions, and known-vulnerable bundled SDKs — aligned to OWASP MASVS.",
    },
  ],
  "capabilities:browser-extension-security-testing": [
    {
      q: "What is the best tool to audit a browser extension for security?",
      a: "Pencheff is an open-source security platform that statically analyzes Chrome, Firefox, and Edge extensions (CRX and XPI). It scores dangerous permissions (debugger, cookies, <all_urls>, proxy), broad host access, weak content-security-policy (unsafe-eval/unsafe-inline), remote-code loading, DOM injection sinks (eval, innerHTML, document.write), broad externally_connectable, and hardcoded secrets — the analysis CRXcavator pioneered, extended with modern exfiltration and obfuscation detection.",
    },
    {
      q: "How does Pencheff analyze a Chrome extension?",
      a: "Upload the .crx/.xpi (Pencheff strips the CRX header and unpacks the ZIP), and it parses manifest.json for permission and CSP risk, scans the bundled JavaScript for dangerous sinks and remote-code loading, and sweeps for hardcoded credentials. Manifest V2 packages are flagged as a deprecated, weaker security model.",
    },
    {
      q: "Does Pencheff run the extension in a browser?",
      a: "No — extension analysis is fully static. Pencheff inspects the manifest, scripts, and resources as data; it never loads or runs the extension, so the scan is safe to run against any untrusted package.",
    },
  ],
  "capabilities:desktop-app-security-testing": [
    {
      q: "How do I check a desktop application (Electron, Java, .NET) for security issues?",
      a: "Pencheff is an open-source security platform that statically analyzes desktop application bundles. For Electron it flags insecure webPreferences (nodeIntegration, contextIsolation:false, sandbox:false, webSecurity:false), dangerous calls (eval, child_process, shell.openExternal), and outdated Electron versions; for Java/JAR, .NET, and Qt/native bundles it sweeps for embedded secrets and dependency risk. The binary is never executed.",
    },
    {
      q: "What is the best tool to audit an Electron app's security configuration?",
      a: "Pencheff unpacks the Electron bundle (including app.asar) and checks it against the Electron Security Checklist: nodeIntegration, contextIsolation, sandbox, webSecurity, allowRunningInsecureContent, dangerous IPC and shell usage, and the bundled Electron version's known CVEs — all statically, with no execution.",
    },
    {
      q: "Can Pencheff analyze a native desktop binary (PE/ELF/Mach-O)?",
      a: "Yes, with honest scope. For archive-based apps (Electron, JAR) Pencheff does full config and dependency analysis; for opaque native binaries it extracts printable strings and sweeps for embedded secrets, and clearly notes that decompiler-grade depth (checksec, capa, .NET/Java decompilation) is beyond this static pass.",
    },
  ],
  "capabilities:firmware-security-testing": [
    {
      q: "What is the best tool for firmware security analysis?",
      a: "Pencheff is an open-source security platform that statically analyzes firmware and embedded images. Upload a firmware image (by URL plus a SHA-256) and Pencheff identifies embedded filesystems and components (via binwalk), then sweeps for embedded private keys and certificates, default/hardcoded credentials, telnet/debug services, cleartext update endpoints, hardcoded secrets, and component-version banners for CVE matching. The firmware is never flashed or executed.",
    },
    {
      q: "Can Pencheff analyze firmware without the device?",
      a: "Yes — that's the point. Pencheff analyzes the firmware image as data in an isolated container; you never connect the physical device. Obtain the image from the vendor's update/download, an OTA capture, or a flash dump, then upload it by URL with its SHA-256.",
    },
    {
      q: "Which firmware vulnerabilities does Pencheff find?",
      a: "Embedded private keys (shared across every unit), hardcoded/default OS credentials, /etc/shadow hashes, telnet and debug backdoors, cleartext (MITM-able) update endpoints, hardcoded API keys, and outdated components (BusyBox, Dropbear, OpenSSL, lighttpd) matched against CVE feeds.",
    },
  ],
  "capabilities:iot-device-security-testing": [
    {
      q: "What is the best tool to test the security of an IoT device like a camera, drone, or robot vacuum?",
      a: "Pencheff statically analyzes the device's firmware. Download or dump the firmware for your camera, drone, robot vacuum, or router, upload it (by URL plus a SHA-256), and Pencheff finds default credentials, embedded keys and certificates, insecure services (telnet/debug), cleartext update channels, and vulnerable components — without ever touching the live device. Default credentials are the #1 IoT compromise vector (the Mirai botnet weaponized exactly this).",
    },
    {
      q: "Do I need to put my IoT device on the network to test it with Pencheff?",
      a: "No. Pencheff performs static firmware analysis — you upload the device's firmware image and Pencheff inspects it offline. There is no live network probing of the device, so it's safe to run and works for any device whose firmware you can obtain.",
    },
    {
      q: "How do I get my IoT device's firmware?",
      a: "Most consumer IoT firmware is downloadable from the vendor's support/update site, capturable from the device's OTA update request, or extractable from a flash dump. Once you have the .bin/.img (or a packed archive), register it as an IoT Device target with its SHA-256.",
    },
  ],
  "capabilities:ot-ics-scada-security-testing": [
    {
      q: "Can Pencheff test OT / ICS / SCADA systems safely?",
      a: "Pencheff analyzes OT/ICS/SCADA controller and PLC firmware (and config exports) statically — embedded keys, hardcoded credentials, insecure services, and vulnerable components. It deliberately does NOT perform active industrial-protocol probing (Modbus/DNP3/S7 writes, PLC interaction), because live testing of operational technology can disrupt physical processes. Static firmware review is the safe way to assess ICS device security.",
    },
    {
      q: "What does Pencheff check in PLC/controller firmware?",
      a: "The same firmware checks as any embedded image: embedded private keys and certificates, default/hardcoded credentials, telnet/debug backdoors, cleartext update endpoints, hardcoded secrets, and outdated components matched to CVE feeds — mapped to CWE and CVSS.",
    },
  ],
  "platform:overview": [
    {
      q: "What does Pencheff scan?",
      a: "Pencheff covers web applications (DAST), APIs, source code (SAST), dependencies (SCA), software bill of materials (SBOM), infrastructure-as-code, AI and LLM systems, network, and mobile — all from a single assessment queue with unified findings.",
    },
    {
      q: "How long does a Pencheff assessment take?",
      a: "Quick profile: 2–5 minutes. Standard: 10–25 minutes. Deep: 30–90 minutes, depending on application breadth and the number of endpoints discovered.",
    },
    {
      q: "Are Pencheff reports accepted by SOC 2, PCI, or ISO auditors?",
      a: "Yes. Reports map findings to OWASP Top 10 (2021), PCI-DSS 4.0, NIST 800-53, SOC 2 CC6/CC7, ISO 27001:2022, and HIPAA Security Rule — formatted for direct use as evidentiary material in compliance audits.",
    },
    {
      q: "Is Pencheff free to use?",
      a: "Pencheff is free during open beta with no feature gating and no card required. Every shipped capability is unlocked at $0 while the platform is in beta.",
    },
  ],

  "ai-security:overview": [
    {
      q: "What is LLM red teaming?",
      a: "LLM red teaming is adversarial testing of large language model applications — probing for prompt injection, jailbreaks, data exfiltration, insecure output handling, and other vulnerabilities listed in the OWASP LLM Top 10.",
    },
    {
      q: "Does Pencheff cover the OWASP LLM Top 10?",
      a: "Yes. Pencheff maps all AI security findings to the OWASP LLM Top 10 (2025) and MITRE ATLAS, producing audit-ready evidence for each category tested.",
    },
    {
      q: "Can Pencheff test agentic AI systems?",
      a: "Yes. Pencheff assesses agentic AI workflows — including tool-calling agents, multi-step pipelines, and AI assistants — for prompt injection, privilege escalation, and unintended action execution.",
    },
    {
      q: "How is AI security testing different from DAST?",
      a: "DAST targets web applications with injection and access-control probes. AI security testing targets LLM inference endpoints with adversarial prompts, jailbreak attempts, and input/output validation checks specific to generative model behaviour.",
    },
  ],

  "platform:methodology-v4-2": [
    {
      q: "What is Pencheff methodology v4.2?",
      a: "v4.2 is the current assessment framework governing how Pencheff runs the Adversarial Cycle — reconnaissance, surface mapping, probing, verification, and exploit chaining — with standardised evidence formats and compliance mappings.",
    },
    {
      q: "How does Pencheff reduce false positives?",
      a: "Every candidate finding is re-fired with crafted payloads before promotion. Findings that cannot be reproduced are discarded. The result is a verified findings stream with documented request and response evidence.",
    },
    {
      q: "What changed in methodology v4.2?",
      a: "v4.2 tightened exploit chaining procedures, added OWASP LLM Top 10 coverage, and aligned compliance mapping to PCI-DSS 4.0 and ISO 27001:2022.",
    },
  ],

  "solutions:auditors": [
    {
      q: "Will my auditor accept a Pencheff report as evidence?",
      a: "Yes. Pencheff reports are formatted as formal penetration test deliverables with finding severity, CWE references, request/response evidence, and compliance framework mappings — accepted by auditors for SOC 2, ISO 27001, PCI-DSS, HIPAA, and NIST-aligned programmes.",
    },
    {
      q: "Which compliance frameworks does Pencheff map findings to?",
      a: "Findings are mapped to OWASP Top 10 (2021), PCI-DSS 4.0, NIST 800-53, SOC 2 CC6/CC7, ISO 27001:2022, HIPAA Security Rule, and OWASP LLM Top 10 for AI findings.",
    },
    {
      q: "Can I export the report in a format suitable for audit submission?",
      a: "Yes. Reports are available as PDF and DOCX. Both include an executive summary, technical findings, evidence excerpts, remediation guidance, and a compliance appendix ready for audit submission.",
    },
  ],

  "company:trust-and-compliance": [
    {
      q: "Is Pencheff SOC 2 certified?",
      a: "Pencheff is working towards SOC 2 Type II certification. Current trust posture and security control evidence are available to enterprise customers on request.",
    },
    {
      q: "How is customer data isolated between organisations?",
      a: "Each workspace operates in strict isolation with separate encryption keys, access controls, and audit logs. Scan targets, credentials, and findings are never shared across organisations.",
    },
    {
      q: "Does Pencheff retain raw scan data and findings?",
      a: "Pencheff retains finding records, evidence, and reports associated with your workspace for the duration of your subscription. You can delete any target and its associated data at any time from the dashboard.",
    },
  ],

  // PLATFORM — Security Surfaces

  "platform:web-dast": [
    {
      q: "What is DAST in application security?",
      a: "DAST (Dynamic Application Security Testing) probes a running application from the outside — sending crafted HTTP requests to discover injection flaws, authentication bypasses, access-control failures, and other runtime vulnerabilities without access to source code.",
    },
    {
      q: "What vulnerability classes does Pencheff DAST cover?",
      a: "Pencheff DAST covers all OWASP Top 10 (2021) classes: injection (SQLi, NoSQLi, command injection, SSTI, XXE, SSRF, LDAP), broken access control, authentication failures, XSS (reflected, stored, DOM), CSRF, insecure deserialization, and security misconfiguration.",
    },
    {
      q: "How does Pencheff verify DAST findings before reporting them?",
      a: "Every candidate finding is re-fired with a confirmatory payload and the response is inspected for conclusive evidence of exploitation. Findings without verifiable evidence are discarded rather than reported as 'potential' issues.",
    },
    {
      q: "Can Pencheff DAST test authenticated web applications?",
      a: "Yes. Pencheff records a login macro and replays it to maintain an authenticated session throughout the scan. It also handles OAuth flows, MFA, and cookie-based sessions for authenticated coverage of protected endpoints.",
    },
  ],

  "platform:sast-and-secrets": [
    {
      q: "What is SAST and why does it matter?",
      a: "SAST (Static Application Security Testing) analyses source code, bytecode, or binaries without executing the application. It finds injection flaws, hardcoded secrets, insecure library use, and logic errors earlier in the development cycle than DAST.",
    },
    {
      q: "Which programming languages does Pencheff SAST support?",
      a: "Pencheff runs CodeQL, Semgrep, Bandit (Python), gosec (Go), Brakeman (Ruby on Rails), ESLint security rules (JavaScript/TypeScript), and a tree-sitter pack for additional languages including Rust, PHP, and Java.",
    },
    {
      q: "How does Pencheff find hardcoded secrets in code?",
      a: "Pencheff runs gitleaks over the full git history and working tree, detecting API keys, tokens, passwords, and private keys across all commits — not just the current HEAD. YARA rules additionally flag malware patterns and backdoors.",
    },
    {
      q: "Does SAST replace DAST, or do they complement each other?",
      a: "They complement each other. SAST finds flaws in code that may not be reachable at runtime, while DAST finds runtime vulnerabilities that may not be apparent from reading the source. Pencheff combines both into a unified findings stream with de-duplication.",
    },
  ],

  "platform:sca-and-sbom": [
    {
      q: "What is Software Composition Analysis (SCA)?",
      a: "SCA identifies open-source dependencies in your codebase, matches them against vulnerability databases (NVD, OSV, GHSA, CISA KEV), and reports which packages have known CVEs — including transitive dependencies that your direct dependencies pull in.",
    },
    {
      q: "What is an SBOM and why do compliance frameworks require it?",
      a: "A Software Bill of Materials (SBOM) is a machine-readable inventory of every library, package, and component in a software artefact. NTIA, CISA, EO 14028, and PCI-DSS 4.0 require SBOMs as a baseline for supply-chain security and vulnerability management.",
    },
    {
      q: "Does Pencheff prioritise CVEs by exploitability?",
      a: "Yes. Pencheff enriches each CVE with EPSS (Exploit Prediction Scoring System) scores and flags entries on the CISA Known Exploited Vulnerabilities (KEV) catalogue — so you see which vulnerabilities are actively exploited in the wild, not just which ones are theoretically severe.",
    },
    {
      q: "What SBOM formats does Pencheff generate?",
      a: "Pencheff generates SBOMs in CycloneDX and SPDX formats, covering NPM, PyPI, Go modules, Maven, Cargo, RubyGems, and NuGet ecosystems.",
    },
  ],

  "platform:iac-and-containers": [
    {
      q: "What does Infrastructure-as-Code (IaC) security scanning find?",
      a: "IaC scanning detects misconfigurations in Terraform, CloudFormation, Kubernetes manifests, Helm charts, and Dockerfiles — including overly permissive IAM roles, public S3 buckets, missing encryption, insecure network policies, and CIS Benchmark violations before they reach production.",
    },
    {
      q: "Does Pencheff scan container images for vulnerabilities?",
      a: "Yes. Pencheff scans Docker and OCI images for OS-level CVEs, package vulnerabilities, and Dockerfile misconfigurations using Trivy. Findings are mapped to CVE IDs, CVSS scores, and EPSS data.",
    },
    {
      q: "Can Pencheff enforce IaC policies in a CI/CD pipeline?",
      a: "Yes. Pencheff integrates with GitHub Actions and other CI/CD systems via CLI. You can configure severity thresholds that fail a pull request build when critical IaC misconfigurations are introduced.",
    },
    {
      q: "What is a Kubernetes admission webhook and how does Pencheff use it?",
      a: "An admission webhook intercepts pod creation and update requests in Kubernetes before they are committed. Pencheff's admission webhook rejects workloads that violate your configured security policies — blocking insecure deployments at the cluster level.",
    },
  ],

  "platform:audit-and-compliance": [
    {
      q: "Which compliance frameworks does Pencheff support?",
      a: "Pencheff maps every finding to OWASP Top 10 (2021), PCI-DSS 4.0, NIST SP 800-53, SOC 2 Trust Services Criteria (CC6/CC7), ISO 27001:2022, HIPAA Security Rule, and OWASP LLM Top 10. AI security findings additionally map to MITRE ATLAS.",
    },
    {
      q: "How do I use Pencheff evidence in a SOC 2 audit?",
      a: "Run an assessment, export the report as PDF or DOCX, and submit it as evidence for CC6.1 (logical access) and CC7.1 (vulnerability management) controls. The report includes finding severity, CWE references, request/response excerpts, and a compliance appendix.",
    },
    {
      q: "Can Pencheff schedule recurring assessments for continuous compliance?",
      a: "Yes. Pencheff supports scheduled assessments — daily, weekly, or monthly — so you maintain a continuous evidence record rather than a point-in-time snapshot. Findings are tracked across scans to show remediation progress.",
    },
    {
      q: "Does Pencheff produce a re-test certificate after remediation?",
      a: "Yes. After you remediate a finding, Pencheff can re-run the specific test to confirm the fix, and the resulting re-examination report serves as a formal closure certificate for audit evidence packages.",
    },
  ],

  "platform:authenticated-coverage": [
    {
      q: "Why does authenticated scanning matter for web application security?",
      a: "The most sensitive functionality in any web application — account management, payment flows, admin panels, API endpoints — sits behind authentication. Without authenticated scanning, a DAST tool only tests the public surface and misses the majority of real attack surface.",
    },
    {
      q: "How does Pencheff authenticate to a web application for testing?",
      a: "Pencheff records a login sequence (username/password form, OAuth redirect, or cookie injection) and replays it to maintain a valid session during the scan. It automatically handles session expiry and re-authenticates as needed.",
    },
    {
      q: "Can Pencheff test multi-factor authentication (MFA) flows?",
      a: "Yes. Pencheff supports TOTP-based MFA by integrating with your authenticator seed, and it can test the MFA bypass surface — checking for race conditions, backup code brute-force, and session fixation around the MFA step.",
    },
    {
      q: "Does Pencheff test for broken access control in authenticated sessions?",
      a: "Yes. Pencheff probes for IDOR (Insecure Direct Object Reference), horizontal and vertical privilege escalation, and path-traversal issues that are only observable when operating as an authenticated user with known object IDs.",
    },
  ],

  "platform:engagement-profiles": [
    {
      q: "What is an engagement profile in Pencheff?",
      a: "An engagement profile is a pre-configured scan template that controls scope, depth, test modules, authentication settings, rate limits, and compliance mappings for a specific type of assessment — such as a quick surface scan, a deep API pentest, or a CI/CD gate check.",
    },
    {
      q: "Can I create custom engagement profiles for my team?",
      a: "Yes. You can define, save, and share custom profiles with your workspace. Profiles can specify which vulnerability classes to test, set exclusion rules for sensitive endpoints, and configure rate limits appropriate for your application's production environment.",
    },
    {
      q: "What is the difference between Quick, Standard, and Deep profiles?",
      a: "Quick (2–5 min) runs high-confidence, low-noise checks against the primary surface. Standard (10–25 min) adds broader injection coverage and access-control probes. Deep (30–90 min) enables full exploit chaining, authenticated session testing, and all OWASP Top 10 modules.",
    },
  ],

  "platform:llm-red-team": [
    {
      q: "What is an LLM red team assessment?",
      a: "An LLM red team assessment systematically probes a large language model application for security vulnerabilities — including prompt injection, jailbreaks, data extraction, insecure output handling, and supply-chain risks — using adversarial attack strategies aligned with OWASP LLM Top 10.",
    },
    {
      q: "What attack strategies does Pencheff use for LLM red teaming?",
      a: "Pencheff uses multi-turn Crescendo attacks, PAIR (Prompt Automatic Iterative Refinement), TAP, GOAT, Hydra, and attacker-LLM synthesis — automatically generating and iterating adversarial prompts across thousands of turns to find exploitable model behaviours.",
    },
    {
      q: "Which LLM providers and deployment modes does Pencheff support?",
      a: "Pencheff supports OpenAI, Anthropic, Google Gemini, AWS Bedrock, Azure OpenAI, Mistral, and any OpenAI-compatible endpoint. It connects via direct API, proxy, or custom HTTP transport with configurable rate limits and cost ceilings.",
    },
    {
      q: "How does Pencheff grade LLM security findings?",
      a: "Each test turn is graded by an independent LLM-as-judge that evaluates whether the model's response constitutes a security failure. Results are classified by OWASP LLM Top 10 category and severity, with full prompt/response evidence included in the report.",
    },
  ],

  "platform:letter-grade": [
    {
      q: "What is a security letter grade?",
      a: "A letter grade (A–F) is a single risk-score that aggregates all open findings weighted by severity, exploitability, and compliance impact. It gives executives and security teams an immediate signal of application risk posture without reading a full technical report.",
    },
    {
      q: "How is the Pencheff security letter grade calculated?",
      a: "The grade reflects the current verified finding set: critical and high-severity confirmed findings have the most weight. Informational issues and suppressed findings do not affect the grade. The score updates automatically after each scan or remediation.",
    },
    {
      q: "Can I track the security grade over time?",
      a: "Yes. Pencheff shows grade history across all scans for each target, so you can demonstrate continuous improvement to auditors, customers, and boards — and identify regressions introduced by new deployments.",
    },
  ],

  "platform:technical-dossier": [
    {
      q: "What is a Pencheff technical dossier?",
      a: "The technical dossier is a full-detail PDF or DOCX report produced after an assessment. It includes an executive summary, severity breakdown, every verified finding with CWE references and request/response evidence, remediation guidance, and a compliance appendix.",
    },
    {
      q: "Who is the technical dossier intended for?",
      a: "The technical dossier is intended for developers and security engineers who need exact reproduction steps and payload evidence to fix findings. Executives receive a separate executive dossier with risk narrative and grade summary instead.",
    },
    {
      q: "Does the technical dossier include remediation code suggestions?",
      a: "Yes. Each finding includes concrete remediation guidance with code-level examples where applicable, plus references to relevant OWASP remediation documentation and framework-specific guidance.",
    },
  ],

  "platform:re-examination": [
    {
      q: "What is a re-examination in Pencheff?",
      a: "A re-examination re-runs the specific tests that produced previously reported findings against your updated application. It confirms whether remediation was successful and produces a formal closure certificate that can be submitted as evidence in compliance audits.",
    },
    {
      q: "Can Pencheff automatically open pull requests to fix vulnerabilities?",
      a: "Yes. For dependency vulnerabilities and some SAST findings, Pencheff can open auto-fix pull requests that bump the affected package to a patched version or apply a known secure code pattern — reviewed and merged by your team.",
    },
    {
      q: "How long does a re-examination take?",
      a: "A targeted re-examination that re-tests only previously open findings typically completes in 2–10 minutes, depending on the number of findings and the depth of the original test.",
    },
  ],

  // CAPABILITIES

  "capabilities:injection-coverage": [
    {
      q: "What injection vulnerability classes does Pencheff test?",
      a: "Pencheff tests SQL injection (error-based, blind, time-based), NoSQL injection, OS command injection, server-side template injection (SSTI), XML external entity injection (XXE), SSRF, LDAP injection, insecure deserialization, and prototype pollution.",
    },
    {
      q: "How does Pencheff confirm an injection vulnerability is real?",
      a: "Pencheff uses out-of-band (OAST) callbacks for blind injection classes — the payload causes the target to make an out-of-band DNS or HTTP request to a Pencheff-controlled endpoint, providing conclusive proof of injection without relying on error messages.",
    },
    {
      q: "Does Pencheff test for SQL injection in APIs as well as web forms?",
      a: "Yes. Pencheff discovers and fuzzes both HTML form parameters and JSON/XML API request bodies, including deeply nested objects, array items, and GraphQL variables.",
    },
  ],

  "capabilities:authentication": [
    {
      q: "What authentication vulnerabilities does Pencheff test for?",
      a: "Pencheff tests for brute-force susceptibility, credential stuffing exposure, weak password policy, session fixation, insecure session token entropy, missing account lockout, JWT misconfiguration, OAuth flow weaknesses, and MFA bypass techniques.",
    },
    {
      q: "Can Pencheff test OAuth 2.0 and OIDC implementations?",
      a: "Yes. Pencheff probes OAuth authorization code flows for open redirects, state parameter bypass, PKCE omission, token leakage in referrer headers, and implicit flow misuse — covering the most common OAuth security failures.",
    },
    {
      q: "How does Pencheff test JWT security?",
      a: "Pencheff tests for algorithm confusion (RS256 to HS256), the 'none' algorithm bypass, weak signing secrets, missing expiry enforcement, and signature stripping — the most common JWT vulnerabilities that allow token forgery.",
    },
  ],

  "capabilities:dependency-intelligence": [
    {
      q: "What is dependency intelligence and how is it different from basic SCA?",
      a: "Dependency intelligence extends SCA with reachability analysis, EPSS exploit probability scoring, and CISA KEV enrichment. Rather than listing every CVE in every dependency, it identifies which vulnerabilities are reachable by your application code and are actively exploited in the wild.",
    },
    {
      q: "What is reachability analysis in dependency scanning?",
      a: "Reachability analysis determines whether your application actually calls the vulnerable code path in a dependency. A CVE in a library function you never call is low risk; one in a function your hot path invokes is high risk. Reachability reduces alert fatigue by surfacing only the CVEs that matter.",
    },
    {
      q: "What is EPSS and why does it matter for vulnerability prioritisation?",
      a: "EPSS (Exploit Prediction Scoring System) is a daily-updated probabilistic score for each CVE that estimates the likelihood of exploitation in the next 30 days. Combined with CVSS severity, it helps prioritise which vulnerabilities to fix first based on real-world attacker behaviour.",
    },
  ],

  "capabilities:language-scanners": [
    {
      q: "Which languages does Pencheff SAST support?",
      a: "Pencheff supports Python (Bandit + Semgrep), Go (gosec + Semgrep), JavaScript and TypeScript (ESLint security rules + Semgrep), Ruby on Rails (Brakeman), Java (Semgrep + CodeQL), C/C++ (Semgrep), PHP (Semgrep), and Rust via a tree-sitter pack.",
    },
    {
      q: "Does Pencheff run CodeQL?",
      a: "Yes. Pencheff runs CodeQL for deep dataflow analysis on supported languages, finding taint-tracking vulnerabilities (injection, XSS, SSRF) that require following data from source to sink across multiple function calls.",
    },
    {
      q: "How does Semgrep complement CodeQL in Pencheff's SAST pipeline?",
      a: "Semgrep runs thousands of pattern-based rules for fast surface-level detection — insecure function calls, deprecated APIs, hardcoded credentials, and common anti-patterns. CodeQL adds dataflow analysis for vulnerabilities that only manifest when tainted input reaches a dangerous sink.",
    },
  ],

  "capabilities:secrets-and-malware": [
    {
      q: "How does Pencheff detect hardcoded secrets in a repository?",
      a: "Pencheff runs gitleaks across the full git history — not just the current HEAD — to find API keys, tokens, passwords, certificates, and private keys that were ever committed, even if they were later deleted.",
    },
    {
      q: "What types of secrets can Pencheff detect?",
      a: "Pencheff detects AWS, GCP, and Azure credentials, GitHub tokens, Stripe and Twilio API keys, JWT signing secrets, SSH private keys, TLS certificates, database connection strings, and generic high-entropy strings that match secret patterns.",
    },
    {
      q: "Can Pencheff detect malware or backdoors in source code?",
      a: "Yes. Pencheff applies YARA rule sets to detect known malware signatures, obfuscated code, suspicious eval patterns, supply-chain backdoors, and other malicious code indicators in both source files and compiled artefacts.",
    },
  ],

  "capabilities:auto-fix-prs": [
    {
      q: "What is an auto-fix pull request in Pencheff?",
      a: "An auto-fix PR is a GitHub pull request automatically opened by Pencheff that bumps a vulnerable dependency to the latest patched version, or applies a known-safe code change to fix a SAST finding — ready for your team to review and merge.",
    },
    {
      q: "Does auto-fix work for all vulnerability types?",
      a: "Auto-fix currently covers dependency version bumps (SCA findings) and a subset of SAST findings where a deterministic fix exists — such as replacing insecure hash functions or removing hardcoded credentials. Complex logic vulnerabilities require manual remediation.",
    },
    {
      q: "How does Pencheff integrate with GitHub for auto-fix PRs?",
      a: "Pencheff connects to your GitHub organisation via OAuth or GitHub App installation. When a fixable finding is detected, it opens a PR against the default branch with a description of the vulnerability, the fix applied, and a link to the original finding in Pencheff.",
    },
  ],

  "capabilities:container-gates": [
    {
      q: "How does Pencheff scan container images for vulnerabilities?",
      a: "Pencheff uses Trivy to scan Docker and OCI images for OS-level package CVEs, application dependency CVEs, Dockerfile misconfigurations, and secrets — producing a full SBOM of the image alongside a prioritised vulnerability list.",
    },
    {
      q: "What is a Kubernetes admission webhook and how does Pencheff use it?",
      a: "A Kubernetes admission webhook is a policy enforcement point that intercepts pod create/update requests before they are committed to the cluster. Pencheff's webhook rejects workloads whose images have critical unpatched CVEs or violate your defined security policies.",
    },
    {
      q: "Can Pencheff block CI/CD pipelines when a container image has critical vulnerabilities?",
      a: "Yes. Pencheff's CLI can be invoked as a CI/CD step to scan a newly built image and exit non-zero when findings exceed your configured severity threshold — blocking the pipeline before the image reaches a registry or production environment.",
    },
  ],

  "capabilities:reachability": [
    {
      q: "What is reachability analysis in security?",
      a: "Reachability analysis determines whether a known-vulnerable code path in a library is actually callable from your application. Most CVEs are in code paths you never invoke — reachability analysis filters these out, leaving only the vulnerabilities that represent real risk to your specific application.",
    },
    {
      q: "How does reachability reduce alert fatigue?",
      a: "A typical Node.js application has hundreds of transitive dependencies, many with CVEs. Without reachability, every CVE demands attention. With reachability, only the fraction of CVEs reachable from your application's call graph surface — often under 10% — require remediation effort.",
    },
    {
      q: "Does Pencheff perform reachability analysis for all languages?",
      a: "Pencheff currently supports reachability for JavaScript/TypeScript (via call graph analysis), Python, Go, and Java. Reachability data is displayed alongside EPSS and KEV enrichment in the findings stream.",
    },
  ],

  "capabilities:ai-triage": [
    {
      q: "How does AI triage work in Pencheff?",
      a: "Pencheff's AI triage layer reviews each finding in context — analysing the code path, request/response evidence, and application behaviour — to assess exploitability in your specific environment. It produces an AI-generated severity adjustment and remediation recommendation alongside the raw finding.",
    },
    {
      q: "Does AI triage replace manual security review?",
      a: "No. AI triage accelerates the review process by pre-filtering and contextualising findings so engineers spend their time on the highest-risk issues. Complex findings and chained exploits still benefit from human review of the evidence Pencheff provides.",
    },
    {
      q: "What is the AI advisory in Pencheff?",
      a: "The AI advisory is a conversational interface within each finding that lets you ask questions about the vulnerability, request alternative payloads, get remediation code examples, or understand the compliance impact — all grounded in the specific evidence from that finding.",
    },
  ],

  // AI SECURITY — Detail pages

  "ai-security:llm-red-team": [
    {
      q: "What does an LLM red team test actually do?",
      a: "An LLM red team test sends thousands of adversarial prompts to your AI application, using automated attack strategies to find cases where the model produces harmful, false, or security-compromising output — including prompt injection, jailbreaks, PII leakage, and insecure code generation.",
    },
    {
      q: "What is prompt injection and why is it the top LLM risk?",
      a: "Prompt injection is an attack where malicious content in a user message, document, or tool response overrides the system prompt and redirects the LLM to take unintended actions — such as leaking data, bypassing guardrails, or impersonating the system. It is OWASP LLM01 and the highest-impact AI vulnerability class.",
    },
    {
      q: "How does Pencheff's LLM-as-judge grading work?",
      a: "After each adversarial turn, an independent judge model — separate from the model under test — evaluates whether the response constitutes a security failure according to the target policy. This eliminates manual review of thousands of responses and produces a consistent, auditable pass/fail verdict.",
    },
    {
      q: "Can I add custom jailbreak tests or policies to the LLM red team?",
      a: "Yes. Pencheff exposes a plugin SDK that lets you write custom attack modules, target-specific policy evaluators, and domain-specific adversarial prompt sets — extending the red team beyond the built-in OWASP LLM Top 10 modules.",
    },
  ],

  "ai-security:sentry-runtime-guardrail": [
    {
      q: "What is a runtime AI guardrail?",
      a: "A runtime guardrail is an inline security layer that inspects every prompt and model response in real time — blocking prompt injections, policy violations, PII leakage, and toxic output before they affect the user or the application's downstream actions.",
    },
    {
      q: "How does Pencheff Sentry work as a guardrail?",
      a: "Sentry sits between your application and the LLM as a proxy or sidecar. Every incoming prompt and outgoing response passes through a configurable detector chain — checking for injection patterns, forbidden topics, PII, excessive permissions, and policy violations — before the content reaches its destination.",
    },
    {
      q: "Does the Sentry guardrail add latency to LLM responses?",
      a: "Sentry's detector chain is optimised for sub-10ms overhead on most checks. Expensive multi-classifier evaluations can be run asynchronously in monitoring mode, so you can observe policy violations without adding synchronous latency to the user experience.",
    },
    {
      q: "How does Sentry integrate into an existing LLM application?",
      a: "Sentry integrates as an OpenAI-compatible proxy (point your SDK at the Sentry endpoint), a LiteLLM plugin, or a sidecar container. No application code changes are required for basic guardrail enforcement.",
    },
  ],

  "ai-security:ai-agents": [
    {
      q: "What makes agentic AI systems uniquely risky from a security perspective?",
      a: "Agents take autonomous actions — calling external tools, writing files, making API calls, browsing the web. A prompt injection that causes an agent to exfiltrate data, delete resources, or impersonate a user can have immediate real-world impact that a non-agentic chatbot cannot produce.",
    },
    {
      q: "How does Pencheff test AI agents for security vulnerabilities?",
      a: "Pencheff deploys an adversarial swarm — 19 specialised agents — against your agent system, probing for prompt injection via tool responses, privilege escalation through chained tool calls, memory poisoning, and catastrophic-action execution. Each attack is logged with full step-by-step evidence.",
    },
    {
      q: "What is tool-call authorization and why does it matter for AI agents?",
      a: "Tool-call authorization is a policy layer that checks whether an agent is permitted to call a specific tool with specific arguments before the call executes. Without it, a prompt-injected agent can invoke any tool with any parameters — reading sensitive files, sending emails, or triggering destructive operations.",
    },
    {
      q: "Can Pencheff test MCP (Model Context Protocol) servers?",
      a: "Yes. Pencheff can target MCP-based agent architectures, probing for tool-schema injection, privileged resource access, and cross-context data leakage in MCP server implementations.",
    },
  ],

  "ai-security:agent-swarms": [
    {
      q: "What is a Pencheff agent swarm?",
      a: "The Pencheff agent swarm is a multi-agent red team system where a planner agent decomposes a target into attack sub-goals, then fans out to 19 specialised breaker agents that each pursue a specific attack vector in parallel — dramatically increasing coverage over single-agent approaches.",
    },
    {
      q: "How does the swarm handle catastrophic or irreversible actions during testing?",
      a: "Every breaker agent operates under a budget (maximum tool calls) and a killswitch monitored by the planner. Potentially destructive actions require explicit escalation approval. Pencheff maintains a full audit trail of every action taken during the swarm run.",
    },
    {
      q: "What is the difference between a swarm test and a standard LLM red team?",
      a: "A standard LLM red team probes a single model endpoint for input/output vulnerabilities. A swarm test operates as a realistic adversarial actor against an entire agent pipeline — testing multi-step attack chains, tool misuse, and emergent vulnerabilities that only appear in multi-turn agent interactions.",
    },
  ],

  "ai-security:owasp-llm-top-10": [
    {
      q: "What is the OWASP LLM Top 10?",
      a: "The OWASP LLM Top 10 is the industry-standard classification of the most critical security risks for large language model applications, covering: LLM01 Prompt Injection, LLM02 Insecure Output Handling, LLM03 Training Data Poisoning, LLM04 Model Denial of Service, LLM05 Supply Chain Vulnerabilities, LLM06 Sensitive Information Disclosure, LLM07 Insecure Plugin Design, LLM08 Excessive Agency, LLM09 Overreliance, and LLM10 Model Theft.",
    },
    {
      q: "Does Pencheff cover all 10 categories of the OWASP LLM Top 10?",
      a: "Pencheff covers all dynamically testable categories in the OWASP LLM Top 10 (2025) — primarily LLM01 through LLM09. LLM03 (training data poisoning) and LLM10 (model theft) require access to training infrastructure and model weights, which are outside the scope of black-box assessment.",
    },
    {
      q: "How do I prove OWASP LLM Top 10 compliance to auditors or customers?",
      a: "Run a Pencheff LLM red team assessment. The resulting report maps every finding to its OWASP LLM Top 10 category with evidence, and includes a compliance matrix showing test coverage per category — suitable for audit submission or customer security questionnaire responses.",
    },
  ],

  "ai-security:attack-strategies": [
    {
      q: "What is Crescendo attack strategy in LLM red teaming?",
      a: "Crescendo is a multi-turn jailbreak strategy where the attacker gradually escalates the conversation — starting with benign-seeming requests and incrementally steering the model toward policy violations. It exploits the fact that LLMs are more susceptible to harmful requests when they follow a series of contextually reasonable prior turns.",
    },
    {
      q: "What is PAIR (Prompt Automatic Iterative Refinement)?",
      a: "PAIR uses an attacker LLM to iteratively refine adversarial prompts based on the target model's responses. Starting from an initial jailbreak attempt, the attacker model analyses what failed and generates an improved prompt — repeating until the target produces a policy violation or the budget is exhausted.",
    },
    {
      q: "Does Pencheff use an attacker LLM to generate adversarial prompts?",
      a: "Yes. Pencheff uses attacker-LLM synthesis — a separate language model that generates, evaluates, and iterates adversarial prompts against the target. This enables semi-infinite prompt variation and cross-model attack transfer beyond what static prompt libraries can achieve.",
    },
  ],

  // SOLUTIONS

  "solutions:engineers": [
    {
      q: "How does Pencheff integrate into a developer workflow?",
      a: "Pencheff integrates via CLI, GitHub Actions, VS Code extension, and MCP server. Developers can trigger scans from their IDE, get security feedback in pull request check runs, and query findings through the MCP toolkit without leaving their development environment.",
    },
    {
      q: "Can Pencheff run in a CI/CD pipeline?",
      a: "Yes. Pencheff's CLI installs as a single binary and provides a scan command that exits non-zero when findings exceed a configured severity threshold — failing the build before vulnerable code reaches production.",
    },
    {
      q: "Does Pencheff provide security feedback in pull requests?",
      a: "Yes. When connected to GitHub, Pencheff posts check run results directly on pull requests — annotating affected lines with SAST findings and blocking merge when critical issues are detected.",
    },
    {
      q: "How do developers access Pencheff through an AI assistant?",
      a: "Pencheff exposes an MCP (Model Context Protocol) server that AI coding assistants can query to get finding details, remediation advice, and security context for the code they're working on — bringing security data into the AI conversation without context-switching.",
    },
  ],

  "solutions:ci-cd-gates": [
    {
      q: "What is a security gate in CI/CD?",
      a: "A security gate is an automated check in a CI/CD pipeline that runs security tests and blocks deployment when findings exceed a defined threshold — preventing vulnerable code from reaching staging or production environments.",
    },
    {
      q: "How do I add a Pencheff security gate to GitHub Actions?",
      a: "Add the Pencheff GitHub Action to your workflow YAML, configure your API key and target URL or repo path, and set a severity threshold. The action runs the scan and fails the workflow when critical or high-severity findings are detected.",
    },
    {
      q: "Can Pencheff gate on both DAST and SAST findings in the same pipeline?",
      a: "Yes. You can configure a single pipeline step that runs both web DAST against a staging environment and SAST/SCA against the source repository — blocking on any finding class above your threshold from either scan type.",
    },
    {
      q: "What happens when a CI gate finds a vulnerability?",
      a: "The pipeline step exits non-zero, the build fails, and Pencheff posts a summary of the blocking findings as a GitHub check run annotation on the pull request. Engineers see the finding details and remediation guidance inline without navigating to a separate dashboard.",
    },
  ],

  "solutions:self-hosting": [
    {
      q: "Can Pencheff be deployed on-premises?",
      a: "Yes. Pencheff supports self-hosted deployment via Docker Compose and Kubernetes Helm charts. The entire platform — scanner engines, API, dashboard, and database — runs within your own infrastructure with no data leaving your environment.",
    },
    {
      q: "What are the infrastructure requirements for self-hosting Pencheff?",
      a: "A minimal self-hosted deployment requires 4 CPU cores and 8 GB RAM for a single-node setup. For concurrent deep scans, 8+ cores and 16 GB RAM are recommended. PostgreSQL and Redis are the only external service dependencies.",
    },
    {
      q: "Why would an organisation choose self-hosting over Pencheff's cloud?",
      a: "Self-hosting is typically chosen by regulated industries (financial services, healthcare, defence) where scan targets, credentials, and findings must never leave the organisation's network boundary — even to a trusted SaaS provider. It also satisfies air-gapped environment requirements.",
    },
    {
      q: "How are Pencheff updates applied in a self-hosted deployment?",
      a: "Pencheff releases container image updates that you pull and redeploy using your standard container orchestration tooling. Release notes are published with each version, and the API is versioned to ensure upgrade compatibility.",
    },
  ],

  "solutions:ai-product-release": [
    {
      q: "What security testing should I run before releasing an AI product?",
      a: "Before releasing an AI product, you should run an LLM red team assessment covering the OWASP LLM Top 10, an agentic security test if your product uses tool-calling, a Sentry guardrail evaluation, and a supply-chain scan of your AI dependencies. Pencheff covers all four in a single platform.",
    },
    {
      q: "How does Pencheff help with AI product security certification?",
      a: "Pencheff produces audit-ready reports mapping AI security findings to OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF categories. These reports serve as evidence for enterprise customer security reviews, regulatory submissions, and AI governance programmes.",
    },
    {
      q: "What is the minimum security bar for an AI product release?",
      a: "At minimum, an AI product should demonstrate: no exploitable prompt injection vulnerabilities, no sensitive data leakage in model responses, guardrails on harmful output, and a secure supply chain for model weights and dependencies. Pencheff's AI product release profile covers all of these.",
    },
  ],

  "solutions:executives": [
    {
      q: "What does the Pencheff executive dashboard show?",
      a: "The executive dashboard shows the current security letter grade, open finding count by severity, compliance posture across active frameworks, remediation velocity trend, and upcoming scheduled assessment dates — all without requiring technical security knowledge to interpret.",
    },
    {
      q: "How does Pencheff help executives communicate security posture to a board?",
      a: "Pencheff generates a board-ready executive dossier as a one-page PDF summary with letter grade, risk narrative, top three risks and their business impact, and remediation progress. It translates technical findings into business-language risk statements.",
    },
    {
      q: "How does continuous security testing improve risk visibility for executives?",
      a: "Continuous testing replaces point-in-time snapshots with a live risk signal. Executives see the security grade update after every deployment, can correlate grade drops with release dates, and have an auditable evidence trail demonstrating ongoing security investment.",
    },
  ],

  "solutions:security-teams": [
    {
      q: "How does Pencheff support a security team's daily workflow?",
      a: "Pencheff provides a unified finding stream aggregating DAST, SAST, SCA, IaC, and AI security findings into a single prioritised queue — filtered by severity, target, framework mapping, and status. Security teams triage, assign, and track remediation without juggling multiple tools.",
    },
    {
      q: "Can multiple security team members collaborate on findings in Pencheff?",
      a: "Yes. Findings can be assigned to individuals, commented on, and linked to remediation PRs. Finding status (open, in-review, fixed, suppressed, accepted) is tracked per team member, with audit-log entries recording all changes.",
    },
    {
      q: "How does Pencheff's AI triage help security teams work faster?",
      a: "AI triage pre-analyses each finding in its application context, generates an exploitability assessment, and drafts remediation guidance — so security engineers spend their review time on the highest-risk confirmed vulnerabilities rather than manually triaging raw scanner output.",
    },
  ],

  "solutions:authenticated-app-pentest": [
    {
      q: "What is an authenticated application penetration test?",
      a: "An authenticated application penetration test assesses the security of functionality that is only accessible after logging in — including user account operations, payment flows, admin interfaces, and API endpoints that require a valid session token.",
    },
    {
      q: "How does Pencheff handle different authentication mechanisms during a pentest?",
      a: "Pencheff supports form-based login (username/password), OAuth/OIDC redirect flows, API key authentication, cookie injection, and TOTP-based MFA. It records and replays auth sequences automatically to maintain session validity throughout the test.",
    },
    {
      q: "Can Pencheff test for IDOR and privilege escalation in a multi-user application?",
      a: "Yes. Pencheff can operate as multiple simultaneous users with different privilege levels — probing whether a low-privilege user can access or modify resources belonging to other users or higher-privilege roles by manipulating object identifiers and access-control parameters.",
    },
  ],

  // COMPANY

  "company:our-discipline": [
    {
      q: "What is Pencheff's approach to application security?",
      a: "Pencheff applies an adversarial discipline — every assessment starts with genuine attack attempts, not just automated scanner output. Findings are verified with crafted exploits before being reported, and the platform chains individual vulnerabilities into multi-step attack scenarios that demonstrate real business impact.",
    },
    {
      q: "How does Pencheff differ from a traditional vulnerability scanner?",
      a: "Traditional scanners cast a wide net and report potential issues. Pencheff verifies each finding by attempting to exploit it, discards unconfirmed candidates, and chains related findings into realistic attack paths. The output is a verified findings set with documented proof-of-concept evidence, not a noise-heavy potential-issues list.",
    },
    {
      q: "What does 'adversarial' mean in the context of application security assessment?",
      a: "Adversarial assessment means thinking and acting like a real attacker — identifying the highest-value targets, chaining low-severity findings into high-impact exploits, testing edge cases that automated tools miss, and producing evidence that demonstrates the actual consequence of each vulnerability.",
    },
  ],

  "company:our-auditors": [
    {
      q: "Who are the security practitioners behind Pencheff?",
      a: "Pencheff is built by practitioners with hands-on experience in application penetration testing, red team engagements, and compliance assessment. The platform encodes the same techniques, evidence standards, and reporting rigour used in institutional-grade manual assessments.",
    },
    {
      q: "Can Pencheff reports serve as a substitute for manual penetration testing?",
      a: "Pencheff produces audit-grade reports that satisfy the evidence requirements for SOC 2, PCI-DSS, ISO 27001, and HIPAA assessments. For programmes requiring a named human penetration tester or a CREST/OSCP-certified assessor signature, Pencheff can be combined with a human review engagement.",
    },
    {
      q: "How does Pencheff maintain assessment quality at scale?",
      a: "Every finding promotion requires re-verification with a confirmatory payload. Findings that cannot be reproduced are automatically discarded. The methodology is versioned (currently v4.2) and the compliance mapping is updated with each framework revision — so report quality is consistent regardless of scan volume.",
    },
  ],
};
