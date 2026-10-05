# Pencheff

Autonomous penetration testing platform. Provide a target URL and credentials in natural language — Pencheff handles reconnaissance, vulnerability scanning, exploit chain analysis, and compliance-mapped reporting.

Unlike static scanners, Pencheff plans like a human pentester. Each testing module returns structured findings and `next_steps` recommendations, and the engine adaptively decides what to test next, chains discovered vulnerabilities together, and prioritizes the surface that actually matters.

**Current version: v0.4.0**

## Features

- **30-specialist playbook suite** — 28 adapted from
  [0xSteph/pentest-ai-agents](https://github.com/0xSteph/pentest-ai-agents)
  plus `crawl_first` and `api_authenticator` that anchor the
  HTTP-first reconnaissance + login-discovery flow. Each is a CLI
  subcommand and an MCP tool (`playbook_<name>`). See
  [docs/PLAYBOOKS.md](docs/PLAYBOOKS.md).
- **`pencheff engage`** drives the **9-phase** swarm orchestration
  end-to-end: Scoping → **Crawl** → **Auth** → Recon → Vuln →
  Exploitation → Post-ex → Detection eng → Reporting. The crawl phase
  populates the real endpoint surface BEFORE auth runs, so the auth
  phase picks a discovered login URL instead of guessing from a
  static path list. See [docs/ENGAGEMENT-LIFECYCLE.md](docs/ENGAGEMENT-LIFECYCLE.md).
- **Subdomain fan-out** — `pencheff engage --max-subdomains 100` runs
  crawl + auth + vuln + exploit on each discovered subdomain.
- **Tier 1 (advisory) / Tier 2 (execution)** model with `--tier` filtering;
  Tier 2 requires a `--scope FILE` declaration validated against every target.
- **OPSEC noise tagging** (QUIET / MODERATE / LOUD) on every playbook;
  filter via `pencheff engage --noise quiet`.
- **Engagement DB** at `~/.pencheff/engagements.db` (SQLite, stdlib) with
  cross-session state: engagements, hosts, services, vulns, credentials,
  chains, session_log. Drive via `pencheff engagement {init,list,show,log,handoff,export,chains,migrate}`.
- **MITRE ATT&CK mapping** baked into every Finding (`mitre_id` field).
- **Deterministic threat modeler** — `pencheff threatmodel --method stride|dread`.
- **Deterministic detection-rule synthesis** — `pencheff detect --format sigma|spl|kql`.
- **DISA STIG catalog lookup** — `pencheff stig --asset webapp`.
- **HackerOne / Bugcrowd writeup formatter** — `pencheff bugbounty --platform h1|bc`.
- **Gap modules** — thin Python wrappers around BloodHound / Impacket /
  NetExec / Certipy (AD), aircrack-ng / hcxtools / bettercap (wireless),
  apktool / jadx / MobSF (mobile), Volatility / Plaso / Sleuth Kit
  (forensics), YARA / ClamAV / FLOSS (malware).
- **50 MCP tools** covering the full pentest lifecycle — from reconnaissance to ticketing export (now includes mobile static analysis)
- **57 attack modules** across 13 categories implementing real detection logic (now with Android manifest, mobile secrets, mobile crypto, iOS static)
- **326 payloads** across 17 payload files for injection, bypass, and exploitation testing
- **Adaptive testing** — the engine reasons about discovered tech stack, WAF detection, and vulnerabilities to guide testing strategy
- **OWASP Top 10 2021** category mapping with CVSS v3.1 and CVSS v4.0 scoring
- **6 compliance frameworks** — OWASP Top 10, PCI-DSS 4.0, NIST 800-53, SOC 2, ISO 27001:2022, HIPAA mapped to every finding
- **3 dashboard scan profiles** (`quick` / `standard` / `deep`) with the prior specialised profiles folded in: `cicd → quick`; `api-only`/`asm`/`sca`/`iac → standard`; `engage`/`compliance`/`compliance-full`/`supply-chain`/`network-va`/`hackme`/`continuous → deep`. The CLI still exposes every subcommand by name (`pencheff engage`, `pencheff scan --profile sca`, …); the alias map only collapses the API/UI-facing surface.
- **OAST (Out-of-Band Application Security Testing)** — blind SSRF/SQLi/XSS detection via interactsh-client callbacks
- **Playwright integration** — SPA browser crawling, DOM XSS detection, login macro recording with headed browser
- **OpenAPI 3.x / Swagger 2.0 / Postman v2.1 import** — seed all endpoints automatically from existing specs
- **CI/CD first-class** — CLI (`pencheff scan`), GitHub Actions workflow, fail-on severity gate
- **Ticketing export** — create GitHub Issues or Jira tickets directly from findings
- **Delta scanning** — compare scans across sessions to track new/fixed/regressed findings
- **Finding suppression lifecycle** — accepted_risk, wont_fix, false_positive, duplicate, out_of_scope
- **Multi-credential support** — test authorization boundaries between user roles
- **Exploit chain analysis** — automatically identifies multi-step attack paths across findings
- **WAF-aware payloads** — detects WAF vendor and generates bypass-optimized payloads
- **Optional external security tools** — run allowlisted scanners via `run_security_tool` when they are installed and licensed for your environment
- **Exploitation-first methodology** — every scan finding is verified with `test_endpoint`, false positives eliminated, PoCs demonstrated
- **Export to Word, CSV, JSON** — professional reports with verification status, compliance mapping, suppression state
- **Secure by design** — credentials wrapped in `MaskedSecret`, never logged or leaked in findings

## Installation

### From Source

```bash
git clone https://github.com/BalaSriharsha-Ch/pencheff.git
cd pencheff
```

Connect any MCP-compatible client by adding to its `.mcp.json` (or
equivalent config):

```json
{
  "mcpServers": {
    "pencheff": {
      "command": "uv",
      "args": ["run", "--project", "./plugins/pencheff", "python", "-m", "pencheff"]
    }
  }
}
```

### Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) for dependency management
- Any MCP-compatible client (Cursor, Continue, Cline, Zed, custom MCP host, …) — or use the standalone CLI

## Quick Start

Use the built-in skill for a full automated pentest:

```
/pencheff:pentest https://example.com username: admin, password: test123
```

Or use the agent directly:

```
@pencheff Run a full pentest against https://api.example.com with API key: sk-abc123
```

Or call individual tools for targeted testing:

```
Use pentest_init to start a session against https://example.com, then run scan_injection on the /api/login endpoint.
```

## CLI Usage

Pencheff ships a standalone CLI for headless scans and CI/CD pipelines:

```bash
# Run a standard scan and save the report as JSON
pencheff scan --target https://example.com --format json --output ./reports

# Run a fast CI/CD-optimized scan; exit non-zero if high or critical found
pencheff scan --target https://example.com --profile cicd --fail-on high

# Authenticated scan with credentials
pencheff scan --target https://example.com --profile deep \
  --username admin --password secret --save-history

# List saved scan history
pencheff history

# Compare two scans to find new/fixed/regressed findings
pencheff compare <session_id_a> <session_id_b>

# Lightweight Pencheff TCP/UDP port map for assets you are authorized to test
pencheff map --target 10.0.0.10 --ports top-100 --format table
pencheff map --target 10.0.0.0/24 --ports 22,80,443 --format json
pencheff map --target 10.0.0.10 --all-ports --format table
pencheff map --target 10.0.0.10 --all-ports -A --format json
pencheff map --target 10.0.0.10 --all-ports -sU -T4 --format xml

# Non-destructive first-party SQL injection assessment
pencheff sqli --url "https://app.example.com/item?id=1" --format table
pencheff sqli --url "https://app.example.com/login" --method POST \
  --data "username=alice&password=test" --param username --format json
pencheff sqli -r request.txt --profile deep --tamper space2comment \
  --traffic-log .pencheff/sqli-evidence.jsonl --format json
pencheff sqli --burp-xml burp-export.xml --risk 2 --level 4

# Non-destructive first-party web server exposure assessment
pencheff webscan --target https://app.example.com --profile standard
pencheff webscan --target https://app.example.com --profile deep \
  --path /custom-status --traffic-log .pencheff/webscan-evidence.jsonl --format json
pencheff webscan --targets-file targets.txt --tuning apps --tuning files \
  --check-db team-web-checks.json --suppressions webscan-suppressions.json --format html
pencheff webscan --update-checks

# Non-destructive first-party template detection
pencheff pulse --target https://app.example.com --profile standard
pencheff pulse --targets-file targets.txt --tag exposure --format jsonl
pencheff pulse --target https://app.example.com -t team-templates/ \
  --template-id exposed-env-file --format html
pencheff pulse --target https://app.example.com -t pulse-safe-http.yaml \
  --cache-dir .pencheff/pulse-cache --stats-file .pencheff/pulse-stats.json --resume
pencheff pulse --target https://app.example.com --ignore-file .pulse-ignore \
  --require-signed --trusted-author security-team --headless
```

`pencheff map` supports Pencheff-native discovery flags: `-sV` for safe
service/version detection, `-O` for passive OS guesses, `--script-scan` and
`--vuln-scan` for built-in low-impact checks, `--traceroute` for system
traceroute when available, `-sU` for a small UDP probe set, `-T0` through `-T5`
for timing profiles, XML/JSON/CSV/table output, and `-A` to bundle those checks.
`-sS` is accepted as a low-noise TCP connect mode; Pencheff does not perform raw
SYN stealth/evasion scans. The Pencheff pentest workflow's `recon_active` stage
uses full TCP port discovery by default.

`pencheff sqli` is a safe SQL injection assessor for authorized targets. It
supports error-signature, boolean-differential, capped time-delay, UNION-shape,
and safe stacked-query checks; request-file, bulk-file, Burp XML, same-origin
crawl import; cookies, headers, proxy, CSRF token refresh, anti-cache nonces;
profiles, level/risk tuning, tamper transforms, JSONL evidence, and cache/resume.
It does not dump database contents, enumerate schemas, read/write files, create
UDFs, or attempt shell access.

`pencheff webscan` is a safe web server exposure assessor. It checks security
headers, cookies, informational headers, HTTP methods, common exposed files,
default/admin paths, backup artifacts, directory listings, diagnostic pages,
and disclosure patterns. It uses a local JSON check database with matcher
expressions such as `CODE:200&&BODY:Swagger UI`, supports extra check packs,
multi-target files, tuning tags, HTML/XML/CSV/JSON/table reports, auth profiles,
suppressions, JSONL evidence, and a first-party `--update-checks` command. The
normal `scan_infrastructure` workflow runs this first-party engine through the
`web_server` module.

`pencheff pulse` is a safe template scanner. Templates are
first-party JSON/YAML checks and a Pulse-compatible safe HTTP subset, including
raw HTTP requests, request chaining, named extractors, variables, helper
functions, status/word/regex/header/size/simple-DSL matchers, and bounded
query/body/header fuzzing. It also supports passive DNS/TCP/TLS detection,
optional Playwright headless DOM checks, `.pulse-ignore`, signature/trusted
author metadata, CVSS/CWE/CPE-style classification fields, user template update
channels, cache/resume, stats files, target files, auth profiles, JSONL/JSON/CSV/XML/HTML/table output,
and workflow ingestion through the `scan_pulse` stage. Pulse intentionally
does not execute arbitrary code templates or poll OAST callbacks; `--interactsh-url`
is a safe placeholder for templates that need a callback token.

### Scan Profiles

The CLI accepts every profile in the table below. The dashboard / API
expose only `quick` / `standard` / `deep`; the legacy names are still
accepted there for backward compatibility and coerced to one of the
three tiers at the runner — see the **Folds into** column.

| Profile | Description | Depth | Max Pages | Folds into |
|---------|-------------|-------|-----------|------------|
| `quick` | Fast surface-level scan — recon + top injection checks + auth | quick | 20 | _self_ |
| `standard` | Balanced web assessment with OWASP Top 10 category mapping (default) | standard | 100 | _self_ |
| `deep` | Exhaustive pentest — all modules + advanced attacks + swarm + deterministic orchestrator | deep | 500 | _self_ |
| `api-only` | REST/GraphQL API security — no browser crawl, auth + injection + IDOR | standard | 0 | `standard` |
| `compliance` | Mapped to PCI-DSS, NIST, SOC 2, ISO 27001, HIPAA | standard | 50 | `deep` |
| `cicd` | Lightweight CI/CD gate — fast, non-destructive, fails on high+ | quick | 10 | `quick` |
| `engage` | Full 9-phase swarm orchestration | deep | 500 | `deep` |
| `mobile-static` | Static analysis of an APK or IPA — manifest, secrets, crypto, plist (no device) | standard | 0 | _CLI only_ |

## Mobile App Testing (Static)

Pencheff can scan Android APK and iOS IPA files without an emulator or rooted device.
The static path covers OWASP Mobile Top 10 issues — debuggable/backup flags, exported
components, hardcoded secrets, weak crypto, ATS bypass on iOS — and emits the same
`Finding` objects the web flow produces, so reports/CSV/JSON exports work unchanged.

```python
# Initialize a session — placeholder URL is fine for mobile targets
session = pentest_init(target_url="file:///abs/path/to/app.apk")

# Run static analysis (Android)
scan_mobile_static(session_id=session["session_id"],
                   apk_path="/abs/path/to/app.apk")

# Or iOS
scan_mobile_static(session_id=session["session_id"],
                   ipa_path="/abs/path/to/app.ipa")

# Review findings, then export
get_findings(session_id=session["session_id"], category="mobile_secrets")
export_report(session_id=session["session_id"], formats=["docx", "json"])
```

### What it detects

- **AndroidManifest.xml** — `android:debuggable=true`, `allowBackup=true`, `usesCleartextTraffic=true`,
  exported activities/services/receivers/providers without `permission`, missing `networkSecurityConfig`,
  dangerous `minSdkVersion`.
- **Hardcoded secrets** in jadx-decompiled Java — AWS access keys, Google API keys, Firebase URLs,
  Slack/GitHub/Stripe tokens, Twilio/SendGrid/Mailgun keys, JWTs, PEM private keys, password assignments.
- **Insecure crypto** — DES, 3DES, RC4, ECB mode, MD5/SHA-1 hashing, hardcoded `SecretKeySpec` /
  `IvParameterSpec`, `java.util.Random` for security values.
- **Cleartext URLs** in compiled code (excluding RFC1918 / localhost / standard schema URLs).
- **iOS Info.plist** — `NSAllowsArbitraryLoads`, ATS exceptions for media / WebView, custom URL
  schemes (deeplink hijacking risk), embedded provisioning profile presence.
- **iOS binary hardening** — missing PIE flag (via `otool -hv`, macOS only).

### Required tools

`apktool` and `jadx` for Android. For iOS, `plistlib` (stdlib) handles plist parsing; `otool` (macOS
only, ships with Xcode CLT) is used opportunistically for binary hardening checks. Optional:
`mobsfscan` / `qark` / `androguard` via `run_security_tool` for additional rule depth, or set
`MOBSF_API_KEY` and pass `use_mobsf=True` for MobSF REST enrichment.

### Out of scope (Phase 2)

Dynamic instrumentation — Frida, objection, drozer, runtime SSL pinning bypass — requires an
emulator or rooted/jailbroken device and is not part of `scan_mobile_static`. Run those tools
manually via `run_security_tool` once a device is attached.

## GitHub Actions

The included workflow at `.github/workflows/pencheff-scan.yml` provides:

- Automatic scan on push/PR to `main`/`master`
- Nightly full scan (02:00 UTC)
- Manual dispatch with configurable target, profile, and fail-on severity
- Artifact upload of JSON/CSV reports
- Automatic GitHub Issue creation on critical/high findings
- PR comment with finding summary table

```yaml
# Manual trigger
gh workflow run pencheff-scan.yml \
  -f target_url=https://staging.example.com \
  -f profile=cicd \
  -f fail_on=high
```

## MCP Tools (50)

### Session Management (3)

| Tool | Description |
|------|-------------|
| `pentest_init` | Initialize session with target URL, credentials, scope, depth, and scan profile |
| `pentest_status` | Get progress — completed modules, finding counts, intelligent next-step recommendations |
| `pentest_configure` | Update credentials, scope, or depth mid-session |

### Reconnaissance (3)

| Tool | Description |
|------|-------------|
| `recon_passive` | DNS enumeration, WHOIS, certificate transparency, subdomain discovery, technology fingerprinting |
| `recon_active` | TCP port scanning (top-100/top-1000), web crawling (Playwright SPA crawl when available, HTTP fallback), service fingerprinting, endpoint discovery |
| `recon_api_discovery` | OpenAPI/Swagger spec detection, GraphQL introspection, API route enumeration from JavaScript/sitemap/robots.txt |

### Vulnerability Scanning (11)

| Tool | Description |
|------|-------------|
| `scan_injection` | 10 injection types: SQLi (error/blind/time-based), NoSQLi, command injection, SSTI, XXE, SSRF (with OAST blind detection), LDAP injection, second-order injection, open redirect, HTTP header injection |
| `scan_auth` | Session management flaws, JWT attacks (none algorithm, claim tampering, RS256→HS256 confusion), brute force resistance, password policy |
| `scan_authz` | IDOR, horizontal/vertical privilege escalation, RBAC bypass (requires multiple credential sets for best results) |
| `scan_client_side` | XSS (reflected/stored/DOM-based), CSRF token analysis, clickjacking, DOM XSS (static sink analysis + dynamic Playwright-based detection) |
| `scan_infrastructure` | SSL/TLS configuration, security headers (CSP, HSTS, X-Frame-Options, etc.), CORS misconfigurations, HTTP method enumeration |
| `scan_api` | REST parameter fuzzing, GraphQL depth/batch attacks, mass assignment / object injection testing |
| `scan_cloud` | S3 bucket enumeration/permissions, cloud metadata service access (AWS/GCP/Azure) |
| `scan_waf` | WAF detection and fingerprinting (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5, Fortinet, Sucuri, Barracuda, Wordfence), bypass testing |
| `scan_advanced` | HTTP request smuggling (CL.TE, TE.CL, TE.TE with 12 obfuscation variants), web cache poisoning/deception, insecure deserialization (Java/Python/PHP/.NET/YAML), prototype pollution, DNS rebinding |
| `scan_websocket` | CSWSH, WebSocket auth bypass, message injection (SQLi/XSS/CMDi via WebSocket), insecure transport detection |
| `scan_subdomain_takeover` | Dangling CNAME detection for 20+ services with HTTP response signature matching |

### Authentication & Authorization Deep Dive (2)

| Tool | Description |
|------|-------------|
| `scan_oauth` | OAuth/OIDC testing: redirect_uri manipulation (13+ bypass techniques), state parameter validation, token leakage via Referer, scope escalation |
| `scan_mfa_bypass` | 2FA/MFA bypass: direct endpoint access, OTP brute force, backup code abuse, race condition on code validation |

### Specialized Scanning (3)

| Tool | Description |
|------|-------------|
| `scan_file_handling` | File upload bypass (extension, MIME type, magic bytes), path traversal with encoding bypasses |
| `scan_business_logic` | Rate limiting adequacy, race conditions (concurrent requests), workflow bypass, state manipulation |
| `scan_mobile_static` | APK/IPA static analysis — AndroidManifest checks, jadx-decompiled secret/crypto sweep, iOS Info.plist ATS bypass + URL scheme + binary hardening |

### Intelligence Tools (2)

| Tool | Description |
|------|-------------|
| `exploit_chain_suggest` | Analyzes all findings against 14 chain rules to identify multi-step attack paths. Returns ranked chains with combined CVSS and exploitation narratives |
| `payload_generate` | Generates context-aware payloads optimized for the target's tech stack and WAF. Supports 13 attack types with framework-specific mutations and WAF bypass encodings |

### Browser & Authentication (4)

| Tool | Description |
|------|-------------|
| `browser_crawl` | SPA crawling via Playwright (Chromium headless) — intercepts network requests, discovers routes via `framenavigated`, evaluates DOM links/forms, extracts API endpoints from inline JavaScript |
| `scan_dom_xss` | DOM XSS detection: static script sink analysis (always runs) + dynamic Playwright-based payload injection via URL fragments/params (7 DOM XSS payloads: img onerror, svg onload, iframe onload, details ontoggle) |
| `authenticated_crawl` | Playwright crawl using active session credentials — injects cookies and Authorization headers for post-login endpoint discovery |
| `record_login_macro` | Interactive login recording via headed Playwright browser — tracks navigation events and network requests, extracts cookies/localStorage tokens, seeds endpoints from captured traffic |

### OAST (Out-of-Band Testing) (3)

| Tool | Description |
|------|-------------|
| `oast_init` | Initialize OAST session — auto-detects backend: interactsh-client if installed, `OAST_HOST` env var, or placeholder mode |
| `oast_new_url` | Generate a unique labeled callback URL for blind vulnerability detection (HTTP protocol) |
| `oast_poll` | Poll for received callbacks — returns probe hits with source IP, protocol, and raw request data |

### API Specification Import (1)

| Tool | Description |
|------|-------------|
| `import_api_spec` | Import OpenAPI 3.x, Swagger 2.0, or Postman v2.1 collection — resolves `$ref` references, generates body examples, seeds all endpoints into the session for scanning |

### Finding Lifecycle (2)

| Tool | Description |
|------|-------------|
| `suppress_finding` | Suppress a finding with a reason: `accepted_risk`, `wont_fix`, `false_positive`, `duplicate`, or `out_of_scope`. Suppressed findings are excluded from reports and counts by default |
| `unsuppress_finding` | Remove suppression — finding returns to active state |

### Scan History & Delta (4)

| Tool | Description |
|------|-------------|
| `save_scan` | Persist current session findings to `~/.pencheff/history/` as JSON |
| `list_scan_history` | List saved scans, optionally filtered by target URL |
| `compare_scans` | Compare two saved sessions — returns new findings, fixed findings, persisted findings, and severity regressions |
| `list_scan_profiles` | List all available scan profiles with module lists and configuration |

### Scoring (1)

| Tool | Description |
|------|-------------|
| `calculate_cvss40` | Calculate CVSS v4.0 base score from a vector string — returns numeric score and severity label |

### External Tool Execution (1)

| Tool | Description |
|------|-------------|
| `run_security_tool` | Execute allowlisted external security tools when they are installed and licensed for your environment. Returns stdout/stderr with intelligent next-step recommendations |

### Manual / Targeted Testing (3)

| Tool | Description |
|------|-------------|
| `test_endpoint` | Custom HTTP request with specific payloads against a single endpoint. Accepts `body` as string, dict, or list (auto-serialized). Supports `PENCHEFF` marker substitution |
| `test_chain` | Multi-step attack sequence with JSONPath variable extraction and substitution between steps |
| `analyze_response` | Analyze an HTTP response for information disclosure, error messages, sensitive data patterns (AWS keys, JWTs, emails), and missing security headers |

### Reporting & Export (5)

| Tool | Description |
|------|-------------|
| `get_findings` | Retrieve findings filtered by severity, category, or OWASP category; toggle suppressed finding visibility |
| `generate_report` | Full pentest report — executive summary, technical details, CVSS scores, 6-framework compliance mapping (Markdown/JSON) |
| `export_report` | Export to **Word (.docx)**, **CSV**, and **JSON** simultaneously. Includes verification status, suppression state, and all 6 compliance frameworks. Saved to `~/pencheff-reports/<session_id>/` |
| `verify_finding` | Set verification status: `true_positive`, `false_positive`, `true_negative`, `false_negative`, or `unverified` |
| `check_dependencies` | Verify Python packages and all 116 system tools; reports capability gaps with install instructions |

### Ticketing Export (2)

| Tool | Description |
|------|-------------|
| `export_to_github` | Create GitHub Issues from findings via `gh` CLI — severity labels, OWASP category labels, full evidence and compliance mapping in issue body. Supports `dry_run` preview |
| `export_to_jira` | Create Jira tickets via REST API v3 — Atlassian Document Format (ADF) descriptions, priority mapping, severity labels. Reads `JIRA_URL`, `JIRA_TOKEN`, `JIRA_EMAIL`, `JIRA_PROJECT` env vars |

## Attack Modules (57)

### Reconnaissance (5 modules)

| Module | File | Techniques |
|--------|------|------------|
| DNS Enumeration | `recon/dns_enum.py` | A/AAAA/MX/TXT/NS/CNAME records, AXFR zone transfer, SPF/DMARC analysis |
| Subdomain Discovery | `recon/subdomain.py` | Certificate transparency logs, DNS brute force |
| Technology Fingerprint | `recon/tech_fingerprint.py` | Headers, cookies, HTML patterns, JavaScript framework detection |
| Port Scanner | `recon/port_scan.py` | TCP connect scan (top-100/top-1000), banner grabbing, service identification |
| Subdomain Takeover | `recon/subdomain_takeover.py` | Dangling CNAME detection for 20+ services, NS delegation takeover check |

### Web Infrastructure (7 modules)

| Module | File | Techniques |
|--------|------|------------|
| Web Crawler | `web/crawler.py` | Recursive HTTP spidering, endpoint discovery, parameter extraction |
| Browser Crawler | `web/browser_crawler.py` | Playwright Chromium headless — network request interception, SPA route discovery via `framenavigated`, DOM link/form extraction, inline JS API pattern matching |
| Web Server Scan | `web/server_scan.py` | First-party `webscan` engine: headers, cookies, HTTP methods, exposed files, default pages, directory listings, diagnostics, backup artifacts |
| SSL/TLS | `web/ssl_tls.py` | Protocol version check, weak cipher detection, certificate analysis |
| Security Headers | `web/headers.py` | 7+ header checks (HSTS, CSP, X-Frame-Options, etc.), cookie flag analysis |
| CORS | `web/cors.py` | Wildcard origin, reflected origin, null origin, subdomain bypass, credential leak |
| HTTP Methods | `web/http_methods.py` | PUT/DELETE/TRACE/CONNECT enumeration, method override testing |

### Injection (10 modules)

| Module | File | Techniques |
|--------|------|------------|
| SQL Injection | `injection/sqli.py` | First-party `sqlprobe` engine: error, blind boolean, capped time, UNION-shape, safe stacked probes, request/Burp/bulk/crawl import, tamper/profile/cache/evidence support |
| NoSQL Injection | `injection/nosqli.py` | MongoDB operator injection ($gt, $ne, $regex, $where), JavaScript injection |
| Command Injection | `injection/cmdi.py` | Pipe, semicolon, backtick, $() with output-based and time-based detection |
| SSTI | `injection/ssti.py` | Jinja2, Twig, Freemarker, ERB, Mako template detection and exploitation |
| XXE | `injection/xxe.py` | Classic external entity, blind XXE, parameter entities, billion laughs detection |
| SSRF | `injection/ssrf.py` | Cloud metadata (AWS/GCP/Azure), internal scanning, IP encoding bypasses (octal, hex, IPv6), OAST blind detection via interactsh-client |
| LDAP Injection | `injection/ldap.py` | Filter injection, authentication bypass, blind boolean LDAP |
| Second-Order Injection | `injection/second_order.py` | Stored SQLi/XSS/SSTI via two-phase inject-then-trigger with canary markers |
| Open Redirect | `injection/open_redirect.py` | 25+ redirect parameter names, 12 bypass techniques (protocol-relative, encoding, backslash, null byte) |
| Header Injection | `injection/header_injection.py` | CRLF injection, HTTP response splitting, host header poisoning for password reset attacks |

### Authentication (7 modules)

| Module | File | Techniques |
|--------|------|------------|
| Session Management | `auth/session_mgmt.py` | Session timeout, fixation, hijacking, concurrent session testing |
| JWT Attacks | `auth/jwt_attacks.py` | None algorithm, claim tampering, key confusion (RS256→HS256), expiration checks |
| Brute Force | `auth/brute_force.py` | Account enumeration, lockout policy detection, rate limit testing |
| Password Policy | `auth/password_policy.py` | Complexity requirements, common password acceptance |
| OAuth/OIDC | `auth/oauth_attacks.py` | redirect_uri bypass (13+ techniques), state parameter validation, token leakage, scope escalation, PKCE bypass |
| MFA Bypass | `auth/mfa_bypass.py` | Direct endpoint access, OTP brute force, backup code abuse, race condition on validation |
| Login Macro | `auth/login_macro.py` | Playwright headed browser for interactive login recording; auto-login fallback with fill/click/wait steps; extracts cookies and localStorage tokens; seeds discovered endpoints from captured network traffic |

### Authorization (3 modules)

| Module | File | Techniques |
|--------|------|------------|
| IDOR | `authz/idor.py` | Numeric ID manipulation, UUID enumeration, cross-user access testing |
| Privilege Escalation | `authz/privilege_esc.py` | Vertical/horizontal escalation via parameter and path manipulation |
| RBAC Bypass | `authz/rbac_bypass.py` | Role injection, forced browsing, path normalization bypass |

### Client-Side (4 modules)

| Module | File | Techniques |
|--------|------|------------|
| XSS | `client_side/xss.py` | Reflected, stored indicators, DOM-based, context-aware detection, encoding bypasses |
| DOM XSS | `client_side/dom_xss.py` | Static: regex extraction of `<script>` blocks, source→sink proximity analysis. Dynamic (Playwright): 7 payload types injected via URL fragment and query params — img onerror, svg onload, iframe onload, details ontoggle |
| CSRF | `client_side/csrf.py` | Token absence/weakness, SameSite bypass, custom header bypass |
| Clickjacking | `client_side/clickjacking.py` | X-Frame-Options testing, CSP frame-ancestors analysis |

### API Security (4 modules)

| Module | File | Techniques |
|--------|------|------------|
| REST Discovery | `api/rest_discovery.py` | OpenAPI/Swagger detection (15+ common paths), GraphQL introspection, full endpoint seeding via `parse_api_spec` with `$ref` resolution and body examples |
| GraphQL | `api/graphql.py` | Introspection dump, query depth limits, batch query limits, field suggestion |
| API Fuzzer | `api/api_fuzzer.py` | Parameter type fuzzing, boundary values, method enumeration |
| Mass Assignment | `api/mass_assignment.py` | Privilege property injection (role, admin, is_staff), framework-specific payloads (Rails, Django, Node.js, Laravel) |

### Business Logic (3 modules)

| Module | File | Techniques |
|--------|------|------------|
| Rate Limiting | `logic/rate_limiting.py` | Rapid request burst testing, rate limit header analysis |
| Race Conditions | `logic/race_condition.py` | Concurrent request testing for double-spend, TOCTOU |
| Workflow Bypass | `logic/workflow_bypass.py` | Multi-step process skip, state manipulation |

### Cloud (2 modules)

| Module | File | Techniques |
|--------|------|------------|
| S3 Enumeration | `cloud/s3_enum.py` | Bucket naming patterns, public listing, permission testing |
| Cloud Metadata | `cloud/metadata.py` | IMDSv1/v2 access via SSRF, credential theft |

### File Handling (2 modules)

| Module | File | Techniques |
|--------|------|------------|
| File Upload | `file_handling/upload.py` | Extension bypass (double ext, null byte), MIME type confusion, magic byte injection |
| Path Traversal | `file_handling/path_traversal.py` | LFI with encoding bypasses (double URL encoding, UTF-8, null byte) |

### Advanced (7 modules)

| Module | File | Techniques |
|--------|------|------------|
| WAF Detection | `advanced/waf_detection.py` | Fingerprinting for 10 WAF vendors via response signature matching, encoding/obfuscation bypass testing |
| HTTP Smuggling | `advanced/http_smuggling.py` | CL.TE, TE.CL desync via raw sockets, TE.TE with 12 header obfuscation variants, CRLF request splitting |
| Cache Poisoning | `advanced/cache_poisoning.py` | Unkeyed header injection (10 headers), cache deception via path suffix, fat GET parameter cloaking |
| Deserialization | `advanced/deserialization.py` | Java (magic bytes, ysoserial endpoints), Python pickle, PHP unserialize, .NET ViewState, YAML constructor injection |
| Prototype Pollution | `advanced/prototype_pollution.py` | Server-side JSON body pollution (`__proto__`, `constructor.prototype`), client-side URL parameter pollution, gadget detection |
| DNS Rebinding | `advanced/dns_rebinding.py` | Host header validation assessment, IP binding check |
| WebSocket Security | `advanced/websocket_security.py` | CSWSH (origin validation), auth bypass, message injection, insecure transport, auto-discovery from JavaScript |

## Payload Library (326 payloads across 17 files)

| File | Payloads | Description |
|------|----------|-------------|
| `sqli.txt` | 20 | Error-based, UNION, time-based, blind boolean SQLi |
| `xss.txt` | 18 | Reflected XSS, encoding bypasses, event handlers, javascript: protocol |
| `ssti.txt` | 10 | Jinja2, Twig, Mako, ERB, Freemarker template payloads |
| `path_traversal.txt` | 16 | ../../../, encoding variants, Windows paths, null byte |
| `xxe.txt` | 18 | External entity, blind OOB, parameter entity, CDATA exfil, PHP/Java-specific |
| `nosqli.txt` | 13 | MongoDB operators ($gt, $ne, $regex, $where), URL-encoded variants |
| `cmdi.txt` | 24 | Pipe, semicolon, backtick, $(), blind via sleep/ping, argument injection |
| `ssrf.txt` | 23 | Cloud metadata (AWS/GCP/Azure/DO), IP encoding (octal, hex, IPv6), protocol tricks |
| `waf_bypass.txt` | 38 | Double encoding, Unicode, case mutation, nested tags, comment injection, null byte |
| `oauth.txt` | 20 | redirect_uri bypass (subdomain, encoding, fragment, protocol-relative, backslash) |
| `deserialization.txt` | 19 | Java gadget indicators, Python pickle, PHP objects, YAML constructors, Node.js |
| `smuggling.txt` | 27 | CL.TE/TE.CL probes, 12 TE obfuscation variants, CRLF sequences, H2 smuggling |
| `prototype_pollution.txt` | 15 | `__proto__` JSON injection, constructor.prototype, URL parameter variants |
| `websocket.txt` | 15 | XSS/SQLi/CMDi via WebSocket, oversized messages, admin channel subscribe |
| `ldap.txt` | 15 | Filter injection (*, )(, \00), auth bypass, attribute enumeration |
| `open_redirect.txt` | 25 | Protocol-relative, double encoding, null byte, @-bypass, backslash, data: URI |
| `header_injection.txt` | 10 | CRLF injection (%0d%0a), response splitting, Set-Cookie injection |

## Architecture

```
plugins/pencheff/
├── .mcp.json                        # MCP server launch config
├── .github/workflows/
│   └── pencheff-scan.yml            # GitHub Actions CI/CD workflow
└── pencheff/
    ├── __main__.py                  # CLI entry: serve | scan | history | compare
    ├── server.py                    # FastMCP server — 49 tools, 1 prompt
    ├── config.py                    # Constants, 6 compliance maps, 6 scan profiles
    ├── core/
    │   ├── session.py               # PentestSession state (endpoints, subdomains, tech
    │   │                            #   stack, WebSocket/OAuth endpoints, WAF info, chains)
    │   ├── credentials.py           # MaskedSecret, CredentialSet, CredentialStore
    │   ├── findings.py              # Finding model, CVSS scoring, deduplication,
    │   │                            #   SuppressReason enum, FindingsDB with lifecycle
    │   ├── http_client.py           # httpx wrapper: HTTP/1.1, HTTP/2, WebSocket, raw
    │   │                            #   sockets, credential injection, rate limiting
    │   ├── openapi_import.py        # OpenAPI 3.x / Swagger 2.0 / Postman v2.1 parser;
    │   │                            #   $ref resolution, body example generation
    │   ├── oast.py                  # OAST probe manager — interactsh-client, custom
    │   │                            #   OAST_HOST, or placeholder mode
    │   ├── scan_history.py          # Delta scanning — save/list/compare sessions;
    │   │                            #   fingerprint-based new/fixed/regressed tracking
    │   ├── ticketing.py             # GitHub Issues (gh CLI) + Jira REST API v3 export
    │   ├── payload_loader.py        # Centralized payload file loader
    │   ├── tool_runner.py           # Safe subprocess execution (no shell=True)
    │   └── dependency_manager.py   # Python/system tool availability (116 tools);
    │                                #   Playwright capability check
    ├── modules/
    │   ├── base.py                  # BaseTestModule ABC
    │   ├── recon/                   # 5 modules: DNS, subdomains, tech fingerprint,
    │   │                            #   port scan, subdomain takeover
    │   ├── web/                     # 6 modules: crawler, browser_crawler (Playwright),
    │   │                            #   SSL/TLS, headers, CORS, HTTP methods
    │   ├── injection/               # 10 modules: SQLi, NoSQLi, CMDi, SSTI, XXE,
    │   │                            #   SSRF (OAST-enabled), LDAP, second-order,
    │   │                            #   open redirect, header injection
    │   ├── auth/                    # 7 modules: session mgmt, JWT, brute force,
    │   │                            #   password policy, OAuth/OIDC, MFA bypass,
    │   │                            #   login_macro (Playwright)
    │   ├── authz/                   # 3 modules: IDOR, privilege escalation, RBAC bypass
    │   ├── client_side/             # 4 modules: XSS, DOM XSS (Playwright), CSRF,
    │   │                            #   clickjacking
    │   ├── api/                     # 4 modules: REST discovery (OpenAPI import),
    │   │                            #   GraphQL, API fuzzer, mass assignment
    │   ├── logic/                   # 3 modules: rate limiting, race conditions,
    │   │                            #   workflow bypass
    │   ├── cloud/                   # 2 modules: S3 enum, metadata service
    │   ├── file_handling/           # 2 modules: upload bypass, path traversal
    │   └── advanced/                # 7 modules: WAF detection, HTTP smuggling,
    │                                #   cache poisoning, deserialization, prototype
    │                                #   pollution, DNS rebinding, WebSocket security
    ├── reporting/
    │   ├── cvss.py                  # CVSS v3.1 + CVSS v4.0 base score calculators
    │   ├── compliance.py            # 6-framework compliance summary (OWASP, PCI-DSS,
    │   │                            #   NIST, SOC 2, ISO 27001, HIPAA)
    │   ├── renderer.py              # Markdown and JSON report rendering
    │   └── exporter.py             # Word (.docx), CSV, JSON file export
    └── payloads/                    # 17 payload files, 326 total payloads
```

## How It Works

### Adaptive Intelligence

Every tool returns a structured response:

```json
{
  "findings": [...],
  "findings_summary": { "critical": 1, "high": 3, "medium": 5, "low": 2, "info": 4 },
  "next_steps": [
    "WAF detected: Cloudflare. Use payload_generate to create WAF-aware payloads.",
    "3 bypass techniques succeeded — use these for injection scans.",
    "Run scan_injection and scan_advanced with WAF-aware strategy."
  ]
}
```

The Pencheff engine reads these `next_steps` and decides what to test next. This feedback loop means Pencheff adapts to each target instead of running the same static checks every time.

### Exploitation-First Methodology

Pencheff doesn't just scan — it **hacks**. The agent follows 7 core rules:

1. **Verify, don't just scan** — After every scan tool, use `test_endpoint` or focused first-party probes to verify findings with harmless PoC payloads.
2. **Eliminate false positives** — Re-test with different payloads, confirm manually. An elite report has 5 verified criticals, not 50 unverified potentials.
3. **Chain everything** — Every finding is a building block. SSRF + cloud metadata = credential theft. XSS + weak sessions = account takeover. Use `exploit_chain_suggest` and `test_chain`.
4. **Go deep safely** — Don't stop at the first layer; prove impact with non-destructive evidence and avoid accessing secrets or executing destructive actions.
5. **Adapt to defenses** — WAF detected? Generate bypass payloads. Rate limited? Slow down and rotate.
6. **Use first-party engines first** — Use Pencheff map/recon_active for ports, Pencheff webscan/scan_infrastructure for web server exposure, Pencheff sqli/scan_injection for SQLi, and Pulse/scan_pulse for template scanning. Use auxiliary tools only where they add value.
7. **Manual hacking between scans** — Use `test_endpoint` to probe interesting behavior. Don't wait for a scan tool.

### Testing Phases (10)

The built-in `pentest_methodology` prompt guides the Pencheff engine through a comprehensive 10-phase assessment:

1. **Preparation** — Initialize session with `pentest_init`, verify tools, run Pencheff recon_active
2. **Reconnaissance** — Map full attack surface: DNS, subdomains, ports, tech stack, APIs. Use `subfinder`, `amass`, `whatweb`
3. **Infrastructure** — web server exposure, SSL/TLS, security headers, CORS, HTTP methods. Use `pencheff webscan`, `sslscan`, `testssl`
4. **Authentication** — Session management, JWT vulnerabilities, brute force resistance. Use `hydra` for credential testing
5. **WAF Detection** — Fingerprint WAF with `scan_waf` and `wafw00f` before injection testing
6. **Injection Warfare** — 10 injection types across all discovered endpoints. Use `scan_injection` and `pencheff sqli` for SQLi confirmation, verify every finding with `test_endpoint`
7. **Advanced Attacks** — HTTP smuggling, cache poisoning, deserialization, prototype pollution. Use `scan_pulse` for template-based detection
8. **API, Business Logic & Specialized** — GraphQL, mass assignment, race conditions, cloud, file handling, OAuth, MFA bypass, WebSocket, subdomain takeover
9. **Exploit Chain Analysis** — Automatic chain detection with `exploit_chain_suggest` + manual verification with `test_chain`
10. **Reporting** — CVSS-scored findings with 6-framework compliance mapping; export to Word/CSV/JSON; create GitHub Issues or Jira tickets

### OpenAPI / Swagger / Postman Import

`import_api_spec` parses API specification files and seeds all endpoints directly into the session, enabling full coverage without crawling:

```
# Import from a local file or URL
import_api_spec(session_id, content="<spec content>", base_url="https://api.example.com", hint="auto")
```

- **OpenAPI 3.x**: full `$ref` resolution, request body example generation, parameter typing
- **Swagger 2.0**: body parameter extraction, basePath resolution
- **Postman v2.1**: recursive folder traversal, variable substitution in URLs
- Returns `spec_type`, `title`, `version`, `endpoint_count`, and all endpoint details

### OAST — Blind Vulnerability Detection

Out-of-Band Application Security Testing detects vulnerabilities that produce no visible response change:

```
oast_init(session_id)         # registers with interactsh-client backend
oast_new_url(session_id, "ssrf-probe-1")  # → http://<probe_id>.oast.fun
# inject into target payload
oast_poll(session_id)         # returns any callbacks received
```

Backend priority:
1. **interactsh-client** (ProjectDiscovery) — if installed via `go install`
2. **`OAST_HOST` env var** — custom collaborator server
3. **Placeholder mode** — generates valid-looking URLs for payload construction; won't receive real callbacks

The SSRF module automatically generates and injects OAST HTTP and DNS callbacks alongside standard payloads.

### Delta Scanning

Track vulnerability lifecycle across scan sessions:

```
save_scan(session_id)                          # saves to ~/.pencheff/history/
compare_scans(session_id_a, session_id_b)      # baseline vs current
```

Compare output includes:
- **new_findings** — in current scan but not baseline (regressions)
- **fixed_findings** — in baseline but not current (resolved)
- **persisted** — present in both
- **regressions** — same finding but higher severity in current scan

Fingerprint: `endpoint|parameter|category|title`

### Finding Suppression Lifecycle

Manage noise and acknowledged risks without deleting findings:

| Reason | Meaning |
|--------|---------|
| `accepted_risk` | Known risk, business decision to accept |
| `wont_fix` | Acknowledged but not in remediation scope |
| `false_positive` | Scanner error — not actually vulnerable |
| `duplicate` | Same vulnerability already tracked elsewhere |
| `out_of_scope` | Valid finding but outside the agreed test scope |

Suppressed findings are excluded from `count`, reports, and exports by default. They persist with `suppressed_at` timestamp, reason, and notes. `unsuppress_finding` fully restores them.

### CVSS Scoring

Pencheff calculates scores for both versions:

**CVSS v3.1** — Full base score calculator using the official formula (Impact + Exploitability sub-scores, scope modifier). Every finding ships with a pre-calculated v3.1 vector and score.

**CVSS v4.0** — Base score calculator supporting the v4.0 metric groups:
- Attack Vector (AV), Attack Complexity (AC), Attack Requirements (AT)
- Privileges Required (PR), User Interaction (UI)
- Vulnerable System (VC/VI/VA), Subsequent System (SC/SI/SA)
- Uses the official EQ lookup table approach for scoring

```
calculate_cvss40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
# → { "score": 9.0, "severity": "Critical", "vector": "..." }
```

### Exploit Chain Analysis

The `exploit_chain_suggest` tool evaluates all findings against 14 chain rules:

| Chain | Components | Impact |
|-------|------------|--------|
| SSRF + Cloud Metadata | SSRF → metadata service → IAM credentials | Full cloud account compromise |
| XSS + Weak Sessions | XSS → session theft → account takeover | User compromise |
| Open Redirect + OAuth | Redirect → redirect_uri bypass → token theft | OAuth token theft |
| SQLi + Credential Reuse | SQLi → credential dump → admin login | Full application compromise |
| File Upload + Traversal | Upload bypass → path traversal → web shell | Remote code execution |
| HTTP Smuggling + Cache | Desync → cache poisoning → mass XSS | All users compromised |
| Prototype Pollution + XSS | `__proto__` pollution → gadget chain → stored XSS | Persistent XSS |
| Deserialization | Serialized object → gadget chain → RCE | Remote code execution |
| MFA Bypass + Auth | Skip 2FA → full authenticated access | Authentication bypass |
| Mass Assignment + Authz | Property injection → role escalation → admin | Privilege escalation |

### Compliance Mapping

Every finding automatically maps to all 6 frameworks based on vulnerability category:

| Framework | Controls |
|-----------|---------|
| **OWASP Top 10 2021** | A01–A10 category with full name |
| **PCI-DSS 4.0** | Requirements 2.2, 4.1, 6.2, 6.5.x, 6.6, 7.x, 8.x |
| **NIST 800-53** | AC, AU, CM, IA, SC, SI control families |
| **SOC 2** | Trust Services Criteria: CC6.x, CC7.x, A1.x |
| **ISO 27001:2022** | Annex A controls: A.5.x, A.8.x |
| **HIPAA Security Rule** | Safeguards: 164.308, 164.312 |

Reports include per-framework coverage summaries showing which OWASP categories and categories were tested.

### Verification Status

Every finding carries a `verification_status` field:

| Status | Meaning |
|--------|---------|
| `unverified` | Default — scan detected it, not yet manually verified |
| `true_positive` | Confirmed exploitable via `test_endpoint` |
| `false_positive` | Debunked — scan flagged it but manual testing shows it's safe |
| `true_negative` | Confirmed absent — tested and verified not present |
| `false_negative` | Missed by scanner — found via manual testing after scan reported clean |

Use `verify_finding` to set the status. All export formats include this field.

### Report Export Formats

The `export_report` tool saves findings to three formats simultaneously:

| Format | File | Use Case |
|--------|------|----------|
| **Word (.docx)** | `pencheff_report_<timestamp>.docx` | Professional report for stakeholders — formatted tables, severity colors, compliance mapping, remediation roadmap |
| **CSV** | `pencheff_findings_<timestamp>.csv` | Import into Jira, Linear, or spreadsheets — one row per finding with all fields including suppression and compliance |
| **JSON** | `pencheff_findings_<timestamp>.json` | Programmatic analysis, CI/CD integration, data pipelines |

All files saved to `~/pencheff-reports/<session_id>/` by default.

CSV columns include: `id`, `title`, `severity`, `cvss_score`, `cvss_vector`, `category`, `owasp`, `endpoint`, `parameter`, `cwe`, `verification_status`, `suppressed`, `suppress_reason`, `suppress_notes`, `pci_dss`, `nist`, `soc2`, `iso27001`, `hipaa`, `description`, `remediation`.

JSON export includes: all findings with full evidence, `suppressed_findings` list, and compliance summaries for all 6 frameworks.

### Ticketing Integration

**GitHub Issues** (requires `gh` CLI):
```
export_to_github(session_id, repo="myorg/myapp", severities=["critical","high"])
```
Each issue includes: severity label, `owasp:<category>` label, `security` label, full evidence, compliance mapping table, remediation steps.

**Jira** (requires `JIRA_URL`, `JIRA_TOKEN`, `JIRA_EMAIL` env vars):
```
export_to_jira(session_id, project_key="SEC", severities=["critical","high","medium"])
```
Issues created as Bugs with: priority mapping (critical→Highest, high→High, etc.), `security-<severity>` + `pentest` + `pencheff` labels, ADF-formatted description with endpoint, CVSS, CWE, OWASP, remediation.

Both support `dry_run=True` for preview without creating issues.

### HTTP Client Capabilities

The core `PencheffHTTPClient` provides:

- **HTTP/1.1 and HTTP/2** — configurable per session
- **WebSocket support** — via `websockets` library for WebSocket security testing
- **Raw socket connections** — via `asyncio.open_connection` for HTTP smuggling (sends malformed HTTP that httpx would refuse)
- **Rate limiting** — configurable max requests per second
- **Credential injection** — automatic header injection (Bearer, Basic, API key, Cookie, custom headers)
- **SSL verification toggle** — disabled by default for testing self-signed certs
- **Connection pooling** — max 20 connections, 10 keepalive
- **Request audit logging** — every request logged with method, URL, status, module, and duration

## Test Depth

| Depth | Description |
|-------|-------------|
| `quick` | Fast scan — common vulnerabilities only, fewer payloads |
| `standard` | Balanced coverage and speed (default) |
| `deep` | Thorough testing — all payloads, extended port ranges, full crawl |

## Dependencies

### Python (all required, auto-installed)

- `mcp[cli]` — MCP protocol SDK
- `httpx[http2]` — Async HTTP client (HTTP/1.1 and HTTP/2)
- `pydantic` — Data validation
- `pyjwt` — JWT token analysis
- `cryptography` — SSL/TLS and crypto operations
- `jinja2` — Report template rendering
- `pyyaml` — YAML parsing (OpenAPI YAML specs)
- `dnspython` — DNS enumeration
- `beautifulsoup4` + `lxml` — HTML parsing
- `anyio` — Async runtime
- `python-docx` — Word document generation
- `boto3` — AWS S3 bucket testing
- `paramiko` — SSH testing
- `websockets` — WebSocket security testing
- `h2` — HTTP/2 support
- `playwright` — Browser crawler, DOM XSS detection, login macro recording, authenticated crawl

After installing, run once to download the Chromium browser binary:

```bash
playwright install chromium
```

The agent will run this automatically if Chromium is not yet installed.

### OAST (recommended)

```bash
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

Used by the SSRF module and OAST tools to detect blind out-of-band callbacks. Without it, OAST runs in placeholder mode — payloads are constructed but callbacks won't be received. Set `OAST_HOST` env var to use a custom collaborator server instead.

## External Security Tools (116)

All 116 tools are allowlisted for execution via `run_security_tool`. Pencheff runs them with safe subprocess execution (no `shell=True`, array arguments only). Use `check_dependencies` to see which are installed.

### Network Scanning (10)

| Tool | Description |
|------|-------------|
| `ipscan` | Angry IP Scanner — fast IP address and port scanning |
| `fping` | Fast ICMP ping to multiple hosts simultaneously |
| `unicornscan` | Asynchronous TCP/UDP scanner for large networks |
| `netcat` | Port scanning, file transfer, reverse shells, banner grabbing |
| `masscan` | Ultra-fast port scanning (100K+ ports/sec) |
| `naabu` | Fast port scanner (ProjectDiscovery) — SYN/CONNECT scanning |
| `nessus` | Tenable vulnerability scanner — comprehensive network assessment |
| `hping3` | Packet crafting and analysis — firewall testing, idle scanning |

### Vulnerability Scanning (5)

| Tool | Description |
|------|-------------|
| `openvas` | Open Vulnerability Assessment Scanner |
| `gvm-cli` | Greenbone Vulnerability Management CLI |
| `skipfish` | Web app security recon with interactive sitemap |
| `vega` | Web vulnerability scanner — SQLi, XSS, sensitive data |

### Password Cracking (9)

| Tool | Description |
|------|-------------|
| `john` | John the Ripper — 100s of hash types |
| `hashcat` | GPU-accelerated password recovery — 300+ hash types |
| `rcrack` | RainbowCrack — precomputed rainbow table attacks |
| `aircrack-ng` | WiFi security suite — WEP/WPA/WPA2 cracking |
| `hydra` | Network login brute-forcer — 50+ protocols |
| `medusa` | Parallel network login brute-forcer |
| `l0phtcrack` | Password auditing — dictionary, brute-force, rainbow tables |
| `cowpatty` | WPA2-PSK brute-force cracking |
| `ophcrack` | Windows password cracker using rainbow tables |

### Exploitation (10)

| Tool | Description |
|------|-------------|
| `msfconsole` | Metasploit Framework — exploit development, post-exploitation |
| `msfvenom` | Metasploit payload generator — shellcode, executables, scripts |
| `msfdb` | Metasploit database management |
| `setoolkit` | Social-Engineer Toolkit — phishing, credential harvesting |
| `beef-xss` | Browser Exploitation Framework — XSS targeting browser sessions |
| `armitage` | Graphical Metasploit frontend |
| `zap-cli` | OWASP ZAP CLI — automated web security scanning |
| `zaproxy` | OWASP Zed Attack Proxy |
| `commix` | Automated OS command injection exploiter |

### Packet Sniffing & Spoofing (9)

| Tool | Description |
|------|-------------|
| `tshark` | Wireshark CLI — deep packet inspection |
| `tcpdump` | Command-line packet analyzer |
| `ettercap` | MitM attack suite — ARP spoofing, DNS spoofing |
| `bettercap` | Network attack Swiss Army knife — WiFi, BLE, Ethernet MitM |
| `snort` | Intrusion detection/prevention system |
| `ngrep` | Network grep — pattern-matching packet analyzer |
| `nemesis` | Packet crafting and injection |
| `scapy` | Interactive packet manipulation |
| `dsniff` | Password sniffer — network auditing |

### Wireless Hacking (7)

| Tool | Description |
|------|-------------|
| `wifite` | Automated wireless auditing — WEP/WPA/WPS attacks |
| `kismet` | Wireless detector, sniffer, IDS — WiFi, Bluetooth, Zigbee, RF |
| `reaver` | WPS brute-force — recover WPA/WPA2 passphrases |
| `bully` | WPS brute-force (C-based) |
| `wifiphisher` | Rogue AP framework — WiFi phishing |
| `hostapd-wpe` | Rogue RADIUS server for WPA2-Enterprise attacks |
| `mdk4` | WiFi testing — beacon flooding, deauth, WDS confusion |

### Directory / Path Brute Force (6)

| Tool | Description |
|------|-------------|
| `ffuf` | Fast web fuzzer — directory brute force, parameter fuzzing, vhost discovery |
| `gobuster` | Directory/DNS/vhost brute-force — fast, Go-based |
| `dirb` | Web content scanner — recursive directory brute force |
| `wfuzz` | Web fuzzer — headers, POST data, URLs, authentication |
| `feroxbuster` | Recursive content discovery — smart wordlists, auto-filtering |
| `dirsearch` | Web path brute-forcer with recursive scanning |

### Web Application Hacking (5)

| Tool | Description |
|------|-------------|
| `whatweb` | Web technology fingerprinting — CMS, frameworks, servers |
| `wafw00f` | WAF fingerprinting — identifies 100+ WAF products |
| `wpscan` | WordPress vulnerability scanner — plugins, themes, users |
| `dalfox` | XSS scanner with DOM analysis and parameter mining |
| `xsstrike` | Advanced XSS detection — fuzzing, crawling, context analysis |

### Subdomain Enumeration (7)

| Tool | Description |
|------|-------------|
| `subfinder` | Passive subdomain discovery (ProjectDiscovery) — 30+ sources |
| `amass` | OWASP attack surface mapping — active/passive subdomain enumeration |
| `fierce` | DNS reconnaissance — subdomain brute-forcing |
| `dnsrecon` | DNS enumeration — zone transfers, brute force, cache snooping |
| `sublist3r` | Subdomain enumeration via search engines |
| `knockpy` | Subdomain scanner with takeover detection |
| `dnsenum` | DNS enumeration — subdomains, MX, NS, zone transfers |

### DNS Tools (3)

| Tool | Description |
|------|-------------|
| `dig` | DNS lookups with full record control |
| `whois` | Domain registration info — registrar, nameservers, dates |
| `host` | Simple DNS lookup — forward and reverse |

### SSL/TLS Testing (4)

| Tool | Description |
|------|-------------|
| `sslscan` | SSL/TLS scanner — cipher suites, protocols, certificate analysis |
| `testssl` | Comprehensive SSL/TLS testing — BEAST, POODLE, Heartbleed |
| `sslyze` | Fast SSL/TLS scanner — certificate validation, protocol support |
| `openssl` | SSL/TLS cryptography toolkit |

### OSINT / Social Engineering (9)

| Tool | Description |
|------|-------------|
| `theHarvester` | OSINT — emails, subdomains, IPs from public sources |
| `maltego` | OSINT and link analysis — 100s of data sources |
| `recon-ng` | Web reconnaissance framework — modular OSINT collection |
| `sherlock` | Username enumeration across 400+ social networks |
| `spiderfoot` | Automated OSINT collection — 200+ data sources |
| `gophish` | Phishing campaign toolkit |
| `king-phisher` | Phishing simulation — credential harvesting |
| `evilginx2` | MitM framework — session cookie theft, 2FA bypass |
| `social-engineer-toolkit` | SET — social engineering attack framework |

### Digital Forensics (8)

| Tool | Description |
|------|-------------|
| `autopsy` | Digital forensics platform — disk image analysis |
| `foremost` | File recovery/carving for forensic analysis |
| `scalpel` | Fast file carver — improved Foremost |
| `fls` | The Sleuth Kit — list files in disk images |
| `mmls` | The Sleuth Kit — partition layout display |
| `icat` | The Sleuth Kit — extract file content from images |
| `volatility` | Memory forensics framework — RAM analysis |
| `binwalk` | Firmware analysis — extract embedded files and code |

### Post-Exploitation / Credentials (10)

| Tool | Description |
|------|-------------|
| `mimikatz` | Windows credential extraction — pass-the-hash, pass-the-ticket |
| `crackmapexec` | Post-exploitation — SMB, LDAP, WinRM, MSSQL credential testing |
| `impacket-secretsdump` | Dump NTLM hashes, Kerberos tickets from DC |
| `impacket-psexec` | Remote command execution via SMB |
| `impacket-smbexec` | SMB-based remote execution |
| `impacket-wmiexec` | WMI-based remote execution |
| `responder` | LLMNR/NBT-NS/MDNS poisoner — credential capture on LAN |
| `enum4linux` | SMB/Windows enumeration — shares, users, groups, policies |
| `smbclient` | SMB client — connect to file shares |
| `pcredz` | Credential extraction from PCAP files — 20+ protocols |

### Web Proxy / API Testing (3)

| Tool | Description |
|------|-------------|
| `curl` | HTTP requests — full protocol control, auth, proxies |
| `wget` | HTTP downloader — recursive website mirroring |
| `httpx-toolkit` | HTTP probing (ProjectDiscovery) — tech detection, status codes |

### Static Analysis / Secret Scanning (4)

| Tool | Description |
|------|-------------|
| `semgrep` | Static analysis — 5000+ rules across 30+ languages |
| `bandit` | Python security analysis |
| `trufflehog` | Secret scanning — git repos, S3 buckets, filesystem |
| `git-dumper` | Extract git repositories from misconfigured web servers |

### Miscellaneous (4)

| Tool | Description |
|------|-------------|
| `interactsh-client` | OAST out-of-band callback detection (ProjectDiscovery) — blind SSRF/SQLi/XSS |
| `gau` | URL discovery from web archives — AlienVault, Wayback, CommonCrawl |
| `waybackurls` | Fetch URLs from Wayback Machine |
| `xsser` | Cross-site scripting framework — automated XSS exploitation |

## Recommended Test Targets

For testing Pencheff, use intentionally vulnerable applications:

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — `docker run -p 3000:3000 bkimminich/juice-shop`
- [DVWA](https://github.com/digininja/DVWA) — `docker run -p 80:80 vulnerables/web-dvwa`
- [WebGoat](https://owasp.org/www-project-webgoat/) — `docker run -p 8080:8080 webgoat/webgoat`

**Never run penetration tests against systems you do not own or have explicit written authorization to test.**

## License

MIT

## Author

**Bala Sriharsha** — [github.com/BalaSriharsha-Ch](https://github.com/BalaSriharsha-Ch)
