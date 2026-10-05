# Pencheff Engagement Lifecycle

Adapted from
[0xSteph/pentest-ai-agents](https://github.com/0xSteph/pentest-ai-agents)'s
swarm-orchestrator methodology. Each phase is encoded in pencheff Python
playbooks and driven by `pencheff engage`.

## Quick start

```bash
# 1. Declare scope
cat > scope.yaml <<'EOF'
client: ACME Corp
type: webapp                  # external | internal | webapp | cloud | wireless | mobile
domains:
  - acme.example.com
  - "*.acme.example.com"
ip_ranges:
  - 198.51.100.0/24
urls:
  - https://app.acme.example.com
oast_callbacks:
  - acme.oast.fun
allow_destructive: false
authorized_by: jane@acme.example.com
EOF

# 2. Run the swarm
pencheff engage --target https://app.acme.example.com --scope scope.yaml \
    --tier 2 --output ./acme-report --format docx,csv,json

# 3. Inspect engagement state
pencheff engagement list
pencheff engagement show <engagement_id>
pencheff engagement export <engagement_id> --format md > engagement.md
```

## The 9 phases

1. **Scoping** — `engagement_planner` produces a phased plan + MITRE coverage
   map for the engagement type. `threat_modeler` builds a STRIDE table per
   asset.
2. **Crawl** — `crawl_first` runs an HTTP-only crawl (link/form/JS extraction)
   + sitemap.xml + robots.txt + OpenAPI/Swagger spec discovery. Filters the
   merged set through `route_filter.is_useful_for_pentest` (drops static
   assets, third-party CDN URLs, fragment links). The result populates
   `session.discovered.endpoints` *before* auth and *before* every vuln
   module — so the rest of the pipeline tests the real surface, not just
   the base URL.
3. **Auth** — `api_authenticator` reads the crawled endpoint list, scores each
   URL via `login_finder.pick_login_url` (path shape, password-param
   presence, POST method, etc.), and hands the highest scorer to
   `ApiLoginModule`. Falls back to ApiLoginModule's static 14-path probe
   only if no candidate was discovered. Cookies + bearer tokens land on
   the session for every subsequent module.
4. **Reconnaissance** — `osint_collector` (passive: DNS, cert transparency,
   Wayback) and `recon_advisor` (active: nmap/masscan via existing
   `recon_passive` / `recon_active` MCP tools) run in parallel. The
   browser-crawl inside `recon_active` now augments the already-populated
   endpoint set with JS-rendered routes.
5. **Vulnerability assessment** — `vuln_scanner` runs scan_pulse +
   scan_infrastructure + nuclei. `web_hunter` runs scan_client_side +
   browser_crawl + ffuf. `api_security` runs recon_api_discovery + scan_api.
   `cloud_security` runs scan_cloud. `bizlogic_hunter` runs
   scan_business_logic. `stig_analyst` looks up DISA STIGs for the asset.
6. **Exploitation** — `exploit_guide` (methodology cards), `attack_planner`
   (graph findings → MITRE chains), `exploit_chainer` (suggest + verify),
   `poc_validator` (test_endpoint + verify_finding).
7. **Post-exploitation** — `privesc_advisor` (linpeas/winpeas triage cards).
8. **Detection engineering** — `detection_engineer` renders Sigma / SPL /
   KQL rules from observed findings.
9. **Reporting** — `report_generator` (Word + CSV + JSON via existing
   exporter), `bug_bounty` (HackerOne / Bugcrowd writeup formatter).

## Tier 1 vs Tier 2

| Tier | What runs | Network egress |
|---|---|---|
| Tier 1 (advisory) | Plan, threat model, OSINT, STIG lookup, methodology cards, attack-plan graph, detection rules, report | DNS resolution and public OSINT databases only |
| Tier 2 (execution) | Active recon, vuln scanners, web hunting, API testing, cloud, AD, wireless, mobile, credential testing, exploit chaining, PoC validation | Active scanning of in-scope targets |

`pencheff engage --tier 1` runs only advisors. `pencheff engage --tier 2`
runs the full loop.

## OPSEC noise tagging

Each playbook carries a noise level: `quiet`, `moderate`, `loud`.

```bash
pencheff engage --noise quiet     # advisors + OSINT only
pencheff engage --noise moderate  # adds passive scans & API testing
pencheff engage --noise loud      # adds brute force, AD attacks, wireless
```

## Subdomain fan-out

After the master target's recon phase, the orchestrator iterates each
discovered subdomain and runs `crawl → auth → vuln → exploit` per
subdomain. Each subdomain gets its own crawl + auth pass so the
credentials and discovered routes are scoped to *that* subdomain
(admin., api., www. usually have different routing and auth backends).

```bash
# Default: up to 10 subdomains
pencheff engage --target https://acme.example.com --scope scope.yaml

# Spread the engage across more subdomains
pencheff engage --target https://acme.example.com --scope scope.yaml \
    --max-subdomains 100

# Disable entirely — only the master target
pencheff engage --target https://acme.example.com --scope scope.yaml \
    --no-subdomains
```

Subdomain findings are merged into the master session's findings DB
so the report at the end reflects the full surface. The engagement DB
records each subdomain hand-off in `session_log` with
`action='subdomain:<host>'`.

## Engagement DB

A SQLite store at `~/.pencheff/engagements.db` (override with
`PENCHEFF_ENGAGEMENT_DB`) tracks cross-session engagement state. Schema is
the verbatim source-repo schema:
`engagements`, `hosts`, `services`, `vulns`, `credentials`, `chains`,
`session_log`, `schema_version`.

```bash
pencheff engagement init --client ACME --type external --scope scope.yaml
pencheff engagement log <id> --agent recon_advisor --action found-host \
    --summary "10.0.0.5 alive"
pencheff engagement handoff <id> --from recon_advisor --to vuln_scanner \
    --payload '{"hosts": [...]}'
pencheff engagement chains <id>
pencheff engagement export <id> --format md
```
