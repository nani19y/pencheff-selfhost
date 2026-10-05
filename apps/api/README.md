<div align="center">

<img src="keyed_logo.png" alt="Pencheff" width="120" />

# Pencheff Community Edition

### The self-hostable, no-login AI penetration-testing platform

Point it at a target, describe the engagement in plain language, and let it run reconnaissance, vulnerability scanning, exploit-chain analysis, and reporting — entirely on your own infrastructure.

[![License](https://img.shields.io/badge/License-AGPL_3.0-blue.svg?style=flat-square)](LICENSE)
[![Self-hosted](https://img.shields.io/badge/deploy-self--hosted-brightgreen?style=flat-square)](#quick-start)
[![No login](<https://img.shields.io/badge/auth-none_(single_user)-blueviolet?style=flat-square>)](#community-edition-scope)
[![Docker](https://img.shields.io/badge/run-docker_compose-2496ED?style=flat-square&logo=docker&logoColor=white)](#quick-start)
[![Backend](https://img.shields.io/badge/api-FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](#architecture)
[![Frontend](https://img.shields.io/badge/web-Next.js-000000?style=flat-square&logo=nextdotjs&logoColor=white)](#architecture)
[![Targets](https://img.shields.io/badge/target_types-39-orange?style=flat-square)](#target-types)
[![MCP](https://img.shields.io/badge/MCP_tools-80%2B-9cf?style=flat-square)](#use-it-from-an-ai-agent-mcp)

[Quick Start](#quick-start) · [Capabilities](#whats-inside) · [Target Types](#target-types) · [Architecture](#architecture) · [AI / MCP](#use-it-from-an-ai-agent-mcp) · [Configuration](#configuration) · [Scope](#community-edition-scope)

</div>

> **Community Edition** — This is the open-source, single-user build of Pencheff. No accounts, no login, no billing, no multi-tenancy. You own the box, you own the data. **Use it only against systems you are authorized to test.**

---

## What it is

Pencheff CE is a complete offensive-security platform you run yourself with **one command**. There's no sign-up and no login screen — `docker compose up`, open `http://localhost:3000`, and you land straight on the dashboard.

It pairs a **deterministic scan engine** (the same reconnaissance, fuzzing, and exploitation primitives a pentester reaches for) with **optional AI orchestration** (bring your own LLM key) that triages findings, proposes fixes, and can drive autonomous assessment passes. Without an LLM key, every scan, finding, and report still works — the AI paths simply stay dark.

- **Zero-auth, single-user** — one implicit operator, no orgs/teams/SSO.
- **Full engine** — recon -> scan -> verify -> exploit-chain -> report, end to end.
- **Bring-your-own AI** — optional LLM-assisted triage, grading, and remediation.
- **Agent-native** — drive the whole platform from any MCP-capable AI agent.
- **One-command deploy** — Docker Compose brings up the entire stack.
- **AGPL-3.0** — free to run, fork, and self-host; network-deployed modifications must share their source.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Magadha-IG/pencheff-ce.git
cd pencheff-ce

# 2. Copy the environment templates (defaults work out of the box)
cp .env.example .env
cp apps/api/.env.example apps/api/.env

# 3. Bring up the whole stack
docker compose up --build

# 4. Open the app — no login, straight to the dashboard
open http://localhost:3000
```

That's it. The `FERNET_KEY` auto-generates on first boot, migrations run automatically, and a single workspace is seeded for you. Verify everything is healthy any time with:

```bash
./scripts/smoke.sh   # asserts /targets and /dashboard return 200
```

> **Want AI features?** Drop an `LLM_API_KEY` into `apps/api/.env` (see [Configuration](#configuration)). Everything else runs without one.

---

## What's inside

The full scan surface, organized by capability. Coverage is computed live on the **`/scans`** dashboard from your real activity.

| Capability              | What it does                                                                                           |
| ----------------------- | ------------------------------------------------------------------------------------------------------ |
| **Recon**               | Passive + active reconnaissance, API discovery, subdomain enumeration, asset mapping                   |
| **DAST**                | Live web-app scanning — OWASP Top 10, injection, auth/authz, business-logic, client-side & DOM XSS     |
| **SAST**                | Source-code analysis via Semgrep + tree-sitter packs across cloned repositories                        |
| **Secrets**             | Hardcoded-credential and secret detection (Gitleaks)                                                   |
| **SCA**                 | Dependency / advisory scanning (OSV + GitHub Advisory DB) with SBOM ingest                             |
| **IaC**                 | Terraform / Kubernetes misconfiguration scanning (Trivy, Checkov)                                      |
| **Container**           | Container-image CVE & misconfig scanning                                                               |
| **Cloud**               | Cloud-posture scanning for accounts, storage, serverless, databases, CDN & secrets managers            |
| **Network & Host**      | Network-exposure port-scan, TLS/SSL posture, DNS, SPF/DKIM/DMARC, VPN/remote-access exposure           |
| **Mobile & Client**     | Static analysis of Android (APK/AAB), iOS (IPA), desktop apps & browser extensions — never executed    |
| **Firmware / IoT / OT** | Static analysis of firmware, IoT-device & OT/ICS/SCADA images — never flashed or run                   |
| **AI-target scan**      | Source-aware scanners for MCP servers, AI agents, RAG / vector DBs, ML models, voice AI & agent memory |
| **LLM Red Team**        | Prompt-injection, jailbreak, and safety testing for LLM-backed targets                                 |
| **Compliance**          | Map findings to GDPR / ISO 42001 / OWASP controls with per-scan rollups                                |
| **Manual tooling**      | Burp-style **Repeater**, **Intruder** (fuzzing), and an intercepting **Proxy**                         |
| **OAST**                | Out-of-band callback testing for blind SSRF / RCE / injection                                          |
| **Scoring**             | CVSS v4.0 calculation and severity grading                                                             |
| **Agentic Fix**         | AI-proposed remediations and patch suggestions (optional LLM)                                          |
| **Reporting**           | Export findings to Word, PDF, HTML, Markdown, CSV, and JSON                                            |
| **Schedules**           | Recurring, on-demand scan scheduling                                                                   |

---

## Target types

Register and scan **39 target types across 8 security disciplines** — each with its own purpose-built scan pipeline:

| Discipline                       | Target types                                                                                                           |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **AI & LLM Security**            | `llm` · `mcp` · `agent` · `rag` · `ml_model` · `voice` · `memory`                                                      |
| **Web & API Security**           | `web_app` · `rest_api` · `graphql` · `websocket` · `grpc`                                                              |
| **Code & Supply Chain Security** | `source_code` · `cicd_pipeline` · `iac` · `container_image` · `k8s_cluster` · `package_registry` · `sbom`              |
| **Infrastructure & Cloud**       | `cloud_account` · `cloud_storage` · `serverless_function` · `cloud_database` · `load_balancer_cdn` · `secrets_manager` |
| **Network & Host Security**      | `host` · `tls_ssl` · `dns` · `email_security` · `vpn`                                                                  |
| **Mobile & Client Security**     | `android_app` · `ios_app` · `desktop_app` · `browser_extension`                                                        |
| **OT / IoT & Hardware Security** | `firmware` · `iot_device` · `ot_ics_scada`                                                                             |
| **Identity, Data & Compliance**  | `idp` · `data_store`                                                                                                   |

> Mobile, client, firmware, IoT and OT targets are analyzed **statically** — artifacts are never executed or flashed. Memory / vector-store targets scan through the dedicated `POST /v1/memory/scan` endpoint.

---

## Architecture

```
docker compose
├── web      Next.js app on :3000  ── dashboard, no login, dynamic routing
├── api      FastAPI on :8000      ── REST + WebSocket + SSE
├── worker   Celery worker         ── scan jobs & long-running tasks
├── postgres pgvector              ── primary data store
└── redis                          ── task queue + pub/sub
```

| Service      | Port   | Role                                                  |
| ------------ | ------ | ----------------------------------------------------- |
| **web**      | `3000` | Next.js frontend — lands on the dashboard, no auth    |
| **api**      | `8000` | FastAPI backend — REST, WebSocket, Server-Sent Events |
| **worker**   | —      | Celery worker — executes scans and background jobs    |
| **postgres** | `5432` | Primary datastore (pgvector image)                    |
| **redis**    | `6379` | Job queue and pub/sub                                 |

The browser talks to the API directly (CORS is preconfigured for `localhost:3000`); the worker pulls scan jobs off Redis and streams progress back over SSE/WebSocket.

---

## Use it from an AI agent (MCP)

Pencheff ships an **MCP server with 80+ security tools** — recon, scanning across every discipline, payload generation, OAST, exploit-chain suggestion, CVSS scoring, finding verification, and report export. Point any MCP-capable agent (Claude Code, Claude Desktop, or your own) at it and drive a full engagement conversationally:

```
You:   "Recon example.com, then run an injection + auth scan and chain anything you find."
Agent: pentest_init -> recon_passive -> recon_active -> scan_injection -> scan_auth
       -> exploit_chain_suggest -> test_chain -> verify_finding -> generate_report
```

A representative slice of the toolset: `pentest_init` · `recon_active` · `scan_injection` · `scan_auth` · `scan_cloud` · `scan_websocket` · `payload_generate` · `oast_poll` · `exploit_chain_suggest` · `test_endpoint` · `calculate_cvss40` · `verify_finding` · `export_report`.

---

## Configuration

Everything is configured through environment variables in `.env` (root) and `apps/api/.env`. Sensible defaults ship in the `*.env.example` files.

<table>
<tr><th>Setting</th><th>Default</th><th>Purpose</th></tr>
<tr><td><code>LLM_API_KEY</code></td><td><em>(unset)</em></td><td>Enables AI triage, grading, agentic fixes, and autonomous scanning. Optional — pair with <code>LLM_BASE_URL</code> / <code>LLM_MODEL</code>. Any OpenAI-compatible or Anthropic endpoint works; per-workspace providers (incl. AWS Bedrock, Google Vertex) can also be configured from <strong>Settings</strong>.</td></tr>
<tr><td><code>INTEGRATIONS_ENABLED</code></td><td><code>false</code></td><td>Turns on outbound integrations (GitHub, webhooks, etc.).</td></tr>
<tr><td><code>OBSERVABILITY_INGEST_ENABLED</code></td><td><code>false</code></td><td>Turns on OpenTelemetry / OTLP trace ingest.</td></tr>
<tr><td><code>FERNET_KEY</code></td><td><em>auto</em></td><td>Encrypts stored credentials. Auto-generated on first boot; set it explicitly to persist across rebuilds.</td></tr>
</table>

Check which AI features are live at any time:

```bash
curl http://localhost:8000/capabilities/ai      # -> {"available": true|false}
```

---

## Community Edition scope

This build is deliberately lean and single-tenant. The following are **intentionally not included**:

- Authentication / login / SSO (one implicit operator)
- Multi-tenant orgs, teams, or workspace management
- Billing, plans, credits, or usage metering
- Coordinated multi-target attack campaigns and the multi-analyst engagement workbench
- Bring-your-own Security-Lake (external object-storage) export and audit-log export
- Hosted/SaaS integrations that require paid back-ends (off by default)

What you get instead: the complete scanning engine, the full local dashboard, compliance mapping, the MCP toolset, and reporting — yours to run, fork, and extend.

---

## Tech stack

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![Celery](https://img.shields.io/badge/Celery-37814A?style=flat-square&logo=celery&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-000000?style=flat-square&logo=nextdotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)
![Postgres](https://img.shields.io/badge/PostgreSQL-pgvector-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat-square&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/Docker_Compose-2496ED?style=flat-square&logo=docker&logoColor=white)

---

## Star history

<a href="https://star-history.com/#Magadha-IG/pencheff-ce&Date">
  <img src="https://api.star-history.com/svg?repos=Magadha-IG/pencheff-ce&type=Date" alt="Star History Chart" width="600" />
</a>

---

## Legal & responsible use

Pencheff is an **offensive-security tool**. Only scan, probe, or exploit systems you own or have **explicit written authorization** to test. Unauthorized use may be illegal. You are responsible for how you use it.

## License

Licensed under the **GNU Affero General Public License, Version 3** — see [LICENSE](LICENSE). Third-party component notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

<div align="center">

**If Pencheff CE is useful to you, consider giving it a star**

[Star](https://github.com/Magadha-IG/pencheff-ce) · [Fork](https://github.com/Magadha-IG/pencheff-ce/fork) · [Issues](https://github.com/Magadha-IG/pencheff-ce/issues)

<sub>© 2026 Magadha Group · AGPL-3.0 · Built for self-hosted security work.</sub>

</div>
