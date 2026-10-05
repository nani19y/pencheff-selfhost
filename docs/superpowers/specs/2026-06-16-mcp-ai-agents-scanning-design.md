# MCP / AI Agents — Source-Aware Registration & Attack-Specific Scanning (v1)

- **Date:** 2026-06-16
- **Status:** Approved design → ready for implementation plan
- **Author:** Pencheff (founder + eng)
- **Series:** First of three. Sequence: **MCP/AI Agents → RAG/Vector DB → Agent Memory**. ML Model & Voice deferred. MCP establishes the reusable per-type pattern (own wire kind + own KindConfig + own scanner module + own consent disclosures).

---

## 1. Goal

Turn the "MCP / AI Agents" register-target card from an undifferentiated `kind="llm"` chat probe into a **first-class, source-aware target type** with a **dedicated scanner** that covers the real MCP/agent attack surface (validated by cited 2024–2026 research, §8).

Today (verified): the card maps to `kind="llm"`, collects the generic `LlmFormSection`, and runs the full `scan_llm_red_team` pack — the `mcp.yaml` plugin fires only because _all_ plugins default-on, and the scanner cannot connect to a real MCP server, enumerate its tools, or test transport/auth. There is no MCP protocol awareness.

## 2. Non-goals (v1)

- ML Model/Pipeline and Voice/Speech AI types (later in series).
- MCP server **discovery** (auto-finding servers on a network).
- Continuous **rug-pull monitoring** (we lay the baseline hash for `compare_scans`; we do not run a watcher).
- Framework-specific agent introspection beyond HTTP/browser (no LangChain/CrewAI internals).
- Re-wiring the remaining `llm` cards (LLM Endpoint stays generic-`llm`; RAG becomes its own kind in the next sub-project).

## 3. Scope decisions (captured from brainstorming)

| Decision        | Choice                                                                                                                                        |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Target modeling | **New wire kind `mcp`** (not a subtype inside `llm_config`). `Target.kind` is `String(16)` — no DB enum migration.                            |
| Sources (all 4) | `mcp_http` (remote, SSE + streamable-HTTP), `mcp_stdio` (local command), `agent_http` (chat endpoint w/ tools), `agent_browser` (Playwright). |
| Static analysis | Always on; zero side-effects.                                                                                                                 |
| Dynamic depth   | **Full dynamic, consent-gated** — invoke all tools incl. destructive, behind explicit disclosure; intended for sandbox/throwaway targets.     |
| Coverage        | Comprehensive, research-validated catalog (§8).                                                                                               |

## 4. Architecture & data flow

```
Register (kind="mcp", McpConfig.source_type)
  → Commission scan (consent gate: mcp disclosures, §9)
  → scan_runner dispatches kind="mcp" → MCP_SCAN_STAGES
  → pencheff `scan_mcp` orchestrator branches on source_type:
       ├─ mcp_http / mcp_stdio (MCP-server sources):
       │     MCP protocol client: initialize → tools/list → resources/list
       │       → prompts/list → resources/templates/list
       │     ├─ STATIC analyzers (§7a): poisoning, hidden-content, excessive agency, schema, baseline hash
       │     ├─ FINGERPRINT (§7b): known-vuln impl/version checks (CVE list)
       │     ├─ TRANSPORT/AUTH PROBES (§7c): DNS-rebind, session entropy, OAuth-endpoint, audience, passthrough
       │     └─ [consent] DYNAMIC tool fuzzing (§7d): param injection/SSRF/LFI/cred-theft, OAST-backed
       └─ agent_http / agent_browser (agent sources):
             existing LlmProbe engine + enriched mcp.yaml attack pack (§7f)
             + TOXIC-FLOW analysis (§7e) via test_chain
  → Findings (OWASP-LLM + mcp:* technique tags, CVSS, PoC transcript) → DB → report
```

Findings, judge, suppression, reporting, `compare_scans`, OAST all reuse existing infra. The only genuinely new engineering is the **MCP protocol client** (§6) and the **analyzer set** (§7).

## 5. Registration & config

### 5.1 Wire kind

Add `"mcp"` to:

- `TargetKind` literal — `apps/api/pencheff_api/schemas/targets.py`
- `SupportedKind` — `apps/web/components/register-target/target-types.ts` **and** the drifted local copy in `apps/web/app/targets/page.tsx`
- `_KINDS_REQUIRING_CONFIG` frozenset — `schemas/targets.py`
- `KindConfig` discriminated union — `schemas/targets.py`

### 5.2 `McpConfig` (kind_config union member)

```python
class McpConfig(_KindConfigBase):
    kind: Literal["mcp"] = "mcp"
    source_type: Literal["mcp_http", "mcp_stdio", "agent_http", "agent_browser"]

    # mcp_http
    url: HttpUrl | None = None
    transport: Literal["sse", "streamable_http"] | None = None

    # mcp_stdio
    command: list[str] | None = None
    env: dict[str, str] | None = None     # non-secret only; secrets via kind_credentials
    cwd: str | None = None

    # agent_http  (LLM-style; reuses LlmProbe engine)
    provider: LlmProvider | None = None
    model: str | None = None
    request_template: str | None = None
    response_path: str | None = None

    # agent_browser (Playwright)
    prompt_selector: str | None = None
    send_selector: str | None = None
    response_selector: str | None = None

    # common dynamic-testing controls
    tool_allowlist: list[str] = Field(default_factory=list)   # if set, only these are invoked
    tool_denylist: list[str] = Field(default_factory=list)    # never invoked
    dynamic_invocation: bool = False                          # master switch for tools/call
    destructive_opt_in: bool = False                          # allow tools classed destructive

    @model_validator(mode="after")
    def _validate_source(self) -> "McpConfig":
        # mcp_http requires url+transport; mcp_stdio requires command;
        # agent_http requires provider; agent_browser requires url+selectors.
        ...
```

Auth secrets (bearer tokens / API keys / headers for HTTP MCP and agent endpoints) ride on `Target.kind_credentials_encrypted` (same Fernet pattern as k8s/container_image), **not** in `McpConfig`.

### 5.3 Frontend form

New `McpFormSection` in `apps/web/app/targets/new/page.tsx` (+ `[id]/edit/page.tsx`): a `source_type` picker that conditionally reveals the relevant field group, the tool allow/deny lists, and the `dynamic_invocation` / `destructive_opt_in` switches (the latter wired to the consent disclosure in §9). `target-types.ts`: `mcp-ai-agents` card → `kind:"mcp"`. List/detail pages: add an `MCP` kind badge.

## 6. MCP protocol client (new)

New module `plugins/pencheff/pencheff/modules/mcp_scan/client.py`.

- **Transports:** stdio (spawn `command`), HTTP+SSE, and Streamable-HTTP.
- **Handshake:** `initialize` → `notifications/initialized`; capture server `serverInfo` (name/version → fingerprinting, §7b).
- **Enumerate:** `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`.
- **Invoke (dynamic):** `tools/call`, `resources/read`, `prompts/get`.
- **Dependency:** use the official **`mcp` Python SDK pinned `>=1.23.0`** (CVE-2025-66416 fix; our scanner must not ship a vulnerable SDK), with a minimal JSON-RPC fallback if the SDK is unavailable. Add to `plugins/pencheff` optional deps; ensure it lands in the API Docker image.

## 7. Scanner analyzers

### 7a. Static manifest analyzers (always; zero side-effects)

Run over enumerated tools/resources/prompts:

- **Line-jumping / tool-description poisoning** — imperative/override language ("ignore", "always append", "do not tell the user"), command prefixes, cross-server relay directives.
- **Hidden-content smuggling** — any codepoint in **Unicode Tags block U+E0000–U+E007F**, zero-width chars, ANSI escapes, HTML comments, whitespace padding.
- **Excessive agency / dangerous capability** — tool names/schemas implying exec/shell/fs-write/delete/network/payment; over-broad free-string params; `additionalProperties: true`.
- **Schema weaknesses** — missing constraints, injection-prone params.
- **Sensitive resource exposure** — `resources/list` leaking files/env/secrets; **prompt-template poisoning** in `prompts/list`.
- **Rug-pull baseline** — hash tool descriptions+schemas; persist for `compare_scans` drift detection.

### 7b. Known-vuln implementation fingerprinting (static)

Version-pinned, **refreshable** advisory list checked against `serverInfo`, the stdio launch command/package, and (remote) fingerprints:

- `mcp-remote` `< 0.1.16` → CVE-2025-6514 (9.6)
- MCP Python SDK `mcp < 1.23.0` → CVE-2025-66416
- MCP Inspector `< 0.14.1` → CVE-2025-49596 (9.4)
- `oatpp-mcp` (pointer session IDs) → CVE-2025-6515

The list lives in a single data file (e.g. `mcp_scan/advisories.yaml`) so it can be updated as new MCP CVEs land (research caveat: the 2024–2026 window is active).

### 7c. Transport / auth CVE probes (dynamic, low-risk)

- **DNS-rebinding** probe against local HTTP/SSE servers (CVE-2025-66416 class): verify `TransportSecuritySettings`/allowed-hosts enforced.
- **Session-ID entropy/predictability** on SSE/streamable endpoints (CVE-2025-6515 class).
- **Hostile OAuth authorization-endpoint** injection probe (CVE-2025-6514 class).
- **Localhost-proxy cross-origin/CSRF** probe (CVE-2025-49596 class).
- **Auth-spec compliance** (MCP auth spec 2025-06-18): wrong-audience token rejected? client token forwarded upstream (passthrough)? per-client consent on static client IDs (confused deputy)?

### 7d. Dynamic tool-invocation fuzzing (consent-gated)

Gated by `dynamic_invocation` (+ `destructive_opt_in` for destructive-classed tools) **and** the matching consent disclosure (§9). OAST-backed (`oast_init`/`oast_new_url`/`oast_poll`) for blind detection:

- **Param injection** → command injection / SSRF / path-traversal / arbitrary file read / cloud-credential theft (hendryadrian PoC pattern).
- **Injection-via-tool-output** — canary inputs; does output carry agent-compromising content.
- **Excessive agency in practice** — confirm dangerous tools actually execute (sandbox only).
- **Auth bypass** — privileged tool call without/with manipulated auth.

### 7e. Toxic-flow analysis (agent sources)

Model the **"lethal trifecta"** (untrusted input + private-data access + exfiltration channel) as a dynamic chain via `test_chain`: inject via an untrusted-content channel → observe whether a privileged tool is driven → check for an exfil sink. Confirms confused-deputy/toxic-flow (Invariant GitHub MCP pattern).

### 7f. Agent-endpoint probing (agent_http / agent_browser)

Reuse the existing `LlmProbe` engine + an **enriched `mcp.yaml`** attack pack (tool-poisoning realization, excessive agency, injection-via-tool-output, system-prompt/tool-manifest leakage). For `kind="mcp"` agent sources, the `scan_mcp` orchestrator builds an `LlmProbe` from the `agent_http`/`agent_browser` fields and runs the pack.

## 8. Attack & exploit catalog (research-validated, cited)

All claims below were independently verified 3-0 in the deep-research pass (2026-06-16); see §16.

| Attack                                                      | Detection layer           | Mapping                              | Source / CVE                 |
| ----------------------------------------------------------- | ------------------------- | ------------------------------------ | ---------------------------- |
| Line jumping (tool-desc injection at `tools/list`)          | 7a static                 | LLM01 / CWE-94, CWE-77               | Trail of Bits 2025-04-21     |
| Unicode-tag smuggling (U+E0000–E007F)                       | 7a static                 | LLM01 / CWE-176, CWE-150             | Rehberger/Goodside 2024      |
| Tool poisoning / rug-pull                                   | 7a static + baseline      | LLM01                                | Invariant Labs (mcp-scan)    |
| Toxic-flow / confused deputy                                | 7e dynamic chain          | LLM01/LLM02/LLM06 / CWE-441, CWE-200 | Invariant GitHub MCP 2025-05 |
| Tool-param injection → SSRF/LFI/cred theft                  | 7d dynamic + OAST         | CWE-78/918/22                        | hendryadrian.com PoC         |
| mcp-remote RCE                                              | 7b fingerprint + 7c probe | CWE-78                               | CVE-2025-6514 (9.6)          |
| MCP Inspector RCE                                           | 7b fingerprint + 7c probe | CWE-306, CWE-352                     | CVE-2025-49596 (9.4)         |
| MCP Python SDK DNS-rebinding                                | 7b fingerprint + 7c probe | CWE-1188, CWE-350                    | CVE-2025-66416               |
| oatpp-mcp session hijacking                                 | 7c probe                  | CWE-330, CWE-384                     | CVE-2025-6515                |
| Auth-spec violations (audience/passthrough/confused-deputy) | 7c probe                  | CWE-287/863/441                      | MCP auth spec 2025-06-18     |
| Prompt injection / goal hijacking (anchor)                  | 7f probe                  | LLM01                                | OWASP GenAI LLM01            |

Reference scanners (to learn from, not vendor): Invariant **mcp-scan**, Cisco **mcp-scanner**, Trail of Bits **mcp-context-protector**, **vulnerablemcp.info**.

## 9. Consent & safety

Add `mcp` to `KIND_REQUIRED_DISCLOSED_ACTIONS` (`apps/api/pencheff_api/schemas/scans.py`) and mirror in FE `apps/web/lib/consent-disclosures.ts`. Graduated disclosed actions:

- `mcp_enumerate` — passive enumeration + static analysis (always).
- `mcp_tool_invocation` — safe/read-only dynamic calls.
- `mcp_destructive_tool_invocation` — gates destructive calls; **required** when `destructive_opt_in` is set.

Destructive invocation fires only when **both** `McpConfig.destructive_opt_in` **and** the `mcp_destructive_tool_invocation` disclosure are present. The `scans.py` `start_scan` gate validates coverage (mirrors existing host/llm gates). Default profile never invokes destructive tools.

## 10. Findings, taxonomy & profiles

- Findings reuse the existing model + judge + reporting, tagged with an OWASP-LLM category **and** an `mcp:*` technique (e.g. `mcp:line-jumping`, `mcp:tool-poisoning`, `mcp:dns-rebinding`). CVSS via existing `calculate_cvss40`.
- **Profiles:** Quick = static + fingerprint only; Standard = + safe read-only dynamic + transport/auth probes; Deep = + full dynamic incl. destructive (if opted in). Map to tool-call budget caps (mirror the LLM profile→max_payloads pattern in `scan_runner.py`).

## 11. Frontend change map

- `components/register-target/target-types.ts` — `mcp-ai-agents` → `kind:"mcp"`.
- `app/targets/new/page.tsx` + `app/targets/[id]/edit/page.tsx` — new `McpFormSection`.
- `app/targets/page.tsx` — add `"mcp"` to local `SupportedKind`; MCP badge; list-row behavior.
- `app/targets/[id]/page.tsx` — MCP kind config view; commission allowed.
- `lib/consent-disclosures.ts` — `mcp` disclosure vocabulary + `REQUIRED_ACTION_IDS_BY_KIND`.
- `components/commission-scan-modal.tsx` — surface mcp disclosures + destructive opt-in acknowledgement.

## 12. Backend change map

- `schemas/targets.py` — `TargetKind`, `_KINDS_REQUIRING_CONFIG`, `McpConfig`, `KindConfig` union.
- `schemas/scans.py` — `KIND_REQUIRED_DISCLOSED_ACTIONS["mcp"]`.
- `routers/scans.py` — `start_scan` validation for `mcp` (require `kind_config`; gate destructive).
- `services/scan_runner.py` — add `mcp` to `_NON_DAST_NEW_KINDS`; `_run_kind_aware_scan` branch; `MCP_SCAN_STAGES`; profile→budget mapping; entrypoint to pencheff `scan_mcp`.
- `db/migrations/versions/` — new migration following the host/memory (0047/0048) pattern (kind is `String(16)`; no enum change — migration documents the kind + any index/constraint refresh).
- `plugins/pencheff/pencheff/modules/mcp_scan/` — `client.py` (protocol client), `static_analyzers.py`, `advisories.yaml` (fingerprint list), `transport_probes.py`, `dynamic.py`, `toxic_flow.py`.
- `plugins/pencheff/pencheff/server.py` — new MCP tool `scan_mcp` (+ optionally `mcp_enumerate`).
- `plugins/pencheff/pencheff/modules/llm_red_team/payloads/mcp.yaml` — enrich pack; `addon_plugins.py` already registers `mcp`.
- `plugins/pencheff` deps — `mcp>=1.23.0`; verify present in `apps/api/Dockerfile` image.

## 13. Testing strategy

- **Unit:** `McpConfig` validation per source_type; each static analyzer against fixture manifests with known-bad tools (poisoned descriptions, Unicode-tag payloads, dangerous schemas); fingerprint matcher against the advisory list; consent gate (destructive blocked without disclosure → mirror `test_scans_memory_kind_gate.py` / `test_scans_host_kind_gate.py`).
- **Integration:** a **mock MCP server** fixture (stdio + HTTP) exposing poisoned/dangerous tools and a predictable session ID; assert the expected findings + techniques + severities. Mock OAST for blind-detection paths.
- **FE:** `McpFormSection` renders correct fields per source_type; commission modal shows mcp disclosures.
- Add `apps/api/tests/test_scans_mcp_*`.

## 14. Out of scope / deferred

See §2. Plus: MCP advisory **feed ingestion** (auto-refresh of `advisories.yaml`) — v1 ships a manually-maintained pinned list.

## 15. Open questions (from research; refine during implementation)

1. Exact check inventory of mcp-scan / Cisco mcp-scanner / mcp-context-protector — mine for additional static signatures.
2. Deeper detection signatures for **rug-pull**, **cross-server shadowing**, **sampling abuse** — named in scope but lacking a single verified primary claim; refine pack signatures during implementation.
3. Canonical continuously-updated MCP advisory feed beyond GHSA/NVD keyword search (informs §14 deferral).

## 16. Sources (primary, verified 2026-06-16)

- Trail of Bits — _Jumping the line_ (line jumping), 2025-04-21.
- Embrace The Red (Rehberger) — Unicode Tags hiding/finding, 2024-01.
- JFrog + GHSA-6xpm-ggf7-wc3p — CVE-2025-6514 (mcp-remote RCE, 9.6).
- Oligo + GHSA-7f8r-222p-6f5g + NVD — CVE-2025-49596 (MCP Inspector RCE, 9.4).
- GitLab advisory + GHSA-9h52-p55h-vw2f — CVE-2025-66416 (MCP Python SDK DNS-rebinding).
- JFrog + GHSA-rvw9-mm8q-456q — CVE-2025-6515 (oatpp-mcp session hijacking).
- modelcontextprotocol.io — Authorization spec 2025-06-18.
- Invariant Labs — GitHub MCP toxic-flow; mcp-scan; tool-poisoning; toxic-flow-analysis.
- hendryadrian.com — unauthenticated MCP server → SSRF/LFI/AWS cred theft.
- OWASP GenAI — LLM01 Prompt Injection. Simon Willison — lethal trifecta.
- Reference scanners: github.com/cisco-ai-defense/mcp-scanner; vulnerablemcp.info.
