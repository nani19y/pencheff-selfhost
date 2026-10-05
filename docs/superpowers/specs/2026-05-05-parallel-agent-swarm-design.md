# Parallel Multi-Agent Scan Swarm — Design

> **Status update (2026-05-06):** This spec describes the v1 swarm design (9 agents). The pipeline has since been extended in three batches:
>
> - **Batch A (`1b94a50`):** Added `LLMRedTeamAgent`, `SupplyChainAgent`, `K8sAgent` (Phase 2) and `ComplianceAgent` (Phase 3). Extended `ChainAgent`'s mandate with blast-radius scoring + cross-system chain detection.
> - **Batch B (`f486949`, `f1d883b`, `0cb2c22`):** Added consent screen at scan creation. Migration `0037` introduced `Scan.consent_payload`.
> - **Batch C (`02b70c8`, `a93aedb`, `b2c26f9`):** Added `EvidenceCaptureAgent` and `AdminAccessAgent` (Phase 3). New Playwright-driven pencheff MCP tools. New `GET /scans/{id}/evidence/{finding_id}.png` endpoint.
> - Plus Batch A1 from earlier session: `ProofOfImpactAgent` and `PayloadCraftingAgent` (Phase 3, schema-only impact + PoC synthesis).
>
> Current production state: **17 agents in 3 phases** (1 + 10 + 6). The architecture, data flow, IP-safety contract, and orchestrator design from this spec all remain accurate; the agent count and Phase 3 fan-out are wider than originally specified.
>
> Operator-facing docs at `apps/docs/pages/features/swarm.mdx`. Destructive agents blueprint at `2026-05-06-destructive-agents-blueprint.md`.

**Date:** 2026-05-05
**Status:** Approved (brainstorming complete; awaiting implementation plan)
**Owners:** Pencheff API team
**Replaces (as default):** the single-agent loop in `apps/api/pencheff_api/services/agent_runner.py`
**Does NOT replace:** the deterministic populator (`_run_deterministic_stages`, `_run_engage_pipeline`)

---

## 1. Goal

Replace the **default LLM-driven phase** of a Pencheff scan — currently a single agent looping through tool calls in `agent_runner.run_agent` — with a **parallel multi-agent swarm**: one Recon agent, seven specialised "breaker" agents fanning out concurrently, then one Chain agent. The deterministic populator path is unchanged and stays available exactly as it is today.

The single-agent loop is **kept as a fallback**, gated behind `SWARM_ENABLED` (default `true`). Catastrophic failures of the swarm route automatically to the legacy loop so users never see an empty scan.

## 2. Non-goals

* Not removing the deterministic populator. It coexists.
* Not removing `agent_runner.py`. It coexists as fallback.
* Not changing `dispatch_mode.py`. The three existing dispatch modes (`deterministic_only`, `agent_only`, `deterministic_then_agent`) keep their semantics — only the engine inside `_engine(...)` becomes smarter.
* Not introducing new LLM credentials. Reuses `AGENT_LLM_*`.
* Not redesigning the scan-detail UI. Per-agent UI grouping is filed as follow-up F1.
* Not adding new external dependencies. `THIRD_PARTY_NOTICES.md` is unchanged.

## 3. IP-safety contract

This design references — but does not derive code, prompts, or distinctive prose from — the public README of [`0x4m4/hexstrike-ai`](https://github.com/0x4m4/hexstrike-ai). The clean-room rules below are binding for the implementation:

1. **No source code from hexstrike-ai** is read, ported, adapted, or referenced beyond its public README. We learned the general concept (role-specialised agents under a coordinator) and stopped there. That concept is generic industry practice, not project-specific IP.
2. **No prompts, system messages, tool descriptions, or distinctive prose** are copied. Every per-agent system prompt in `agent_swarm/prompts.py` is written from scratch, building on the existing `agent_runner.SYSTEM_PROMPT` (already ours, in-tree since `f6d024d`) and the existing pencheff tool docstrings.
3. **Agent names are generic OWASP / pentesting taxonomy** (`ReconAgent`, `InjectionAgent`, `ClientSideAgent`, `AuthAgent`, `AuthzAgent`, `APIAgent`, `InfraAgent`, `CloudAgent`, `ChainAgent`). None of them mirror hexstrike-ai's identifiers (`BugBountyWorkflowManager`, `VulnerabilityCorrelator`, `AIExploitGenerator`, etc.). The names describe attack classes that already exist as `scan_*` tools in our own `pencheff.server`.
4. **No orchestration code is copied.** Our orchestrator uses `asyncio.gather` over our existing `httpx`-based agent loop, our existing `dispatch_mode`, our existing `scan_runner` integration. Nothing about it derives from hexstrike-ai's MCP-server / FastMCP coordinator pattern.
5. **No new dependencies.** No package is added that pulls in hexstrike-ai or any vendored copy.
6. **Even though hexstrike-ai is MIT-licensed**, we deliberately take the clean-room route to avoid both licensing-attribution overhead and any future ambiguity about whether something is "ours."
7. During implementation, **hexstrike-ai source is not opened.** Reading their README — which has already happened during this brainstorm — is the only direct contact.

## 4. Architecture overview

```
                ┌────────────────────────────────────────┐
                │ scan_runner.run_scan (existing)        │
                │   resolves dispatch_mode               │
                │   if SWARM_ENABLED → run_swarm(...)    │
                │   else                → legacy path    │
                └────────────────────┬───────────────────┘
                                     │
                                     ▼
              ┌─────────── Phase 1: Recon ─────────────┐
              │ ReconAgent (LLM, master psession)      │
              │   tools: recon_passive, recon_active,  │
              │          recon_api_discovery, scan_waf,│
              │          authenticated_crawl (cond.),  │
              │          finish                        │
              │   → emits a frozen ReconSnapshot       │
              └────────────────┬───────────────────────┘
                               │ snapshot frozen
                               ▼
        ┌──── Phase 2: Breakers (asyncio.gather, 7-wide) ────┐
        │ Each gets its OWN psession seeded from snapshot.    │
        │ Each is a self-contained LLM agent loop.            │
        │                                                     │
        │   InjectionAgent     ClientSideAgent   AuthAgent    │
        │   AuthzAgent         APIAgent          InfraAgent   │
        │   CloudAgent                                        │
        │                                                     │
        │ Per-agent retry-once on transient LLM errors.       │
        │ Per-agent isolated try/except. Survivors continue.  │
        └────────────────┬───────────────────────────────────┘
                         │ asyncio.gather → list[BreakerResult]
                         ▼
              ┌────── Merge step (deterministic) ──────┐
              │ Union all findings into master psession│
              │ + add discovered_by_agent tag           │
              │ + merge cookie/token deltas if any      │
              │ + collect per-agent stats               │
              └────────────────┬───────────────────────┘
                               │
                               ▼
              ┌──── Phase 3: Chain ────────────────────┐
              │ ChainAgent (LLM, master psession)      │
              │   tools: get_findings, exploit_chain_  │
              │          suggest, test_chain,          │
              │          test_endpoint, oast_*, finish │
              │   produces executive summary           │
              └────────────────┬───────────────────────┘
                               │
                               ▼
              ┌──── Catastrophic-fallback gate ────────┐
              │ if recon_failed OR all_breakers_failed:│
              │   log "swarm produced no output, fall- │
              │     back to single-agent loop"         │
              │   call agent_runner.run_agent(...)     │
              └────────────────────────────────────────┘
```

The dependency graph between phases is real — breakers need parameters/URLs from recon, the chainer needs findings from breakers — so "fully concurrent from t=0" was rejected in favour of three-phase staged execution. Phase 2 (the breaker fan-out) is where ~80 % of wallclock lives and is genuinely 7-wide parallel.

## 5. The agents

Each agent is its own LLM tool-calling loop, talking to the same OpenAI-compatible chat-completions endpoint the legacy loop already uses. Each gets its own clean-room system prompt, scoped strictly to its mandate.

| # | Agent | Mandate | Tools |
|---|-------|---------|-------|
| 1 | `ReconAgent` | Map attack surface; produce frozen snapshot | `recon_passive`, `recon_active`, `recon_api_discovery`, `scan_waf`, `authenticated_crawl` (only if creds), `finish` |
| 2 | `InjectionAgent` | SQLi/NoSQLi/XXE/SSTI/cmdi + path traversal + file uploads | `scan_injection`, `scan_file_handling`, `test_endpoint`, `oast_*`, `get_findings`, `suppress_finding`, `finish` |
| 3 | `ClientSideAgent` | Reflected/DOM XSS, CSRF, open redirect, CORS | `scan_client_side`, `scan_dom_xss`, `test_endpoint`, `get_findings`, `suppress_finding`, `finish` |
| 4 | `AuthAgent` | Login weakness, JWT confusion, OAuth, MFA bypass | `scan_auth`, `scan_oauth`, `scan_mfa_bypass`, `test_endpoint`, `get_findings`, `suppress_finding`, `finish` |
| 5 | `AuthzAgent` | IDOR, vertical/horizontal privesc (auth-only) | `scan_authz`, `test_endpoint`, `get_findings`, `suppress_finding`, `finish` |
| 6 | `APIAgent` | API/GraphQL flaws, websocket, business logic | `scan_api`, `scan_websocket`, `scan_business_logic`, `test_endpoint`, `get_findings`, `suppress_finding`, `finish` |
| 7 | `InfraAgent` | TLS/headers, smuggling, CRLF, subdomain takeover, external probes | `scan_infrastructure`, `scan_advanced`, `scan_subdomain_takeover`, `run_security_tool`, `test_endpoint`, `get_findings`, `suppress_finding`, `finish` |
| 8 | `CloudAgent` | Cloud misconfig, IAM, public blobs, blind SSRF callbacks | `scan_cloud`, `test_endpoint`, `oast_*`, `get_findings`, `suppress_finding`, `finish` |
| 9 | `ChainAgent` | After-merge: walk multi-step exploits, write executive summary | `get_findings`, `exploit_chain_suggest`, `test_chain`, `test_endpoint`, `oast_*`, `finish` |

**Allocation invariant:** every `scan_*` tool appears in exactly one breaker. `test_endpoint` and `get_findings` are everywhere because verification is everyone's job.

**`AuthzAgent` quiet-quit:** if `ReconAgent` reports no authenticated session was established, `AuthzAgent` `finish`-es immediately with `"skipped: no authenticated session"`. This counts as **success**, not failure (so it does not contribute to the `all_breakers_failed` catastrophic-fallback condition).

**Per-agent system-prompt skeleton** (every agent shares this skeleton; the mandate-specific section is the only thing that differs):

1. **Identity-protection block** — copied as-is from existing `agent_runner.SYSTEM_PROMPT`. Already ours.
2. **Exploit-don't-scan rule** — copied as-is. Already ours.
3. **Passive-misconfig non-suppression rule** — copied as-is. Already ours.
4. **Mandate-specific section** — written fresh per agent: *"You are the X agent. Your scope is Y. Do not call any tool that is not in your registry — those tools do not exist for you. Findings outside your scope, leave to other agents."*
5. **Stop condition** — call `finish` with a short summary (≤ 200 words) once your mandate is covered.

Strict scoping prevents an agent from drifting and trying to call tools it doesn't own. The per-agent registry is the canonical source of truth for what an agent can do.

## 6. Turn budgets — profile-tiered

```
| Profile  | Recon | Each breaker (×7) | Chain | Worst-case sum |
| quick    |   8   |        6          |   8   |       58       |
| standard |  12   |       10          |  12   |       94       |
| deep     |  18   |       16          |  20   |      150       |
```

Tied to the existing `quick / standard / deep` knob users already pick at scan-creation time. The user has already signalled their cost tolerance through the profile. Quick stays roughly at today's single-agent budget; deep is generous but bounded.

There is **no global `MAX_TOTAL_TOOL_CALLS_PER_SCAN` ceiling.** The per-agent caps are the only bound.

All numbers land in `config.py` as new settings (named `SWARM_TURNS_<PHASE>_<PROFILE>`) so we can tune per-tier without code changes after we see real cost data.

## 7. ReconSnapshot — the bridge between phases

`ReconSnapshot` is the **only** thing that crosses from Phase 1 into Phase 2. It is frozen and read-only.

```python
# apps/api/pencheff_api/services/agent_swarm/snapshot.py

@dataclass(frozen=True)
class DiscoveredEndpoint:
    url: str
    method: str
    status: int | None
    content_type: str | None
    parameters: tuple[str, ...]   # query/form/JSON-key names

@dataclass(frozen=True)
class ReconSnapshot:
    # ── Provenance / scope ─────────────────────────────────────
    target_base_url: str
    profile: Literal["quick", "standard", "deep"]
    scope_include: tuple[str, ...]
    scope_exclude: tuple[str, ...]

    # ── Surface ────────────────────────────────────────────────
    endpoints: tuple[DiscoveredEndpoint, ...]
    api_spec_urls: tuple[str, ...]   # swagger.json / openapi.yaml / /graphql / etc.
    subdomains: tuple[str, ...]
    robots_txt: str | None
    sitemap_urls: tuple[str, ...]
    security_txt: str | None

    # ── Fingerprint ────────────────────────────────────────────
    tech_stack: Mapping[str, str]    # {"server": "nginx/1.18", "framework": "Django", ...}
    waf_vendor: str | None

    # ── Auth handoff ───────────────────────────────────────────
    authenticated: bool
    auth_login_url: str | None
    auth_cookies: tuple[tuple[str, str], ...]
    auth_tokens: Mapping[str, str]              # {"bearer": "...", "csrf": "...", ...}

    # ── OAST sharing ───────────────────────────────────────────
    oast_session_handle: str | None  # ReconAgent calls oast_init once; breakers reuse

    # ── Provenance / debugging ─────────────────────────────────
    recon_agent_summary: str
    recon_findings_ids: tuple[str, ...]
    snapshot_built_at: datetime
```

**Construction (Phase 1 finalisation):** after `ReconAgent` calls `finish`, `_freeze_snapshot(master_session_id, outcome)` reads relevant pencheff session state into the dataclass. Tuples and frozen dataclass enforce read-only.

**Seeding (Phase 2 setup):** for each breaker, `seed_breaker_session(snapshot) -> session_id` calls `pencheff.server.pentest_init` to get a fresh isolated pencheff session, then bulk-imports the snapshot via three new pencheff helpers:

* `import_endpoints(sid, snapshot.endpoints)`
* `set_auth_state(sid, cookies=…, tokens=…)`
* `attach_oast(sid, snapshot.oast_session_handle)`

A fourth pencheff helper, `copy_finding(...)`, is needed at merge time (Section 8.2). Together these four are the complete list of new pencheff API surface this design adds. Without the seeding three, breakers would each have to re-crawl the target — wasted work and noisy traffic against the customer's app. Without `copy_finding`, breaker findings could not be unioned back into the master session for `ChainAgent`.

**Why `ReconAgent` writes findings to the master session:** passive-recon findings (missing security headers, weak TLS, exposed `.git`, …) get populated automatically by pencheff during recon, and we want those visible in the final report regardless of whether the swarm later succeeded. Breakers each get their own fresh session and their findings get unioned back into the master at merge time.

## 8. Orchestrator

```python
# apps/api/pencheff_api/services/agent_swarm/orchestrator.py

@dataclass
class BreakerResult:
    agent_name: str
    success: bool
    finding_ids: tuple[str, ...]
    summary: str
    turns: int
    tool_calls: int
    error: str | None

@dataclass
class SwarmOutcome:
    summary: str
    breaker_results: tuple[BreakerResult, ...]
    used_fallback: bool
    used_fallback_reason: str | None
    total_tool_calls: int
    total_turns: int

async def run_swarm(*, master_session_id, target, credentials, profile,
                    scope, exclude_paths, on_event, session_prepopulated):
    # ── Phase 1 ────────────────────────────────────────────────
    try:
        snapshot = await run_recon_phase(...)
    except ReconFailed as exc:
        return await _catastrophic_fallback(reason=f"recon_failed: {exc}", ...)

    # ── Phase 2 ────────────────────────────────────────────────
    breaker_specs = _build_breakers(profile=profile, snapshot=snapshot)
    raw_results = await asyncio.gather(
        *[_run_breaker_with_retry(spec, snapshot, on_event) for spec in breaker_specs],
        return_exceptions=True,
    )
    breaker_results = _normalise(raw_results, breaker_specs)
    if all(not r.success for r in breaker_results):
        return await _catastrophic_fallback(reason="all_breakers_failed", ...)

    # ── Merge ──────────────────────────────────────────────────
    await _merge_breaker_findings_into_master(...)

    # ── Phase 3 ────────────────────────────────────────────────
    try:
        chain_outcome = await _run_chain_phase(...)
        chain_summary = chain_outcome.summary
    except Exception as exc:
        log.warning("chain phase failed: %s", exc)
        await on_event(f"[Chain] failed: {exc}; keeping breaker findings")
        chain_summary = _synthesise_summary_from_breakers(breaker_results)

    return SwarmOutcome(...)
```

### 8.1 Per-breaker retry wrapper

```python
async def _run_breaker_with_retry(spec, snapshot, on_event) -> BreakerResult:
    breaker_sid = await seed_breaker_session(snapshot)
    prefixed = _prefix(f"[{spec.name}] ", on_event)
    for attempt in range(2):  # 1 initial + 1 retry
        try:
            return await _run_single_agent(
                agent=spec.agent, session_id=breaker_sid,
                on_event=prefixed, profile=snapshot.profile,
            )
        except _TransientLLMError as exc:
            if attempt == 0:
                await prefixed(f"transient error ({exc}); retrying once")
                await asyncio.sleep(SWARM_BREAKER_RETRY_BACKOFF_SEC)
                continue
            return BreakerResult(spec.name, success=False, ...,
                                 error=f"transient_after_retry: {exc}")
        except Exception as exc:
            return BreakerResult(spec.name, success=False, ...,
                                 error=f"{type(exc).__name__}: {exc}")
```

`_TransientLLMError` is raised by the inner agent loop on any of: `httpx.ReadTimeout`, `httpx.ConnectTimeout`, `httpx.ReadError`, `httpx.RemoteProtocolError`, HTTP 429, HTTP 5xx — i.e. the same set already retried mid-loop in `agent_runner.py:914-948`. Because mid-loop retry has already happened inside `_run_single_agent`, a transient that escapes is treated as a real per-breaker failure for this scan, but the breaker still gets one more whole-run attempt before being abandoned.

### 8.2 Merge step (deterministic, no LLM)

```python
async def _merge_breaker_findings_into_master(*, master_session_id,
                                              breaker_results, on_event):
    for r in breaker_results:
        if not r.success or not r.finding_ids:
            continue
        for fid in r.finding_ids:
            await pencheff_server.copy_finding(
                src_session=r.breaker_session_id,
                dst_session=master_session_id,
                finding_id=fid,
                tag={"discovered_by_agent": r.agent_name},
            )
        await on_event(f"[Merge] {r.agent_name}: {len(r.finding_ids)} findings merged")
```

`copy_finding` is the fourth (and last) new pencheff helper this design needs. Single owner: only the orchestrator calls it.

### 8.3 Catastrophic fallback

```python
async def _catastrophic_fallback(*, reason, master_session_id, target, ...):
    await on_event(f"[Swarm] {reason}; falling back to single-agent loop")
    legacy = await agent_runner.run_agent(
        session_id=master_session_id, target_url=target.base_url, ...,
    )
    return SwarmOutcome(
        summary=legacy.summary, breaker_results=(),
        used_fallback=True, used_fallback_reason=reason,
        total_tool_calls=legacy.tool_calls, total_turns=legacy.turns,
    )
```

The two trigger conditions are exactly:

* `ReconAgent` raised `ReconFailed` (recon crashed or produced an empty snapshot), OR
* every entry in `breaker_results` has `success == False`.

A successful chain phase is not required: chain failure is non-fatal, breaker findings still ship.

### 8.4 `_run_single_agent`

Extracted from the body of `agent_runner.run_agent` into a reusable function that takes an `Agent` (system prompt + tool registry + turn budget) and a `session_id`. The legacy path becomes a thin wrapper that builds an `Agent` from `agent_runner.SYSTEM_PROMPT` + the full tool registry. This refactor is a pure code-move and ships in the same change as the swarm.

## 9. Configuration

New settings in `apps/api/pencheff_api/config.py`:

```python
swarm_enabled: bool = Field(True, alias="SWARM_ENABLED")

swarm_turns_recon_quick:    int = Field(8,  alias="SWARM_TURNS_RECON_QUICK")
swarm_turns_recon_standard: int = Field(12, alias="SWARM_TURNS_RECON_STANDARD")
swarm_turns_recon_deep:     int = Field(18, alias="SWARM_TURNS_RECON_DEEP")

swarm_turns_breaker_quick:    int = Field(6,  alias="SWARM_TURNS_BREAKER_QUICK")
swarm_turns_breaker_standard: int = Field(10, alias="SWARM_TURNS_BREAKER_STANDARD")
swarm_turns_breaker_deep:     int = Field(16, alias="SWARM_TURNS_BREAKER_DEEP")

swarm_turns_chain_quick:    int = Field(8,  alias="SWARM_TURNS_CHAIN_QUICK")
swarm_turns_chain_standard: int = Field(12, alias="SWARM_TURNS_CHAIN_STANDARD")
swarm_turns_chain_deep:     int = Field(20, alias="SWARM_TURNS_CHAIN_DEEP")

swarm_breaker_retry_attempts: int = Field(1, alias="SWARM_BREAKER_RETRY_ATTEMPTS")
swarm_breaker_retry_backoff_sec: int = Field(2, alias="SWARM_BREAKER_RETRY_BACKOFF_SEC")
```

LLM credentials reuse the existing `AGENT_LLM_*` settings. No new credentials, no new vendor relationship.

**Killswitch:** `SWARM_ENABLED=false` instantly reverts every scan to the legacy single-agent path. Safe for incident response.

## 10. Integration with `scan_runner.py`

Single integration point: the existing `_engine(...)` closure at `scan_runner.py:656-665` becomes feature-gated:

```python
async def _engine(session_prepopulated: bool = False) -> str | None:
    settings = get_settings()
    if settings.swarm_enabled:
        from .agent_swarm.orchestrator import run_swarm
        outcome = await run_swarm(
            master_session_id=psession.session_id,
            target=target,
            credentials=creds,
            profile=canonical_profile,
            scope=scope_include,
            exclude_paths=exclude_paths,
            on_event=lambda line: _publish_log(scan_id, line),
            session_prepopulated=session_prepopulated,
        )
        await _persist_swarm_telemetry(scan_id, outcome,
                                       db_session_factory=Session)
        return outcome.summary
    return await _run_agent_stage(
        scan_id=scan_id, psession=psession, target=target,
        profile=canonical_profile, credentials=creds,
        db_session_factory=Session,
        session_prepopulated=session_prepopulated,
    )
```

`dispatch_mode.py` is **not touched**. The three modes (`deterministic_only`, `agent_only`, `deterministic_then_agent`) keep their semantics; they just call a smarter `_engine`.

## 11. Telemetry

`_persist_swarm_telemetry` writes to the existing `Scan.summary` JSON column:

```python
summary_payload["swarm"] = {
    "used_fallback": outcome.used_fallback,
    "used_fallback_reason": outcome.used_fallback_reason,
    "breakers": [
        {
            "agent": r.agent_name,
            "success": r.success,
            "findings": len(r.finding_ids),
            "turns": r.turns,
            "tool_calls": r.tool_calls,
            "error": r.error,
        }
        for r in outcome.breaker_results
    ],
}
```

Lets the scan-detail page surface a per-agent table later (follow-up F1) without another schema change.

A structured `log.info("swarm_run", ...)` line at end of `run_swarm` reports `total_tool_calls`, `total_turns`, `wallclock_sec`, `breaker_count_succeeded` for Grafana monitoring.

## 12. Observability — events & log prefixing

Every event emitted by an agent gets a `[AgentName]` prefix in the SSE / scan-log channel:

```
[Recon]     tool: recon_passive
[Recon]     tool: recon_active
[Recon]     finished: 47 endpoints, 3 subdomains
[InjectionAgent] tool: scan_injection
[AuthAgent] tool: scan_auth
[InjectionAgent] tool: test_endpoint → /search?q=…
[CloudAgent] tool: scan_cloud
[Merge]     InjectionAgent: 2 findings merged
[Chain]     tool: exploit_chain_suggest
```

Real-time interleaving is expected and acceptable for v1. Per-agent UI grouping (tabbed/collapsible per-agent panels in `apps/web/app/scans/[id]/page.tsx`) is filed as **follow-up F1** for a separate brainstorm with the visual companion.

## 13. Scope safety

`ReconSnapshot.scope_include / scope_exclude` are passed to every seeded breaker session, and pencheff's existing `core/scope_guard.py` enforces them on every tool call. No new scope-bypass surface is introduced — breakers are at most as permissive as the legacy single agent.

## 14. File layout

All new code lives under `apps/api/pencheff_api/services/agent_swarm/`:

```
agent_swarm/
├── __init__.py            # exports run_swarm, SwarmOutcome
├── orchestrator.py        # run_swarm + _run_breaker_with_retry + fallback gate
├── snapshot.py            # ReconSnapshot, DiscoveredEndpoint
├── recon.py               # run_recon_phase + _freeze_snapshot
├── breakers.py            # BreakerSpec, _build_breakers (the 7-agent table)
├── chain.py               # _run_chain_phase
├── agent_loop.py          # _run_single_agent — refactored from agent_runner.run_agent
├── prompts.py             # per-agent system prompts (clean-room, ours)
├── tools.py               # per-agent tool subset selectors over pencheff registry
└── telemetry.py           # _persist_swarm_telemetry, event-prefix helper
```

New helpers added to `pencheff.server` (the only changes outside `apps/api`):

* `import_endpoints(session_id, endpoints)`
* `set_auth_state(session_id, cookies=…, tokens=…)`
* `attach_oast(session_id, oast_session_handle)`
* `copy_finding(src_session, dst_session, finding_id, tag)`

## 15. Testing strategy

### 15.1 Unit tests (`apps/api/tests/services/agent_swarm/`)

| Test file | What it covers |
|-----------|----------------|
| `test_snapshot.py` | `_freeze_snapshot` reads master psession → produces correct `ReconSnapshot`; tuples are immutable; `seed_breaker_session` round-trip preserves URLs/auth/OAST |
| `test_orchestrator_happy.py` | Stubbed LLM: recon succeeds → 7 breakers all return findings → chain runs → merged outcome surfaces |
| `test_orchestrator_partial.py` | 3 of 7 breakers crash, 4 survive → merge keeps the 4, chain runs, `breaker_results` reports failures with reasons |
| `test_orchestrator_recon_fail.py` | Recon raises `ReconFailed` → catastrophic gate fires → `agent_runner.run_agent` invoked → `used_fallback=True`, reason `recon_failed: <…>` |
| `test_orchestrator_all_breakers_fail.py` | Recon succeeds but every breaker fails → catastrophic gate fires for `all_breakers_failed` |
| `test_breaker_retry.py` | Transient on attempt 1 + success on attempt 2 → success; transient on both → failure; non-transient → no retry |
| `test_chain_failure.py` | Chain phase raises → orchestrator does NOT crash; uses `_synthesise_summary_from_breakers`; breaker findings still merged |
| `test_telemetry.py` | `summary_payload["swarm"]` shape exactly matches the documented schema; per-agent stats add up |
| `test_budgets.py` | Profile=quick passes 6 to each breaker; standard 10; deep 16; recon and chain follow their own table |
| `test_scope.py` | Scope-include/exclude propagates from snapshot into every breaker's seeded session; out-of-scope tool call rejected by `scope_guard` |
| `test_killswitch.py` | `SWARM_ENABLED=false` → `_engine` calls legacy `_run_agent_stage`; `SWARM_ENABLED=true` → calls `run_swarm` |
| `test_authz_quietquit.py` | If `snapshot.authenticated == False`, `AuthzAgent` finishes immediately with `"skipped: no authenticated session"` and counts as success |

### 15.2 Stubbed-LLM scaffolding

Tests inject a fake `httpx.AsyncClient` whose `.post(...)` returns scripted chat-completions responses (a sequence of tool calls per turn, then a `finish`). Helper `make_scripted_llm(turns: list[ScriptedTurn])` produces a client that `_run_single_agent` accepts unchanged. **No real LLM calls in CI.**

### 15.3 Integration test (live, off-CI)

`apps/api/tests/integration/test_swarm_against_dvwa.py`, marked `@pytest.mark.live`, runs the real swarm against locally-running DVWA / Juice-Shop in `docker-compose.toolchain.yml`. Asserts:

* All 9 agents start, all emit at least one `[AgentName] tool: …` event.
* Recon snapshot is non-empty.
* At least one finding gets attributed to a breaker via `discovered_by_agent`.
* Total wallclock < `(worst_case_sum_of_budgets × per_tool_call_ceiling)` — proves parallelism is real, not accidentally serial.
* `summary_payload["swarm"]["breakers"]` has 7 entries.

### 15.4 Manual smoke checklist

Lives at the top of `agent_swarm/__init__.py` as an ops note:

1. `SWARM_ENABLED=true`, run a scan against DVWA. Check the SSE event log shows interleaved `[Recon]…[InjectionAgent]…[AuthAgent]…[Chain]…`.
2. Force a recon failure (set `AGENT_LLM_API_KEY` to a value that 401s). Confirm the scan log emits the catastrophic-fallback line and finishes via the legacy path.
3. `SWARM_ENABLED=false`. Run again. Confirm the event log shows the plain unprefixed legacy-loop output (no `[AgentName]` prefixes anywhere), proving the killswitch reroutes through `agent_runner.run_agent`.

## 16. Open follow-ups (out of scope)

| # | Item | Why deferred |
|---|------|--------------|
| F1 | Per-agent UI grouping in `apps/web/app/scans/[id]/page.tsx` | Separate brainstorm with the visual companion once we've seen the raw `[AgentName]`-prefixed stream in production |
| F2 | Streaming recon → breaker handoff | Rejected for v1 — phase-staged is enough wallclock win; revisit if breaker-phase wallclock dominates |
| F3 | Live cross-breaker blackboard | Rejected for v1 — `ChainAgent` covers cross-finding work post-merge; revisit if Chain quality is poor |
| F4 | Per-agent model routing (cheap for `ReconAgent`, strong for `InjectionAgent`) | Out of scope; `AGENT_LLM_MODEL` is shared today. Revisit after we have cost data per agent role |
| F5 | More breakers (mobile, ML-supply-chain, hardware) | Out of scope; we add scaffolding for future agents but ship 7 |
| F6 | Removing legacy `agent_runner.py` (Q1-A) | Out of scope; only after the swarm path has run cleanly across paid-tier traffic for ≥ 4 weeks with no fallback firings |
| F7 | Operator-facing knob to disable individual agents | Out of scope; ship the orchestrator first, then expose if there is demand |

## 17. Decisions log (Q&A from brainstorm)

| Q | Decision |
|---|----------|
| Q1 | Keep `agent_runner.py` as fallback. Swarm becomes the default for `agent_only` and `deterministic_then_agent` |
| Q2 | Medium granularity: 7 breakers + dedicated `ChainAgent` + `ReconAgent` = 9 agents |
| Q3 | Three-phase staged execution: Recon → 7 parallel breakers → Chain |
| Q4 | Isolated per-breaker pencheff sessions; read-only recon snapshot; merge at end |
| Q5 | Profile-tiered turn budgets (`quick`/`standard`/`deep`); no global ceiling |
| Q6 | Best-effort with one transient retry per breaker; partial coverage acceptable |
| Q7 | Per-agent prefix in the event stream now; UI grouping deferred to follow-up F1 |
| Q8 | Catastrophic fallback fires iff `ReconFailed` OR every breaker failed |
