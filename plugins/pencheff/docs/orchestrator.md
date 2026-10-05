# Pencheff Deterministic Orchestrator

The orchestrator runs a complete penetration-test engagement end-to-end with
**no language model in the loop**. Every decision — which tool to run, what
arguments to pass, which fallback to choose, when to back off, which attack
chains to consider — is driven by versioned YAML policy tables.

## Design

```
       CLI (auto-pentest, ctf-solve, …)        MCP (run_workflow)
                 │                                       │
                 ▼                                       ▼
       ┌──────────────────────────────────────────────────────┐
       │  workflows/   bug_bounty • ctf_solve • cve_intel     │
       │               red_team    • auto_pentest             │
       └──────────────────────────────────────────────────────┘
                                │
                                ▼
       ┌──────────────────────────────────────────────────────┐
       │  core/orchestrator/                                  │
       │    engine.py        — top-level Orchestrator         │
       │    state_machine.py — 9-phase FSM                    │
       │    selector.py      — picks tools                    │
       │    param_optimizer  — picks CLI args                 │
       │    chain_planner    — matches finding chains         │
       │    fallback.py      — graceful degradation           │
       │    throttle.py      — AIMD rate adapter              │
       │    cache.py         — LRU + disk spill               │
       │    result_normalizer — stdout → Finding              │
       └──────────────────────────────────────────────────────┘
                                │
                                ▼
       ┌──────────────────────────────────────────────────────┐
       │  modules/    + 116 → ~160 wrapped tools              │
       └──────────────────────────────────────────────────────┘
```

## Engagement phases

The state machine (`pencheff/core/orchestrator/state_machine.py`) drives
phases in this order:

1. **SCOPE** — validate the target against the scope guard.
2. **RECON_PASSIVE** — DNS / WHOIS / CT / wayback URLs.
3. **RECON_ACTIVE** — port scan / service fingerprint.
4. **AUTH** — auth surface mapping (if creds provided).
5. **SURFACE_MAP** — content discovery, parameter discovery.
6. **VULN_PROBE** — template-driven scans.
7. **EXPLOIT** — chains from `chains.yaml` whose preconditions are met.
8. **POST_EX** — generate post-ex helpers (no autonomous execution).
9. **REPORT** — finalize findings, run normalizers.

Each phase is a pure function of the engagement context. A phase can be
overridden via `Orchestrator.register_phase(phase, handler)` from a
workflow.

## Determinism

Reproducible runs are a first-class goal:

- All policy decisions read from YAML — no in-code thresholds.
- All randomness goes through `core/orchestrator/rng.py`, seeded from
  `(session_id, phase)`.
- The state machine records every transition; `tests/orchestrator/test_state_machine.py`
  treats the trace as a golden artefact.
- Two runs of the same target with the same policies produce the same
  Finding set up to network jitter (timestamps differ, decisions don't).

## Running the orchestrator

CLI:

```sh
pencheff auto-pentest   --target https://demo.local --intensity default
pencheff bb-recon       --target https://demo.local
pencheff ctf-solve      --challenge ./capture.png
pencheff cve-correlate  --findings findings.json
pencheff redteam-narrative --findings findings.json
pencheff explain-policy chains   # print the active YAML for review
```

MCP (from any LLM client):

```python
mcp__plugin_pencheff_pencheff__run_workflow(
    name="auto_pentest",
    target="https://demo.local",
    intensity="default",
)
```

## What it replaces (vs hexstrike-ai)

| Hexstrike component                | Pencheff replacement (deterministic) |
|------------------------------------|--------------------------------------|
| IntelligentDecisionEngine          | `selector.py` + `tool_selection.yaml` |
| ParameterOptimizer                 | `param_optimizer.py` + `parameters.yaml` |
| VulnerabilityCorrelator            | `chain_planner.py` + `chains.yaml` |
| AIExploitGenerator                 | (chain payload templates only — no model output) |
| GracefulDegradation                | `fallback.py` + `fallbacks.yaml` |
| RateLimitDetector                  | `throttle.py` + `throttle.yaml` (AIMD) |
| BugBountyWorkflowManager           | `workflows/bug_bounty.py` |
| CTFWorkflowManager                 | `workflows/ctf_solve.py` + `modules/ctf/` |
| CVEIntelligenceManager             | `workflows/cve_intel.py` + `cve_correlation.yaml` |
| Smart caching layer                | `cache.py` (LRU + disk spill) |

Every YAML has a `version` field that gets recorded into the engagement
result, so a report can be tied back to the exact policy set that produced
it.

## Dashboard / API integration

The web app and `POST /scans` only expose three tiers — Quick,
Standard, Deep. The deterministic orchestrator is wired in as follows:

| Dashboard tier | What runs |
|----------------|-----------|
| Quick    | URL pipeline (top-severity probes only). |
| Standard | URL pipeline + deterministic orchestrator phase (`bug_bounty` → `cve_intel` → `red_team`). |
| Deep     | Full Engage swarm + deterministic orchestrator (same chain, larger budget). |

Older specialised profile names (`engage`, `compliance`, `api-only`,
`cicd`, `sca`, `iac`, `supply-chain`, `network-va`, `hackme`,
`continuous`, `compliance-full`) are still accepted by the API and get
coerced to one of these three tiers at the runner — see
`apps/api/pencheff_api/services/scan_runner.py::_PROFILE_ALIASES`.

## See also

- `docs/policies.md` — how to author / override decision tables.
- `docs/workflows.md` — pre-built deterministic workflows.
- `THIRD_PARTY_NOTICES.md` — wrapped binary inventory + licenses.
- `CLEAN_ROOM.md` — provenance / IP posture.
