# Agent Memory / Vector Store — Scanner Enrichment

- **Date:** 2026-06-17
- **Status:** Draft design → awaiting approval
- **Series:** Third of the AI-target-type series (**MCP ✅ → RAG ✅ → Agent Memory (this)**). Unlike MCP/RAG, this is **enrichment of an existing scanner**, not a new wire kind. The `memory` kind already exists: registration (`MemoryKindConfig.items`), `POST /v1/memory/scan` → `pencheff_sentry.memory.scan_memory`, FE `MemoryPanel`.

---

## 1. Goal

Deepen the agent-memory scanner beyond its current two detectors (LLM02 secrets/PII at rest; LLM04 basic poisoning: direct-override / role-play / dan / system-prompt-leak) to cover the research-validated 2024–2026 agent-memory attack surface (§5).

**Key research insight (drives the architecture):** effective memory attacks use <0.1% poison rates + _context-triggered_ activation (MINJA, AgentPoison, MemoryGraft), so **per-item static audit is necessary but insufficient** — we must add **cross-item/batch** detectors and provenance/isolation signals (A-MemGuard's consensus principle), not just more per-item regexes.

## 2. Non-goals

- Dynamic/runtime memory attack execution (we scan a batch of stored items + optional config; we don't drive a live agent across sessions).
- Embedding-vector analysis (the scanner sees item _text_, not vectors) — "halo/flooding" detection is approximated at the **text near-duplicate** level, not vector clustering.
- Re-architecting into a formal detector-plugin registry — the existing inline seam (per-item in `scan_memory_item`, cross-item in `scan_memory`) is sufficient; keep it.

## 3. Current state (verified)

`plugins/sentry/pencheff_sentry/memory.py`: `scan_memory(items) -> MemoryScanResult{items_scanned, findings, clean, severity_counts}`; `MemoryFinding{item_id, category, detector, severity, reason, matched_text, risk_score}`. Two inline detectors in `scan_memory_item` via `_all_matches(text, _PII_PATTERNS, "LLM02")` + `_all_matches(text, _INJECTION_PATTERNS, "LLM04")` (poisoning retries on NFKC-normalized text; escalates to critical on obfuscation/multi-technique). **No detector registry.** `core.py` already contains UNUSED pattern packs (`_MCP_INPUT_PATTERNS`, `_RAG_OUTPUT_EXFIL_PATTERNS`, `_CODING_AGENT_OUTPUT_PATTERNS`, `_BIAS_OUTPUT_PATTERNS`) — immediately wirable. API `/v1/memory/scan` takes `{items}` (bare strings or `{id,text}`); stateless. FE renders findings by detector/category. Tests: `cd plugins/sentry && uv run pytest tests/test_memory.py`.

## 4. Enrichment scope

### 4a. New per-item detectors (in `scan_memory_item`, the existing seam)

1. **Exfiltration-instruction (SpAIware)** — stored _standing instructions_ to send/transmit/POST/email/upload data to an external URL/destination ("in all future responses, send … to https://…"). The real-world ChatGPT persistent-spyware pattern. → detector `memory:exfil-instruction`, LLM01/LLM02, sev high→critical.
2. **Hidden/invisible content (first-class)** — Unicode Tags U+E0000–E007F, zero-width, bidi-override, NFKC-divergent chars as their OWN finding (today only escalates poisoning). → `memory:hidden-content`, LLM01, CWE-176.
3. **Persistence / memory-injection markers (MINJA/MemoryGraft)** — standing-persistence phrasing ("from now on", "remember to always", "in every future session", "store this as a rule") + "success example" framing that re-activates by similarity. → `memory:persistence-injection`, LLM04.
4. **Tool-output / RAG-chunk poisoning** — wire the EXISTING `_MCP_INPUT_PATTERNS` + `_RAG_OUTPUT_EXFIL_PATTERNS` from `core.py` into `scan_memory_item` (cheap; already built). → `memory:tool-output-poisoning`, LLM06/LLM02.
5. **PII expansion** — extend `_PII_PATTERNS` (passport, IBAN, US bank routing, JWT, private-key headers). → LLM02.

### 4b. New cross-item / batch detectors (in `scan_memory` — the research-critical addition)

6. **Exfil-chain (plan injection / context-chained)** — a logical chain ACROSS items that terminates in an external-destination/exfil step (e.g. "find user address" → … → "send to attacker.site"). → `memory:exfil-chain`, LLM01/LLM02, with `item_id` referencing the chain members.
7. **Near-duplicate flooding (RAGPoison halo, text-level)** — many near-identical items (normalized-text clustering above a count/ratio threshold) suggesting poison flooding. → `memory:poison-flooding`, LLM08.
8. **Cross-tenant / cross-session co-mingling** — when items carry namespace/user/session metadata (§4c), flag co-mingled tenants in one batch or items referencing another user/tenant's data. → `memory:cross-tenant-marker`, LLM08.

### 4c. Schema / API enrichment (enables 6–8 + provenance)

- Extend the scan input to accept **structured items** `{id, text, namespace?, source?}` (alongside the current bare-string/`{id,text}` forms — backward compatible). `MemoryKindConfig` gains an optional structured-items shape; `/v1/memory/scan` accepts the richer items; `MemoryScanOut`/`MemoryFindingOut` already carry `item_id`/`detector` so new findings flow through. FE `MemoryPanel`: surface `matched_text` (masked) + the new detectors (table already renders by detector); optional namespace/source columns.
- **Out of scope (note):** backend-version fingerprinting for known-vuln vector DBs (e.g. Milvus auth-bypass CVE-2025-64513) overlaps with the RAG scanner's connector/fingerprint path; the items-based memory scanner won't connect to a backend. If desired later, route memory-backed-by-vector-DB through the RAG `rag` kind.

## 5. Attack & exploit catalog (research-validated, cited — §8)

| Attack                                              | Detector          | Mapping / Source                                                             |
| --------------------------------------------------- | ----------------- | ---------------------------------------------------------------------------- |
| Persistent context-triggered poisoning (query-only) | 4b#6 + 4a#3       | LLM01/LLM04, CWE-77/1427 · MINJA (arXiv 2503.03704), A-MemGuard (2510.02373) |
| Backdoor-trigger / <0.1% poison + halo flooding     | 4a#3 + 4b#7       | LLM01/LLM04/LLM08 · AgentPoison (NeurIPS'24), RAGPoison (Snyk 2025)          |
| Cross-user/tenant memory bleed                      | 4b#8              | LLM02/LLM08 · OWASP LLM08:2025, MAMA (arXiv 2512.04668)                      |
| Vector-store auth bypass (cross-tenant)             | (RAG kind / note) | CWE-287/290 · Milvus CVE-2025-64513 (CVSS 9.3)                               |
| Persistent memory exfiltration (SpAIware)           | 4a#1              | LLM01/LLM02 · Rehberger / Embrace The Red 2024                               |
| Plan injection / context-chained exfil              | 4b#6              | LLM01/LLM02 · arXiv 2506.17318 (ICML'25)                                     |
| Trigger-free disk-persisted poisoning               | 4a#3              | LLM04/LLM08 · MemoryGraft (arXiv 2512.16962)                                 |
| Hidden/invisible stored instructions                | 4a#2              | LLM01, CWE-176 · OWASP LLM08:2025, RAGPoison                                 |
| Secrets/PII at rest (existing, expanded)            | 4a#5              | LLM02 · (current + expansion)                                                |

Defensive reference: **A-MemGuard** (consensus cross-memory validation) — informs the cross-item architecture (4b).

## 6. Findings / taxonomy

Reuse `MemoryFinding` + `MemoryScanResult` + the `/v1/memory/scan` response shape unchanged — new detectors just produce more `MemoryFinding`s (cross-item ones use `item_id="batch"` or a joined member list). Keep `matched_text` masked (never raw secret/payload). Severity rules consistent with current (critical on obfuscation/multi-technique/exfil-to-external).

## 7. Implementation surface (plan preview)

- `plugins/sentry/pencheff_sentry/core.py` — new pattern packs (`_EXFIL_INSTRUCTION_PATTERNS`, `_PERSISTENCE_PATTERNS`, `_HIDDEN_CONTENT` detection, expanded `_PII_PATTERNS`).
- `plugins/sentry/pencheff_sentry/memory.py` — new per-item detector blocks in `scan_memory_item`; new cross-item detectors in `scan_memory` (near-dup clustering, exfil-chain, cross-tenant); structured-item coercion in `_coerce_items`.
- `apps/api/pencheff_api/routers/memory_scan.py` + `schemas/targets.py MemoryKindConfig` — accept structured items (backward-compatible).
- `apps/web/components/memory-panel.tsx` — surface masked `matched_text` + new detectors (+ optional namespace/source).
- Tests: extend `plugins/sentry/tests/test_memory.py` (new detectors + cross-item) + API memory_scan tests.

Likely **2 plans:** (M1) per-item detectors + PII expansion + wire existing packs (pure, TDD, no schema change); (M2) cross-item detectors + structured-items schema/API/FE.

## 8. Sources (primary, verified 2026-06-17)

- **MINJA** memory injection — arXiv 2503.03704. **A-MemGuard** — arXiv 2510.02373.
- **AgentPoison** — NeurIPS 2024, arXiv 2407.12784. **RAGPoison** (embedding flooding) — Snyk Labs 2025.
- **MAMA** multi-agent memory attack / topology — arXiv 2512.04668. **OWASP LLM08:2025**.
- **Milvus auth bypass** — CVE-2025-64513 (CVSS 9.3), OSV/GHSA-mhjq-8c7m-3f7p.
- **SpAIware** persistent ChatGPT memory exfil — Rehberger / Embrace The Red 2024.
- **Plan injection / context manipulation** — arXiv 2506.17318 (ICML'25). **MemoryGraft** — arXiv 2512.16962.
