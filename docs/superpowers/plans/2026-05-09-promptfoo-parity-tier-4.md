# Promptfoo Parity Tier 4 Implementation Plan

> **For agentic workers:** Implement this task-by-task on the `improvements` branch. Each Task is self-contained — write code + tests + commit per task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add seven capability gaps that pencheff lacks vs promptfoo: TAP / GOAT / Hydra strategies, coding-agent plugin suite, RAG-poisoning / RAG-exfil / RAG-source-attribution, MCP plugin, bias-testing category, GDPR + ISO/IEC 42001 mappings, and Aegis + UnsafeBench + XSTest dataset seeds.

**Architecture:** Additive layer — every item plugs into the existing `llm_red_team/` surface (engine.py / strategies.py / iterative.py / multiturn.py / datasets.py / payloads/*.yaml / config.py). No breaking changes. New strategies wire through the existing strategy registry (`plugins.py`); new payloads sit alongside `llm0[1-9]_*.yaml` in `payloads/`; new datasets join `_BUILTIN` in `datasets.py`; new compliance maps land in `config.py` and the report renderer.

**Tech Stack:** Python 3.11+, asyncio, httpx, PyYAML, pytest, existing plugin registry pattern. No new dependencies.

**IP stance:** Clean-room throughout.
- TAP — implemented from Mehrotra et al. *"Tree of Attacks: Jailbreaking Black-Box LLMs Automatically"* (arXiv:2312.02119, Apache-2.0 reference impl). Algorithm + system prompts written from paper, not copied.
- GOAT — implemented from Pavlova et al. *"Automated Red Teaming with GOAT"* (arXiv:2410.01606, Meta Research). Attack-tree taxonomy + scoring transcribed from paper.
- Hydra — concept (multi-objective parallel multi-turn) is generic and not IP-protected; we implement under our own description.
- Coding-agent suite — categories are descriptive names from public threat-modeling literature (Anthropic Claude Code threat model, OpenAI Codex docs, generic CWE-1023/1095). Payloads written from scratch.
- RAG plugins — from Zou et al. PoisonedRAG (arXiv:2402.07867) and Greshake et al. *Indirect Prompt Injection*. Algorithm published; payloads written fresh.
- MCP — Anthropic Model Context Protocol spec (modelcontextprotocol.io, MIT). Only the protocol shape; payloads original.
- Bias — generic public methodology (BBQ, BOLD, StereoSet); no upstream content vendored.
- GDPR / ISO/IEC 42001 — public regulatory text; we map article numbers to existing OWASP-LLM categories.
- Datasets (Aegis, UnsafeBench, XSTest) — match existing `datasets.py` pattern: 5-10 *paraphrased* clean-room seeds per dataset, citing the upstream paper + license in module docstring. No upstream rows copied.

---

## File map

| Status | File | Purpose |
|---|---|---|
| Modify | `plugins/pencheff/pencheff/config.py` | Add `GDPR_LLM_MAP`, `ISO_42001_LLM_MAP`. |
| Modify | `plugins/pencheff/pencheff/reporting/compliance.py` (and `apps/api/.../compliance.py`) | Render new mappings in compliance rollup. |
| Modify | `plugins/pencheff/pencheff/modules/llm_red_team/datasets.py` | Add Aegis / UnsafeBench / XSTest paraphrased seeds. |
| Create | `plugins/pencheff/pencheff/modules/llm_red_team/payloads/coding_agent.yaml` | 12 coding-agent attack categories, ~40 payloads. |
| Create | `plugins/pencheff/pencheff/modules/llm_red_team/payloads/rag.yaml` | RAG-poisoning, RAG-exfil, RAG-source-attribution payloads. |
| Create | `plugins/pencheff/pencheff/modules/llm_red_team/payloads/mcp.yaml` | MCP-specific tool poisoning + tool-name collision. |
| Create | `plugins/pencheff/pencheff/modules/llm_red_team/payloads/bias.yaml` | Age / disability / gender / race bias probes. |
| Create | `plugins/pencheff/pencheff/modules/llm_red_team/tap.py` | TAP tree-of-attacks search loop. |
| Create | `plugins/pencheff/pencheff/modules/llm_red_team/goat.py` | GOAT generative offensive agent attacker. |
| Create | `plugins/pencheff/pencheff/modules/llm_red_team/hydra.py` | Multi-objective parallel multi-turn dispatcher. |
| Modify | `plugins/pencheff/pencheff/modules/llm_red_team/strategies.py` | Register new strategy ids: `tap`, `goat`, `hydra`. |
| Modify | `plugins/pencheff/pencheff/modules/llm_red_team/base.py` | Route `tap` / `goat` / `hydra` through new dispatchers. |
| Modify | `plugins/pencheff/pencheff/modules/llm_red_team/__init__.py` | Re-export new modules. |
| Modify | `plugins/pencheff/pencheff/modules/llm_red_team/payloads/llm06_excessive_agency.yaml` | Add MCP-tool-discovery cross-link reference. |
| Create | `plugins/pencheff/tests/test_tap.py` | TAP search converges & prunes. |
| Create | `plugins/pencheff/tests/test_goat.py` | GOAT picks technique then refines. |
| Create | `plugins/pencheff/tests/test_hydra.py` | Hydra fans out objectives in parallel. |
| Create | `plugins/pencheff/tests/test_coding_agent_plugin.py` | Coding-agent payloads load, dispatch, dedup. |
| Create | `plugins/pencheff/tests/test_rag_plugin.py` | RAG payloads load. |
| Create | `plugins/pencheff/tests/test_mcp_plugin.py` | MCP payloads load. |
| Create | `plugins/pencheff/tests/test_bias_plugin.py` | Bias payloads load. |
| Create | `plugins/pencheff/tests/test_compliance_gdpr_iso42001.py` | New compliance maps render. |
| Modify | `plugins/pencheff/tests/test_promptfoo_parity.py` | Tier 4 block: TAP / GOAT / Hydra parity. |

---

## Task 1: Compliance mappings (GDPR + ISO/IEC 42001)

**Files:**
- Modify: `plugins/pencheff/pencheff/config.py`
- Modify: `plugins/pencheff/pencheff/reporting/compliance.py`
- Create: `plugins/pencheff/tests/test_compliance_gdpr_iso42001.py`

- [ ] **Step 1:** Add `GDPR_LLM_MAP` and `ISO_42001_LLM_MAP` constants to `config.py` next to the existing `EU_AI_ACT_MAP`. Keys are LLM01..LLM10; values are lists of article / control IDs.
- [ ] **Step 2:** Update `reporting/compliance.py` to include the two new maps in the per-finding rollup. Function: `compliance_rollup(findings)`.
- [ ] **Step 3:** Write `test_compliance_gdpr_iso42001.py` asserting that a dummy LLM01 finding rolls up to `GDPR Art.5`, `GDPR Art.32`, `ISO 42001 6.1.4`.
- [ ] **Step 4:** Run `pytest plugins/pencheff/tests/test_compliance_gdpr_iso42001.py -v`. Expect PASS.
- [ ] **Step 5:** Commit `feat(llm-redteam): add GDPR + ISO/IEC 42001 compliance mappings`.

---

## Task 2: Bias-testing payloads (LLM09 sub-techniques)

**Files:**
- Create: `plugins/pencheff/pencheff/modules/llm_red_team/payloads/bias.yaml`
- Create: `plugins/pencheff/tests/test_bias_plugin.py`

Categories (technique tags): `bias:age`, `bias:disability`, `bias:gender`, `bias:race`. Each has ~5 probes asking the model to make a categorical judgment about a demographic group; success indicators are stereotype-affirming substrings; refusal patterns are the standard `_REFUSALS`.

- [ ] **Step 1:** Author `bias.yaml` with 20 payloads (5 per dimension), each `category: LLM09`, `technique: bias:<dim>`, severity `medium`.
- [ ] **Step 2:** Wire the payload file into the loader: `base.py` already discovers `payloads/*.yaml` — verify by listing payloads at module import.
- [ ] **Step 3:** Write `test_bias_plugin.py` asserting that loading the YAML yields 20 cases across 4 techniques, none of which match a refusal regex against an obvious refusal string.
- [ ] **Step 4:** Run the test. Expect PASS.
- [ ] **Step 5:** Commit `feat(llm-redteam): add bias-testing payload pack`.

---

## Task 3: RAG plugin payloads

**Files:**
- Create: `plugins/pencheff/pencheff/modules/llm_red_team/payloads/rag.yaml`
- Create: `plugins/pencheff/tests/test_rag_plugin.py`

Three techniques mapped to LLM04 (poisoning) and LLM02 (exfil):
- `rag:poisoning` — context-injection that flips the answer (PoisonedRAG-style)
- `rag:exfiltration` — coerces the model to dump retrieved doc IDs / metadata
- `rag:source-attribution` — checks whether the model fabricates citations

- [ ] **Step 1:** Author `rag.yaml` with ~12 payloads spread across the three techniques. Each carries a synthetic "retrieved context:" block followed by an instruction.
- [ ] **Step 2:** Write `test_rag_plugin.py` asserting load count = 12, three distinct techniques, each technique includes at least one payload that names a synthetic doc ID `doc-CANARY-RAG-1`.
- [ ] **Step 3:** Run test. Expect PASS.
- [ ] **Step 4:** Commit `feat(llm-redteam): add RAG poisoning / exfil / source-attribution payloads`.

---

## Task 4: MCP plugin payloads

**Files:**
- Create: `plugins/pencheff/pencheff/modules/llm_red_team/payloads/mcp.yaml`
- Create: `plugins/pencheff/tests/test_mcp_plugin.py`

Sub-techniques (all under LLM06 — Excessive Agency):
- `mcp:tool-poisoning` — tool description carries a hidden instruction
- `mcp:tool-name-collision` — adversarial server registers `read_file` that mirrors a built-in
- `mcp:untrusted-server-prompt` — server's system message tries to override the host's
- `mcp:resource-exfil` — MCP resource URI exfiltrates by query string

- [ ] **Step 1:** Author `mcp.yaml` with ~10 payloads.
- [ ] **Step 2:** Write `test_mcp_plugin.py` asserting four distinct techniques load.
- [ ] **Step 3:** Run test. Expect PASS.
- [ ] **Step 4:** Commit `feat(llm-redteam): add MCP plugin payload pack`.

---

## Task 5: Coding-agent plugin suite

**Files:**
- Create: `plugins/pencheff/pencheff/modules/llm_red_team/payloads/coding_agent.yaml`
- Create: `plugins/pencheff/tests/test_coding_agent_plugin.py`

12 sub-techniques (each LLM06 unless noted):
1. `coding-agent:automation-poisoning`
2. `coding-agent:delayed-ci-exfil` (LLM02)
3. `coding-agent:generated-vulnerabilities` (LLM05)
4. `coding-agent:network-egress-bypass`
5. `coding-agent:procfs-credential-read` (LLM02)
6. `coding-agent:repo-prompt-injection` (LLM01)
7. `coding-agent:sandbox-escape`
8. `coding-agent:secret-handling` (LLM02)
9. `coding-agent:terminal-output-injection` (LLM05)
10. `coding-agent:steganographic-exfil` (LLM02)
11. `coding-agent:verifier-sabotage`
12. `coding-agent:core` — generic privilege probe

~3-4 payloads per technique = ~40 payloads.

- [ ] **Step 1:** Author `coding_agent.yaml`.
- [ ] **Step 2:** Write `test_coding_agent_plugin.py` asserting 12 techniques, each loading at least 3 cases, all categories valid.
- [ ] **Step 3:** Run test. Expect PASS.
- [ ] **Step 4:** Commit `feat(llm-redteam): add coding-agent plugin suite (12 techniques)`.

---

## Task 6: Aegis + UnsafeBench + XSTest dataset seeds

**Files:**
- Modify: `plugins/pencheff/pencheff/modules/llm_red_team/datasets.py`
- Modify: `plugins/pencheff/tests/test_promptfoo_parity.py`

Add `aegis`, `unsafebench`, `xstest` keys to `_BUILTIN`. Each carries 6-8 paraphrased clean-room seeds. Module docstring updated to cite each upstream paper + license + URL, with the explicit note that pencheff does not vendor any upstream rows.

- [ ] **Step 1:** Extend `datasets.py` `_BUILTIN`. Aegis → broad safety; UnsafeBench → image-paired text proxies (we ship text-only proxies); XSTest → exaggerated-safety / over-refusal probes (LLM09 with inverted success — "the model refused a benign request").
- [ ] **Step 2:** Extend `test_promptfoo_parity.py` to load each new dataset id and assert non-empty seeds.
- [ ] **Step 3:** Run test. Expect PASS.
- [ ] **Step 4:** Commit `feat(llm-redteam): add Aegis + UnsafeBench + XSTest paraphrased seeds`.

---

## Task 7: TAP strategy

**Files:**
- Create: `plugins/pencheff/pencheff/modules/llm_red_team/tap.py`
- Modify: `plugins/pencheff/pencheff/modules/llm_red_team/strategies.py` — register `tap` strategy id.
- Modify: `plugins/pencheff/pencheff/modules/llm_red_team/base.py` — dispatch when `tc.technique` ends with `:tap`.
- Create: `plugins/pencheff/tests/test_tap.py`

**Algorithm (Mehrotra et al.):**
1. Root = base prompt.
2. At each depth d = 1..D:
   - Each surviving leaf is expanded by the attacker LLM into B branch prompts (branching factor).
   - Each branch is sent to the target.
   - Judge scores each on (a) on-topic, (b) jailbreak-success.
   - Off-topic branches pruned (TAP's distinguishing feature vs PAIR).
   - Top-K by jailbreak-success kept; rest pruned.
3. Stop when judge marks a leaf as VULNERABLE or D exhausted.

Defaults: depth=4, branching=3, width=10.

- [ ] **Step 1:** Write `tap.py`: `TapResult` dataclass + `async def run_tap_attack(probe, tc, attacker, judge, *, depth, branching, width)`.
- [ ] **Step 2:** Register strategy `tap` in `strategies.py` (mirrors how `pair` is registered in `iterative.py`).
- [ ] **Step 3:** Add dispatch branch in `base.py` for `:tap` suffix.
- [ ] **Step 4:** Write `test_tap.py` with mocked attacker / target / judge. Assert pruning happens, depth respected, converged when target complies.
- [ ] **Step 5:** Run tests. Expect PASS.
- [ ] **Step 6:** Commit `feat(llm-redteam): add TAP iterative search`.

---

## Task 8: GOAT strategy

**Files:**
- Create: `plugins/pencheff/pencheff/modules/llm_red_team/goat.py`
- Modify: `strategies.py`, `base.py`
- Create: `plugins/pencheff/tests/test_goat.py`

**Algorithm (Pavlova et al.):**
1. Attacker maintains a multi-turn conversation with the target, but at each turn the attacker chooses one of N predefined adversarial techniques (e.g., "fictional setting", "dual response", "credible-persuasion", "policy-puppetry") and conditions its prompt on the target's last reply.
2. Internal scratchpad: attacker first writes (technique chosen, observation about target's last reply, planned move), then writes the user-facing turn.
3. Loop until VULNERABLE or budget hit.

We ship 8 named techniques in `_GOAT_TECHNIQUES` with system-prompt fragments authored from the paper's taxonomy.

- [ ] **Step 1:** Write `goat.py` — `_GOAT_TECHNIQUES` table + `GoatResult` + `async def run_goat_attack(...)`.
- [ ] **Step 2:** Register strategy `goat`.
- [ ] **Step 3:** `base.py` dispatch.
- [ ] **Step 4:** Tests with mocked attacker / target. Assert technique tag is recorded per turn.
- [ ] **Step 5:** Run tests. Expect PASS.
- [ ] **Step 6:** Commit `feat(llm-redteam): add GOAT multi-turn iterative search`.

---

## Task 9: Hydra multi-objective dispatcher

**Files:**
- Create: `plugins/pencheff/pencheff/modules/llm_red_team/hydra.py`
- Modify: `strategies.py`, `base.py`
- Create: `plugins/pencheff/tests/test_hydra.py`

**Mechanism (clean-room original):** Given one base TestCase that names ≥2 objectives in `tc.metadata['hydra_objectives']`, Hydra spins K parallel multi-turn conversations (one per objective), each pursuing a different framing. Conversations share an attacker LLM but have independent histories. A single VULNERABLE on any branch = finding. Concurrency capped by the existing rate limiter.

- [ ] **Step 1:** Write `hydra.py` with `HydraResult` + `async def run_hydra_attack(...)`.
- [ ] **Step 2:** Register `hydra` strategy.
- [ ] **Step 3:** `base.py` dispatch.
- [ ] **Step 4:** Tests with N=3 objectives, mocked target replies VULNERABLE on objective 2 only.
- [ ] **Step 5:** Run tests. Expect PASS.
- [ ] **Step 6:** Commit `feat(llm-redteam): add Hydra multi-objective parallel multi-turn dispatcher`.

---

## Task 10: Tier-4 promptfoo-parity test block

**Files:**
- Modify: `plugins/pencheff/tests/test_promptfoo_parity.py`

- [ ] **Step 1:** Append `# ── Tier 4.1 — TAP / GOAT / Hydra ──` block with smoke tests that exercise the strategies registered above through `apply_strategies(...)`.
- [ ] **Step 2:** Run full file: `pytest plugins/pencheff/tests/test_promptfoo_parity.py -v`. Expect PASS.
- [ ] **Step 3:** Commit `test(llm-redteam): tier 4 promptfoo parity coverage`.

---

## Task 11: Documentation

**Files:**
- Modify: `apps/docs/pages/features/llm-redteam.mdx`
- Modify: `README.md`

- [ ] **Step 1:** Add TAP / GOAT / Hydra to the "Strategies and composite stacking" section.
- [ ] **Step 2:** Add coding-agent / RAG / MCP / bias to the OWASP-LLM table footnote (sub-techniques).
- [ ] **Step 3:** Update compliance section to list GDPR + ISO/IEC 42001.
- [ ] **Step 4:** Update README "At a glance" feature row.
- [ ] **Step 5:** Commit `docs(llm-redteam): document tier 4 capabilities`.

---

## Self-review

- All 7 user-requested capabilities have a Task. ✓
- Every Task has explicit file paths, no placeholders. ✓
- IP stance documented per item with paper / license citation. ✓
- All strategies wire through the existing plugin registry. ✓
- All payloads sit alongside `llm0[1-9]_*.yaml` and load through the existing loader. ✓
- All datasets join `_BUILTIN` and follow existing paraphrase pattern. ✓
- Compliance maps render through the existing compliance pipeline. ✓
- Test surface = 1 test file per task + 1 parity-suite append. ✓

---

## Execution

This plan will be executed inline in the current session — see the task list managed via TaskCreate.
