# RAG / Vector DB — Source-Aware Registration & Attack-Specific Scanning

- **Date:** 2026-06-17
- **Status:** Draft design → awaiting approval
- **Series:** Second of the AI-target-type series (**MCP/AI Agents ✅ shipped → RAG/Vector DB (this) → Agent Memory enrichment**). Reuses the per-type pattern MCP established: new wire kind + dedicated `*Config` + dedicated scanner module + graduated consent + `scan_runner` dispatch mirroring the `llm`/`mcp` special-case path.

---

## 1. Goal

Make the "RAG / Vector DB" register-target card a first-class, source-aware target with a dedicated scanner covering the research-validated RAG/vector-DB attack surface (§8). Today it's an undifferentiated `kind="llm"` chat probe.

Distinction from the existing **Agent Memory / Vector Store** (`kind="memory"`, scans a _batch of stored items_ for secrets+poisoning via `/v1/memory/scan`): RAG here is the **live retrieval system** — the vector DB and/or the query→retrieve→augment→LLM pipeline.

## 2. Non-goals (v1)

- Re-implementing every vector-DB vendor SDK — v1 ships a connector abstraction with a starter set (below) + a generic REST path; more vendors are additive.
- Training/running embedding-inversion models in-product (vec2text et al.) — v1 **flags invertibility _risk_** from config signals (raw-embedding export enabled, weak/known encoder, no access control), it does not perform inversion.
- Continuous monitoring; Agent Memory's batch scanner (separate kind).

## 3. Scope decisions (from kickoff)

| Decision                   | Choice                                                                                                                                                                                                                                                                |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Target modeling            | **New wire kind `rag`** + `RagConfig` (mirrors MCP `kind`/`McpConfig`). `Target.kind` is `String(16)` — no DB enum migration.                                                                                                                                         |
| Sources (all 4)            | `managed_vdb` (Pinecone/Weaviate Cloud/Qdrant Cloud via API), `self_hosted_vdb` (pgvector/Chroma/Milvus/Qdrant/Weaviate/Redis-vector via connection), `rag_endpoint` (live query→LLM HTTP endpoint, black-box), `embedding_artifact` (offline embeddings/index dump). |
| Static analysis            | Always — config/exposure audit, secrets/PII-at-rest in sampled chunks, invertibility-risk signals. Zero side-effects.                                                                                                                                                 |
| Dynamic query probes       | Read-only retrieval/output-observation probes (membership inference, datastore extraction, retrieval leakage, injection realization) — **consent-gated** (`rag_query_probe`).                                                                                         |
| Active poisoning injection | Writing poisoned docs into the index to _prove_ PoisonedRAG-style control — **consent-gated + destructive** (`rag_poison_injection`), sandbox/throwaway index only.                                                                                                   |

## 4. Architecture & data flow

```
Register (kind="rag", RagConfig.source_type)
  → Commission scan (consent gate: rag disclosures, §9)
  → scan_runner dispatches kind="rag" → scan_rag (mirrors the mcp/llm special-case path)
  → pencheff scan_rag orchestrator branches on source_type:
       ├─ managed_vdb / self_hosted_vdb:
       │     connector.connect → enumerate indexes/collections + config
       │     ├─ STATIC (§7a): exposure/auth, multi-tenancy/access-control, secrets-&-PII-at-rest (sampled chunks), invertibility-risk
       │     └─ [consent] DYNAMIC query probes (§7b): membership-inference (canary), retrieval-leakage/cross-tenant, datastore-extraction; [consent+destructive] poisoning-injection (§7c)
       ├─ rag_endpoint:
       │     black-box LlmProbe + rag attack pack (§7d): web-native injection carriers, datastore extraction, citation spoofing
       └─ embedding_artifact:
             offline analysis (§7e): secrets/PII at rest + invertibility-risk (reuses memory-scanner detectors)
  → Findings (OWASP-LLM + rag:* technique tags, CVSS, evidence) → DB → report
```

Reuses Finding/judge/OAST/`test_chain`/reporting/`compare_scans`. New engineering = the **vector-DB connector layer** (§6) + the analyzers (§7).

## 5. Registration & config — `RagConfig`

New `kind="rag"` (TargetKind, SupportedKind ×2, `_KINDS_REQUIRING_CONFIG`, `KindConfig` union). `RagConfig`:

```
kind: "rag"
source_type: "managed_vdb" | "self_hosted_vdb" | "rag_endpoint" | "embedding_artifact"
# managed_vdb / self_hosted_vdb
provider: "pinecone" | "weaviate" | "qdrant" | "chroma" | "milvus" | "pgvector" | "redis"
url: HttpUrl | None          # endpoint / connection URL
index_name: str | None       # index / collection / table
namespace: str | None        # tenant/namespace under test (for cross-tenant probes)
# rag_endpoint (LLM-style; reuses LlmProbe)
provider_llm: LlmProvider | None
request_template / response_path: str | None
# embedding_artifact
items: list[str] | None      # or a reference; sampled chunks / exported vectors
# common dynamic controls
query_probes: bool = False           # gate read-only dynamic probes
poison_injection_opt_in: bool = False # gate destructive index writes
canary_text: str | None              # operator-supplied canary for MIA/leakage probes
```

Auth (vector-DB API keys / connection secrets) → `kind_credentials_encrypted`. New FE `RagFormSection` with a `source_type` picker. Validation: managed/self-hosted→provider+url; rag_endpoint→provider_llm; embedding_artifact→items; poison_injection_opt_in→requires query_probes.

## 6. Vector-DB connector layer (new engineering)

`plugins/pencheff/pencheff/modules/rag_scan/connectors/` — a `VectorDbConnector` protocol (`connect`, `list_indexes`, `describe_index`, `sample_chunks`, `query(vector|text, top_k)`, optional `upsert` for poisoning). v1 connectors: **pgvector** (psycopg), **Qdrant**, **Chroma**, **Weaviate**, **Pinecone** (HTTP APIs — no heavy SDKs where a REST call suffices); a **generic REST** fallback. Connectors normalize into a `RagManifest` (indexes, dimensions, encoder hint, auth-required?, tenancy config) the analyzers consume — same decoupling as MCP's manifest (analyzers stay pure/testable).

## 7. Scanner analyzers

### 7a. Static / config audit (always) — over `RagManifest`

- **Exposure / missing auth** — DB reachable without credentials (the "thousands of open instances" class). _(Research open-question: needs a per-vendor exposure/CVE signal list — built as a refreshable `advisories.yaml` like MCP, seeded during impl.)_
- **Multi-tenancy / access-control config** — no namespace isolation / no metadata-filter enforcement / shared index across tenants (OWASP LLM08 cross-tenant leakage).
- **Secrets & PII at rest** — sample stored chunks; reuse the memory scanner's secret/PII detectors.
- **Invertibility risk** — raw-embedding export enabled + known/weak encoder + no access control → flag embedding-inversion exposure (LLM02/LLM08, CWE-200).

### 7b. Dynamic query probes (consent: `rag_query_probe`; read-only)

- **Membership inference** — insert/observe a canary; probe whether membership is inferable from outputs (output-observation probe).
- **Datastore extraction** — issue verbatim-extraction prompts (the "spill the beans" pattern); measure datastore leakage in responses.
- **Retrieval leakage / cross-tenant** — query namespace A for namespace B's content; detect isolation breaks.
- **Retrieval manipulation** — confirm query-similar crafted chunks dominate top-k (PoisonedRAG retrieval condition) without writing.

### 7c. Active poisoning injection (consent: `rag_poison_injection`; destructive, sandbox only)

- Upsert a PoisonedRAG-style doc (S⊕I: retrieval-anchor + injected instruction) for a benign canary question; confirm it lands in top-k AND steers generation → proves end-to-end control. Cleanup/remove after. Gated by both `poison_injection_opt_in` and the destructive disclosure.

### 7d. RAG-endpoint black-box probing (`rag_endpoint`)

Reuse `LlmProbe` + a new `rag` attack pack: **web-native injection carriers** (hidden spans, off-screen CSS, alt/ARIA, zero-width/confusable Unicode — Hidden-in-Plain-Text), datastore-extraction prompts, citation/source spoofing, retrieved-content indirect injection.

### 7e. Embedding-artifact offline analysis (`embedding_artifact`)

Reuse the memory scanner's secret/PII-at-rest detectors over sampled chunks + the invertibility-risk signal. Lowest-effort source.

## 8. Attack & exploit catalog (research-validated, cited — §15)

| Attack                                                                             | Layer                   | Detection                                                        | Mapping / Source                                            |
| ---------------------------------------------------------------------------------- | ----------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------- |
| Knowledge-base / document poisoning (PoisonedRAG)                                  | 7b/7c dynamic           | retrieval+generation condition probe; static hidden-carrier scan | LLM04/LLM01, CWE-20 · PoisonedRAG (USENIX'25)               |
| Web-native indirect injection (hidden spans, off-screen CSS, alt/ARIA, zero-width) | 7a static + 7d dynamic  | carrier detectors + injection probe                              | LLM01/LLM04 · Hidden-in-Plain-Text (WWW'26)                 |
| Verbatim datastore extraction                                                      | 7b/7d dynamic           | extraction-prompt output probe                                   | LLM02/LLM01 · "Spill the Beans" (ICLR'25)                   |
| Embedding inversion (text/PII from vectors)                                        | 7a static (risk signal) | invertibility-risk config signal                                 | LLM08/LLM02, CWE-200/359 · vec2text, transferable-inversion |
| Membership inference                                                               | 7b dynamic              | canary output-observation probe                                  | LLM02, CWE-200 · "Is My Data in Your Retrieval DB?"         |
| Cross-tenant / multi-tenant retrieval leakage                                      | 7a static + 7b dynamic  | isolation-config audit + cross-namespace query                   | LLM08 · OWASP LLM08:2025                                    |
| Exposed / unauth vector DB                                                         | 7a static               | reachability without auth + vendor advisory list                 | CWE-306 · (exposure list seeded in impl)                    |
| Trigger-based poisoning / brand promotion                                          | 7c dynamic              | trigger-token upsert + observe                                   | LLM04 · formal threat model (arXiv 2509.20324)              |

Reference tools (learn from, not vendor): **NVIDIA garak**, **promptfoo** (`red-team/rag` + `rag-poisoning` plugin).

## 9. Consent & safety

Add `rag` to `KIND_REQUIRED_DISCLOSED_ACTIONS` + FE `consent-disclosures.ts`. Graduated (mirrors MCP):

- `rag_enumerate` — passive connect + config/static audit (always).
- `rag_query_probe` — read-only dynamic query probes (when `query_probes`).
- `rag_poison_injection` — **destructive** index writes; required when `poison_injection_opt_in` (which itself requires `query_probes`). Sandbox/throwaway index only; probe cleans up after.

`_required_disclosed_actions` extension + `start_scan` gate mirror MCP. Default profile never writes to the index.

## 10. Findings, taxonomy & profiles

Findings reuse model+judge+reporting, tagged OWASP-LLM + `rag:*` technique (`rag:kb-poisoning`, `rag:embedding-inversion-risk`, `rag:membership-inference`, `rag:cross-tenant-leak`, `rag:datastore-extraction`, `rag:exposed-db`). Profiles: **Quick** = static/config only; **Standard** = + read-only query probes; **Deep** = + active poisoning injection (if opted in). Tool-call / query budget caps per profile.

## 11. Frontend change map

`target-types.ts` (`rag-vector-db`→`kind:"rag"` + SupportedKind), `RagFormSection`, `new`/`[id]/edit` pages, list badge + `effectiveKind`, `[id]` KindConfigView, `consent-disclosures.ts`.

## 12. Backend change map

`schemas/targets.py` (TargetKind, `_KINDS_REQUIRING_CONFIG`, `RagConfig`, KindConfig union), `schemas/scans.py` (disclosed actions), `routers/scans.py` (`_required_disclosed_actions` + gate until scanner lands), `services/scan_runner.py` (`rag` dispatch mirroring mcp + `scan_rag` entrypoint + profile caps + session `rag_config`), `plugins/pencheff/.../modules/rag_scan/` (connectors, manifest, static_analyzers, query_probes, poison, advisories.yaml, rag attack pack, module), `server.py` (`scan_rag` tool), migration marker.

## 13. Testing

Pure analyzers (carrier detection, invertibility-risk scoring, leakage/MIA verdict logic, config audit) unit-tested against fixture manifests; connectors tested with mock transports / a fixture pgvector or Chroma in-memory; consent gate tests (destructive blocked without disclosure) mirror `test_scans_*_kind_gate.py`. `test_scans_rag_*`.

## 14. Out of scope / open questions (refine during impl)

- **Vector-DB exposure/CVE list** — research found no consolidated primary source for unauth-endpoint signatures / per-vendor CVEs / internet-exposed counts. Seed `advisories.yaml` from Shodan/Censys patterns + vendor advisories during implementation.
- **Metadata-filter-bypass & citation-spoofing PoCs** — named but unsourced; refine probe signatures during impl.
- Embedding inversion is a **risk flag** in v1, not an executed attack.

## 15. Sources (primary, verified 2026-06-17)

- OWASP **LLM08:2025 Vector & Embedding Weaknesses** (canonical slug `llm082025-vector-and-embedding-weaknesses`).
- **PoisonedRAG** — USENIX Security 2025 (arXiv 2402.07867).
- **Hidden-in-Plain-Text** — WWW '26 (arXiv 2601.10923).
- **"Follow My Instruction and Spill the Beans"** (verbatim datastore extraction) — ICLR 2025 (arXiv 2402.17840).
- **vec2text** (EMNLP 2023, arXiv 2310.06816) + **transferable embedding inversion** (ACL 2024, arXiv 2406.10280).
- **"Is My Data in Your Retrieval Database?"** (membership inference) — arXiv 2405.20446.
- **Formal RAG threat model** — arXiv 2509.20324.
- Tools: NVIDIA garak; promptfoo RAG red-team + rag-poisoning plugin.
