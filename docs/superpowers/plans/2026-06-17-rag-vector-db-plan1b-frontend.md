# RAG / Vector DB — Plan R1b: Frontend Registration

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Make `kind="rag"` registerable/displayable/editable in the web UI — `rag-vector-db` card → `kind:"rag"`, a source-aware `RagFormSection`, mirrored consent vocabulary, list/detail/edit support.

**Architecture:** Mirrors the SHIPPED MCP 1b exactly (`RagFormSection` is a sibling of `mcp-form-section.tsx`). Auth secrets use flat `credentials.headers` (managed/self-hosted DBs send API keys/connection secrets as headers); RAG config sent as `kind_config` (discriminated by `kind:"rag"`). Consent via `getKindDisclosures` with rag conditional logic mirroring backend `_required_disclosed_actions`.

**Tech Stack:** Next.js 15 static export, React, TS, Tailwind, `@/components/brutal`. Verify: `cd apps/web && npx tsc --noEmit` (no FE unit tests; tsc + `next build` are the gate).

**Branch:** `feat/rag-vector-db`. **Reference (verbatim-mirror the shipped MCP equivalents):** `components/register-target/mcp-form-section.tsx`; the mcp entries in `target-types.ts`, `lib/consent-disclosures.ts`, `app/targets/page.tsx`, `app/targets/new/page.tsx`, `app/targets/[id]/page.tsx`, `app/targets/[id]/edit/page.tsx`.

**RagConfig contract (from Plan R1):** `kind:"rag"`, `source_type` ∈ {managed_vdb, self_hosted_vdb, rag_endpoint, embedding_artifact}, `provider` (pinecone|weaviate|qdrant|chroma|milvus|pgvector|redis), `url`, `index_name`, `namespace`, `provider_llm` (LlmProvider), `request_template`, `response_path`, `items: string[]`, `query_probes: bool`, `poison_injection_opt_in: bool`, `canary_text`. Validation: managed/self_hosted→provider+url; rag_endpoint→provider_llm; embedding_artifact→items; poison_injection_opt_in→requires query_probes. Consent actions: `rag_enumerate` (always), `rag_query_probe` (when query_probes), `rag_poison_injection` (when poison_injection_opt_in).

---

## File structure

| File                                              | Change                                                                                                     |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `components/register-target/target-types.ts`      | `"rag"` in SupportedKind; `rag-vector-db` card `kind:"rag"`                                                |
| `lib/consent-disclosures.ts`                      | 3 ACTIONS; rag in REQUIRED/ADDITIONAL; getKindDisclosures rag conditional; KindConfigForDisclosures fields |
| `components/register-target/rag-form-section.tsx` | **New** controlled component                                                                               |
| `app/targets/new/page.tsx`                        | rag state, mount, submit branch, renderable                                                                |
| `app/targets/page.tsx`                            | local SupportedKind; TYPE_BADGE/COVERAGE maps; effectiveKind                                               |
| `app/targets/[id]/page.tsx`                       | SupportedKind; KindConfigView rag block                                                                    |
| `app/targets/[id]/edit/page.tsx`                  | Kind union; NEW_KIND_FORM_SECTIONS; hydrate; state + submit                                                |

Each task ends with `cd apps/web && npx tsc --noEmit` (clean) + commit.

---

## Task 1: Wire kind + list-page display

- [ ] **Step 1** — `target-types.ts`: add `"rag"` to `SupportedKind`; change the `rag-vector-db` card `kind:"llm"`→`kind:"rag"` (only that card).
- [ ] **Step 2** — `app/targets/page.tsx`: add `"rag"` to local `SupportedKind`; `TYPE_BADGE_BY_KIND` add `rag: "RAG / VECTOR DB"`; `COVERAGE_BADGES_BY_KIND` add `rag: ["RAG", "VECTOR DB"]`; in `effectiveKind`, add `if (k === "rag") return "llm";` before the final `return "url"`. If `COVERAGE_STYLES`/`TypeBadge` style maps need entries for new labels, reuse the llm style values (as the mcp wiring did).
- [ ] **Step 3** — `cd apps/web && npx tsc --noEmit` → clean (adding to `SupportedKind` will force exhaustive `Record<SupportedKind,...>` entries in `commission-scan-modal.tsx` + `consent-disclosures.ts` — add minimal `rag` entries there mirroring how `mcp` was added; the proper consent-disclosures values land in Task 2).
- [ ] **Step 4** — Commit: `git add components/register-target/target-types.ts app/targets/page.tsx components/commission-scan-modal.tsx lib/consent-disclosures.ts && git commit -m "feat(web): map rag-vector-db card to kind=rag + list-page badges"`

## Task 2: Consent disclosures for rag

- [ ] **Step 1** — In `lib/consent-disclosures.ts`, add 3 `ACTIONS` entries (shape `{id, displayName, description}`):
  - `rag_enumerate` — "RAG/vector-DB enumeration & static analysis" — connect + enumerate indexes/collections + audit config (auth, multi-tenancy) + sample chunks for secrets/PII at rest; no writes.
  - `rag_query_probe` — "RAG query probing (read-only)" — issue read-only retrieval/extraction queries to detect membership inference, datastore extraction, retrieval leakage, poisoning susceptibility.
  - `rag_poison_injection` — "RAG poisoning injection (destructive)" — write poisoned documents into the index to prove PoisonedRAG-style control; modifies the target — sandbox/throwaway index only; probe removes them after.
- [ ] **Step 2** — `REQUIRED_ACTION_IDS_BY_KIND` add `rag: ["rag_enumerate"]`; `ADDITIONAL_ACTIONS_BY_KIND` add `rag: ["rag_query_probe", "rag_poison_injection"]` (these are conditionally added, not auto-merged — see Step 4).
- [ ] **Step 3** — `KindConfigForDisclosures`: add `query_probes?: boolean` + `poison_injection_opt_in?: boolean`.
- [ ] **Step 4** — In `getKindDisclosures`, after the mcp conditional block, add (mirror mcp's nesting; preserve invariant "no query_probes ⇒ only rag_enumerate"):

```ts
if (k === "rag" && kindConfig?.query_probes) {
  ids.add("rag_query_probe");
  if (kindConfig?.poison_injection_opt_in) ids.add("rag_poison_injection");
}
```

Same caveat as mcp: if `ADDITIONAL_ACTIONS_BY_KIND` is merged unconditionally into `ids`, set `ADDITIONAL_ACTIONS_BY_KIND.rag = []` and rely solely on this conditional (the invariant: no query_probes → only `rag_enumerate`). Match whichever wiring mcp uses.

- [ ] **Step 5** — `cd apps/web && npx tsc --noEmit` → clean.
- [ ] **Step 6** — Commit: `git add lib/consent-disclosures.ts && git commit -m "feat(web): rag consent disclosure vocabulary"`

## Task 3: `RagFormSection` component

**Read first:** `components/register-target/mcp-form-section.tsx` — mirror its conventions (controlled flat props; `Input`/`Label`; `button role=radio` enum pickers; raw textarea/select/checkbox; auth-headers K-V grid; the dynamic-testing reveal pattern). Create `components/register-target/rag-form-section.tsx`.

- [ ] **Step 1** — Props (controlled getter/setter pairs): `name`; `sourceType` (4 values); `provider` (RagProvider); `url`; `indexName`; `namespace`; `providerLlm` (LlmProvider); `requestTemplate`; `responsePath`; `items` (textarea, one per line); `canaryText`; `queryProbes` (bool); `poisonInjectionOptIn` (bool); `headerRows` (auth K-V grid).
      Sections: (1) **source type** radio grid (4 options w/ descriptions); (2) **connection** conditional on sourceType — managed_vdb/self_hosted_vdb: provider radio grid (7) + url `Input` + index_name + namespace; rag_endpoint: providerLlm radio grid (reuse llm/mcp provider list) + requestTemplate (when custom) + responsePath; embedding_artifact: items `<textarea>`; (3) **name** optional; (4) **auth headers** K-V grid (copy from mcp form); (5) **dynamic testing**: `queryProbes` checkbox → when on, reveal `canaryText` `Input` + `poisonInjectionOptIn` checkbox (disabled + forced false when queryProbes off) + a warning line ("Poisoning injection writes documents into the index — sandbox/throwaway only").
- [ ] **Step 2** — `cd apps/web && npx tsc --noEmit` → clean (commit with Task 4 if an unused-import error blocks standalone).
- [ ] **Step 3** — Commit: `git add components/register-target/rag-form-section.tsx && git commit -m "feat(web): RagFormSection (source-aware RAG/vector-DB registration form)"`

## Task 4: Wire RagFormSection into new-target page

**Read first:** `app/targets/new/page.tsx` mcp wiring (state block, `renderable`, the `selectedKinds.includes("mcp")` mount, the mcp submit branch).

- [ ] **Step 1** — Import `RagFormSection`; add `rag*` useState for every prop (defaults: `ragSourceType="managed_vdb"`, `ragProvider="pinecone"`, `ragProviderLlm="openai-chat"`, `queryProbes=false`, `poisonInjectionOptIn=false`, strings "", rows []).
- [ ] **Step 2** — Add `"rag"` to `renderable`.
- [ ] **Step 3** — Mount `<RagFormSection .../>` under `selectedKinds.includes("rag")` (mirror the mcp mount; pass all props with names matching the component's Props).
- [ ] **Step 4** — Submit branch (mirror the mcp branch structure + post-success navigation):

```tsx
if (selectedKinds.includes("rag")) {
  const st = ragSourceType;
  if (
    (st === "managed_vdb" || st === "self_hosted_vdb") &&
    !(ragProvider && ragUrl.trim())
  )
    throw new Error("Vector DB requires provider and URL.");
  if (st === "rag_endpoint" && !ragProviderLlm)
    throw new Error("RAG endpoint requires a provider.");
  if (st === "embedding_artifact" && !ragItems.trim())
    throw new Error("Embedding artifact requires items.");
  if (ragPoisonInjectionOptIn && !ragQueryProbes)
    throw new Error("Poison injection requires query probes.");
  const headers: Record<string, string> = {};
  for (const r of ragHeaderRows) {
    const k = r.key.trim(),
      v = r.value.trim();
    if (k && v) headers[k] = v;
  }
  const cfg: Record<string, unknown> = { kind: "rag", source_type: st };
  if (st === "managed_vdb" || st === "self_hosted_vdb") {
    cfg.provider = ragProvider;
    cfg.url = ragUrl;
    if (ragIndexName.trim()) cfg.index_name = ragIndexName.trim();
    if (ragNamespace.trim()) cfg.namespace = ragNamespace.trim();
  }
  if (st === "rag_endpoint") {
    cfg.provider_llm = ragProviderLlm;
    if (ragProviderLlm === "custom") {
      cfg.request_template = ragRequestTemplate;
      cfg.response_path = ragResponsePath;
    }
  }
  if (st === "embedding_artifact")
    cfg.items = ragItems
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
  cfg.query_probes = ragQueryProbes;
  cfg.poison_injection_opt_in = ragPoisonInjectionOptIn;
  if (ragCanaryText.trim()) cfg.canary_text = ragCanaryText.trim();
  const baseUrl =
    st === "managed_vdb" || st === "self_hosted_vdb"
      ? ragUrl
      : `rag://${ragName || st}`;
  const t = await api<{ id: string }>("/targets", {
    method: "POST",
    json: {
      name: ragName || baseUrl,
      base_url: baseUrl,
      kind: "rag",
      kind_config: cfg,
      disciplines: disciplinesFor("rag"),
      ...(Object.keys(headers).length ? { credentials: { headers } } : {}),
    },
  });
  // reuse the mcp branch's post-create navigation
}
```

(`disciplinesFor("rag")` — if no rag entry, `[]` is acceptable for v1; note it.)

- [ ] **Step 5** — `cd apps/web && npx tsc --noEmit` → clean. (run `next build` in Task 6.)
- [ ] **Step 6** — Commit: `git add app/targets/new/page.tsx && git commit -m "feat(web): wire RagFormSection into new-target flow"`

## Task 5: Detail view + edit page

- [ ] **Step 1** — `app/targets/[id]/page.tsx`: add `"rag"` to the local kind union; in `KindConfigView` add a `{kind === "rag" && (...)}` block rendering source_type/provider/url/index_name/namespace/provider_llm/query_probes/poison_injection via `<Field>` (match sibling Field usage exactly).
- [ ] **Step 2** — `app/targets/[id]/edit/page.tsx`: add `"rag"` to the `Kind` union + `NEW_KIND_FORM_SECTIONS`; `case "rag"` hydrate (items array→textarea string; all fields from kc); render `<RagFormSection/>`; submit branch building the SAME kind_config shape as Task 4 + `credentials:{headers}` (PATCH).
- [ ] **Step 3** — `cd apps/web && npx tsc --noEmit` → clean.
- [ ] **Step 4** — Commit: `git add app/targets/[id]/page.tsx app/targets/[id]/edit/page.tsx && git commit -m "feat(web): rag kind config view + edit-page support"`

## Task 6: Build verification

- [ ] **Step 1** — `cd apps/web && npx tsc --noEmit` → clean.
- [ ] **Step 2** — `cd apps/web && npx next build` → succeeds (static export). Fix any reported file inline; if build too slow for the env, run tsc + note it.
- [ ] **Step 3** — Commit any fixups.

---

## Self-review

**Spec coverage (spec §5.3, §11):** card→kind + badges (T1) ✓; consent vocab FE (T2) ✓; RagFormSection 4 sources (T3) ✓; new-page wiring + submit (T4) ✓; detail + edit (T5) ✓; build gate (T6) ✓.
**Placeholder scan:** deterministic files (target-types, consent-disclosures) complete; component (T3) specified field-by-field with `mcp-form-section.tsx` as the explicit template.
**Type consistency:** kind_config keys (`source_type`, `provider`, `url`, `index_name`, `namespace`, `provider_llm`, `request_template`, `response_path`, `items`, `query_probes`, `poison_injection_opt_in`, `canary_text`) match Plan R1 `RagConfig`; consent action IDs match Plan R1 backend + FE-mirror test; client validation mirrors backend (poison→query, source-type required fields).
**Risk note:** `getKindDisclosures` additional-vs-conditional handling (T2 Step 4) must preserve "no query_probes ⇒ only rag_enumerate" — match the mcp wiring.
