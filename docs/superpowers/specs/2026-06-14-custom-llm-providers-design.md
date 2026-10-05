# Custom LLM Providers (Bring-Your-Own-LLM) — Design

**Date:** 2026-06-14
**Status:** Approved design (pre-implementation)
**Scope:** apps/api (backend) + apps/web (Settings UI). macOS/Electron desktop = follow-up (not in this spec).

## Summary

Let an org add and manage their **own** LLM providers from Settings (full CRUD), mark
**one active**, and have that active provider+model power **all** of Pencheff's AI
features. Providers are **typed/native** (OpenAI, Anthropic, Google, Azure OpenAI, and a
generic OpenAI-compatible endpoint), each with a native API adapter behind a uniform
chat interface. When no provider is configured, every AI feature behaves exactly as it
does today (Pencheff's env-default models). When a provider IS active, it overrides the
defaults everywhere; if it errors at runtime the feature **fails closed** (AI treated as
unavailable) rather than silently falling back to Pencheff's key.

## Confirmed decisions

| Decision                 | Choice                                                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| Which AI features use it | **All** AI features (FP triage, grading, AI-Triage-2.0, fix proposals, agentic fixer, scan agent, advisory AI)                       |
| Provider representation  | **Typed/native providers** (openai, anthropic, google, azure_openai, openai_compatible) with native adapters + curated model catalog |
| Selection model          | **Many providers (CRUD), exactly one active** org-wide; the active provider+model powers all features                                |
| Scope                    | **Org-scoped** (matches `security_lake_enabled`, `allow_private_targets`)                                                            |
| Permission               | **Owner/admin** can manage + activate; members read-only                                                                             |
| Runtime failure policy   | **Fail-closed** — a BYO-provider error makes the feature behave as "AI unavailable"; never silently use Pencheff's key               |
| Quotas / cost metering   | **Bypassed** when a BYO provider is active (customer pays their own LLM spend)                                                       |
| API key handling         | Fernet-encrypted at rest (existing `encrypt_credentials`); **never returned** by any endpoint (only `key_set` + last-4 hint)         |

## Why this shape

Every AI service today (`services/llm.py`, `fix_llm.py`, `triage_llm.py`, `advisory_ai.py`,
the scan agent in `agent_runner`, the agentic fixer) builds its own `httpx` call to an
OpenAI-compatible `/chat/completions` endpoint using env-var `base_url` + `api_key` +
`model`. There is no per-org override today. Per-target `Target.llm_config` exists but is
unrelated (it configures red-team probing of a customer's _own_ LLM endpoint).

The cross-cutting risk is provider-specific request/response code leaking into all six
services. We contain it in one package (`services/llm_providers/`) behind a single
`ChatClient` interface + one resolver, so the six services only gain a tiny "use org
client if present, else current behavior" guard.

## Architecture

```
Settings UI ─CRUD─> /llm-providers ─> llm_providers table (org-scoped, key encrypted)
                                       Org.active_llm_provider_id ─┐
                                                                   ▼
6 AI services ─> resolve_chat_client(org_id) ─> ChatClient adapter ─> OpenAI│Anthropic│Gemini│Azure│compat
                                       └─ returns None ─> existing env-default path (unchanged)
```

Two planes / two implementation plans:

- **Plan A — Management plane:** migration + model + CRUD API + activate/test endpoints +
  Settings UI. Fully testable on its own (you can manage providers before they're wired in).
- **Plan B — Data plane:** `ChatClient` interface + per-provider adapters + resolver +
  the guard in each of the six services + quota bypass. Depends on Plan A's data model.

## 1. Data model

New table **`llm_providers`** (Alembic migration `0056`, down_revision `0055`):

| column              | type                                    | notes                                                                           |
| ------------------- | --------------------------------------- | ------------------------------------------------------------------------------- |
| `id`                | UUID PK                                 |                                                                                 |
| `org_id`            | UUID FK→orgs ON DELETE CASCADE, indexed | org-scoped                                                                      |
| `label`             | String(120) NOT NULL                    | user display name                                                               |
| `provider`          | String(32) NOT NULL                     | `openai` \| `anthropic` \| `google` \| `azure_openai` \| `openai_compatible`    |
| `model`             | String(200) NOT NULL                    | selected model id (catalog suggestion or free text)                             |
| `base_url`          | String(1024) NULL                       | required for `openai_compatible`; optional override for `openai`/`azure_openai` |
| `api_key_encrypted` | LargeBinary NULL                        | Fernet blob via `encrypt_credentials({"api_key": ...})`                         |
| `azure_deployment`  | String(200) NULL                        | azure_openai only                                                               |
| `azure_api_version` | String(40) NULL                         | azure_openai only                                                               |
| `extra`             | JSONB NULL                              | optional: extra headers, openai `organization`, google project, etc.            |
| `created_at`        | DateTime(tz) server_default now()       |                                                                                 |
| `created_by`        | UUID FK→users ON DELETE SET NULL, NULL  | audit                                                                           |

Constraints: `UniqueConstraint(org_id, label)`; `Index(org_id)`.

New column on **`orgs`**: `active_llm_provider_id` UUID FK→`llm_providers.id`
**ON DELETE SET NULL**, NULL default. This single pointer enforces "exactly one active"
and makes delete-of-active fall back to defaults automatically.

(Note: `Org.active_llm_provider_id → llm_providers.id` and `llm_providers.org_id → orgs.id`
are two FKs between the tables but not a hard cycle; Alembic adds `active_llm_provider_id`
after `llm_providers` exists. The `org_id`→orgs cascade and the SET NULL pointer don't
conflict.)

### Pydantic schemas (`schemas/llm_providers.py`)

- `LlmProviderKind = Literal["openai","anthropic","google","azure_openai","openai_compatible"]`
- `LlmProviderCreate`: `label`, `provider`, `model`, `base_url?`, `api_key`, `azure_deployment?`, `azure_api_version?`, `extra?`. Validators:
  - `openai_compatible` → `base_url` required.
  - `azure_openai` → `base_url` + `azure_deployment` + `azure_api_version` required.
  - `api_key` required on create for all kinds except a `base_url`-only self-host that needs no key (allow empty key only for `openai_compatible`).
- `LlmProviderUpdate`: all optional; `api_key` omitted/None = unchanged, `""` = clear (mirrors the PAT-rotation rule in `routers/repos.py`).
- `LlmProviderOut`: `id, label, provider, model, base_url, azure_deployment, azure_api_version, extra, key_set: bool, key_hint: str|None ("…AB12"), is_active: bool, created_at`. **No api_key field ever.**

## 2. CRUD API (`routers/llm_providers.py`)

Mounted under the existing app router. All endpoints scoped to the active org and gated
`require_org_role("owner","admin")` for writes; reads allowed for any member.

- `GET /llm-providers` → `list[LlmProviderOut]` for the active org. `is_active` computed
  by comparing `org.active_llm_provider_id`.
- `POST /llm-providers` → create; encrypt `api_key`; return `LlmProviderOut`.
- `PATCH /llm-providers/{id}` → edit fields; key rule above; re-validate per-kind.
- `DELETE /llm-providers/{id}` → delete (FK SET NULL clears the org pointer if it was active).
- `POST /llm-providers/{id}/activate` → `org.active_llm_provider_id = id`; returns updated `OrgOut`.
- `POST /llm-providers/deactivate` → `org.active_llm_provider_id = None` (revert to Pencheff defaults).
- `POST /llm-providers/{id}/test` → build the adapter, send a minimal 1-token chat
  ("reply 'ok'"), return `{ok: bool, latency_ms: int, error: str|null, model: str}`. The
  primary guardrail for typed providers: a wrong key/model/endpoint fails here, not mid-scan.

Every mutating endpoint writes an `AuditLog` row (action `org.llm_provider.{created|updated|
deleted|activated|deactivated}`, with `request_ip`/`user_agent`, before/after summary —
**never the key**), matching the `security_lake_enabled` audit pattern in `routers/orgs.py`.

## 3. Adapters + resolver (`services/llm_providers/`)

- `base.py` — `class ChatMessage` (role, content); `ChatResult` (text, raw, usage?);
  `class ChatClient(Protocol)` with `async def chat(self, messages, *, temperature=0.0,
max_tokens=1024, json=False, timeout=60.0) -> ChatResult`.
- `openai_compat.py` — `OpenAICompatClient` covering `openai`, `openai_compatible`, and
  `azure_openai` (azure swaps to `{base_url}/openai/deployments/{deployment}/chat/completions
?api-version=...` with `api-key` header). This is the exact shape the services use today.
  Honors `json=True` via `response_format={"type":"json_object"}`.
- `anthropic.py` — `AnthropicClient`: POST `{base_url|https://api.anthropic.com}/v1/messages`,
  header `x-api-key` + `anthropic-version`, system prompt split into the top-level `system`
  field, response text from `content[0].text`. `json=True` appended as a strict
  "return only JSON" instruction and parsed.
- `google.py` — `GeminiClient`: POST Gemini `generateContent`, key as `?key=` or header,
  messages mapped to `contents[].parts[].text`, system via `system_instruction`,
  `json=True` via `generationConfig.responseMimeType="application/json"`.
- `catalog.py` — `MODEL_CATALOG: dict[kind, list[ModelInfo]]` with current models
  (Anthropic: claude-opus-4-8, claude-sonnet-4-6, claude-haiku-4-5; OpenAI: gpt-5 family;
  Google: gemini-2.x). Exposed via `GET /llm-providers/catalog` for the UI dropdown.
  Free-text model is always allowed so new models don't require a deploy.
- `resolver.py` — `async def resolve_chat_client(org_id, db) -> ChatClient | None`: load
  `org.active_llm_provider_id`; if unset return `None`; else load the provider row, decrypt
  the key, construct the matching adapter. Small per-request cache keyed by provider id+
  updated marker is optional (not required for v1).

### JSON-mode

AI-Triage-2.0 and grading rely on JSON output. The adapter normalizes `json=True` per
provider (native where supported, instruction+parse otherwise) and returns parsed-safe
text, so callers keep their existing parse logic.

## 4. Wiring into the six AI services (Plan B)

Each service gains a small guard at the point it builds its client/call. Pattern:

```
client = await resolve_chat_client(org_id, db)   # None when no active provider
if client is not None:
    text = await client.chat(messages, json=..., max_tokens=...)
    # BYO path: NO quota check, NO Pencheff-cost metering
else:
    ... existing env-default httpx behavior, unchanged ...
```

Services to wire: `services/llm.py` (FP triage + grading + `advisory_ai.py` via the shared
client), `services/fix_llm.py` (fix patches, both free/pro routes collapse to the org model),
`services/triage_llm.py` (AI-Triage-2.0), the scan agent (`agent_runner`), and the agentic
fixer. Each service must already have (or be given) the `org_id` at the call site; where a
service currently has no `org_id` in scope, thread it from the scan/finding/repo it operates
on (these all carry `org_id`).

**Fail-closed:** if `client.chat` raises, the service treats it as "AI unavailable" using
its existing no-AI path (triage/grade skipped, fix not proposed, agent step errors out) —
it does **not** fall back to the Pencheff env client. The org's data-residency choice is
never silently violated.

**Quota bypass:** when `client is not None`, the free-tier fix/triage quota checks
(`fix_quota`, `ai_free_tier_enabled` gates) are skipped — the org is on their own key/spend.

## 5. Web Settings UI (`apps/web`)

- New section/page "AI / LLM Provider" in Settings (owner/admin editable, members read-only),
  reachable from the existing Settings nav.
- A table of the org's providers (label, provider badge, model, "Active" pill) with
  Add / Edit / Delete / Activate / Test actions — full CRUD.
- Add/Edit form: provider-kind select → reveals the relevant fields (base_url for
  compatible/azure, deployment+api-version for azure), model field with catalog-suggestion
  datalist (from `GET /llm-providers/catalog`) + free text, api-key field (write-only;
  shows "key set ••••AB12" when editing, blank = unchanged).
- "Test" button calls `/test` and shows ok/latency/error inline before the user relies on it.
- Data via the existing `api()` client; list refetched after each mutation. `Org`
  type/context unchanged except optionally surfacing `active_llm_provider_id` for the pill.

## 6. Error handling

- Create/edit validation errors → 422 with field detail.
- `/test` failures → 200 with `{ok:false, error}` (so the UI shows it inline; not an HTTP error).
- Runtime adapter errors in the six services → fail-closed (see §4); logged, not surfaced as
  a fallback.
- Deleting the active provider → allowed; org pointer SET NULL; AI reverts to Pencheff
  defaults on the next call.

## 7. Testing (repo convention: pure unit, hand-built fakes, no DB)

- **Adapters:** per provider, assert the outgoing request shape (URL, headers, body) and
  response→text mapping, including `json=True`. Use a fake httpx transport / monkeypatched
  client.
- **Resolver:** returns `None` when `active_llm_provider_id` is unset; builds the right
  adapter class per kind; decrypts the key.
- **CRUD:** create encrypts the key and `LlmProviderOut` never includes it (`key_set`/
  `key_hint` only); PATCH with no api_key leaves it unchanged, `""` clears it; activate sets
  the org pointer; delete-of-active nulls it; audit row written per mutation.
- **Catalog:** endpoint returns the expected kinds.
- **Wiring (per service):** with a stubbed resolver returning a fake client, the service
  routes through it and skips quota; when the fake client raises, the service takes its
  no-AI path (fail-closed) and does NOT call the env client.
- **Key round-trip:** `encrypt_credentials`/`decrypt_credentials` for the api_key.

## Out of scope

- macOS/Electron desktop parity (documented follow-up after the web ships).
- Per-feature provider routing (explicitly rejected: one active provider org-wide).
- Streaming responses, embeddings, or non-chat modalities.
- Usage/billing dashboards for the customer's own spend.
- Changing Pencheff's default env-based models or the per-target red-team `llm_config`.
