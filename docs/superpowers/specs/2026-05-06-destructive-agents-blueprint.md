# Destructive Agents — Implementation Blueprint

> **Status:** **DO NOT IMPLEMENT YET.** This document is a planning artifact.
> Each agent listed here changes target state, degrades availability, exits scope, or extracts data. Shipping any of them on the current "paste-a-URL" consent model is **not safe and probably not legal**.
> The shared prerequisites in §2 must be in place **before** any of these agents land in production.

**Date:** 2026-05-06
**Owners:** Pencheff API + Legal + Product
**Companion docs:** `docs/superpowers/specs/2026-05-05-parallel-agent-swarm-design.md`

---

## 1. Why this document exists

The current swarm (Recon → 10 breakers → Chain + Compliance) is **non-destructive**: every agent reads or probes; none change state, degrade availability, or extract data. That keeps the consent model simple ("paste a URL").

The agents below all break that property. They take an action that:
- changes the target's state (creates/deletes records, plants files, modifies sessions),
- impacts availability (slow-loris, query-of-death, resource exhaustion),
- exits the original target scope (lateral movement, leaked-credential pivots), or
- extracts customer data beyond schema-level introspection.

Because of that, they cannot reuse the existing consent + scope + telemetry plumbing. Each one has a meaningful product, legal, and engineering surface that must be solved before the agent's first line of code.

This blueprint enumerates **what each one would do, what it needs, and what must be true before implementation begins.**

---

## 2. Shared prerequisites (apply to every destructive agent)

These are blockers for the entire class. If any of these are missing, **no destructive agent ships**.

### 2.1 Per-scan consent — granular checkboxes
- A scan-creation UI surface that lists every destructive capability the operator is opting into, with one checkbox per class.
- Default: all OFF.
- Each checkbox shows a one-paragraph explanation of what the agent will do, the risk to the target, and that it cannot be undone.
- A free-text field where the operator pastes/types the customer authorization statement.
- Persisted per-scan: `Scan.destructive_consent: JSONB` (which checkboxes were ticked + verbatim authorization text + timestamp + operator user id).
- API rejects scan creation if any destructive flag is set without all three of {checkbox, authorization text ≥ 50 chars, operator click-through "I take responsibility").

### 2.2 Scope-guard hardening (already-flagged M-5 from prior review)
- `pencheff/core/scope_guard.py` is currently a process-global singleton that the API path **never invokes** (`set_scope()` is never called in API code). Effectively no scope enforcement on swarm scans today.
- Required change: scope is per-`PentestSession`. Add `PentestSession.scope_include / scope_exclude` (already on `ReconSnapshot` for breakers, but not on the master session). Every tool call routed through the session must `validate(url)` before issuing the request.
- Destructive agents must **abort the entire scan** on the first out-of-scope attempt (don't silently skip — it indicates the agent is misbehaving).

### 2.3 State-mutation journal
- Any agent that mutates target state must record the mutation to a `Scan.mutations: JSONB` array before performing it.
- Schema per entry: `{type, url, method, payload_hash, created_at, undo_action}`.
- A `CleanupAgent` runs at end-of-scan (success OR failure) and walks the journal in reverse, executing each `undo_action`.
- If cleanup fails on any entry, the scan reports `cleanup_partial` status — visible in the report — and notifies the operator.

### 2.4 Provider data-residency review
- Any agent that captures real target data (admin-panel screenshots, dumped rows, customer PII) sends it through the LLM provider's context.
- Required artifact: data-handling agreement with the LLM provider explicitly covering pentest-discovered customer data. Specifically:
  - Does the provider train on inputs?
  - Does the provider's prompt cache retain inputs?
  - What's the data-deletion timeline?
  - Where (region) is processing performed?
- Customers in regulated industries (HIPAA, PCI, GDPR Article 28) need this answered before they sign the engagement.

### 2.5 Legal authorization template
- Customer-side authorization template signed before the engagement. Specific carve-outs for:
  - Availability testing (with a fire window)
  - State mutation (with a rollback contract)
  - Data extraction (with retention and disposal terms)
  - Lateral movement (with explicit asset list / ASN / IP ranges)
  - Credential pivoting (with explicit list of "if a credential to system X is found, you are authorized to test it against system Y; otherwise stop")
- Pencheff cannot legally execute these without a signed authorization. Engineering enforcement: the consent UI requires uploading the signed authorization PDF before destructive flags can be ticked.

### 2.6 Liability + insurance
- A destructive scan has a non-zero chance of breaking customer prod (target DB locked, RDS bill spike, IAM credentials exhausted, app fully offline).
- Open questions for legal/insurance:
  - What's Pencheff's liability cap if the scan causes downtime?
  - Does Pencheff carry E&O / cyber liability insurance covering this?
  - Is per-engagement opt-in indemnity required from the customer?

### 2.7 Heartbeat + auto-abort
- All destructive agents run inside a heartbeat-watched envelope. Signals that trigger immediate abort:
  - Target returns ≥ 3 consecutive HTTP 5xx within 30s
  - Target response time crosses a threshold (e.g., p50 > 30s)
  - Customer-provided status-page URL flips to red (operator can pass `--status-page https://status.example.com` at scan creation)
  - Operator hits a "stop now" button in the scan-detail UI (new endpoint: `POST /scans/{id}/abort`)

### 2.8 Telemetry + reporting
- Every destructive action lands in:
  - The LLM trace (already exists)
  - The mutation journal (new — §2.3)
  - A new structured `destructive_actions` array on `Scan` (so reports can audit exactly what was done)
- The final report MUST include a "Destructive actions taken" appendix listing every action, observed effect, and cleanup status.

---

## 3. Agent: `AvailabilityAgent`

### 3.1 What it does
Probes for availability-impacting vulnerabilities by triggering controlled resource exhaustion against the target. Demonstrates that an attacker could degrade or stop the application.

### 3.2 Techniques in scope
- **Slow-loris** — opens many concurrent connections, sends partial requests at a slow trickle to exhaust connection pool
- **Regex DoS (ReDoS)** — submits inputs that trigger catastrophic backtracking on detected regex patterns (server-side validation)
- **GraphQL depth-bomb** — recursive query that explodes server-side cost
- **GraphQL alias-batching** — single request, thousands of aliased identical queries
- **ZIP-bomb upload** — uploads a small ZIP that decompresses to many GB
- **Query-of-death** — submits a request known to trigger a slow query (e.g., `LIKE '%xx%'` on an unindexed text column)

### 3.3 Required pencheff tooling (none exist today)
- New module `pencheff/modules/availability/` with one file per technique
- Each file exposes a single `probe(*, session_id, target_url, budget_seconds, ceiling_rps) -> ProbeResult` async function
- Hard internal caps: max 100 concurrent connections, max 100 RPS, max budget = 60s
- `ProbeResult` includes: technique, observed_response_times, http_status_distribution, abort_reason

### 3.4 Steps before implementation
1. **Customer authorization template** carve-out for availability testing — §2.5 done
2. **Operator opt-in flow** — §2.1 with checkbox: "Authorise short-burst availability probes (max 60s per technique)"
3. **Fire window** — operator selects a 5–10 minute window. Agent only runs within window. New schema field: `Scan.availability_fire_window: tstzrange`
4. **Heartbeat client** — §2.7 wired up before agent ever runs
5. **Per-technique budget enforcement** at three layers: agent prompt, `pencheff/modules/availability/` internal caps, and a hard kill-switch via `asyncio.wait_for`
6. **Observed-effect reporting** — every probe records exactly what response degradation was observed; the report shows "ZIP-bomb upload caused HTTP 504 on requests to /api/v1/upload for 12s"
7. **Status-page integration** — §2.7 status-page polling
8. **Insurance review** — §2.6
9. **Legal sign-off** — sign-off log entry per release

### 3.5 Phase placement
- Phase 4 (NEW) — runs solo, after Phase 3 finishes, only when `consent.availability == True`
- All other agents have completed by then (so degradation doesn't taint other agents' results)
- Strict serial: only one technique at a time

### 3.6 Risk tier
**Critical.** This agent can take a customer's production app offline. Untested launch is unacceptable.

### 3.7 Estimated effort
- Infrastructure (consent UI, scope guard, mutation journal, heartbeat, status-page integration): **8–12 weeks** for the cross-cutting pieces
- Agent + DoS modules + tests: **3–4 weeks**
- Legal/insurance/customer-template review: **2–4 weeks** (parallel)

---

## 4. Agent: `StateMutationAgent`

### 4.1 What it does
Given a verified write-capable bug (CSRF, IDOR-write, mass assignment, unauthenticated POST endpoint), creates a clearly-marked test record, reads it back to prove write+read worked, then deletes it. Proves "we could change your data."

### 4.2 Techniques in scope
- Insert: POST a record with `pencheff-pentest-{uuid}` as a clearly-marked identifier
- Read-back: GET / search to confirm the record exists
- Modify: PUT/PATCH a value on the record we created
- Delete: DELETE the record we created (cleanup)

### 4.3 Required pencheff tooling
- `pencheff/core/state_journal.py` — new module that records every write before it's executed
- New helper `mutate_with_journal(*, session_id, request, undo_request) -> MutationResult` that:
  1. Records the planned mutation to `Scan.mutations` (DB insert)
  2. Executes the forward request
  3. Records the actual response (success/failure)
  4. Schedules the `undo_request` for the cleanup phase

### 4.4 Steps before implementation
1. **§2.1** — opt-in checkbox: "Allow create/modify/delete of records bearing the `pencheff-pentest-` prefix"
2. **§2.3** — state-mutation journal infrastructure shipped
3. **CleanupAgent** must exist and run reliably before this agent is enabled
4. **Customer test-account requirement** — agent ONLY mutates within explicitly-marked test records. The operator provides a list of permitted prefixes / namespaces / customer IDs at scan creation
5. **Auto-quarantine** — any mutation that fails cleanup must trigger an alert (Slack / email to operator + customer security contact)
6. **Idempotency rules** — agent must never re-attempt a write whose journal entry shows "succeeded but cleanup failed" — that record exists in customer state and needs human triage
7. **Audit-log emission** — agent emits a clearly-labelled audit event for each mutation (`X-Pencheff-Action: write-test`) so the customer's audit log shows the activity

### 4.5 Phase placement
- Phase 2 — but only when consent and per-finding gating both pass
- Per-finding gating: agent only acts on findings tagged `verified:true` AND `category in {idor_write, csrf, mass_assignment, unauth_write}`

### 4.6 Risk tier
**High.** State mutation can corrupt customer data. Cleanup failure can leave artifacts. Customer audit logs get noisy.

### 4.7 Estimated effort
- Mutation journal + cleanup agent: **2–3 weeks**
- Agent + per-finding gating + tests: **2–3 weeks**

---

## 5. Agent: `PersistenceAgent`

### 5.1 What it does
Given a verified RCE / unrestricted file upload, plants a benign marker file (literally a text file containing `pencheff-pentest-marker-{uuid}`), proves it's reachable from the public surface, then deletes it. Demonstrates "we could leave a backdoor."

### 5.2 Techniques in scope
- Upload-to-webroot: POSTs the marker via the verified upload endpoint
- Reachability check: GETs the marker URL to confirm public access
- Cleanup: DELETE / re-upload empty / re-upload original
- **Explicitly out of scope:** webshells, executable payloads, privilege-escalating files, anything that changes server-side behaviour beyond the marker file

### 5.3 Required pencheff tooling
- `pencheff/modules/persistence/marker_lifecycle.py` — strict marker schema (`pencheff-pentest-marker-{uuid}.txt`, ≤ 200 bytes, plain text only)
- `mutate_with_journal` from §4.3 (shared)
- Pre-upload check: file extension and content-type must match the marker schema; agent rejects any payload that deviates

### 5.4 Steps before implementation
1. **§2.1** — opt-in checkbox: "Allow upload of a 200-byte plain-text marker file to verify file-upload findings (auto-deleted)"
2. **§2.3 + CleanupAgent** functioning
3. **Strict payload schema** enforced in code, not in prompt — the LLM cannot construct an arbitrary payload; it can only pick the verified-upload endpoint, and the marker content is generated server-side
4. **Path-traversal interaction with cleanup** — if the upload landed in a path the cleanup endpoint can't reach, the agent must emit a "manual cleanup required" finding with the exact path
5. **Customer authorization** explicitly carving out file uploads to webroot
6. **Forensic artifact** — agent stores SHA256 of the planted file so the customer can search their filesystem post-engagement

### 5.5 Phase placement
- Phase 2 — only fires on findings tagged `category == "unrestricted_file_upload"` AND `verified == true`

### 5.6 Risk tier
**High.** A persistence demonstration that fails to clean up leaves a real backdoor (even if benign). Anti-virus tools may quarantine the marker, breaking the cleanup contract.

### 5.7 Estimated effort
- Marker lifecycle module + tests: **1–2 weeks**
- Agent + per-finding gating + manual-cleanup-required path: **1–2 weeks**

---

## 6. Agent: `LateralMovementAgent`

### 6.1 What it does
Given a verified SSRF / RCE / SSO-misconfig foothold, enumerates internal-network adjacent services reachable from the foothold, identifies databases / admin panels / internal APIs, and reports exactly what an attacker could reach next. **No data extraction; only reachability.**

### 6.2 Techniques in scope
- SSRF → cloud metadata → enumerate IAM roles, attached policies (read-only, no API calls with the credentials)
- SSRF → internal-IP scan → identify services on internal subnets
- SSO misconfig → enumerate accessible apps in the SSO directory (read-only)

### 6.3 Required pencheff tooling
- `pencheff/modules/lateral/` — new module with internal-network probing primitives
- New scope-aware probe helper that accepts a per-engagement allowlist of internal IPs / ranges / ASNs

### 6.4 Steps before implementation
1. **§2.2** — scope-guard hardening **REQUIRED**. Without a working per-session scope guard, this agent will probe arbitrary internal infrastructure
2. **§2.5** — customer authorization MUST list the internal asset scope explicitly (e.g., "you are authorized to enumerate internal services on 10.0.0.0/8 and `*.internal.example.com`; you are NOT authorized to send any payload to those services")
3. **Two-phase consent** — operator at scan creation time pastes the explicit IP/ASN/CIDR list permitted for lateral enumeration. Agent silently aborts on any host outside that list
4. **Read-only enforcement** — agent's tool registry omits `test_endpoint` for internal hosts; only an `enumerate_only` tool that performs `GET /` and reports response code, never sends payloads
5. **Cloud-vendor terms** — many cloud providers' AUPs prohibit unauthorised metadata access even from within the customer's account. Customer must accept that lateral testing can hit their cloud vendor's abuse detection
6. **Provider notification** — for AWS / GCP / Azure customers, recommend (or require) advance notification per the cloud provider's pentest policy

### 6.5 Phase placement
- Phase 3 — runs after the merge step, only on verified `category in {ssrf, rce, sso_misconfig}` findings

### 6.6 Risk tier
**Critical.** Probing internal services without the right scope is unauthorised access. Even within scope, the boundary between "enumerate" and "probe" is fuzzy and easy to cross by accident.

### 6.7 Estimated effort
- Scope-guard hardening (M-5): **3–4 weeks**
- Internal probing primitives + tests: **3–4 weeks**
- Customer authorization template + per-scan asset list UI: **1–2 weeks**
- Agent + per-finding gating: **2 weeks**

---

## 7. Agent: `CredentialPivotAgent`

### 7.1 What it does
Given leaked credentials discovered by other agents (API keys in JS bundles, AWS keys in `.env` leaks, JWT secrets in source maps, default-cred database services), tests them against the customer's adjacent infrastructure to demonstrate the scope of compromise.

### 7.2 Techniques in scope
- Try AWS keys against the customer's allowlisted AWS account (read-only API calls only — `sts:GetCallerIdentity`, `iam:ListUserPolicies`, `s3:ListAllMyBuckets`)
- Try API keys against the corresponding API endpoint (read-only)
- Try database creds against allowlisted DB hosts (connect-only, no query)

### 7.3 Required pencheff tooling
- `pencheff/modules/credential_pivot/` — credential-typed test harness (one file per credential class)
- Allowlist enforcement: agent only tests creds against hostnames on the customer-provided allowlist

### 7.4 Steps before implementation
1. **CRITICAL FIRST**: legal opinion on the difference between "credential found in customer source code" and "authorisation to use that credential against the issuing system." Many jurisdictions treat the latter as unauthorised access regardless of how the credential was obtained
2. **§2.5** — customer authorization template explicitly carving out credential pivoting **per credential class**
3. **§2.2** — scope-guard hardening
4. **Per-credential allowlist** — operator pastes, at scan creation, an allowlist mapping like `{"aws": ["123456789012"], "github": ["org-name"], "internal-api": ["api.internal.example.com"]}`. Agent ONLY tests creds whose target system matches an allowlist entry
5. **Read-only enforcement** in code — the agent's tool registry contains only `test_credential` which does the minimum-rights API call per credential class; no general "make HTTP request with credential" capability
6. **Audit trail** — every credential test emits a structured event including credential hash (not the credential), target host, API call made, and result. Customer can replay this against their CloudTrail / audit logs

### 7.5 Phase placement
- Phase 3 — runs after merge, only on verified `category == "leaked_credential"` findings

### 7.6 Risk tier
**Critical.** "Credential found in customer code" is a finding; "credential successfully used to access customer cloud account" is a different category of action with different legal exposure.

### 7.7 Estimated effort
- Legal opinion + customer authorization template: **2–4 weeks** (parallel)
- Allowlist enforcement + per-credential test harness: **2–3 weeks**
- Agent + per-finding gating: **2 weeks**

---

## 8. Order of work (if/when this batch is greenlit)

The agents above have hard prerequisites. Implementation order should track those, not customer demand:

1. **§2.1 + §2.3** — consent UI + state-mutation journal + CleanupAgent **(blocking everything)**
2. **§2.2** — scope-guard hardening **(blocking lateral + credential-pivot)**
3. **§2.4–§2.7** — provider review, legal templates, insurance, heartbeat **(parallel with above)**
4. `StateMutationAgent` (lowest-risk destructive — small surface, clear cleanup story)
5. `PersistenceAgent` (small surface, clear cleanup, but content-handling adds AV / quarantine concerns)
6. `LateralMovementAgent` (after scope guard is live)
7. `CredentialPivotAgent` (after allowlist UX exists)
8. `AvailabilityAgent` **(last — highest risk, requires fire-window + heartbeat + insurance)**

A reasonable timeline assuming dedicated focus and legal/insurance unblocking on time: **6–9 months end-to-end** for the full destructive set. Skip steps at your own legal risk.

---

## 9. What NOT to do

Things engineering should not silently invent before the cross-cutting infrastructure ships:

- Don't add a `--dump` exception to `_DANGEROUS_ARG_SUBSTRINGS` "just to demonstrate impact." Once that line moves, every customer's data flows through the LLM provider's context.
- Don't ship `AvailabilityAgent` behind a single global feature flag. The flag becomes the only thing standing between an internal misconfiguration and a customer outage.
- Don't ship cleanup as a "best effort" library. If cleanup fails, the customer needs to know which mutations remain and how to undo them.
- Don't reuse the existing `paste-a-URL` consent for any of these. The legal exposure changes.
- Don't allow these agents to run on `quick` or `standard` profiles. Restrict to a new `destructive` profile that the operator explicitly opts into per scan.

---

## 10. Open questions for the next planning cycle

- Does Pencheff want to ship destructive testing as a product capability, or stay in the non-destructive lane? Both are defensible. Picking the non-destructive lane simplifies the legal posture significantly.
- If yes, which destructive agents are highest priority for customer demand? `AvailabilityAgent` is the most often-asked-for but the riskiest to ship.
- What's the customer-facing pricing for a destructive scan? These cost more to run safely.
- Does the pricing model justify the engineering+legal+insurance investment?
