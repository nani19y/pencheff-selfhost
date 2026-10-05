# Pencheff Security Lake — Deploy & External-Access Ops

**Date:** 2026-06-13
**Audience:** whoever deploys the Security Lake to prod and onboards external (customer) consumers.
**Companion docs:** design spec (`…-pencheff-security-lake-design.md`), threat model (`…-security-lake-threat-model.md`). This doc closes the threat model's **[GATE]** items for external access.

> **Sandbox caveat:** the dev/CI environment has no Cloudflare R2 and no customer buckets, so everything in §1 and §3 below is **deploy-verified only** — it cannot be exercised by the test suite. The export _artifacts_ (NDJSON/Parquet) and org-scoping ARE tested locally (`tests/test_security_lake_export.py`, `…_router.py`, `…_tenancy.py`).

## 1. Prod catalog configuration — DEPLOYED 2026-06-13

The lake defaults to a local SQLite catalog for dev. **Prod uses the `sql` catalog backed by the existing Postgres + R2 as the object-store warehouse** (S3 FileIO). This was chosen over R2 Data Catalog (`rest`) because the Cloudflare token's R2-Storage scope does not cover R2 Data Catalog `enable`, and Postgres-as-catalog is proven, concurrency-safe across the api/worker containers, and needs no extra service. `build_catalog`'s `sql` branch passes the `r2_*` creds as S3 FileIO props (verified against real R2).

Env vars set in the VM `/home/pencheff/pencheff/.env` (flow to both `api` + `worker` via `env_file`):

| Setting (env var)                           | Deployed value                                                                                                |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `LAKE_CATALOG_TYPE`                         | `sql`                                                                                                         |
| `LAKE_CATALOG_URI`                          | `postgresql+psycopg2://pencheff:pencheff@postgres:5432/pencheff` (Postgres catalog; **sync** psycopg2 driver) |
| `LAKE_WAREHOUSE`                            | `s3://pencheff-lake/warehouse` (R2)                                                                           |
| `R2_ENDPOINT_URL`                           | `https://<account-id>.r2.cloudflarestorage.com`                                                               |
| `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` | R2 S3 token (Object Read & Write) — **internal creds, never issued to a customer**                            |
| `LAKE_NAMESPACE` / `LAKE_TABLE`             | `pencheff` / `findings`                                                                                       |

Postgres holds only the Iceberg catalog pointer tables (`iceberg_tables`, `iceberg_namespace_properties`, auto-created); all metadata + data Parquet live in R2 under `pencheff-lake/warehouse/pencheff/findings/`, partitioned `org_id/class_uid/dt`.

`build_catalog`'s `rest` branch (R2 Data Catalog) remains supported for a future switch — it needs an R2-Data-Catalog-scoped token + `enable` on the bucket.

These R2 creds are internal (workers + API) and grant full read/write — **never** issued to a customer (threat model §3). Rotate on a schedule.

Verified at deploy: `build_catalog(settings)` connects, `LakeWriter.ensure_table()` created the empty `pencheff.findings` table, and a `map_finding → R2 append → read` round-trip succeeded inside the live `pencheff-api-1` container.

## 2. Database migration

Apply Alembic `0054` for the audit tables (`lake_ingestion`, `lake_quarantine`):

```
cd apps/api && alembic upgrade head    # expect 0054 applied
```

Without it, the Celery ingest tasks' idempotency check and audit writes fail.

## 3. External access (subscribers) — the two safe modes

Per threat model §4–5, **never** hand a customer a raw Iceberg REST-catalog token or a shared-bucket credential — the shared metadata leaks all tenants. Use one of:

### (A) Push-export to the customer's own bucket — default for SIEM/lake subscribers

A scheduled per-org job:

1. `export_org_parquet(settings, org_id=<org>)` (lake-to-lake) or `export_org_ndjson(...)` (SIEM).
2. PUT the artifact into the **customer's** R2/S3 bucket using the **customer's** credentials (stored per-org, encrypted at rest; never logged).
3. The customer's SIEM/lake reads from _their_ storage. Pencheff grants nothing on its own bucket/catalog.

This mirrors AWS Security Lake's subscriber model. The org boundary is enforced inside `export_org_*` (server-derived `org_id` → `EqualTo` partition scan); the only cross-tenant risk is mis-routing an artifact to the wrong customer bucket — so the per-org bucket-credential mapping is itself sensitive config and should be covered by the §4 gate check.

### (C) Mediated pull — live as of Slice 5

Customers call `GET /security-lake/export?format=ndjson|parquet` with their **Pencheff API key** (scope `security_lake:read`). `org_id` is derived server-side from the key's workspace/org; the customer cannot select another org. Filters: `format`, `source`. This is the only safe form of "direct access" on the shared table.

### Not shipped (by design)

- Raw Iceberg REST-catalog / shared-bucket tokens for customers (threat model §4–5).
- Ad-hoc customer SQL — deferred (higher surface); mediated export covers SIEM/lake.

## 4. [GATE] Deploy-time adversarial isolation check

**Before enabling any external subscriber**, run and record this check (the threat model gate that cannot run in CI):

1. **Mediated pull (C):** provision API keys for two orgs A and B (each with `security_lake:read`). With A's key, call `GET /security-lake/export`; confirm the response contains only A's findings and none of B's (compare against B's known finding set). Repeat with B's key. Expect zero overlap.
2. **Push-export (A):** if used, confirm the per-org job for org A writes only to A's configured bucket and that the artifact contains only A's `org_id` rows (`export_org_parquet` → check the `org_id` column is single-valued).
3. **Per-org bucket/token (only if architecture B is ever used):** issue org A's scoped R2 token, then attempt `GET` on an object under org B's prefix (`data/org_id=<B>/…`). **Expect 403.** Also confirm A's token cannot read `metadata/` on a shared table (it must not be a shared-table token at all).

Record the results (date, who ran it, outcomes) alongside the subscriber's onboarding ticket. Re-run on any change to token issuance or the export path.

### Gate run record

- **2026-06-13 (deploy bring-up):** PASS. Two-org export disjointness verified against the live R2 catalog (orgA=2 findings, orgB=1, UID overlap 0; each org's NDJSON excluded the other's content; an unknown org returned empty) — run on a throwaway `_gate_test` table to avoid polluting `pencheff.findings`, then dropped/purged. Live endpoints `GET /security-lake/{export,findings}` returned **HTTP 401** unauthenticated and with a bogus bearer (scope gate active). `org_id` is derived server-side from `get_active_workspace()`, never client-supplied (code + unit tests). No real external subscriber is onboarded yet; re-run the full two-API-key variant when the first subscriber's keys exist.

## 5. Operational notes

- **Scale:** `export_org_*` and the `/security-lake/*` query endpoints currently materialize an org's current-state in memory. Fine at current volumes; for very large orgs, add a `since_dt` bound and/or stream (`StreamingResponse`) — tracked in the Slice 3/5 plan carry-forwards.
- **Ingestion is at-least-once** (Slice 2): retries can write duplicate events sharing a `finding_uid`; the query/export layer dedups via latest-event-per-`finding_uid`, so exports are duplicate-free. Raw event count in the lake may exceed distinct findings.
- **Runtime-source ingestion is deferred** — the runtime mapper exists but no ingestion path is wired (needs a `runtime_spans` shaping layer; Slice 1 carry-forward I-1).
