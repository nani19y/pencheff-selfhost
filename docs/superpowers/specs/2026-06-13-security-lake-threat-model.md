# Pencheff Security Lake — Tenancy Threat Model (Slice 4)

**Date:** 2026-06-13
**Status:** Hard gate for Slice 5 (external access). External BYO-bucket / SIEM-pull / direct-SQL modes MUST NOT ship to a real customer until the controls marked **[GATE]** below are in place and the adversarial isolation tests pass.
**Scope:** the multi-tenant confidentiality boundary of the Security Lake — internal queries (Slice 3, shipped) and the planned external access (Slice 5).

## 1. Assets & trust boundary

- **Asset:** OCSF finding events for every org, in one shared Iceberg table on R2 (`{warehouse}/pencheff/findings/`).
- **Tenant boundary:** `org_id`. An org's findings must never be readable by another org. Org is the boundary because the lake stores `org_id` (not `workspace_id`) — see Slice 3 carry-forward.
- **Actors:**
  - _Internal_ — Pencheff API (Slice 3 query endpoints), Celery ingest workers (Slice 2). Trusted; run with full-bucket credentials.
  - _External_ (Slice 5, not yet built) — a customer wanting their OCSF data in their own SIEM / lake / SQL tool.

## 2. Physical layout (verified 2026-06-13)

A live local lake confirmed pyiceberg's layout:

```
{warehouse}/pencheff/findings/
  data/org_id=<ORG>/class_uid=<C>/dt=<YYYY-MM-DD>/*.parquet   ← per-org, row content
  metadata/*.metadata.json                                     ← SHARED, table-wide
  metadata/*.avro  (manifests, snapshots)                      ← SHARED, lists ALL orgs' files
```

- **Data files** are physically segregated under `data/org_id=<ORG>/`. ✓
- **Metadata is shared**: the table `metadata.json`, manifest lists, and manifest files enumerate **every** org's data-file paths and per-file column statistics (row counts, and value min/max which can include `finding_uid`, `dt`, `severity_id` ranges). ✗ for tenant isolation.

## 3. STRIDE — external access surface

| Threat                                    | Vector                                                                                                                                                                                                                                                    | Severity     | Control                                                                                                                                                                                                          |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Information disclosure (data content)** | Customer reads another org's `data/org_id=<other>/*.parquet`                                                                                                                                                                                              | **Critical** | R2 token scoped to read ONLY `data/org_id=<own>/` **[GATE]**; or per-org bucket/table                                                                                                                            |
| **Information disclosure (metadata)**     | Customer reads shared `metadata/*` (manifest/avro) and enumerates other orgs' IDs, partition counts, column stat ranges                                                                                                                                   | **High**     | Shared metadata cannot be prefix-isolated → do NOT grant raw metadata read on the shared table to external actors **[GATE]**. Use per-org tables/buckets or a mediated path (§5)                                 |
| **Spoofing / privilege**                  | Caller supplies a forged `org_id` to read another tenant                                                                                                                                                                                                  | High         | `org_id` is NEVER client-supplied — derived server-side from `get_active_workspace().org_id` (Slice 3, enforced + tested). External tokens are minted per-org by Pencheff, not selected by the caller **[GATE]** |
| **Tampering**                             | External actor writes/deletes lake data                                                                                                                                                                                                                   | High         | External credentials are **read-only**; writes only via internal Celery workers **[GATE]**                                                                                                                       |
| **Internal worker compromise**            | A compromised Celery worker (the only holder of full-bucket write creds — `r2_*`, `lake_catalog_token`) writes rows for any org, corrupts, or drops the table. Workers process external scan data, so task-payload/deserialization bugs are a real vector | **Critical** | Least-privilege worker creds (write only, no delete-table); validate/trust-boundary task payloads; rotate creds; keep the catalog token off external surfaces                                                    |
| **Elevation (catalog)**                   | A REST-catalog token can hit mutation endpoints (create/rename/**drop** table). R2 Data Catalog tokens lack S3-style per-verb scoping, so a read token over-issued at the catalog level can be destructive                                                | High         | NEVER issue a catalog (REST) token to external actors on the shared table — external access is push-export or Pencheff-mediated query (§5). The internal catalog token is worker-only **[GATE]**                 |
| **Snapshot time-travel**                  | Iceberg retains snapshot history; a reader with catalog access can scan prior snapshots. Append-only today, but a future ingest bug or soft-delete/update would leave wrong-org or deleted rows permanently readable in old snapshots                     | Medium       | No external catalog access (§5); expire old snapshots on a retention policy; an ingest bug that writes a cross-org row is permanent — guard ingestion org-tagging (Slice 2 derives org server-side)              |
| **Repudiation**                           | Disputed access                                                                                                                                                                                                                                           | Low          | R2 access logs + Pencheff audit (`lake_ingestion`); per-customer scoped credentials are individually attributable                                                                                                |
| **DoS**                                   | Expensive scans by external SQL                                                                                                                                                                                                                           | Medium       | Rate-limit + bound external queries; prefer scheduled export over ad-hoc full scans                                                                                                                              |
| **Injection**                             | `org_id`/filters into the scan expression                                                                                                                                                                                                                 | Medium       | pyiceberg `EqualTo("org_id", org_id)` (expression object, not string interpolation) — verified Slice 3; query filters are parameterized DuckDB `?`                                                               |

## 4. Central finding: a shared Iceberg table cannot be tenant-isolated for raw external reads

Because the table's **metadata is shared**, any external actor granted Iceberg-native read access to the table (REST catalog + bucket) can enumerate other tenants via the manifests — even if a data-prefix token blocks reading the other tenants' parquet _content_. Data-prefix scoping gives **content** confidentiality but not **metadata** confidentiality.

**Therefore the spec's original "Iceberg REST catalog read-scoped to the org's partition" is INSUFFICIENT on a single shared table.**

Nuance on the two access mechanisms:

- A **raw S3-compatible R2 object token** scoped to `data/org_id=<own>/` physically cannot GET `metadata/` — so it gives **content-only** isolation with no metadata leak. But without metadata an Iceberg client can't read the table natively; this token is only useful for a flat object dump (e.g. push-export of the org's Parquet/NDJSON), not Iceberg-native SIEM pull.
- An **Iceberg-native read** (REST catalog) needs the shared metadata, which is what leaks other tenants. Hence the shared table is unsafe for native external pull regardless of data-prefix scoping.

## 5. Required architecture for Slice 5 (recommendation)

Pick per customer need; (A) and (C) are the safe defaults:

- **(A) Push export to the customer's own bucket — RECOMMENDED default.** A scheduled job reads the org's partition (internal, full creds), writes OCSF Parquet (or its own per-customer Iceberg table) into the **customer's** R2/S3 bucket. The customer's SIEM/lake reads from _their_ storage. No Pencheff-side cross-tenant surface at all. This matches AWS Security Lake's subscriber model.
- **(B) Per-org physical isolation** — if customers must pull from Pencheff-hosted storage: give each org its **own Iceberg table** (separate metadata tree) or its **own bucket**, then a per-org read token is sufficient (metadata no longer shared). Cost: N tables/buckets, more catalog management.
- **(C) Pencheff-mediated query/SQL — RECOMMENDED for direct-SQL.** Customers never touch the bucket/catalog; they hit a Pencheff endpoint (extend Slice 3, or R2 SQL behind our auth) that injects `org_id` server-side. This is the only safe form of "direct SQL" on a shared table.

**Do NOT** ship raw REST-catalog/bucket access to the shared `pencheff.findings` table for external actors.

## 6. Controls already in place (Slices 1–3)

- `org_id` is derived server-side (`get_active_workspace().org_id`); never a client parameter. Cross-org query returns empty — adversarially tested.
- Internal scans use `EqualTo("org_id", org_id)` partition pruning (expression, not string) + parameterized DuckDB filters.
- Ingestion writes are internal-only (Celery workers with full creds).

## 7. Controls to build / specify in this slice

- `tenancy.org_data_prefix(...)` — the canonical `data/org_id=<org>/` key prefix an export/token must be scoped to (code + tests, this slice).
- Adversarial cross-tenant isolation test suite asserting org A never sees org B at the query layer and that org prefixes are disjoint (this slice).
- **Deploy-config (specified, not testable here — no R2):** external R2 tokens are per-org, read-only, scoped to the org data prefix; metadata is never exposed to external actors on the shared table; Slice 5 uses architecture (A) or (C).

## 8. Residual risks (accepted / deferred)

- **Workspace-level isolation within an org is not enforced** — the lake has no `workspace_id` column; all of an org's findings are visible to any of that org's authorized callers. Accepted for an org-wide lake; revisit if per-workspace confidentiality is required (needs a `workspace_id` column).
- **Manifest column stats** (min/max) can leak coarse value ranges to anyone with metadata read — mitigated by never granting external metadata read on the shared table (§5).
- **R2 token-scoping correctness is unverified in dev** (no R2/creds) — must be validated against Cloudflare R2 at deploy with an adversarial check (a token for org A attempts to GET an org-B object → expect 403).
