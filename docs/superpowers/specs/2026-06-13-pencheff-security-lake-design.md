# Pencheff Security Lake — Design

**Date:** 2026-06-13
**Status:** Approved design (pre-implementation)
**Author:** balasriharsha + Claude

## Summary

Pencheff Security Lake is a centralized, OCSF-normalized security data lake — the
direct analog of AWS Security Lake, built natively on Cloudflare R2. It normalizes
**every** Pencheff finding source (SAST, SCA, secrets, IaC, DAST, and runtime
protection events) into the Open Cybersecurity Schema Framework (OCSF) and persists
them as Apache Iceberg tables on R2, queryable internally, exportable to customer
SIEMs/lakes, and accessible via scoped direct SQL.

This is a **complete product**, not an MVP: all finding sources and all three
consumption modes ship. "Complete" defines the destination; the work is sequenced
into independently-verifiable slices (see §10) so each layer is proven before the
next builds on it.

### Why this matters strategically

No competitor (XBOW, Horizon3 NodeZero, Snyk, Lakera, etc.) offers offensive +
defensive + code findings in one normalized, queryable, SIEM-interoperable store.
The Security Lake turns Pencheff's existing breadth (DAST + SAST + SCA + IaC +
secrets + AI-agent runtime) into a single OCSF source of truth — a "data lake as a
product" that drops directly into a customer's existing SOC tooling.

## Confirmed decisions

| Decision      | Choice                                                                                   |
| ------------- | ---------------------------------------------------------------------------------------- |
| Schema        | OCSF (Open Cybersecurity Schema Framework), pinned to **1.3.0**                          |
| Storage       | **True lake**: Cloudflare R2 + Apache Iceberg (via R2 Data Catalog), OCSF as Parquet     |
| Query engine  | DuckDB (internal) + R2 SQL (customer direct) + Iceberg REST catalog (BYO/SIEM)           |
| OCSF fidelity | **Strict / certifiable** — every event validated against official OCSF 1.3.0 JSON schema |
| Consumption   | All three: internal queries, customer BYO-bucket/SIEM pull, direct customer SQL          |
| Sources       | Complete: SAST, SCA, secrets, IaC, DAST, runtime-protection events                       |
| Record model  | **Append-only event records**; current state derived via latest-event-per-finding        |

## Current-state baseline (what we build on)

From codebase exploration of `apps/api/pencheff_api`:

- **`findings` table** (`db/models.py` ~282–331): DAST/SCA findings — severity, cvss,
  cwe_id, owasp_category, endpoint, parameter, evidence (JSONB), verification_status,
  suppressed, and Pencheff prioritization fields: `ai_triage` (JSONB), `risk_score`,
  `epss`, `kev`, `ssvc_decision`, `reachability`, SLA fields. Scoped by `org_id`,
  `workspace_id`, `scan_id`.
- **`repo_findings` table** (`db/models.py` ~734–764): SAST/SCA/IaC/secrets — `scanner`,
  `rule_id`, `severity`, `title`, `description`, `file_path`, `line_start/end`,
  `code_snippet`, `cve`, `package`, `installed_version`, `fixed_version`, `raw` (JSONB,
  full scanner output preserved). Scoped via `repo_scan_id` → `repository_id` →
  `Repository.workspace_id`.
- **`services/repo_findings.py`**: already normalizes each scanner's raw output into a
  common `RepoFinding` shape with `_SCANNER_TO_SOURCE` map (sast/sca/secret/iac).
- **`/unified-findings`** (`routers/unified_findings.py`): merges DAST + repo findings at
  _query time_, sorted by risk_score; persists nothing unified.
- **Runtime spans**: migration `0053_runtime_spans.py` — Sentry runtime-protection
  tracing (prompt-injection / PII / tool-authz detections).
- **Persistence**: PostgreSQL (asyncpg) + Redis (pub/sub + Celery) + filesystem reports.
  Alembic migrations through `0053`. **No OCSF, SARIF, warehouse, object-store lake,
  ingestion API, dedup, or cross-scan correlation today.**

**Gap the Security Lake fills:** there is no centralized, normalized, historical,
queryable store of findings across sources. Findings live per-scan in tool-shaped rows.

## 1. Architecture

```
ANY scan completes  (RepoScan | DAST Scan | runtime spans)
      │
      ▼
[Celery task: security_lake.ingest(source, scan_id)]
      │   load findings ─► OCSF mapper (per source) ─► validate (OCSF 1.3.0 jsonschema)
      │                                                    │ pass          │ fail
      ▼                                                    ▼               ▼
   identity + first/last-seen enrichment            Parquet batch     quarantine
      │                                                    ▼          (Postgres lake_quarantine
      ▼                                          append to Iceberg      + R2 dead-letter prefix)
   record in lake_ingestion (Postgres)           table (R2 Data Catalog)
      │
      ├── Internal:    DuckDB (iceberg ext) ─► /security-lake/* API
      ├── BYO / SIEM:  Iceberg REST catalog, scoped per-org R2 tokens + connector docs
      └── Direct SQL:  R2 SQL, per-customer scoped credentials (partition-prefix locked)
```

New code lives in `apps/api/pencheff_api/services/security_lake/`. Scan logic is
**not** modified; ingestion hooks off existing scan-completion flows.

### Record model

Append-only event records, like AWS Security Lake. Each scan emits finding events;
the same finding across scans produces multiple events sharing one `finding_info.uid`.
"Current state" is a **latest-event-per-uid** view, not row mutation. This avoids
Iceberg MERGE complexity, gives free history (first_seen/last_seen, regressions, MTTR),
and is faithful to the immutable-event semantics of a security lake.

## 2. OCSF mapping (strict, full source coverage)

All events are OCSF **Findings** category (`category_uid: 2`), pinned to **OCSF 1.3.0**
(vendored schema JSON in-repo).

| Pencheff source                                       | Origin               | OCSF class            | class_uid | Key OCSF objects                                                        |
| ----------------------------------------------------- | -------------------- | --------------------- | --------- | ----------------------------------------------------------------------- |
| SAST (semgrep, bandit, gosec, brakeman, eslint, ruff) | `repo_findings`      | Vulnerability Finding | 2002      | `finding_info`, `vulnerabilities[].affected_code[]`                     |
| SCA (osv, ghsa, pip-audit, npm-audit)                 | `repo_findings`      | Vulnerability Finding | 2002      | `vulnerabilities[].cve`, `affected_packages[]`                          |
| Secrets (gitleaks, detect-secrets)                    | `repo_findings`      | Detection Finding     | 2004      | `finding_info`, `evidences[]`                                           |
| IaC (trivy_iac, checkov)                              | `repo_findings`      | Compliance Finding    | 2003      | `compliance.standards`, `compliance.control`, `compliance.status`       |
| DAST (web + API)                                      | `findings`           | Vulnerability Finding | 2002      | `finding_info`, web `url`; `http_request`/`http_response` in `unmapped` |
| Runtime (Sentry)                                      | runtime spans (0053) | Detection Finding     | 2004      | `finding_info`, detection type in `unmapped`                            |

**Field mappings (all classes):**

- `severity` → OCSF `severity_id`: info=1, low=2, medium=3, high=4, critical=5
  (0=unknown reserved). Original string preserved in `severity`.
- `verification_status` + `suppressed` → OCSF `status_id`: New=1, In Progress=2,
  Suppressed=3 (when `suppressed`), Resolved=4 (when `fixed`/resolved).
- `finding_info.uid` = stable finding fingerprint (see §4).
- `metadata.product` = `{ name: "Pencheff", vendor_name: "Pencheff" }`;
  `metadata.version` = `"1.3.0"` (OCSF schema version).
- `time` = finding creation/observation time (epoch ms).
- **Pencheff differentiators with no OCSF home** — `reachability`, `risk_score`,
  `ssvc_decision`, `ai_triage` — go in the OCSF-sanctioned `unmapped` object so strict
  consumers ignore them cleanly while Pencheff queries retain them.
- **`epss` and `kev`** map to proper OCSF `enrichments[]` entries (these have first-class
  semantics for downstream tools).

A dedicated mapper module per source (`mappers/sast.py`, `mappers/sca.py`,
`mappers/secrets.py`, `mappers/iac.py`, `mappers/dast.py`, `mappers/runtime.py`),
each a pure function `RawFinding -> dict` (OCSF event), behind a common
`map_finding(source, finding)` dispatcher.

## 3. Storage & partitioning

- A single Iceberg table holding all classes (simpler cross-class queries), or
  per-class tables — **single table** chosen, partitioned by `class_uid` so per-class
  scans still prune efficiently.
- **Partitioning:** `org_id` / `class_uid` / `days(time)`. Mirrors AWS Security Lake's
  region/account/eventDay scheme. `org_id` as the leading partition is the backbone of
  tenant isolation (§7).
- Parquet files written per scan-batch; one Iceberg snapshot per append → atomic commit
  - time-travel ("what did we know on date X").
- Catalog: Cloudflare **R2 Data Catalog** (managed Apache Iceberg, REST catalog).

## 4. Finding identity, dedup & history

- **Fingerprint** = stable hash of: `org_id`, asset id (`repository_id` or `target_id`),
  `scanner`/source, `rule_id`/`cve`, normalized location (`file_path` + line range, or
  endpoint+parameter), and `package` where applicable. This becomes `finding_info.uid`.
- Append-only: repeated detections share the `uid`. The **latest-event-per-uid** view
  yields current state; full event history yields `first_seen`, `last_seen`, regression
  detection (re-appearance after resolved), and MTTR.
- **Idempotency:** every event carries `repo_scan_id`/`scan_id`; re-ingestion of the same
  scan is a no-op (checked against `lake_ingestion`).

## 5. Ingestion pipeline & error handling

- New Celery task `security_lake.ingest(source, scan_id)`, enqueued from each existing
  scan-completion flow (RepoScan, DAST Scan, runtime span batch). Scan code unchanged.
- Pipeline: load findings → map to OCSF (per source) → enrich (first_seen lookup via
  prior events) → **validate against OCSF 1.3.0 jsonschema** → buffer → write Parquet →
  append Iceberg snapshot → record in `lake_ingestion`.
- **Validation failures quarantine, never drop:** offending finding + validation error →
  `lake_quarantine` (Postgres) row + R2 dead-letter prefix, with an alert. One malformed
  finding cannot fail the batch.
- **Write/catalog failures:** Celery retry with exponential backoff; idempotent by
  `scan_id`. Iceberg append is atomic (snapshot), so a batch fully commits or not at all.
- **`lake_ingestion` table** (new, Postgres): `scan_id`, `source`, `row_count`,
  `parquet_path`, `snapshot_id`, `status`, `quarantined_count`, timestamps — for
  observability and idempotency.

## 6. Consumption (all three, complete)

1. **Internal queries.** DuckDB (iceberg extension) reads the R2 catalog behind new
   endpoints:
   - `GET /security-lake/findings` — filter/search across full history (source, severity,
     reachability, status, repo/target, date range).
   - `GET /security-lake/trends` — severity-over-time, new-vs-resolved, MTTR.
   - `GET /security-lake/correlate` — same CVE/rule across repos/targets.
     Org/workspace filter is injected **server-side** (reuses `get_active_workspace`),
     never client-supplied.
2. **BYO-bucket / SIEM pull.** Expose the Iceberg REST catalog read-scoped to the org's
   partition via per-org scoped R2 tokens. Ship tested connector docs for **Splunk,
   Microsoft Sentinel, Snowflake, and Spark/Athena**. (Iceberg + OCSF is exactly what
   these consume, so this is configuration, not bespoke integration per tool.)
3. **Direct customer SQL.** R2 SQL with per-customer scoped credentials restricted to the
   org's partition prefix. (Fallback if R2 SQL is not production-grade: a proxied DuckDB
   query endpoint that force-injects the `org_id` filter.)

## 7. Tenancy & security (highest-risk surface — fully built, gated)

External SQL and BYO-bucket mean customers query infrastructure holding **every** other
customer's findings. Controls:

- `org_id` is the leading partition on every event.
- Internal queries force a server-side org/workspace filter; the filter is never derived
  from client input.
- External access: scoped R2 tokens locked to the org's partition **prefix**, with
  per-customer credential issuance + rotation.
- **Hard gate:** a dedicated threat-model + adversarial cross-tenant-isolation test pass
  must pass **before** any external consumption mode (BYO/SIEM, direct SQL) is enabled for
  a real customer. This is a security product surface, not polish.

## 8. Testing

- **Unit:** golden fixtures **per scanner and per source** (incl. DAST + runtime) — raw
  input → expected OCSF event. Property test: **every** emitted event validates against
  the official OCSF 1.3.0 JSON schema.
- **Integration:** ingest a sample scan of each source end-to-end into a local Iceberg
  table (MinIO / local catalog); query back; assert row counts, dedup by `uid`, and
  first/last-seen behavior across two scans of the same asset.
- **Tenancy:** cross-org query returns zero rows; a scoped token cannot read another org's
  partition prefix (adversarial).
- **Connector:** emitted Parquet/Iceberg actually ingests into Splunk + Sentinel test
  instances.
- **Idempotency:** re-ingesting the same `scan_id` produces no duplicate events.

## 9. Risks & dependencies

1. **R2 Data Catalog / R2 SQL maturity** is the load-bearing dependency. Verify during
   implementation planning that catalog + SQL features are GA enough to expose to
   customers. **Fallback:** plain Parquet on R2 + DuckDB (approach B) — shares the entire
   OCSF mapping + ingestion layer, so internal queries and BYO pull lose no work; only
   customer _direct SQL_ specifically depends on R2 SQL being production-grade.
2. **OCSF 1.3.0 schema drift.** Pin the vendored schema; Iceberg schema evolution handles
   version bumps. New OCSF versions are an explicit, tested upgrade, not implicit.
3. **External SQL is a security product surface** — §7 threat model is a hard gate.

## 10. Build order (complete product, sequenced)

"Complete product" is the destination; the build is ordered into independently-shippable,
verifiable slices so a defect is caught before the next layer depends on it:

1. **OCSF mapping + validation layer** (all sources) — pure functions, fully unit-tested
   in isolation against the OCSF schema. No I/O.
2. **Iceberg writer + ingestion pipeline + quarantine** — provable end-to-end on real
   scans; `lake_ingestion`/`lake_quarantine` tables; idempotency.
3. **Internal query API** — `/security-lake/findings|trends|correlate`.
4. **Tenancy hardening + threat model** — cross-tenant isolation proven. (Hard gate for #5.)
5. **External access** — BYO/SIEM pull, then direct SQL — gated behind #4.

This ordering _is_ the plan; it is not a descoping.

## Out of scope (this spec)

- Modifying scan/scanner logic or the existing `findings`/`repo_findings` tables (the lake
  reads from them; it does not replace them).
- A new visualization/dashboard frontend (the API endpoints are in scope; UI is a separate
  spec).
- Ingesting third-party (non-Pencheff) scanner output into the lake (future: a generic
  OCSF/SARIF ingestion envelope).
