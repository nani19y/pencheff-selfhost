# Security Lake — Slice 2: Iceberg Writer + Ingestion Pipeline — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist normalized OCSF findings into an Apache Iceberg table on Cloudflare R2, fed by a Celery task that runs after each scan completes — mapping findings to OCSF (Slice 1), validating them, quarantining invalid ones, and appending valid ones as append-only event records.

**Architecture:** A config-driven pyiceberg catalog (local `SqlCatalog` for dev/tests, R2 Data Catalog `RestCatalog` for prod) writes a **hybrid** table: typed partition/query columns (`org_id`, `class_uid`, `source`, `finding_uid`, `time`, `dt`, `severity_id`) plus an `ocsf_json` string column holding the full validated event. The testable core (schema projection, writer, ingest orchestration) is DB-free and verified against a local Iceberg catalog; thin Celery adapters load findings from Postgres and record per-scan ingestion/quarantine audit rows.

**Tech Stack:** Python 3.13, `pyiceberg[pyarrow,sql-sqlite]` 0.11.1 (already installed), `pyarrow`, the Slice 1 `security_lake` library, SQLAlchemy (sync + async), Alembic, Celery.

**Spec:** `docs/superpowers/specs/2026-06-13-pencheff-security-lake-design.md` (§1, §3, §5). **Slice 1 (complete):** provides `map_finding`, `validate_ocsf`, `LakeContext`.

**Verified before writing:** local pyiceberg round-trip (create → append ×2 → partitioned filter → reopen → scan), and the full chain `map_finding → validate_ocsf → to_lake_row → append → reopen → read ocsf_json back` (uid matches). Idempotent `create_namespace_if_not_exists` / `create_table_if_not_exists` / `table_exists` confirmed on 0.11.1.

---

## Status: COMPLETE ✅ (2026-06-13)

Implemented + reviewed on branch `feature-security-lake-s2`, merged to `feature-pages-design`. 53 security-lake tests green. Final holistic review: SHIP. The one spec gap it found (Celery retry/backoff, §5) was closed (`autoretry_for=(Exception,)`, `retry_backoff`).

### Carry-forward into Slice 3 (query layer)

- **Dedup by `finding_uid` is mandatory.** Ingestion is at-least-once (Iceberg append + Postgres audit are not one transaction), so retries can produce duplicate events sharing a `finding_uid`. The current-state view MUST be latest-event-per-`finding_uid`. Documented in `security_lake_ingest_task.py` module comment.
- **Hot-path columns to consider promoting** via Iceberg schema evolution before Slice 3 ships, if they become frequent filters: `status_id` and `asset_id` currently live only inside `ocsf_json` (queryable via DuckDB `json_extract`, but not partition/predicate-pushdown columns). `org_id`/`class_uid`/`source`/`finding_uid`/`time`/`dt`/`severity_id` are already top-level columns.

### Deferred (later slices, documented not forgotten)

- **R2 dead-letter prefix** for quarantined findings (spec §5 mentions it alongside the Postgres `lake_quarantine` table) — only the Postgres side is built.
- **`parquet_path` / `snapshot_id`** observability columns on `lake_ingestion` (spec §5) — simplified out; add if ingestion observability needs them.
- **Runtime-source ingestion** — mapper exists (Slice 1) but no ingestion path; needs the `runtime_spans` shaping layer (Slice 1 carry-forward I-1).
- **R2 prod catalog path** (`build_catalog` REST branch) is wired but untested here (no R2 creds in dev/CI); verify against R2 Data Catalog at deploy.

## Decisions locked

- **Hybrid table schema** (typed query columns + raw `ocsf_json`) — user-approved 2026-06-13.
- **Append-only** event records; one Iceberg snapshot per scan batch.
- **Partitioning:** identity on `org_id`, `class_uid`, `dt` (YYYY-MM-DD from event `time`).
- **Catalog:** `SqlCatalog` (SQLite) + local filesystem warehouse for dev/tests; `RestCatalog` → R2 Data Catalog for prod (config-driven; the R2 path is wired but NOT exercised in tests — no R2 creds in this environment).
- **Scope:** repo findings (sast/sca/secret/iac) + DAST. **Runtime ingestion is deferred** (carry-forward I-1: `runtime_spans` needs a shaping layer first); the runtime mapper already exists but no ingestion path is wired in this slice.
- **`time`:** all findings in a scan batch use the scan's completion timestamp (ms). Per-finding observation time is a later refinement.

## Integration points (verified)

- Repo scan completion: `pencheff_api/tasks/repo_scan_task.py::run_repo_scan` — **sync** `Session`, findings committed at the `db.commit()` near line 436. `RepoScan` has `org_id`, `workspace_id`, `repository_id`.
- DAST scan completion: `pencheff_api/services/scan_runner.py` (`run_scan` async) — findings committed before final status. `Scan` has `org_id`, `workspace_id`, `target_id`.
- Celery app + `include` list: `pencheff_api/tasks/celery_app.py` (lines ~36–63).
- Scanner→source map: `pencheff_api/services/unified_findings.py::_scanner_to_source`.
- Settings: `pencheff_api/config.py` (pydantic). `sync_database_url` property exists.
- Alembic head: `0053_runtime_spans.py` (`revision="0053"`). New migration chains `down_revision="0053"`.

## File structure

| File                                                               | Responsibility                                                                                                            |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `pencheff_api/services/security_lake/lake_schema.py`               | Iceberg `Schema` + `PartitionSpec` constants; `to_lake_row(event, *, org_id, source)`; `dt_from_ms`. Pure (no I/O).       |
| `pencheff_api/services/security_lake/lake_writer.py`               | `build_catalog(settings)` (local SqlCatalog vs R2 RestCatalog); `LakeWriter` (`ensure_table`, `append_rows`).             |
| `pencheff_api/services/security_lake/ingest.py`                    | `IngestResult`; `ingest_findings(writer, items, *, org_id, asset_id, time_ms)` — map→validate→quarantine→append. DB-free. |
| `pencheff_api/config.py` (modify)                                  | Lake settings (catalog type/uri/warehouse, R2 creds, namespace/table).                                                    |
| `pencheff_api/db/models.py` (modify)                               | `LakeIngestion`, `LakeQuarantine` ORM models.                                                                             |
| `pencheff_api/db/migrations/versions/0054_security_lake_tables.py` | Create the two audit tables.                                                                                              |
| `pencheff_api/tasks/security_lake_ingest_task.py`                  | Celery tasks `ingest_repo_scan` / `ingest_dast_scan`; load findings, call core, persist audit rows, idempotency.          |
| `pencheff_api/tasks/celery_app.py` (modify)                        | Register the new task module in `include`.                                                                                |
| `pencheff_api/tasks/repo_scan_task.py` (modify)                    | Enqueue `ingest_repo_scan.delay(...)` after findings commit (guarded).                                                    |
| `pencheff_api/services/scan_runner.py` (modify)                    | Enqueue `ingest_dast_scan.delay(...)` after findings commit (guarded).                                                    |
| `tests/test_security_lake_lake_schema.py`                          | `to_lake_row` / `dt_from_ms` unit tests.                                                                                  |
| `tests/test_security_lake_writer.py`                               | Local Iceberg round-trip.                                                                                                 |
| `tests/test_security_lake_ingest.py`                               | `ingest_findings` valid/invalid/quarantine, against a local writer.                                                       |
| `tests/test_security_lake_ingest_task.py`                          | Task orchestration with monkeypatched catalog + injected findings.                                                        |

**Environment note for all tasks:** an `rtk` shell wrapper breaks bare `pytest`/`python -m pytest`. Run tests as `./.venv/bin/python -m pytest ...` from `apps/api`.

---

## Task 1: Lake config settings

**Files:**

- Modify: `pencheff_api/config.py`
- Test: `tests/test_security_lake_config.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_config.py
from __future__ import annotations

from pencheff_api.config import get_settings


def test_lake_settings_have_local_defaults():
    s = get_settings()
    assert s.lake_catalog_type in {"sql", "rest"}
    assert s.lake_catalog_type == "sql"           # safe local default
    assert s.lake_namespace == "pencheff"
    assert s.lake_table == "findings"
    assert s.lake_catalog_uri.startswith("sqlite://")
    assert s.lake_warehouse.startswith("file://")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_config.py -v`
Expected: FAIL — `AttributeError`/missing fields.

- [ ] **Step 3: Add settings**

In `pencheff_api/config.py`, add these fields to the Settings class (place them near the other infra fields, after `redis_url`). Use the existing pydantic-settings style in that file:

```python
    # ── Security Lake (OCSF Iceberg) ─────────────────────────────────
    # "sql" = local SQLite catalog + filesystem warehouse (dev/tests).
    # "rest" = Cloudflare R2 Data Catalog (prod); requires the r2_* values.
    lake_catalog_type: str = "sql"
    lake_catalog_uri: str = "sqlite:////tmp/pencheff_lake/catalog.db"
    lake_warehouse: str = "file:///tmp/pencheff_lake/warehouse"
    lake_namespace: str = "pencheff"
    lake_table: str = "findings"
    # R2 (prod, catalog_type="rest") — sourced from env in deployment.
    lake_catalog_token: str | None = None
    r2_endpoint_url: str | None = None
    r2_access_key_id: str | None = None
    r2_secret_access_key: str | None = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_config.py -v`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/config.py apps/api/tests/test_security_lake_config.py
git commit -m "feat(security-lake): lake config settings (local SqlCatalog defaults + R2 fields)"
```

---

## Task 2: Lake schema + row projection

**Files:**

- Create: `pencheff_api/services/security_lake/lake_schema.py`
- Test: `tests/test_security_lake_lake_schema.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_lake_schema.py
from __future__ import annotations

import json

from pencheff_api.services.security_lake.lake_schema import (
    LAKE_SCHEMA, LAKE_PARTITION_SPEC, to_lake_row, dt_from_ms,
)


def _event():
    return {
        "class_uid": 2002, "time": 1_700_000_000_000, "severity_id": 4,
        "finding_info": {"uid": "fp123", "title": "x"},
    }


def test_dt_from_ms_is_utc_date_string():
    assert dt_from_ms(1_700_000_000_000) == "2023-11-14"


def test_to_lake_row_projects_columns():
    row = to_lake_row(_event(), org_id="o1", source="sast")
    assert row["org_id"] == "o1"
    assert row["class_uid"] == 2002
    assert row["source"] == "sast"
    assert row["finding_uid"] == "fp123"
    assert row["time"] == 1_700_000_000_000
    assert row["dt"] == "2023-11-14"
    assert row["severity_id"] == 4
    assert json.loads(row["ocsf_json"])["finding_info"]["uid"] == "fp123"


def test_row_keys_match_schema_fields():
    row = to_lake_row(_event(), org_id="o1", source="sast")
    schema_fields = {f.name for f in LAKE_SCHEMA.fields}
    assert set(row.keys()) == schema_fields


def test_partition_spec_partitions_on_org_class_dt():
    names = {pf.name for pf in LAKE_PARTITION_SPEC.fields}
    assert names == {"org_id", "class_uid", "dt"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_lake_schema.py -v`
Expected: FAIL — `ModuleNotFoundError: ...lake_schema`.

- [ ] **Step 3: Implement**

```python
# pencheff_api/services/security_lake/lake_schema.py
from __future__ import annotations

import datetime as _dt
import json

from pyiceberg.schema import Schema
from pyiceberg.types import NestedField, StringType, IntegerType, LongType
from pyiceberg.partitioning import PartitionSpec, PartitionField
from pyiceberg.transforms import IdentityTransform

# Hybrid layout: typed partition/query columns + the full OCSF event as JSON.
LAKE_SCHEMA = Schema(
    NestedField(1, "org_id", StringType(), required=True),
    NestedField(2, "class_uid", IntegerType(), required=True),
    NestedField(3, "source", StringType(), required=True),
    NestedField(4, "finding_uid", StringType(), required=True),
    NestedField(5, "time", LongType(), required=True),
    NestedField(6, "dt", StringType(), required=True),
    NestedField(7, "severity_id", IntegerType(), required=True),
    NestedField(8, "ocsf_json", StringType(), required=True),
)

LAKE_PARTITION_SPEC = PartitionSpec(
    PartitionField(source_id=1, field_id=1000, transform=IdentityTransform(), name="org_id"),
    PartitionField(source_id=2, field_id=1001, transform=IdentityTransform(), name="class_uid"),
    PartitionField(source_id=6, field_id=1002, transform=IdentityTransform(), name="dt"),
)


def dt_from_ms(time_ms: int) -> str:
    """UTC calendar date (YYYY-MM-DD) used as the daily partition key."""
    return _dt.datetime.fromtimestamp(time_ms / 1000, tz=_dt.timezone.utc).strftime("%Y-%m-%d")


def to_lake_row(event: dict, *, org_id: str, source: str) -> dict:
    """Project a validated OCSF event into one Iceberg row (hybrid layout)."""
    return {
        "org_id": org_id,
        "class_uid": event["class_uid"],
        "source": source,
        "finding_uid": event["finding_info"]["uid"],
        "time": event["time"],
        "dt": dt_from_ms(event["time"]),
        "severity_id": event["severity_id"],
        "ocsf_json": json.dumps(event, separators=(",", ":")),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_lake_schema.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/lake_schema.py apps/api/tests/test_security_lake_lake_schema.py
git commit -m "feat(security-lake): Iceberg hybrid schema + OCSF->row projection"
```

---

## Task 3: Lake writer (catalog + append)

**Files:**

- Create: `pencheff_api/services/security_lake/lake_writer.py`
- Test: `tests/test_security_lake_writer.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_writer.py
from __future__ import annotations

import json

from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog
from pencheff_api.services.security_lake.lake_schema import to_lake_row


def _event(uid="fp1", cls=2002):
    return {"class_uid": cls, "time": 1_700_000_000_000, "severity_id": 4,
            "finding_info": {"uid": uid, "title": "x"}}


def _writer(tmp_path):
    cat = build_local_catalog(
        uri=f"sqlite:///{tmp_path}/cat.db",
        warehouse=f"file://{tmp_path}/wh",
    )
    return LakeWriter(cat, namespace="pencheff", table="findings")


def test_append_and_scan_roundtrip(tmp_path):
    w = _writer(tmp_path)
    w.ensure_table()
    w.append_rows([to_lake_row(_event("a"), org_id="o1", source="sast")])
    w.append_rows([to_lake_row(_event("b", 2003), org_id="o1", source="iac")])
    tbl = w.load_table()
    assert tbl.scan().to_arrow().num_rows == 2
    # append-only: two batches -> two snapshots
    assert len(tbl.metadata.snapshots) == 2


def test_ensure_table_is_idempotent(tmp_path):
    w = _writer(tmp_path)
    w.ensure_table()
    w.ensure_table()  # must not raise
    assert w.load_table() is not None


def test_partition_filter_scopes_by_org_and_class(tmp_path):
    w = _writer(tmp_path)
    w.ensure_table()
    w.append_rows([to_lake_row(_event("a"), org_id="o1", source="sast")])
    w.append_rows([to_lake_row(_event("c"), org_id="o2", source="sast")])
    got = w.load_table().scan(row_filter="org_id == 'o1'").to_arrow()
    assert got.num_rows == 1
    assert json.loads(got.column("ocsf_json")[0].as_py())["finding_info"]["uid"] == "a"


def test_append_empty_is_noop(tmp_path):
    w = _writer(tmp_path)
    w.ensure_table()
    w.append_rows([])  # must not raise, no snapshot
    assert w.load_table().scan().to_arrow().num_rows == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_writer.py -v`
Expected: FAIL — `ModuleNotFoundError: ...lake_writer`.

- [ ] **Step 3: Implement**

```python
# pencheff_api/services/security_lake/lake_writer.py
from __future__ import annotations

from typing import Any

import pyarrow as pa
from pyiceberg.catalog import Catalog
from pyiceberg.catalog.sql import SqlCatalog

from .lake_schema import LAKE_SCHEMA, LAKE_PARTITION_SPEC


def build_local_catalog(*, uri: str, warehouse: str) -> Catalog:
    """A SQLite-backed Iceberg catalog over a local filesystem warehouse (dev/tests)."""
    return SqlCatalog("pencheff", uri=uri, warehouse=warehouse)


def build_catalog(settings: Any) -> Catalog:
    """Build the configured catalog. Local SqlCatalog by default; R2 Data Catalog
    (RestCatalog) when ``lake_catalog_type == 'rest'``.

    The REST/R2 branch is config-only and exercised in prod (no R2 creds in dev/CI).
    """
    if settings.lake_catalog_type == "rest":
        from pyiceberg.catalog.rest import RestCatalog
        props = {
            "uri": settings.lake_catalog_uri,
            "warehouse": settings.lake_warehouse,
        }
        if settings.lake_catalog_token:
            props["token"] = settings.lake_catalog_token
        if settings.r2_endpoint_url:
            props["s3.endpoint"] = settings.r2_endpoint_url
        if settings.r2_access_key_id:
            props["s3.access-key-id"] = settings.r2_access_key_id
        if settings.r2_secret_access_key:
            props["s3.secret-access-key"] = settings.r2_secret_access_key
        return RestCatalog("pencheff", **props)
    return build_local_catalog(uri=settings.lake_catalog_uri, warehouse=settings.lake_warehouse)


class LakeWriter:
    """Appends OCSF rows to the Iceberg findings table. Append-only; one snapshot per batch."""

    def __init__(self, catalog: Catalog, *, namespace: str, table: str):
        self._catalog = catalog
        self._namespace = namespace
        self._table = table
        self._identifier = f"{namespace}.{table}"

    def ensure_table(self) -> None:
        self._catalog.create_namespace_if_not_exists(self._namespace)
        self._catalog.create_table_if_not_exists(
            self._identifier, schema=LAKE_SCHEMA, partition_spec=LAKE_PARTITION_SPEC,
        )

    def load_table(self):
        return self._catalog.load_table(self._identifier)

    def append_rows(self, rows: list[dict]) -> int:
        """Append rows as one Iceberg snapshot. Empty input is a no-op. Returns count."""
        if not rows:
            return 0
        tbl = self.load_table()
        tbl.append(pa.Table.from_pylist(rows, schema=tbl.schema().as_arrow()))
        return len(rows)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_writer.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/lake_writer.py apps/api/tests/test_security_lake_writer.py
git commit -m "feat(security-lake): Iceberg LakeWriter (local + R2 catalog, append-only)"
```

---

## Task 4: Ingest orchestration core

**Files:**

- Create: `pencheff_api/services/security_lake/ingest.py`
- Test: `tests/test_security_lake_ingest.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_ingest.py
from __future__ import annotations

from pencheff_api.services.security_lake.ingest import ingest_findings, IngestResult
from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog


def _writer(tmp_path):
    cat = build_local_catalog(uri=f"sqlite:///{tmp_path}/cat.db", warehouse=f"file://{tmp_path}/wh")
    w = LakeWriter(cat, namespace="pencheff", table="findings")
    w.ensure_table()
    return w


SAST = {"scanner": "semgrep", "rule_id": "py.sqli", "severity": "high", "title": "SQLi",
        "description": "x", "file_path": "app/db.py", "line_start": 10, "line_end": 12,
        "code_snippet": "e", "cve": None, "package": None, "installed_version": None,
        "fixed_version": None, "raw": {"cwe": "CWE-89"}}
IAC = {"scanner": "checkov", "rule_id": "CKV_AWS_20", "severity": "medium", "title": "S3",
       "description": "x", "file_path": "s3.tf", "line_start": 1, "line_end": 8,
       "code_snippet": None, "cve": None, "package": None, "installed_version": None,
       "fixed_version": None, "raw": {}}


def test_ingest_valid_findings_appends_rows(tmp_path):
    w = _writer(tmp_path)
    res = ingest_findings(w, [("sast", SAST), ("iac", IAC)],
                          org_id="o1", asset_id="r1", time_ms=1_700_000_000_000)
    assert isinstance(res, IngestResult)
    assert res.appended == 2
    assert res.quarantined == []
    assert w.load_table().scan().to_arrow().num_rows == 2


def test_invalid_finding_is_quarantined_not_appended(tmp_path):
    w = _writer(tmp_path)
    # An unknown source makes map_finding raise -> quarantined, not fatal.
    res = ingest_findings(w, [("sast", SAST), ("bogus", {})],
                          org_id="o1", asset_id="r1", time_ms=1_700_000_000_000)
    assert res.appended == 1
    assert len(res.quarantined) == 1
    assert res.quarantined[0].source == "bogus"
    assert res.quarantined[0].error  # non-empty reason
    assert w.load_table().scan().to_arrow().num_rows == 1


def test_all_invalid_appends_nothing(tmp_path):
    w = _writer(tmp_path)
    res = ingest_findings(w, [("bogus", {})], org_id="o1", asset_id="r1",
                          time_ms=1_700_000_000_000)
    assert res.appended == 0
    assert len(res.quarantined) == 1
    assert w.load_table().scan().to_arrow().num_rows == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_ingest.py -v`
Expected: FAIL — `ModuleNotFoundError: ...ingest`.

- [ ] **Step 3: Implement**

```python
# pencheff_api/services/security_lake/ingest.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import map_finding, validate_ocsf, LakeContext
from .lake_schema import to_lake_row
from .lake_writer import LakeWriter


@dataclass
class QuarantineItem:
    source: str
    error: str
    finding_repr: str


@dataclass
class IngestResult:
    appended: int = 0
    quarantined: list[QuarantineItem] = field(default_factory=list)


def ingest_findings(writer: LakeWriter, items: list[tuple[str, Any]], *,
                    org_id: str, asset_id: str, time_ms: int) -> IngestResult:
    """Map → validate → append valid; quarantine the rest. One Iceberg snapshot total.

    ``items`` is a list of ``(source, finding)`` pairs. A finding that fails mapping
    or OCSF validation is recorded in ``quarantined`` and skipped — never fatal.
    """
    rows: list[dict] = []
    result = IngestResult()
    for source, finding in items:
        try:
            ctx = LakeContext(org_id=org_id, asset_id=asset_id, source=source,
                              time_ms=time_ms, is_new=True)
            event = map_finding(source, finding, ctx)
            validate_ocsf(event)
            rows.append(to_lake_row(event, org_id=org_id, source=source))
        except Exception as exc:  # noqa: BLE001 — quarantine, never fail the batch
            result.quarantined.append(
                QuarantineItem(source=source, error=str(exc), finding_repr=repr(finding)[:500])
            )
    result.appended = writer.append_rows(rows)
    return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_ingest.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/ingest.py apps/api/tests/test_security_lake_ingest.py
git commit -m "feat(security-lake): ingest orchestration (map/validate/quarantine/append)"
```

---

## Task 5: Audit tables (models + migration)

**Files:**

- Modify: `pencheff_api/db/models.py`
- Create: `pencheff_api/db/migrations/versions/0054_security_lake_tables.py`
- Test: `tests/test_security_lake_models.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_models.py
from __future__ import annotations

from pencheff_api.db.models import LakeIngestion, LakeQuarantine


def test_lake_ingestion_columns():
    cols = set(LakeIngestion.__table__.columns.keys())
    assert {"id", "scan_id", "source", "org_id", "appended_count",
            "quarantined_count", "status", "error", "created_at"} <= cols
    # idempotency: one ingestion row per (scan_id, source)
    uniques = {tuple(sorted(c.name for c in con.columns))
               for con in LakeIngestion.__table__.constraints
               if con.__class__.__name__ == "UniqueConstraint"}
    assert ("scan_id", "source") in uniques


def test_lake_quarantine_columns():
    cols = set(LakeQuarantine.__table__.columns.keys())
    assert {"id", "scan_id", "source", "org_id", "error", "finding_repr",
            "created_at"} <= cols


def test_migration_0054_chains_from_0053():
    import importlib
    mod = importlib.import_module(
        "pencheff_api.db.migrations.versions.0054_security_lake_tables")
    assert mod.revision == "0054"
    assert mod.down_revision == "0053"
    assert hasattr(mod, "upgrade") and hasattr(mod, "downgrade")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_models.py -v`
Expected: FAIL — `ImportError: cannot import name 'LakeIngestion'`.

- [ ] **Step 3: Add the models**

In `pencheff_api/db/models.py`, append (match the existing import set — `Mapped`, `mapped_column`, `UUID`, `String`, `Integer`, `Text`, `DateTime`, `JSONB`, `func`, `Index`, `UniqueConstraint`, and the module's `_uuid` default; add `UniqueConstraint` to the SQLAlchemy import if not already present):

```python
class LakeIngestion(Base):
    """One row per (scan, source) ingested into the Security Lake. Drives idempotency."""
    __tablename__ = "lake_ingestion"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    org_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    appended_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    quarantined_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ok")  # ok | partial | failed
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (UniqueConstraint("scan_id", "source", name="uq_lake_ingestion_scan_source"),)


class LakeQuarantine(Base):
    """A finding that failed OCSF mapping/validation and was not written to the lake."""
    __tablename__ = "lake_quarantine"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    org_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    error: Mapped[str] = mapped_column(Text, nullable=False)
    finding_repr: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
```

- [ ] **Step 4: Create the migration**

```python
# pencheff_api/db/migrations/versions/0054_security_lake_tables.py
"""security lake audit tables

Revision ID: 0054
Revises: 0053
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0054"
down_revision = "0053"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "lake_ingestion",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), nullable=True),
        sa.Column("appended_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("quarantined_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(16), nullable=False, server_default="ok"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("scan_id", "source", name="uq_lake_ingestion_scan_source"),
    )
    op.create_table(
        "lake_quarantine",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), nullable=True),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("finding_repr", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_lake_quarantine_scan_id", "lake_quarantine", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_lake_quarantine_scan_id", table_name="lake_quarantine")
    op.drop_table("lake_quarantine")
    op.drop_table("lake_ingestion")
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_models.py -v`
Expected: PASS (3 passed).

> If a local Postgres is running, also apply the migration: from `apps/api`, `./.venv/bin/python -m alembic upgrade head` → expect `0054` applied. If no Postgres is available, the model+migration unit test above is the gate; migration application is verified in the deploy environment.

- [ ] **Step 6: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/db/models.py apps/api/pencheff_api/db/migrations/versions/0054_security_lake_tables.py apps/api/tests/test_security_lake_models.py
git commit -m "feat(security-lake): lake_ingestion + lake_quarantine audit tables (migration 0054)"
```

---

## Task 6: Celery ingest task

**Files:**

- Create: `pencheff_api/tasks/security_lake_ingest_task.py`
- Modify: `pencheff_api/tasks/celery_app.py` (register in `include`)
- Test: `tests/test_security_lake_ingest_task.py`

The task exposes a DB-free seam, `run_ingest(items, *, scan_id, source_label, org_id, asset_id, time_ms, settings)`, that builds the writer from settings, calls `ingest_findings`, and returns an `IngestResult`. The DB-bound Celery entrypoints (`ingest_repo_scan`, `ingest_dast_scan`) load findings then call `run_ingest`. The test exercises `run_ingest` against a local catalog (settings monkeypatched to a tmp SQLite catalog), which is the orchestration that matters; the thin DB loaders are verified in the deploy environment.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_ingest_task.py
from __future__ import annotations

from types import SimpleNamespace

from pencheff_api.tasks.security_lake_ingest_task import run_ingest


SAST = {"scanner": "semgrep", "rule_id": "py.sqli", "severity": "high", "title": "SQLi",
        "description": "x", "file_path": "app/db.py", "line_start": 10, "line_end": 12,
        "code_snippet": "e", "cve": None, "package": None, "installed_version": None,
        "fixed_version": None, "raw": {"cwe": "CWE-89"}}


def _settings(tmp_path):
    return SimpleNamespace(
        lake_catalog_type="sql",
        lake_catalog_uri=f"sqlite:///{tmp_path}/cat.db",
        lake_warehouse=f"file://{tmp_path}/wh",
        lake_namespace="pencheff",
        lake_table="findings",
    )


def test_run_ingest_appends_and_reports(tmp_path):
    res = run_ingest([("sast", SAST)], scan_id="s1", source_label="repo",
                     org_id="o1", asset_id="r1", time_ms=1_700_000_000_000,
                     settings=_settings(tmp_path))
    assert res.appended == 1
    assert res.quarantined == []


def test_run_ingest_quarantines_bad_finding(tmp_path):
    res = run_ingest([("bogus", {})], scan_id="s2", source_label="repo",
                     org_id="o1", asset_id="r1", time_ms=1_700_000_000_000,
                     settings=_settings(tmp_path))
    assert res.appended == 0
    assert len(res.quarantined) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_ingest_task.py -v`
Expected: FAIL — `ModuleNotFoundError: ...security_lake_ingest_task`.

- [ ] **Step 3: Implement the task**

```python
# pencheff_api/tasks/security_lake_ingest_task.py
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from .celery_app import celery_app
from ..config import get_settings
from ..db.models import RepoScan, RepoFinding, Scan, Finding, LakeIngestion, LakeQuarantine
from ..services.security_lake.ingest import ingest_findings, IngestResult
from ..services.security_lake.lake_writer import LakeWriter, build_catalog
from ..services.unified_findings import _scanner_to_source

log = logging.getLogger(__name__)


def run_ingest(items: list[tuple[str, Any]], *, scan_id: str, source_label: str,
               org_id: str | None, asset_id: str, time_ms: int, settings: Any) -> IngestResult:
    """DB-free core: build the writer from settings, ingest items, return the result."""
    writer = LakeWriter(build_catalog(settings),
                        namespace=settings.lake_namespace, table=settings.lake_table)
    writer.ensure_table()
    return ingest_findings(writer, items, org_id=org_id or "", asset_id=asset_id, time_ms=time_ms)


def _now_ms() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


def _record(db: Session, *, scan_id: str, source_label: str, org_id: str | None,
            res: IngestResult) -> None:
    status = "ok" if not res.quarantined else ("partial" if res.appended else "failed")
    db.add(LakeIngestion(scan_id=scan_id, source=source_label, org_id=org_id,
                         appended_count=res.appended, quarantined_count=len(res.quarantined),
                         status=status))
    for q in res.quarantined:
        db.add(LakeQuarantine(scan_id=scan_id, source=q.source, org_id=org_id,
                             error=q.error, finding_repr=q.finding_repr))
    db.commit()


@celery_app.task(name="pencheff_api.tasks.security_lake_ingest_task.ingest_repo_scan")
def ingest_repo_scan(repo_scan_id: str) -> dict:
    settings = get_settings()
    engine = create_engine(settings.sync_database_url, future=True)
    with Session(engine) as db:
        if db.execute(select(LakeIngestion).where(
                LakeIngestion.scan_id == repo_scan_id,
                LakeIngestion.source == "repo")).first():
            return {"ok": True, "skipped": "already ingested"}
        scan = db.get(RepoScan, repo_scan_id)
        if scan is None:
            return {"ok": False, "error": "no such repo scan"}
        findings = db.execute(
            select(RepoFinding).where(RepoFinding.repo_scan_id == repo_scan_id)).scalars().all()
        items = [(_scanner_to_source(f.scanner), f) for f in findings]
        time_ms = int(scan.completed_at.timestamp() * 1000) if scan.completed_at else _now_ms()
        res = run_ingest(items, scan_id=repo_scan_id, source_label="repo",
                         org_id=scan.org_id, asset_id=scan.repository_id,
                         time_ms=time_ms, settings=settings)
        _record(db, scan_id=repo_scan_id, source_label="repo", org_id=scan.org_id, res=res)
    return {"ok": True, "appended": res.appended, "quarantined": len(res.quarantined)}


@celery_app.task(name="pencheff_api.tasks.security_lake_ingest_task.ingest_dast_scan")
def ingest_dast_scan(scan_id: str) -> dict:
    settings = get_settings()
    engine = create_engine(settings.sync_database_url, future=True)
    with Session(engine) as db:
        if db.execute(select(LakeIngestion).where(
                LakeIngestion.scan_id == scan_id,
                LakeIngestion.source == "dast")).first():
            return {"ok": True, "skipped": "already ingested"}
        scan = db.get(Scan, scan_id)
        if scan is None:
            return {"ok": False, "error": "no such scan"}
        findings = db.execute(
            select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
        items = [("dast", f) for f in findings]
        time_ms = int(scan.finished_at.timestamp() * 1000) if getattr(scan, "finished_at", None) else _now_ms()
        res = run_ingest(items, scan_id=scan_id, source_label="dast",
                         org_id=scan.org_id, asset_id=scan.target_id,
                         time_ms=time_ms, settings=settings)
        _record(db, scan_id=scan_id, source_label="dast", org_id=scan.org_id, res=res)
    return {"ok": True, "appended": res.appended, "quarantined": len(res.quarantined)}
```

> Note: `Finding` is the DAST findings model and `Scan.finished_at` is the DAST completion timestamp — confirm the exact attribute names in `db/models.py` while implementing and adjust if they differ (e.g. `finished_at` vs `completed_at`). The unit test does not touch these DB paths.

- [ ] **Step 4: Register the task module**

In `pencheff_api/tasks/celery_app.py`, add to the `include=[...]` list (alongside the other task modules):

```python
    "pencheff_api.tasks.security_lake_ingest_task",
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_ingest_task.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/tasks/security_lake_ingest_task.py apps/api/pencheff_api/tasks/celery_app.py apps/api/tests/test_security_lake_ingest_task.py
git commit -m "feat(security-lake): Celery ingest tasks (repo + DAST) with idempotency + audit rows"
```

---

## Task 7: Wire enqueue hooks into scan completion

**Files:**

- Modify: `pencheff_api/tasks/repo_scan_task.py` (after findings commit)
- Modify: `pencheff_api/services/scan_runner.py` (after DAST findings commit)
- Test: `tests/test_security_lake_enqueue_hook.py`

Enqueues must NEVER break a scan if the lake is misconfigured — wrap in a guarded helper.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_enqueue_hook.py
from __future__ import annotations

from pencheff_api.tasks.security_lake_ingest_task import enqueue_repo_ingest


def test_enqueue_is_guarded_against_failure(monkeypatch):
    calls = {}

    class _Boom:
        def delay(self, *a, **k):
            raise RuntimeError("broker down")

    monkeypatch.setattr(
        "pencheff_api.tasks.security_lake_ingest_task.ingest_repo_scan", _Boom())
    # must swallow the error and return False, never raise
    assert enqueue_repo_ingest("rs1") is False


def test_enqueue_calls_delay_on_success(monkeypatch):
    seen = {}

    class _Ok:
        def delay(self, scan_id):
            seen["id"] = scan_id

    monkeypatch.setattr(
        "pencheff_api.tasks.security_lake_ingest_task.ingest_repo_scan", _Ok())
    assert enqueue_repo_ingest("rs1") is True
    assert seen["id"] == "rs1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_enqueue_hook.py -v`
Expected: FAIL — `ImportError: cannot import name 'enqueue_repo_ingest'`.

- [ ] **Step 3: Add guarded enqueue helpers**

Append to `pencheff_api/tasks/security_lake_ingest_task.py`:

```python
def enqueue_repo_ingest(repo_scan_id: str) -> bool:
    """Fire-and-forget enqueue of repo-scan lake ingestion. Never raises."""
    try:
        ingest_repo_scan.delay(repo_scan_id)
        return True
    except Exception:  # noqa: BLE001 — lake ingestion must never break a scan
        log.exception("failed to enqueue security-lake repo ingest for %s", repo_scan_id)
        return False


def enqueue_dast_ingest(scan_id: str) -> bool:
    """Fire-and-forget enqueue of DAST-scan lake ingestion. Never raises."""
    try:
        ingest_dast_scan.delay(scan_id)
        return True
    except Exception:  # noqa: BLE001
        log.exception("failed to enqueue security-lake DAST ingest for %s", scan_id)
        return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_enqueue_hook.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Wire the repo hook**

In `pencheff_api/tasks/repo_scan_task.py`, right after the success-path `db.commit()` (near line 436, where status is set to `succeeded`), add:

```python
        from .security_lake_ingest_task import enqueue_repo_ingest
        enqueue_repo_ingest(repo_scan_id)
```

(Use a local import to avoid any circular-import risk at module load.)

- [ ] **Step 6: Wire the DAST hook**

In `pencheff_api/services/scan_runner.py`, immediately after the final commit that persists the terminal scan status (`done`/`failed`) and findings, add:

```python
        from ..tasks.security_lake_ingest_task import enqueue_dast_ingest
        enqueue_dast_ingest(scan_id)
```

Place it so it runs once per completed scan, after findings are committed. Confirm the surrounding variable is named `scan_id` (it is in `run_scan`).

- [ ] **Step 7: Run the full security-lake suite**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_validation.py tests/test_security_lake_primitives.py tests/test_security_lake_mappers.py tests/test_security_lake_config.py tests/test_security_lake_lake_schema.py tests/test_security_lake_writer.py tests/test_security_lake_ingest.py tests/test_security_lake_models.py tests/test_security_lake_ingest_task.py tests/test_security_lake_enqueue_hook.py -v`
Expected: ALL pass.

- [ ] **Step 8: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/tasks/security_lake_ingest_task.py apps/api/pencheff_api/tasks/repo_scan_task.py apps/api/pencheff_api/services/scan_runner.py apps/api/tests/test_security_lake_enqueue_hook.py
git commit -m "feat(security-lake): enqueue lake ingestion on scan completion (guarded)"
```

---

## Add the new runtime dependency to pyproject

Before Task 1, declare the dependency (already installed in the venv). In `apps/api/pyproject.toml`, add to `dependencies`:

```python
    # Security Lake — Apache Iceberg client (local SqlCatalog for dev/tests,
    # R2 Data Catalog REST for prod). Pulls pyarrow.
    "pyiceberg[pyarrow,sql-sqlite]>=0.11.0",
```

Commit this with Task 1 (`git add apps/api/pyproject.toml`).

---

## Self-review (completed by plan author)

**Spec coverage (§1, §3, §5):**

- §3 storage/partitioning — Iceberg table, identity partitions on org/class/dt, hybrid schema → Tasks 2, 3 ✓.
- §5 ingestion pipeline (Celery off scan completion), quarantine-never-drop, atomic snapshot append, `lake_ingestion`/`lake_quarantine` audit, idempotency by (scan_id, source) → Tasks 4, 5, 6, 7 ✓.
- §1 architecture (map→validate→append; internal queries deferred) — query API is Slice 3, explicitly out of scope here ✓.
- Runtime ingestion deferred per carry-forward I-1 — documented in "Decisions locked" ✓.
- R2/prod catalog wired but untested (no creds) — `build_catalog` REST branch, config fields ✓.

**Placeholder scan:** No TBD/TODO. Every code step is complete and runnable. The two "confirm attribute name" notes (DAST `Finding`/`finished_at`) are explicit verification instructions with a stated fallback, not placeholders — the unit tests don't depend on them, and the DB loaders are deploy-verified.

**Type consistency:** `LakeWriter(catalog, namespace=, table=)`, `build_catalog(settings)`, `build_local_catalog(uri=, warehouse=)`, `ingest_findings(writer, items, org_id=, asset_id=, time_ms=)`, `IngestResult(appended, quarantined: list[QuarantineItem])`, `QuarantineItem(source, error, finding_repr)`, `to_lake_row(event, org_id=, source=)`, `LAKE_SCHEMA`/`LAKE_PARTITION_SPEC`, `run_ingest(...)`, `enqueue_repo_ingest`/`enqueue_dast_ingest` — all consistent across tasks. `LakeIngestion` columns (`appended_count`, `quarantined_count`, unique `(scan_id, source)`) match between model (Task 5), migration (Task 5), and the `_record` writer (Task 6).

**Known limitation (documented, not a gap):** the DB-bound Celery entrypoints and Alembic application require a running Postgres and are verified in the deploy environment; the hermetic test suite covers the full Iceberg + mapping + ingest + projection core against a local catalog, plus the guarded-enqueue behavior.
