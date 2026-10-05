# Security Lake — Slice 5: Mediated OCSF Export (External Access) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a customer get their org's findings out of the lake as SIEM-ready OCSF — through a Pencheff-mediated, org-scoped, read-only export endpoint (NDJSON for SIEMs, Parquet for lake-to-lake), with push-to-customer-bucket as documented deploy wiring.

**Architecture:** Reframed by the Slice 4 threat model: a shared Iceberg table cannot be safely exposed to external actors via raw catalog/bucket tokens (shared metadata leaks tenants). So external access is **Pencheff-mediated** — the same org-scoped pyiceberg+DuckDB read path (Slice 3) emits the org's OCSF events as NDJSON/Parquet behind our auth (`org_id` injected server-side). The customer pulls it (or a deploy job pushes it to their bucket). No customer ever touches our catalog/bucket. This is AWS Security Lake's subscriber model.

**Tech Stack:** Python 3.13, `duckdb`, `pyiceberg`, `pyarrow`, FastAPI, the Slice 1–4 `security_lake` modules.

**Spec:** `docs/superpowers/specs/2026-06-13-pencheff-security-lake-design.md` (§6 consumption), **as amended by** `docs/superpowers/specs/2026-06-13-security-lake-threat-model.md` (§5 — export/mediated, NOT raw shared-table tokens). **Slices 1–4 complete.**

**Verified before writing:** org-scoped scan → latest-per-`finding_uid` dedup → NDJSON of the `ocsf_json` column yields valid OCSF events, correctly scoped to one org (offline local lake).

## Decisions locked

- **Mediated pull, not raw access** (threat model §5/C + A). Endpoint runs under existing auth; `org_id` from `get_active_workspace().org_id`, never client-supplied. Read-only.
- **Formats:** `ndjson` (one OCSF event per line — Splunk/Sentinel ingest this directly) and `parquet` (the deduped org rows — for lake-to-lake / Spark/DuckDB).
- **Current-state export** (latest event per `finding_uid`) by default — matches the query layer and absorbs Slice 2 at-least-once duplicates.
- **Scope reused:** `security_lake:read` (export is a read).
- **Push-to-customer-bucket is deploy-config** (per-org customer bucket creds) — specified, not built/tested here (no R2/customer bucket in dev). The export _artifact_ is built and tested locally.
- **Direct customer SQL is deferred** — higher risk surface; mediated export covers the SIEM/lake use case.

## File structure

| File                                            | Responsibility                                                                        |
| ----------------------------------------------- | ------------------------------------------------------------------------------------- | --------- |
| `services/security_lake/lake_query.py` (modify) | Add `export_org_ndjson(...)` + `export_org_parquet(...)` (reuse `_org_arrow`/`_con`). |
| `routers/security_lake.py` (modify)             | Add `GET /security-lake/export?format=ndjson                                          | parquet`. |
| `tests/test_security_lake_export.py` (create)   | Export service tests (org-scoped, deduped, valid OCSF, other-org excluded).           |
| `tests/test_security_lake_router.py` (modify)   | Add export-endpoint handler test.                                                     |
| `docs/.../security-lake-deploy.md` (create)     | Ops: push-export to customer bucket + the deploy-time R2-token adversarial check.     |

**Env note (all tasks):** run tests with `./.venv/bin/python -m pytest <path> -v` (rtk wrapper breaks bare pytest).

---

## Task 1: Export service (NDJSON + Parquet)

**Files:** modify `services/security_lake/lake_query.py`; create `tests/test_security_lake_export.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_export.py
from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pyarrow.parquet as pq

from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog
from pencheff_api.services.security_lake.lake_schema import to_lake_row
from pencheff_api.services.security_lake import map_finding, validate_ocsf, LakeContext
from pencheff_api.services.security_lake.lake_query import (
    export_org_ndjson, export_org_parquet,
)


def _settings(tmp_path):
    return SimpleNamespace(
        lake_catalog_type="sql",
        lake_catalog_uri=f"sqlite:///{tmp_path}/cat.db",
        lake_warehouse=f"file://{tmp_path}/wh",
        lake_namespace="pencheff", lake_table="findings",
    )


def _seed(tmp_path):
    w = LakeWriter(build_local_catalog(uri=f"sqlite:///{tmp_path}/cat.db",
                                       warehouse=f"file://{tmp_path}/wh"),
                   namespace="pencheff", table="findings")
    w.ensure_table()
    base = {"scanner": "osv", "rule_id": None, "severity": "high", "title": "x",
            "description": "d", "file_path": "p", "line_start": None, "line_end": None,
            "code_snippet": None, "package": "p", "installed_version": "1",
            "fixed_version": "2", "raw": {}}
    rows = []
    # o1: two distinct findings (CVE-O1A on a1, CVE-O1B on a2); o2: CVE-O2X on a9
    for org, asset, cve in [("o1", "a1", "CVE-O1A"), ("o1", "a2", "CVE-O1B"),
                            ("o2", "a9", "CVE-O2X")]:
        r = dict(base); r["cve"] = cve
        ctx = LakeContext(org_id=org, asset_id=asset, source="sca",
                          time_ms=1_700_000_000_000, is_new=True)
        e = map_finding("sca", r, ctx); validate_ocsf(e)
        rows.append(to_lake_row(e, org_id=org, source="sca", asset_id=asset))
    w.append_rows(rows)


def test_export_ndjson_org_scoped_valid_ocsf(tmp_path):
    _seed(tmp_path)
    text = export_org_ndjson(_settings(tmp_path), org_id="o1")
    lines = text.splitlines()
    assert len(lines) == 2                                  # only o1's two findings
    events = [json.loads(l) for l in lines]
    assert all(ev["class_uid"] == 2002 for ev in events)    # valid OCSF
    cves = {ev["vulnerabilities"][0]["cve"]["uid"] for ev in events}
    assert cves == {"CVE-O1A", "CVE-O1B"}
    assert "CVE-O2X" not in text                            # other org excluded (structural)


def test_export_ndjson_empty_org(tmp_path):
    _seed(tmp_path)
    assert export_org_ndjson(_settings(tmp_path), org_id="o-none") == ""


def test_export_parquet_org_scoped(tmp_path):
    _seed(tmp_path)
    blob = export_org_parquet(_settings(tmp_path), org_id="o1")
    table = pq.read_table(io.BytesIO(blob))
    assert table.num_rows == 2
    assert set(table.column("org_id").to_pylist()) == {"o1"}
    assert "o2" not in set(table.column("org_id").to_pylist())
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_export.py -v`
Expected: FAIL — `ImportError: cannot import name 'export_org_ndjson'`.

- [ ] **Step 3: Implement (append to `lake_query.py`)**

Add `import io` and `import pyarrow.parquet as pq` at the top of `lake_query.py` (with the existing imports), then append:

```python
def export_org_ndjson(settings: Any, *, org_id: str, source: str | None = None) -> str:
    """The org's current-state OCSF events as NDJSON (one event per line).

    SIEM-ready (Splunk/Sentinel ingest NDJSON directly). Org-scoped server-side;
    latest event per finding_uid.
    """
    arrow = _org_arrow(settings, org_id)
    if arrow is None or arrow.num_rows == 0:
        return ""
    con = _con(arrow)
    rows = con.execute(
        f"""{_LATEST_CTE}
        SELECT ocsf_json FROM latest
        WHERE (? IS NULL OR source = ?)
        ORDER BY finding_uid""",
        [source, source],
    ).fetchall()
    return "\n".join(r[0] for r in rows)


def export_org_parquet(settings: Any, *, org_id: str, source: str | None = None) -> bytes:
    """The org's current-state lake rows as a Parquet blob (lake-to-lake / Spark)."""
    arrow = _org_arrow(settings, org_id)
    if arrow is None or arrow.num_rows == 0:
        return b""
    con = _con(arrow)
    table = con.execute(
        f"""{_LATEST_CTE}
        SELECT finding_uid, org_id, class_uid, source, severity_id, status_id,
               asset_id, time, dt, ocsf_json
        FROM latest
        WHERE (? IS NULL OR source = ?)
        ORDER BY finding_uid""",
        [source, source],
    ).to_arrow_table()
    buf = io.BytesIO()
    pq.write_table(table, buf)
    return buf.getvalue()
```

- [ ] **Step 4: Run to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_export.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/lake_query.py apps/api/tests/test_security_lake_export.py
git commit -m "feat(security-lake): org-scoped OCSF export (NDJSON + Parquet)"
```

---

## Task 2: Export endpoint

**Files:** modify `routers/security_lake.py`; modify `tests/test_security_lake_router.py`.

- [ ] **Step 1: Write the failing test (append to `tests/test_security_lake_router.py`)**

```python
# tests/test_security_lake_router.py  (append)
def test_export_handler_ndjson_org_scoped(tmp_path):
    _seed(tmp_path)  # existing helper seeds org o1 with 2 findings
    resp = asyncio.run(router_mod.export(
        format="ndjson", source=None, workspace=_ws("o1"),
        settings=_settings(tmp_path)))
    body = resp.body.decode() if isinstance(resp.body, bytes) else resp.body
    assert resp.media_type == "application/x-ndjson"
    assert len([l for l in body.splitlines() if l]) == 2
    # other org gets nothing
    empty = asyncio.run(router_mod.export(
        format="ndjson", source=None, workspace=_ws("o-other"),
        settings=_settings(tmp_path)))
    empty_body = empty.body.decode() if isinstance(empty.body, bytes) else empty.body
    assert empty_body == ""


def test_export_handler_parquet(tmp_path):
    _seed(tmp_path)
    resp = asyncio.run(router_mod.export(
        format="parquet", source=None, workspace=_ws("o1"),
        settings=_settings(tmp_path)))
    assert resp.media_type == "application/octet-stream"
    assert isinstance(resp.body, (bytes, bytearray)) and len(resp.body) > 0
```

> The existing `_seed`/`_ws`/`_settings` helpers in this file seed org `o1`; reuse them. (The router test's `_seed` may use a different finding shape than Task 1's — that's fine; assert line/row counts that match whatever it seeds. If the existing `_seed` makes 2 findings for o1, assert 2.)

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_router.py -k export -v`
Expected: FAIL — `AttributeError: module ... has no attribute 'export'`.

- [ ] **Step 3: Implement (add to `routers/security_lake.py`)**

Add imports at the top: `from fastapi import Response` (alongside the existing fastapi imports) and `from ..services.security_lake import lake_query` is already present. Add the handler:

```python
@router.get("/export")
async def export(
    format: Literal["ndjson", "parquet"] = Query("ndjson"),
    source: str | None = Query(None, description="sast | dast | sca | iac | secret"),
    workspace: Workspace = Depends(get_active_workspace),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Mediated, org-scoped OCSF export. NDJSON for SIEMs; Parquet for lakes."""
    if format == "parquet":
        blob = lake_query.export_org_parquet(settings, org_id=workspace.org_id,
                                             source=source)
        return Response(content=blob, media_type="application/octet-stream",
                        headers={"Content-Disposition":
                                 'attachment; filename="pencheff-findings.parquet"'})
    text = lake_query.export_org_ndjson(settings, org_id=workspace.org_id, source=source)
    return Response(content=text, media_type="application/x-ndjson",
                    headers={"Content-Disposition":
                             'attachment; filename="pencheff-findings.ndjson"'})
```

(The `/export` route is covered by the router-level `require_scope("security_lake:read")` dependency — no extra scope needed.)

- [ ] **Step 4: Run to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_router.py -v`
Expected: PASS (existing + 2 new). Then confirm app imports: `./.venv/bin/python -c "import pencheff_api.main"`.

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/routers/security_lake.py apps/api/tests/test_security_lake_router.py
git commit -m "feat(security-lake): GET /security-lake/export (mediated org-scoped OCSF NDJSON/Parquet)"
```

---

## Task 3: Deploy / ops documentation (push-export + R2-token verification)

**Files:** create `docs/superpowers/specs/2026-06-13-security-lake-deploy.md`.

This is the deploy-config the sandbox can't exercise (no R2). It closes the threat model's [GATE] items for external access.

- [ ] **Step 1: Write the doc**

Create `docs/superpowers/specs/2026-06-13-security-lake-deploy.md` with:

1. **Prod catalog config** — set `lake_catalog_type=rest`, `lake_catalog_uri` (R2 Data Catalog REST endpoint), `lake_warehouse` (R2 bucket path), `lake_catalog_token`, `r2_endpoint_url`, `r2_access_key_id`, `r2_secret_access_key`. These are worker/API creds (full access) — NEVER issued to customers.
2. **Migration** — apply Alembic `0054` (`alembic upgrade head`) for `lake_ingestion`/`lake_quarantine`.
3. **Push-export to a customer bucket (architecture A)** — a scheduled job per subscribing org: call `export_org_parquet`/`export_org_ndjson`, then PUT the artifact into the **customer's** bucket using **the customer's** credentials (stored per-org, encrypted). The customer's SIEM/lake reads from their own storage. Pencheff never grants read on its own bucket/catalog.
4. **Mediated pull (architecture C)** — customers call `GET /security-lake/export` with their Pencheff API key (scope `security_lake:read`); `org_id` is server-derived. This is live as of Slice 5.
5. **[GATE] deploy-time adversarial check** — before enabling any external subscriber: issue/configure access for org A; attempt to read an org-B object/export as org A; **expect denial (403 / empty)**. Document the exact check for both the export endpoint (different API key → different org → no overlap) and, if per-org buckets are ever used, the R2 token boundary.
6. **Explicitly NOT done** — raw Iceberg REST-catalog or shared-bucket tokens for customers (threat model §4–5); direct ad-hoc customer SQL (deferred).

- [ ] **Step 2: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add docs/superpowers/specs/2026-06-13-security-lake-deploy.md
git commit -m "docs(security-lake): deploy + external-access ops (push-export, mediated pull, R2 gate check)"
```

---

## Self-review (completed by plan author)

**Spec coverage (threat-model-amended §6):**

- Mediated, org-scoped export (NDJSON + Parquet) → Tasks 1, 2 ✓.
- Server-side org injection (`workspace.org_id`), read-only, scope-gated → Task 2 ✓ (reuses Slice 3/4 tenancy controls).
- Push-to-customer-bucket + R2-token deploy gate → Task 3 (documented; not testable in dev) ✓.
- Raw shared-table tokens explicitly NOT shipped; direct SQL deferred → documented ✓.

**Placeholder scan:** No TBD/TODO. Task 1/2 code is complete and verified against a live local lake. Task 3 is a documentation deliverable (the deploy/ops spec) with concrete config keys and an explicit adversarial check — not a placeholder.

**Type consistency:** `export_org_ndjson(settings, *, org_id, source=None) -> str`, `export_org_parquet(settings, *, org_id, source=None) -> bytes` reuse the existing `_org_arrow`/`_con`/`_LATEST_CTE` from `lake_query.py` (consistent with Slice 3). The `export` handler returns a FastAPI `Response` (the router test reads `resp.body`/`resp.media_type`). `_LATEST_CTE` registers the Arrow table as `findings`; the new queries select from `latest` exactly as the Slice 3 queries do.

**Known limitations (documented):**

- Export materializes the org's current-state into memory (string/bytes) — fine at current scale; stream (FastAPI `StreamingResponse`) and/or a `since_dt` bound for very large orgs later.
- NDJSON export emits current-state (deduped) events, not the full historical event stream; a `?mode=events` raw-history export is a later option if a SIEM wants every event.
- R2 token / customer-bucket push is deploy-verified only (no R2 in dev) — Task 3 specifies the adversarial gate check.
