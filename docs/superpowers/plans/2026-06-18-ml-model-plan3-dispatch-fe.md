# ML Model — Plan 3: Pipeline Dispatch + Frontend

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Wire `kind="ml_model"` end-to-end: scan_runner dispatches it to the `scan_ml_model` tool (Plan 2), the Plan-1 409 gate is removed, and the FE lets users register/edit/list/view an ML-model target (`MlModelFormSection`, consent vocab, ML card flips `llm`→`ml_model`).

**Architecture:** Mirror the SHIPPED `rag` dispatch + FE wiring exactly. pencheff `PentestSession` gains an `ml_config` slot (like `rag_config`); scan_runner binds it and routes `ml_model` to a new `_run_ml_scan` (clone of `_run_rag_scan`) + a dispatch block (clone of the rag block, `target_kind="ml_model"`). Migration `0060` is a no-DDL marker. FE adds `MlModelFormSection`, the `ml_fetch` disclosure, and flips the ML card to the real kind.

**Tech Stack:** Python (pytest `cd apps/api && .venv/bin/python -m pytest`; pytest `cd plugins/pencheff && uv run pytest`); Next.js 15 / React / TS (`cd apps/web && npx tsc --noEmit` + `npx next build`). **Branch:** `feat/ml-voice-scanning` (already checked out — NO worktree, NO branch switching).

**Reference (mirror these):**

- pencheff session: `plugins/pencheff/pencheff/core/session.py` (`rag_config` field at line ~103 + `create_session` param at ~166/188).
- scan_runner: `apps/api/pencheff_api/services/scan_runner.py` — `rag_config=` bind at line ~700; `if target.kind == "rag":` dispatch block at ~872; `_run_rag_scan` at ~2225.
- gate removal + guard test: `apps/api/pencheff_api/routers/scans.py` (the `ml_model` 409 from Plan 1); `apps/api/tests/test_scans_rag_kind_gate.py` is the GUARD pattern (asserts the not-yet-available error is ABSENT) — mirror it for `test_scans_ml_model_kind_gate.py`.
- migration: `apps/api/pencheff_api/db/migrations/versions/0059_rag_target_kind.py` (no-DDL marker template).
- FE: `apps/web/components/register-target/rag-form-section.tsx`; `target-types.ts` (ml-model card line ~319, TargetKind union line ~27); `apps/web/lib/consent-disclosures.ts` (rag entries ~238, `REQUIRED_ACTION_IDS_BY_KIND` ~281); `app/targets/new/page.tsx` (RagFormSection import line 89 + render ~1503); `app/targets/[id]/edit/page.tsx` (import 96 + render ~1489); `app/targets/page.tsx` + `app/targets/[id]/page.tsx` (kind badges/labels).

Spec: `docs/superpowers/specs/2026-06-17-ml-model-scanning-design.md`.

---

## Task 1: `ml_config` slot on the pencheff session

**Files:** `plugins/pencheff/pencheff/core/session.py`; Test `plugins/pencheff/tests/test_ml_session_config.py`.

- [ ] **Step 1: Write failing test** `tests/test_ml_session_config.py` (mirror `test_rag_session_config.py`):

```python
from pencheff.core.session import create_session


def test_ml_config_round_trips():
    cfg = {"kind": "ml_model", "source_type": "huggingface", "hf_repo": "owner/model"}
    s = create_session(target_url="hf://owner/model", depth="quick", ml_config=cfg)
    assert s.ml_config == cfg


def test_ml_config_defaults_none():
    s = create_session(target_url="x", depth="quick")
    assert s.ml_config is None
```

- [ ] **Step 2: Run, confirm FAIL** (`cd plugins/pencheff && uv run pytest tests/test_ml_session_config.py -q`).
- [ ] **Step 3: Implement.** In `PentestSession` after the `rag_config` field (line ~103) add:

```python
    # ML-model targets carry their MlModelConfig dict here (source_type,
    # url/hf_repo/local_path, ...). Empty / None for all other session kinds.
    ml_config: dict[str, Any] | None = None
```

In `create_session`, add the param after `rag_config` (~166):

```python
    ml_config: dict[str, Any] | None = None,
```

and pass it through in the `PentestSession(...)` constructor (~188):

```python
        ml_config=ml_config,
```

- [ ] **Step 4: Run, confirm PASS** (2 tests).
- [ ] **Step 5: Commit** `feat(plugin): ml_config slot on PentestSession`.

---

## Task 2: scan_runner dispatch (`ml_model` → `scan_ml_model`)

**Files:** `apps/api/pencheff_api/services/scan_runner.py`; Test `apps/api/tests/test_scan_runner_ml_dispatch.py`.

- [ ] **Step 1: Write failing test** `tests/test_scan_runner_ml_dispatch.py` (mirror the rag dispatch test if one exists — search `tests/` for `_run_rag_scan`/`rag dispatch`; otherwise this unit test of `_run_ml_scan` suffices):

```python
import asyncio
import types
import pencheff_api.services.scan_runner as sr


def test_run_ml_scan_invokes_tool(monkeypatch):
    called = {}

    async def _fake_scan_ml_model(session_id=None, ml_config=None):
        called["session_id"] = session_id
        called["ml_config"] = ml_config
        return {"new_findings": 0}

    fake_srv = types.SimpleNamespace(scan_ml_model=_fake_scan_ml_model)
    monkeypatch.setitem(__import__("sys").modules, "pencheff.server", fake_srv)

    psession = types.SimpleNamespace(id="sess1", ml_config={"kind": "ml_model", "source_type": "file_url", "url": "https://h/m.pkl"})

    asyncio.run(sr._run_ml_scan(scan_id="scan1", psession=psession, profile="quick",
                                db_session_factory=None))
    assert called["session_id"] == "sess1"
    assert called["ml_config"]["source_type"] == "file_url"


def test_run_ml_scan_missing_tool_is_non_fatal(monkeypatch):
    fake_srv = types.SimpleNamespace()   # no scan_ml_model attr
    monkeypatch.setitem(__import__("sys").modules, "pencheff.server", fake_srv)
    psession = types.SimpleNamespace(id="s", ml_config={})
    # must not raise
    asyncio.run(sr._run_ml_scan(scan_id="x", psession=psession, profile="quick", db_session_factory=None))
```

- [ ] **Step 2: Run, confirm FAIL** (`cd apps/api && .venv/bin/python -m pytest tests/test_scan_runner_ml_dispatch.py -q`).
- [ ] **Step 3: Implement.**
      (a) At the `create_session(...)` call (~line 700), after the `rag_config=` line add:

```python
            ml_config=dict(target.kind_config) if (target.kind == "ml_model" and target.kind_config) else None,
```

(b) Add `_run_ml_scan` right after `_run_rag_scan` (~line 2253), an exact clone with rag→ml:

```python
async def _run_ml_scan(
    *,
    scan_id: str,
    psession: Any,
    profile: str,
    db_session_factory: async_sessionmaker,
) -> None:
    """Invoke the pencheff scan_ml_model tool in-process (mirrors _run_rag_scan)."""
    import pencheff.server as srv
    fn = getattr(srv, "scan_ml_model", None)
    if fn is None:
        log.warning("pencheff scan_ml_model tool unavailable for scan %s", scan_id)
        return
    _timeout_s = {
        "quick":    600.0,
        "standard": 1800.0,
        "deep":     7200.0,
    }.get(profile, 1200.0)
    try:
        await asyncio.wait_for(
            fn(session_id=psession.id, ml_config=psession.ml_config),
            timeout=_timeout_s,
        )
    except asyncio.TimeoutError:
        log.warning("scan_ml_model timed out for scan %s", scan_id)
    except Exception as e:  # noqa: BLE001
        log.warning("scan_ml_model failed for scan %s: %s", scan_id, e)
```

(c) Add the dispatch block right after the `if target.kind == "rag":` block ends (~line 905, after its `return`). Clone the rag block verbatim, replacing `rag`→`ml_model` in the guard, `_run_rag_scan`→`_run_ml_scan`, and `target_kind="rag"`→`target_kind="ml_model"`:

```python
        # ── ML model kind ───────────────────────────────────────────
        # Mirrors the RAG branch: run the static ML scanner (never loads
        # the model), persist findings, grade, finalize. No DAST pipeline.
        if target.kind == "ml_model":
            await _run_ml_scan(
                scan_id=scan_id,
                psession=psession,
                profile=scan.profile,
                db_session_factory=Session,
            )
            all_findings = (
                list(psession.findings.get_all(include_suppressed=True))
                if hasattr(psession.findings, "get_all")
                else []
            )
            if not all_findings and hasattr(psession.findings, "findings"):
                all_findings = list(psession.findings.findings)
            async with Session() as db:
                for f in all_findings:
                    db.add(DbFinding(**_finding_to_db_row(scan_id, f)))
                await db.commit()
            score, grade, counts = compute_grade(
                [_DbFindingProxy(_) for _ in await _read_back_findings(scan_id, Session)],
                target_kind="ml_model",
            )
            summary_payload = dict(counts)
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                s.status = "done"
                s.progress_pct = 100
                s.current_stage = "complete"
                s.finished_at = datetime.now(timezone.utc)
                existing = dict(s.summary or {})
                existing.update(summary_payload)
                s.summary = existing
                s.grade = grade
                s.score = score
                _append_log(s, f"finished: grade {grade} · score {score}")
                await db.commit()
            publish_scan_event(scan_id, {
                "type": "finished", "scan_id": scan_id, "grade": grade, "score": score,
                "summary": counts, "total_findings": len(all_findings),
            })
            try:
                from ..tasks.integration_notify_task import notify_scan_findings as _nsf
                _nsf.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("integration scan_done enqueue failed: %s", exc)
            try:
                from ..tasks.email_task import send_scan_complete_email_task as _scet
                _scet.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("scan-complete email enqueue failed: %s", exc)
            return
```

(d) **Verify `compute_grade`** handles `target_kind="ml_model"`: open the function (grep `def compute_grade`). If it branches on specific kinds with a sensible default for unknown kinds (like `rag` relies on), no change is needed. If `rag`/`mcp` are explicitly enumerated and the default is wrong for findings-only scans, add `ml_model` to the same branch as `rag`/`mcp`. State which you found in your report.

- [ ] **Step 4: Run, confirm PASS** (2 tests).
- [ ] **Step 5: Commit** `feat(api): scan_runner dispatch kind=ml_model → scan_ml_model`.

---

## Task 3: Remove the Plan-1 409 gate + convert its test to a guard

**Files:** `apps/api/pencheff_api/routers/scans.py`; `apps/api/tests/test_scans_ml_model_kind_gate.py`.

- [ ] **Step 1: Rewrite the test as a guard.** Open `tests/test_scans_rag_kind_gate.py` to see how the rag guard asserts the not-yet-available 409 is GONE (i.e., a scan for the now-wired kind no longer returns `*_kind_scanning_not_yet_available`). Rewrite `test_scans_ml_model_kind_gate.py` to mirror it for `ml_model`: starting a scan for an `ml_model` target with `["ml_fetch"]` disclosed must NOT return 409 `ml_model_kind_scanning_not_yet_available` (it now enqueues / proceeds like rag).
- [ ] **Step 2: Run, confirm FAIL** (gate still present → test fails).
- [ ] **Step 3: Remove the gate.** Delete the `if target.kind == "ml_model": raise HTTPException(409, {"error": "ml_model_kind_scanning_not_yet_available", ...})` block added in Plan 1 from `start_scan`.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** `feat(api): enable POST /scans for kind=ml_model (remove gate)`.

---

## Task 4: Migration marker `0060_ml_model_target_kind`

**Files:** Create `apps/api/pencheff_api/db/migrations/versions/0060_ml_model_target_kind.py`.

- [ ] **Step 1: Implement** (copy `0059_rag_target_kind.py`; set `revision="0060"`, `down_revision="0059"`, no-DDL upgrade/downgrade, message about `ml_model` — `Target.kind` is `String(16)`, no schema change):

```python
"""ml_model target kind — Target.kind is String(16); 'ml_model' needs no DDL.

Revision ID: 0060
Revises: 0059
"""
from __future__ import annotations

revision = "0060"
down_revision = "0059"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # No-op: `ml_model` is a new value of the String(16) Target.kind column.
    # This marker keeps the migration history aligned with the wire-kind addition.
    pass


def downgrade() -> None:
    pass
```

- [ ] **Step 2: Verify** the head is reachable: `cd apps/api && .venv/bin/python -m alembic heads` shows `0060` (or run the test suite, which builds the schema). If the project uses a different revision id format than the file shows for 0059, MATCH 0059's exact format.
- [ ] **Step 3: Commit** `feat(api): migration marker 0060 for ml_model kind`.

---

## Task 5: FE — consent vocabulary + TargetKind + ML card flip

**Files:** `apps/web/lib/consent-disclosures.ts`; `apps/web/components/register-target/target-types.ts`.

- [ ] **Step 1: consent-disclosures.ts.** Add an `ml_fetch` entry to the `ACTIONS` map (after the rag entries, ~line 255):

```typescript
  ml_fetch: {
    id: "ml_fetch",
    displayName: "ML model fetch & static inspection",
    description:
      "Download (or read) the model artifact and statically inspect its bytes/opcodes/structure for unsafe-deserialization RCE, unsafe formats, and Keras code-execution. The model is NEVER loaded, deserialized, or executed.",
  },
```

Add to `REQUIRED_ACTION_IDS_BY_KIND` (~line 304, after `rag`):

```typescript
  ml_model: ["ml_fetch"],
```

If there is a `FRONTEND_DISCLOSED_*`/optional-actions map mirroring the backend `_FRONTEND_DISCLOSED_ACTION_IDS_BY_KIND` (search the file for `mcp: []` near line ~357), add `ml_model: ["ml_fetch"]` there too so the modal shows the single disclosure. (If `SupportedKind` is a TS union, add `"ml_model"` to it — search the file/`target-types.ts` for where `SupportedKind` is declared.)

- [ ] **Step 2: target-types.ts.** Add `"ml_model"` to the `TargetKind` union (line ~27, after `"rag"`):

```typescript
  | "ml_model"; // ML model artifact — static no-load scanning
```

Flip the ML card `kind` (line ~324) from `"llm"` to `"ml_model"`. Leave label/num/description as-is.

- [ ] **Step 3: Type-check** `cd apps/web && npx tsc --noEmit` — expect errors only where `ml_model` now needs handling (the form section, render switch). Those are fixed in Task 6; if tsc errors ONLY point at not-yet-written Task-6 sites, proceed.
- [ ] **Step 4: Commit** `feat(web): ml_model consent vocab + TargetKind + card kind`.

---

## Task 6: FE — `MlModelFormSection` + wire into create/edit/list/detail

**Files:** Create `apps/web/components/register-target/ml-model-form-section.tsx`; modify `app/targets/new/page.tsx`, `app/targets/[id]/edit/page.tsx`, `app/targets/page.tsx`, `app/targets/[id]/page.tsx`.

- [ ] **Step 1: Build `MlModelFormSection`** by copying `rag-form-section.tsx` and adapting to `MlModelConfig`. Read `rag-form-section.tsx` for the exact prop shape (`value`/`onChange`/`errors` etc.) and the brutal UI components used (`@/components/brutal`), then implement these fields:
  - `source_type` selector: `file_url` | `huggingface` | `local_path` (radio/segmented, mirroring how rag picks `source_type`).
  - `file_url` → text input `url` (required when selected; placeholder `https://host/model.safetensors`).
  - `huggingface` → text inputs `hf_repo` (required, placeholder `owner/model`) + optional `hf_revision` (placeholder `main`).
  - `local_path` → text input `local_path` (required, placeholder `/models/model.pt`; helper note: "path on the scanner host").
  - optional `format_hint` select with the literal values `auto|pickle|pytorch|safetensors|keras|h5|savedmodel|gguf|joblib` (default `auto`).
  - optional `max_bytes` number input (default 524288000; helper "fetch size cap, bytes").
  - The emitted config object MUST be `{ kind: "ml_model", source_type, url?, hf_repo?, hf_revision?, local_path?, format_hint, max_bytes }` matching the backend `MlModelConfig`.
  - Include the same inline consent/safety note style rag uses; copy: "Static-only: the model is fetched and inspected byte-by-byte. It is never loaded or executed."
    Export `export function MlModelFormSection({ ... })` with the SAME prop signature as `RagFormSection`.
- [ ] **Step 2: Wire into `app/targets/new/page.tsx`.** Add the import beside the Rag import (line ~89):

```typescript
import { MlModelFormSection } from "@/components/register-target/ml-model-form-section";
```

Add a render branch beside the Rag render (~line 1503), gated on the selected kind being `ml_model`, passing the same value/onChange/errors props the Rag section receives (mirror exactly how the create page stores `kind_config` for rag).

- [ ] **Step 3: Wire into `app/targets/[id]/edit/page.tsx`** the same way (import line ~96, render ~1489) so an existing `ml_model` target is editable.
- [ ] **Step 4: List + detail.** In `app/targets/page.tsx` and `app/targets/[id]/page.tsx`, find where the kind→label/badge mapping lives (search for `"rag"` / `"mcp"`). Add `ml_model` with label `"ML Model"` (badge style consistent with the other AI kinds) so it doesn't fall through to a raw/unknown badge. If the detail page branches the "Start scan"/config display on kind, mirror the rag branch for `ml_model`.
- [ ] **Step 5: Type-check + build.** `cd apps/web && npx tsc --noEmit` (clean) then `npx next build` (succeeds). Fix any remaining `ml_model` exhaustiveness errors.
- [ ] **Step 6: Commit** `feat(web): MlModelFormSection + create/edit/list/detail wiring`.

---

## Task 7: Full regression (BE + plugin + FE)

- [ ] **Step 1: API suite** `cd apps/api && .venv/bin/python -m pytest tests/ -q -k "scan or target or kind or consent or memory or ml"` → green.
- [ ] **Step 2: Plugin suite** `cd plugins/pencheff && uv run pytest tests/ -q -k "ml or rag or mcp or smoke or sentry"` → green; `uv run python -c "import pencheff.server; print('ok')"`.
- [ ] **Step 3: FE** `cd apps/web && npx tsc --noEmit` clean + `npx next build` succeeds.
- [ ] **Step 4: Commit** any test-list/snapshot updates if needed: `test(ml_model): end-to-end regression green`.

---

## Self-review

**Spec coverage (§9 dispatch + FE):** ml_config slot (T1) ✓; scan_runner bind + `_run_ml_scan` + dispatch block (T2) ✓; gate removed (T3) ✓; migration marker (T4) ✓; consent vocab + card flip (T5) ✓; MlModelFormSection + create/edit/list/detail (T6) ✓; regression (T7) ✓.
**Type consistency:** session attr `ml_config`; tool kwarg `ml_config`; `target_kind="ml_model"`; FE config object keys exactly match backend `MlModelConfig` (kind/source_type/url/hf_repo/hf_revision/local_path/format_hint/max_bytes); consent action id `ml_fetch` matches backend `KIND_REQUIRED_DISCLOSED_ACTIONS["ml_model"]`. Card kind `"ml_model"` matches `TargetKind` union + `REQUIRED_ACTION_IDS_BY_KIND`.
**FE/BE drift closed:** the live `consent-disclosures.ts` now carries the `ml_model` entry the Plan-1 implementer flagged as missing.
**No migration DDL:** `Target.kind` is `String(16)`; 0060 is a marker (mcp/rag precedent).
