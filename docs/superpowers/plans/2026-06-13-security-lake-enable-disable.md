# Security Lake Enable/Disable + 7-Day Retention — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an org-level enable/disable toggle for the Security Lake (disabled by default), surfaced on a new Settings page; when disabled, ingestion and query/export are off and the org's lake data is purged 7 days after a user-initiated disable.

**Architecture:** Two new `Org` columns (`security_lake_enabled`, `security_lake_disabled_at`) drive everything. The `PATCH /orgs/{id}` endpoint flips them (+ audit). A FastAPI dependency 403s the `/security-lake/*` endpoints when off; the ingest tasks skip when off. A daily Celery-beat task purges orgs disabled > 7 days ago via pyiceberg `table.delete(EqualTo("org_id", …))` (verified against R2). A new `app/settings/page.tsx` hosts the toggle.

**Tech Stack:** FastAPI + SQLAlchemy + Alembic, Celery beat, pyiceberg/R2, Next.js (static export).

**Spec:** `docs/superpowers/specs/2026-06-13-security-lake-enable-disable-design.md`.

**Verified before writing:** `table.delete(delete_filter=EqualTo("org_id", org))` against real R2 removes only that org's partition rows (org A's 2 rows deleted, org B's 1 row intact).

**Env note (all backend tasks):** run tests with `./.venv/bin/python -m pytest <path> -v` from `apps/api` (an rtk wrapper breaks bare pytest).

## File structure

| File                                                                            | Change                                                                                              |
| ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `apps/api/pencheff_api/db/models.py`                                            | + `Org.security_lake_enabled`, `Org.security_lake_disabled_at`                                      |
| `apps/api/pencheff_api/db/migrations/versions/0055_security_lake_org_toggle.py` | new migration (cols)                                                                                |
| `apps/api/pencheff_api/services/security_lake/toggle.py`                        | new — pure transition + purge-due helpers                                                           |
| `apps/api/pencheff_api/schemas/orgs.py`                                         | + `security_lake_enabled` on `OrgUpdate`/`OrgOut`                                                   |
| `apps/api/pencheff_api/routers/orgs.py`                                         | `update_org`: apply toggle + audit + surface on `OrgOut`                                            |
| `apps/api/pencheff_api/routers/security_lake.py`                                | + `require_security_lake_enabled` dependency on the router                                          |
| `apps/api/pencheff_api/tasks/security_lake_ingest_task.py`                      | ingest entrypoints skip when org disabled; + `purge_disabled_lakes` task; + `purge_org_lake` helper |
| `apps/api/pencheff_api/tasks/celery_app.py`                                     | + `security-lake-retention` beat entry                                                              |
| `apps/web/lib/workspace-context.tsx`                                            | + `security_lake_enabled?: boolean` on `Org` type                                                   |
| `apps/web/components/nav.tsx`                                                   | + `Settings` entry in `SETTINGS_NAV`                                                                |
| `apps/web/app/settings/page.tsx`                                                | new — Security Lake toggle + confirm modal                                                          |
| tests                                                                           | `tests/test_security_lake_toggle.py`, `tests/test_security_lake_gate.py`                            |

---

## Task 1: Org columns + migration

**Files:** modify `db/models.py`; create `db/migrations/versions/0055_security_lake_org_toggle.py`; test `tests/test_security_lake_org_columns.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_org_columns.py
from __future__ import annotations

from pencheff_api.db.models import Org


def test_org_has_security_lake_columns():
    cols = Org.__table__.columns
    assert "security_lake_enabled" in cols
    assert "security_lake_disabled_at" in cols
    # default disabled
    assert cols["security_lake_enabled"].default.arg is False
    assert cols["security_lake_enabled"].server_default.arg.text == "false"
    # disabled_at is nullable (the purge clock; null = not running)
    assert cols["security_lake_disabled_at"].nullable is True


def test_migration_0055_chains_from_0054():
    import importlib
    m = importlib.import_module(
        "pencheff_api.db.migrations.versions.0055_security_lake_org_toggle")
    assert m.revision == "0055"
    assert m.down_revision == "0054"
    assert hasattr(m, "upgrade") and hasattr(m, "downgrade")
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_org_columns.py -v` → FAIL (column missing / module not found).

- [ ] **Step 3: Add the columns**

In `db/models.py`, in the `Org` class, immediately after the `allow_private_targets` column and before `created_at`, add:

```python
    # Security Lake (OCSF Iceberg) per-org toggle. Disabled by default. When
    # disabled, ingestion + query/export are off; security_lake_disabled_at is
    # the purge clock — set on a user enable->disable, cleared on disable->enable,
    # and an org disabled for >7d is purged by the retention task. The migration
    # leaves disabled_at NULL so the clock starts only on a user-initiated disable.
    security_lake_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false", default=False
    )
    security_lake_disabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
```

- [ ] **Step 4: Create the migration**

```python
# pencheff_api/db/migrations/versions/0055_security_lake_org_toggle.py
"""security lake per-org enable/disable toggle

Revision ID: 0055
Revises: 0054
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0055"
down_revision = "0054"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("orgs", sa.Column(
        "security_lake_enabled", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("orgs", sa.Column(
        "security_lake_disabled_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("orgs", "security_lake_disabled_at")
    op.drop_column("orgs", "security_lake_enabled")
```

- [ ] **Step 5: Run to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_org_columns.py -v` → PASS (2 passed). Also `./.venv/bin/python -c "import pencheff_api.db.models"` → no error.

- [ ] **Step 6: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/db/models.py apps/api/pencheff_api/db/migrations/versions/0055_security_lake_org_toggle.py apps/api/tests/test_security_lake_org_columns.py
git commit -m "feat(security-lake): org enable/disable columns + migration 0055"
```

---

## Task 2: Toggle transition + purge-due helpers (pure)

**Files:** create `services/security_lake/toggle.py`; test `tests/test_security_lake_toggle.py`.

These are the pure, fully-unit-tested core. The endpoint (Task 3) and retention task (Task 5) call them.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_toggle.py
from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

from pencheff_api.services.security_lake.toggle import (
    apply_lake_toggle, purge_due, PURGE_GRACE_DAYS,
)


def _org(enabled, disabled_at):
    return SimpleNamespace(security_lake_enabled=enabled, security_lake_disabled_at=disabled_at)


NOW = dt.datetime(2026, 6, 13, tzinfo=dt.timezone.utc)


def test_enable_to_disable_starts_clock():
    org = _org(True, None)
    changed = apply_lake_toggle(org, enabled=False, now=NOW)
    assert changed is True
    assert org.security_lake_enabled is False
    assert org.security_lake_disabled_at == NOW


def test_disable_to_enable_clears_clock():
    org = _org(False, NOW)
    changed = apply_lake_toggle(org, enabled=True, now=NOW)
    assert changed is True
    assert org.security_lake_enabled is True
    assert org.security_lake_disabled_at is None


def test_no_change_returns_false_and_leaves_clock():
    org = _org(False, NOW)
    changed = apply_lake_toggle(org, enabled=False, now=NOW)
    assert changed is False
    assert org.security_lake_disabled_at == NOW   # untouched


def test_purge_due_only_after_grace_and_disabled():
    assert PURGE_GRACE_DAYS == 7
    old = NOW - dt.timedelta(days=8)
    recent = NOW - dt.timedelta(days=3)
    assert purge_due(enabled=False, disabled_at=old, now=NOW) is True
    assert purge_due(enabled=False, disabled_at=recent, now=NOW) is False     # within grace
    assert purge_due(enabled=False, disabled_at=None, now=NOW) is False        # clock not running
    assert purge_due(enabled=True, disabled_at=old, now=NOW) is False          # re-enabled
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_toggle.py -v` → FAIL (module not found).

- [ ] **Step 3: Implement**

```python
# pencheff_api/services/security_lake/toggle.py
from __future__ import annotations

import datetime as dt
from typing import Any

PURGE_GRACE_DAYS = 7


def apply_lake_toggle(org: Any, *, enabled: bool, now: dt.datetime) -> bool:
    """Apply an enable/disable to an org. Returns True if the flag changed.

    enable->disable starts the purge clock (disabled_at=now); disable->enable
    clears it (disabled_at=None). No-op if the flag is unchanged.
    """
    before = bool(org.security_lake_enabled)
    if before == enabled:
        return False
    org.security_lake_enabled = enabled
    org.security_lake_disabled_at = None if enabled else now
    return True


def purge_due(*, enabled: bool, disabled_at: dt.datetime | None, now: dt.datetime) -> bool:
    """An org's lake data is due for purge iff it's disabled, the clock is
    running, and the grace window has elapsed."""
    if enabled or disabled_at is None:
        return False
    return disabled_at < now - dt.timedelta(days=PURGE_GRACE_DAYS)
```

- [ ] **Step 4: Run to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_toggle.py -v` → PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/toggle.py apps/api/tests/test_security_lake_toggle.py
git commit -m "feat(security-lake): pure toggle-transition + purge-due helpers"
```

---

## Task 3: Settings API (PATCH /orgs/{id})

**Files:** modify `schemas/orgs.py`, `routers/orgs.py`. (DB-bound endpoint — the pure logic is Task 2; this wires it. Verified at deploy + via the Task 2 tests.)

- [ ] **Step 1: Add the schema fields**

In `schemas/orgs.py`, add to `OrgUpdate` (after `private_targets_disclosure_ack`):

```python
    # Security Lake per-org toggle (owner/admin via PATCH /orgs/{id}).
    security_lake_enabled: bool | None = None
```

Add to `OrgOut` (after `allow_private_targets`):

```python
    security_lake_enabled: bool = False
```

- [ ] **Step 2: Wire the toggle into `update_org`**

In `routers/orgs.py`, add imports at the top of the file (near the other service imports):

```python
from datetime import datetime, timezone
from ..services.security_lake.toggle import apply_lake_toggle
```

In `update_org`, immediately before `await session.commit()` (after the `allow_private_targets` block, ~line 202), add:

```python
    # Security Lake enable/disable. apply_lake_toggle sets/clears the purge
    # clock (security_lake_disabled_at) on the transition. Audited like the
    # other org flags.
    if body.security_lake_enabled is not None:
        before = bool(org.security_lake_enabled)
        if apply_lake_toggle(org, enabled=bool(body.security_lake_enabled),
                             now=datetime.now(tz=timezone.utc)):
            session.add(AuditLog(
                user_id=user.id,
                org_id=org.id,
                action="org.security_lake_enabled.toggle",
                entity_type="org",
                entity_id=org.id,
                meta={"before": before, "after": bool(org.security_lake_enabled),
                      "actor_role": member.role},
            ))
```

And add `security_lake_enabled=bool(org.security_lake_enabled),` to the `OrgOut(...)` return at the end of `update_org`. Also add the same kwarg to any OTHER place that builds `OrgOut` (grep `OrgOut(` in `routers/orgs.py` — e.g. the GET `/orgs/{id}` and list handlers — and add `security_lake_enabled=bool(org.security_lake_enabled)` to each, so the FE always sees current state).

- [ ] **Step 3: Verify it imports + the OrgOut builders are consistent**

Run: `./.venv/bin/python -c "import pencheff_api.routers.orgs, pencheff_api.schemas.orgs; print('ok')"` → `ok`.
Run: `grep -n "OrgOut(" pencheff_api/routers/orgs.py` and confirm every constructor passes `security_lake_enabled=...` (a missing kwarg is fine — it defaults False — but for correctness the FE needs the real value from the GET/list paths).

- [ ] **Step 4: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/schemas/orgs.py apps/api/pencheff_api/routers/orgs.py
git commit -m "feat(security-lake): PATCH /orgs toggles security_lake_enabled (+audit, purge clock)"
```

---

## Task 4: Query/export gate (403 when disabled)

**Files:** modify `routers/security_lake.py`; test `tests/test_security_lake_gate.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_gate.py
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from pencheff_api.routers.security_lake import require_security_lake_enabled


class _FakeSession:
    def __init__(self, org):
        self._org = org
    async def get(self, model, pk):
        return self._org


def test_gate_allows_when_enabled():
    org = SimpleNamespace(id="o1", security_lake_enabled=True)
    ws = SimpleNamespace(id="w1", org_id="o1")
    # must not raise; returns the workspace through
    out = asyncio.run(require_security_lake_enabled(workspace=ws, session=_FakeSession(org)))
    assert out is ws


def test_gate_403_when_disabled():
    org = SimpleNamespace(id="o1", security_lake_enabled=False)
    ws = SimpleNamespace(id="w1", org_id="o1")
    with pytest.raises(HTTPException) as ei:
        asyncio.run(require_security_lake_enabled(workspace=ws, session=_FakeSession(org)))
    assert ei.value.status_code == 403
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_gate.py -v` → FAIL (import error).

- [ ] **Step 3: Implement the dependency + apply it**

In `routers/security_lake.py`, add imports (mirror what the file already imports for `get_active_workspace`/`get_session`/`Workspace`):

```python
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth.deps import get_session
from ..db.models import Org
```

Add the dependency (above the `router` definition):

```python
async def require_security_lake_enabled(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> Workspace:
    """403 unless the caller's org has the Security Lake enabled."""
    org = await session.get(Org, workspace.org_id)
    if org is None or not bool(getattr(org, "security_lake_enabled", False)):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Security Lake is disabled for this organization",
        )
    return workspace
```

Add it to the router's dependency list (alongside the existing `require_scope("security_lake:read")`):

```python
router = APIRouter(
    prefix="/security-lake",
    tags=["security-lake"],
    dependencies=[
        Depends(require_scope("security_lake:read")),
        Depends(require_security_lake_enabled),
    ],
)
```

(Confirm `get_session` is the correct import path used elsewhere in the file/codebase; if the file already imports a session dep, reuse that name.)

- [ ] **Step 4: Run to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_gate.py -v` → PASS (2 passed). Then `./.venv/bin/python -c "import pencheff_api.main"` → no error.

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/routers/security_lake.py apps/api/tests/test_security_lake_gate.py
git commit -m "feat(security-lake): 403 the query/export endpoints when org has the lake disabled"
```

---

## Task 5: Ingestion gate + retention purge

**Files:** modify `tasks/security_lake_ingest_task.py`, `tasks/celery_app.py`; test `tests/test_security_lake_retention.py`.

- [ ] **Step 1: Write the failing test (purge function against a local catalog)**

```python
# tests/test_security_lake_retention.py
from __future__ import annotations

from types import SimpleNamespace

from pencheff_api.services.security_lake.lake_writer import LakeWriter, build_local_catalog
from pencheff_api.services.security_lake.lake_schema import to_lake_row
from pencheff_api.services.security_lake import map_finding, validate_ocsf, LakeContext
from pencheff_api.services.security_lake.lake_query import query_findings
from pencheff_api.tasks.security_lake_ingest_task import purge_org_lake


def _settings(tmp_path):
    return SimpleNamespace(
        lake_catalog_type="sql", lake_catalog_uri=f"sqlite:///{tmp_path}/cat.db",
        lake_warehouse=f"file://{tmp_path}/wh", lake_namespace="pencheff", lake_table="findings")


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
    for org, cve in [("orgA", "CVE-A1"), ("orgA", "CVE-A2"), ("orgB", "CVE-B1")]:
        r = dict(base); r["cve"] = cve
        ctx = LakeContext(org_id=org, asset_id="a", source="sca",
                          time_ms=1_700_000_000_000, is_new=True)
        e = map_finding("sca", r, ctx); validate_ocsf(e)
        rows.append(to_lake_row(e, org_id=org, source="sca", asset_id="a"))
    w.append_rows(rows)


def test_purge_org_lake_removes_only_that_org(tmp_path):
    _seed(tmp_path)
    s = _settings(tmp_path)
    purge_org_lake(s, org_id="orgA")
    _, ta = query_findings(s, org_id="orgA", limit=50, offset=0)
    _, tb = query_findings(s, org_id="orgB", limit=50, offset=0)
    assert ta == 0   # orgA purged
    assert tb == 1   # orgB intact


def test_purge_org_lake_no_table_is_noop(tmp_path):
    # table never created -> purge must not raise
    purge_org_lake(_settings(tmp_path), org_id="orgX")
```

- [ ] **Step 2: Run to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_retention.py -v` → FAIL (`purge_org_lake` not found).

- [ ] **Step 3: Implement the ingestion gate, the purge helper, and the retention task**

In `tasks/security_lake_ingest_task.py`:

(a) Add imports near the top (the file already imports `select`, `Session`, models, `build_catalog`, settings):

```python
from datetime import datetime, timezone
from pyiceberg.expressions import EqualTo
from ..db.models import Org
from ..services.security_lake.toggle import purge_due
```

(b) **Ingestion gate** — at the start of the `with Session(engine) as db:` block in BOTH `ingest_repo_scan` and `ingest_dast_scan`, right after loading `scan` and before loading findings, add the org check. For `ingest_repo_scan` (after `scan = db.get(RepoScan, repo_scan_id)` / the None check):

```python
        org = db.get(Org, scan.org_id)
        if org is None or not bool(org.security_lake_enabled):
            return {"ok": True, "skipped": "lake disabled"}
```

Do the identical check in `ingest_dast_scan` after `scan = db.get(Scan, scan_id)` / None check.

(c) **Purge helper** (DB-free; takes settings + org_id):

```python
def purge_org_lake(settings: Any, org_id: str) -> int:
    """Delete one org's rows from the lake table. Returns 1 if purged, 0 if no table.
    org_id is a partition column, so the delete prunes to that org's partition."""
    catalog = build_catalog(settings)
    identifier = f"{settings.lake_namespace}.{settings.lake_table}"
    try:
        table = catalog.load_table(identifier)
    except Exception:  # noqa: BLE001 — no table yet => nothing to purge
        return 0
    table.delete(delete_filter=EqualTo("org_id", str(org_id)))
    return 1
```

(d) **Retention task** (DB-bound entrypoint; deploy-verified):

```python
@celery_app.task(name="pencheff_api.tasks.security_lake_ingest_task.purge_disabled_lakes")
def purge_disabled_lakes() -> dict:
    """Daily: purge lake data for orgs disabled past the 7-day grace window."""
    settings = get_settings()
    now = datetime.now(tz=timezone.utc)
    engine = create_engine(settings.sync_database_url, future=True)
    purged: list[str] = []
    with Session(engine) as db:
        candidates = db.execute(
            select(Org).where(Org.security_lake_enabled.is_(False),
                              Org.security_lake_disabled_at.is_not(None))).scalars().all()
        due = [o for o in candidates
               if purge_due(enabled=o.security_lake_enabled,
                            disabled_at=o.security_lake_disabled_at, now=now)]
        for org in due:
            try:
                purge_org_lake(settings, org_id=org.id)
                org.security_lake_disabled_at = None  # purge done; stop re-purging
                purged.append(org.id)
            except Exception:  # noqa: BLE001 — one org's failure must not block others
                log.exception("security-lake purge failed for org %s", org.id)
        db.commit()
    return {"ok": True, "purged": purged}
```

(e) **Enqueue short-circuit (best-effort)** — optional but cheap: the guarded `enqueue_repo_ingest`/`enqueue_dast_ingest` already exist; leave them (the authoritative gate is the task in (b)). No change needed.

In `tasks/celery_app.py`, add to `celery_app.conf.beat_schedule`:

```python
    # Purge lake data for orgs that have been disabled past the 7-day grace.
    "security-lake-retention": {
        "task": "pencheff_api.tasks.security_lake_ingest_task.purge_disabled_lakes",
        "schedule": 24 * 3600.0,  # daily
    },
```

- [ ] **Step 4: Run to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_retention.py -v` → PASS (2 passed). Then `./.venv/bin/python -c "import pencheff_api.tasks.security_lake_ingest_task, pencheff_api.tasks.celery_app"` → no error.

- [ ] **Step 5: Run the full security-lake suite**

Run: `./.venv/bin/python -m pytest tests/ -k security_lake -q` → all pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/tasks/security_lake_ingest_task.py apps/api/pencheff_api/tasks/celery_app.py apps/api/tests/test_security_lake_retention.py
git commit -m "feat(security-lake): ingest gate when disabled + daily 7-day retention purge"
```

---

## Task 6: Frontend — Settings page + toggle

**Files:** modify `apps/web/lib/workspace-context.tsx`, `apps/web/components/nav.tsx`; create `apps/web/app/settings/page.tsx`. (Frontend isn't unit-tested in this repo; verification = `next build` + visual QA after deploy.)

- [ ] **Step 1: Add the field to the Org type**

In `apps/web/lib/workspace-context.tsx`, add to the `Org` type (next to `allow_private_targets?`):

```typescript
  security_lake_enabled?: boolean;
```

- [ ] **Step 2: Add the Settings nav entry**

In `apps/web/components/nav.tsx`, define a `SettingsIcon` mirroring the existing icon components in that file (same SVG wrapper props as `KeyIcon`), using a gear path:

```tsx
const SettingsIcon = () => (
  <svg
    width="16"
    height="16"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden
  >
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
  </svg>
);
```

Add to `SETTINGS_NAV` (after API Keys, before Billing):

```tsx
  { href: "/settings", label: "Settings", icon: <SettingsIcon /> },
```

- [ ] **Step 3: Create the Settings page**

Create `apps/web/app/settings/page.tsx`:

```tsx
"use client";

import { useState } from "react";
import { useWorkspace } from "@/lib/workspace-context";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  const { activeOrg, refresh } = useWorkspace();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showDisableModal, setShowDisableModal] = useState(false);
  const enabled = activeOrg?.security_lake_enabled ?? false;
  const canManage = activeOrg?.role === "owner" || activeOrg?.role === "admin";

  async function setEnabled(next: boolean) {
    if (!activeOrg) return;
    setSaving(true);
    setError(null);
    try {
      await api(`/orgs/${activeOrg.id}`, {
        method: "PATCH",
        json: { security_lake_enabled: next },
      });
      await refresh();
      setShowDisableModal(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to update setting");
    } finally {
      setSaving(false);
    }
  }

  if (!activeOrg) return null;

  return (
    <div className="mx-auto max-w-3xl px-6 py-8">
      <h1 className="text-2xl font-semibold mb-6">Settings</h1>

      <section className="border border-hairline rounded-lg p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-medium">Security Lake</h2>
            <p className="text-sm text-muted mt-1 max-w-xl">
              Normalize every finding (SAST, SCA, secrets, IaC, DAST, runtime)
              into OCSF and store it in your queryable, exportable Security
              Lake. Disabled by default.
              <strong>
                {" "}
                Disabling stops ingestion and queries, and deletes your lake
                data after 7 days.
              </strong>
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            disabled={saving || !canManage}
            onClick={() => {
              enabled ? setShowDisableModal(true) : setEnabled(true);
            }}
            className={cn(
              "relative inline-flex shrink-0 h-5 w-9 rounded-full border transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-ink/20 disabled:opacity-50 disabled:cursor-not-allowed",
              enabled ? "bg-ink border-ink" : "bg-paper border-hairline",
            )}
          >
            <span
              className={cn(
                "inline-block h-3.5 w-3.5 rounded-full bg-paper border border-hairline shadow-subtle transform transition-transform duration-200 mt-[2px]",
                enabled ? "translate-x-4" : "translate-x-[2px]",
              )}
            />
          </button>
        </div>
        {!canManage && (
          <p className="text-xs text-muted mt-3">
            Only org owners/admins can change this.
          </p>
        )}
        {error && <p className="text-xs text-red-600 mt-3">{error}</p>}
      </section>

      {showDisableModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-paper border border-hairline rounded-lg p-6 max-w-md mx-4">
            <h3 className="text-lg font-medium">Disable Security Lake?</h3>
            <p className="text-sm text-muted mt-2">
              New findings will stop ingesting and the Security Lake API will be
              turned off for your org. Your existing lake data will be{" "}
              <strong>permanently deleted 7 days</strong> from now unless you
              re-enable before then.
            </p>
            <div className="flex justify-end gap-3 mt-5">
              <button
                className="px-3 py-1.5 text-sm border border-hairline rounded"
                onClick={() => setShowDisableModal(false)}
                disabled={saving}
              >
                Cancel
              </button>
              <button
                className="px-3 py-1.5 text-sm bg-ink text-paper rounded disabled:opacity-50"
                onClick={() => setEnabled(false)}
                disabled={saving}
              >
                {saving ? "Disabling…" : "Disable"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
```

> Before writing, open `app/org/settings/page.tsx` and copy the EXACT import paths/aliases it uses for `useWorkspace`, `api`, and `cn` (the repo may use `../../lib/...` relative paths rather than `@/lib/...`, and the toggle classes reference design tokens `ink`/`paper`/`hairline`/`muted` — match whatever that file uses). Reuse its toggle markup verbatim so styling is consistent.

- [ ] **Step 4: Verify the build**

Run from `apps/web`: `npx next build` → completes, no type errors, `out/settings/index.html` produced (static export). If a type/import error appears, fix the import aliases to match the sibling settings page.

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/web/lib/workspace-context.tsx apps/web/components/nav.tsx apps/web/app/settings/page.tsx
git commit -m "feat(security-lake): Settings page with enable/disable toggle + disable confirm"
```

---

## Self-review (completed by plan author)

**Spec coverage:** §1 columns → Task 1 ✓. §2 settings API → Tasks 2, 3 ✓. §3 gating (ingest skip + query/export 403) → Tasks 4, 5(b) ✓. §4 retention (purge_due + per-org delete + daily beat) → Tasks 2, 5 ✓ (delete verified against R2). §5 frontend (nav + page + toggle + confirm modal + Org type) → Task 6 ✓. §6 testing → toggle/purge_due/gate/purge unit tests across Tasks 2,4,5 ✓.

**Placeholder scan:** No TBD/TODO. Code is complete per step. The "open the sibling page to match import aliases / OrgOut builders" notes are explicit verification instructions (the FE import paths and the set of `OrgOut(` call sites are codebase facts the implementer confirms), not placeholders.

**Type consistency:** `apply_lake_toggle(org, *, enabled, now) -> bool`, `purge_due(*, enabled, disabled_at, now) -> bool`, `PURGE_GRACE_DAYS=7`, `purge_org_lake(settings, org_id) -> int`, `require_security_lake_enabled(workspace, session) -> Workspace`, column names `security_lake_enabled`/`security_lake_disabled_at`, audit action `org.security_lake_enabled.toggle` — all consistent across tasks and with the spec.

**Deploy-verified (not unit-tested, by design, matching the codebase pattern):** the DB-bound entrypoints (`update_org` wiring, ingest-task org gate, `purge_disabled_lakes` selection query), Alembic `0055` application, and the Next build/visual QA. Their pure cores (toggle transition, purge_due, purge_org_lake, the gate dependency) are unit-tested.
