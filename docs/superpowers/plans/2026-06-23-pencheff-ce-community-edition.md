# Pencheff Community Edition (CE) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce an open-source, no-login, single-user self-hostable build of the full Pencheff platform in a new sibling repo `pencheff-ce/`.

**Architecture:** Keep the multi-tenant data model intact but seed exactly one Org + Workspace + User on boot, and rewrite the ~6 auth dependency functions in `auth/deps.py` so they ignore tokens and always return that seeded principal with all scopes. The 39 routers and their `org_id`/`workspace_id` queries are untouched. SaaS-only routers/pages are deleted; paid integrations become env-gated.

**Tech Stack:** Backend — Python 3.13, FastAPI, SQLAlchemy (async), Alembic, Celery, Postgres (pgvector), Redis, `uv`. Frontend — Next.js (App Router), TypeScript, Tailwind. Infra — Docker Compose.

## Global Constraints

- License: **Apache-2.0** (`LICENSE` at repo root; carry over `THIRD_PARTY_NOTICES.md`).
- No account/login/RBAC/multi-tenant/billing concepts reachable by the user.
- Test convention (mirror existing tests): **pure unit tests — no conftest, no HTTP client, no real DB.** Call handlers/dependencies directly as coroutines with hand-built fakes (`SimpleNamespace`, small fake session classes). Run tests with `cd apps/api && uv run pytest`.
- Surgical changes: every deletion/edit must trace to this plan (per repo `CLAUDE.md`).
- Vestigial tenant columns are intentionally kept; do NOT drop them or rewrite router queries.
- AI features must degrade gracefully when `LLM_API_KEY` is unset — never crash, never call a paid default endpoint.
- All work happens inside `pencheff-ce/` (the new repo). `pencheff/` (upstream) is read-only reference.

---

## Phase 1 — Repo bootstrap + single-tenant shim

Outcome: `pencheff-ce/` exists; the API boots as one implicit user with no token required.

### Task 1: Create the `pencheff-ce` repo from a stripped copy

**Files:**

- Create: `../pencheff-ce/` (sibling of `pencheff/`)

- [ ] **Step 1: Copy the tree excluding build/secret artifacts**

Run from inside `pencheff/`:

```bash
cd /Users/balasriharsha/BalaSriharsha/Magadha
rsync -a --delete \
  --exclude '.git' --exclude 'node_modules' --exclude '.venv' \
  --exclude '.next' --exclude 'out' --exclude '.wrangler' \
  --exclude '__pycache__' --exclude '.pytest_cache' --exclude '.serena' \
  --exclude '.gstack' --exclude '.sdd' \
  --exclude '.env' --exclude '.env.local' \
  --exclude 'pencheff-studio' --exclude 'pencheff-studio-windows' \
  pencheff/ pencheff-ce/
```

- [ ] **Step 2: Initialise a fresh git repo**

```bash
cd /Users/balasriharsha/BalaSriharsha/Magadha/pencheff-ce
git init
git add -A
git commit -m "chore: seed pencheff-ce from upstream snapshot"
```

Expected: a single initial commit; `git log --oneline` shows one entry.

- [ ] **Step 3: Verify the copy boots the backend deps**

```bash
cd /Users/balasriharsha/BalaSriharsha/Magadha/pencheff-ce/apps/api
uv sync
uv run python -c "import pencheff_api.main"
```

Expected: imports succeed (no `ModuleNotFoundError`). If it fails because of a missing `.env`, copy `apps/api/.env.example` to `apps/api/.env` first.

> All remaining tasks run inside `pencheff-ce/`.

### Task 2: Single-tenant seed module

**Files:**

- Create: `apps/api/pencheff_api/auth/single_tenant.py`
- Test: `apps/api/tests/test_single_tenant.py`

**Interfaces:**

- Consumes: `db.models.{Org, Workspace, User, OrgMember}`, `sqlalchemy.select`.
- Produces:
  - `DEFAULT_USER_EMAIL = "owner@pencheff.local"`, `DEFAULT_USER_NAME = "Owner"`, `DEFAULT_ORG_NAME = "Pencheff"`, `DEFAULT_WORKSPACE_NAME = "Default"`, `DEFAULT_WORKSPACE_SLUG = "default"` (module constants).
  - `_seed_ids: dict[str, str]` (module global; keys `"org_id"`, `"user_id"`, `"workspace_id"`).
  - `async def ensure_single_tenant(session) -> dict[str, str]` — idempotently creates the org/user/owner-membership/workspace if absent, populates and returns `_seed_ids`.
  - `async def seed_ids(session) -> dict[str, str]` — returns `_seed_ids`, lazily calling `ensure_single_tenant` if empty.

- [ ] **Step 1: Write the failing test**

```python
# apps/api/tests/test_single_tenant.py
"""Unit tests for the single-tenant seed shim.

Convention: no real DB. A FakeSession returns canned 'existing row' lookups
in order and records add()/commit() calls.
"""
from __future__ import annotations

import asyncio

import pencheff_api.auth.single_tenant as st
from pencheff_api.db.models import Org, OrgMember, User, Workspace


class _Result:
    def __init__(self, value):
        self._value = value

    def scalars(self):
        return self

    def first(self):
        return self._value


class FakeSession:
    """Returns queued scalar results for execute() in order; records adds."""

    def __init__(self, canned):
        self._canned = list(canned)
        self.added: list = []
        self.commits = 0

    async def execute(self, _stmt):
        return _Result(self._canned.pop(0) if self._canned else None)

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        self.commits += 1

    async def refresh(self, _row):
        pass


def teardown_function():
    st._seed_ids.clear()


def test_creates_all_rows_when_empty():
    # No existing org, user, workspace.
    session = FakeSession([None, None, None])
    ids = asyncio.run(st.ensure_single_tenant(session))
    kinds = {type(r) for r in session.added}
    assert {Org, User, OrgMember, Workspace} <= kinds
    assert set(ids) == {"org_id", "user_id", "workspace_id"}
    assert all(ids.values())


def test_idempotent_when_rows_exist():
    org = Org(id="org-1", name=st.DEFAULT_ORG_NAME, plan="self_hosted")
    user = User(id="user-1", email=st.DEFAULT_USER_EMAIL, name=st.DEFAULT_USER_NAME)
    ws = Workspace(id="ws-1", org_id="org-1", name=st.DEFAULT_WORKSPACE_NAME, slug=st.DEFAULT_WORKSPACE_SLUG)
    session = FakeSession([org, user, ws])
    ids = asyncio.run(st.ensure_single_tenant(session))
    assert session.added == []  # nothing created
    assert ids == {"org_id": "org-1", "user_id": "user-1", "workspace_id": "ws-1"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_single_tenant.py -v`
Expected: FAIL — `ModuleNotFoundError`/`AttributeError` (no `ensure_single_tenant`).

- [ ] **Step 3: Write minimal implementation**

```python
# apps/api/pencheff_api/auth/single_tenant.py
"""Seed and resolve the one implicit tenant for the community edition.

The CE has no login. Exactly one Org + Workspace + User exist; every request
resolves to them. This module owns creating those rows (idempotently) and
caching their IDs for the auth dependencies in ``auth/deps.py``.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Org, OrgMember, User, Workspace

DEFAULT_ORG_NAME = "Pencheff"
DEFAULT_WORKSPACE_NAME = "Default"
DEFAULT_WORKSPACE_SLUG = "default"
DEFAULT_USER_EMAIL = "owner@pencheff.local"
DEFAULT_USER_NAME = "Owner"

_seed_ids: dict[str, str] = {}


async def _first(session: AsyncSession, stmt):
    return (await session.execute(stmt)).scalars().first()


async def ensure_single_tenant(session: AsyncSession) -> dict[str, str]:
    """Idempotently ensure the single tenant exists; cache and return its IDs."""
    org = await _first(session, select(Org).limit(1))
    if org is None:
        org = Org(name=DEFAULT_ORG_NAME, plan="self_hosted")
        session.add(org)
        await session.commit()
        await session.refresh(org)

    user = await _first(
        session, select(User).where(User.email == DEFAULT_USER_EMAIL).limit(1)
    )
    if user is None:
        user = User(
            email=DEFAULT_USER_EMAIL, name=DEFAULT_USER_NAME, org_id=org.id, is_active=True
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        session.add(OrgMember(org_id=org.id, user_id=user.id, role="owner"))
        await session.commit()

    ws = await _first(
        session, select(Workspace).where(Workspace.org_id == org.id).limit(1)
    )
    if ws is None:
        ws = Workspace(
            org_id=org.id,
            name=DEFAULT_WORKSPACE_NAME,
            slug=DEFAULT_WORKSPACE_SLUG,
            created_by_user_id=user.id,
        )
        session.add(ws)
        await session.commit()
        await session.refresh(ws)

    _seed_ids.update(org_id=org.id, user_id=user.id, workspace_id=ws.id)
    return _seed_ids


async def seed_ids(session: AsyncSession) -> dict[str, str]:
    """Return cached seed IDs, seeding on first use."""
    if not _seed_ids:
        await ensure_single_tenant(session)
    return _seed_ids
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_single_tenant.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/auth/single_tenant.py apps/api/tests/test_single_tenant.py
git commit -m "feat(auth): single-tenant seed shim for community edition"
```

### Task 3: Rewrite `auth/deps.py` to bypass tokens

**Files:**

- Modify: `apps/api/pencheff_api/auth/deps.py` (replace the dependency bodies; keep signatures)
- Test: `apps/api/tests/test_single_tenant_deps.py`

**Interfaces:**

- Consumes: `single_tenant.seed_ids`, `db.base.get_session`.
- Produces (signatures unchanged so the 39 routers keep importing them):
  - `async def get_current_user(request, session=Depends(get_session)) -> User`
  - `async def get_active_workspace(request, user=Depends(get_current_user), session=Depends(get_session)) -> Workspace`
  - `async def get_membership(session, user_id, org_id) -> OrgMember` (synthesizes an owner row)
  - `def require_role(*allowed)` / `def require_org_role(*allowed)` → factories returning permissive deps
  - `def require_scope(scope)` → factory returning a permissive dep
  - `async def session_only(request, user=Depends(get_current_user)) -> User` → never raises

- [ ] **Step 1: Write the failing test**

```python
# apps/api/tests/test_single_tenant_deps.py
"""The CE auth deps must resolve a principal with NO Authorization header."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pencheff_api.auth.deps as deps
import pencheff_api.auth.single_tenant as st
from pencheff_api.db.models import OrgMember, User, Workspace


class FakeSession:
    def __init__(self, objs):
        self._objs = objs  # {(Model, id): instance}

    async def get(self, model, pk):
        return self._objs.get((model, pk))


def _request_without_auth():
    # No 'authorization' header, no token query param.
    return SimpleNamespace(headers={}, query_params={}, state=SimpleNamespace())


def setup_function():
    st._seed_ids.update(org_id="org-1", user_id="user-1", workspace_id="ws-1")


def teardown_function():
    st._seed_ids.clear()


def test_get_current_user_needs_no_token():
    user = User(id="user-1", email=st.DEFAULT_USER_EMAIL)
    session = FakeSession({(User, "user-1"): user})
    out = asyncio.run(deps.get_current_user(_request_without_auth(), session))
    assert out.id == "user-1"


def test_get_active_workspace_ignores_header():
    ws = Workspace(id="ws-1", org_id="org-1", name="Default", slug="default")
    user = User(id="user-1", email=st.DEFAULT_USER_EMAIL)
    session = FakeSession({(Workspace, "ws-1"): ws, (User, "user-1"): user})
    out = asyncio.run(deps.get_active_workspace(_request_without_auth(), user, session))
    assert out.id == "ws-1"


def test_require_scope_always_allows():
    user = User(id="user-1", email=st.DEFAULT_USER_EMAIL)
    dep = deps.require_scope("scans:write")
    out = asyncio.run(dep(_request_without_auth(), user))
    assert out is user


def test_session_only_never_rejects():
    user = User(id="user-1", email=st.DEFAULT_USER_EMAIL)
    out = asyncio.run(deps.session_only(_request_without_auth(), user))
    assert out is user
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_single_tenant_deps.py -v`
Expected: FAIL — `get_current_user` raises `HTTPException(401, "missing bearer token")`.

- [ ] **Step 3: Replace the dependency bodies**

Replace the bodies of the public functions in `apps/api/pencheff_api/auth/deps.py` (keep their signatures). Delete the now-unused Clerk/native-token helpers (`_provision_user_from_clerk`, `_sync_plan_for_user`, `_user_from_token`, `_user_from_native_token`, `_plan_from_claims`, `_extract_token`, `_resolve_active_workspace`) and their imports (`clerk`, `jwt`, `decode_native_token`, `api_key`, `scopes`). New bodies:

```python
from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.base import get_session
from ..db.models import OrgMember, User, Workspace
from .single_tenant import seed_ids

ONBOARDING_REQUIRED = "ONBOARDING_REQUIRED"  # kept for import compatibility


async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> User:
    request.state.auth_kind = "session"
    ids = await seed_ids(session)
    return await session.get(User, ids["user_id"])


async def get_active_workspace(
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Workspace:
    ids = await seed_ids(session)
    return await session.get(Workspace, ids["workspace_id"])


async def get_membership(session: AsyncSession, user_id: str, org_id: str) -> OrgMember:
    return OrgMember(org_id=org_id, user_id=user_id, role="owner")


def require_role(*allowed: str):
    async def _dep(
        user: User = Depends(get_current_user),
        workspace: Workspace = Depends(get_active_workspace),
    ) -> tuple[User, Workspace]:
        return user, workspace

    return _dep


def require_org_role(*allowed: str):
    async def _dep(
        org_id: str,
        user: User = Depends(get_current_user),
    ) -> tuple[User, OrgMember]:
        return user, OrgMember(org_id=org_id, user_id=user.id, role="owner")

    return _dep


def require_scope(scope: str):
    async def _dep(
        request: Request,
        user: User = Depends(get_current_user),
    ) -> User:
        return user

    return _dep


async def session_only(
    request: Request,
    user: User = Depends(get_current_user),
) -> User:
    return user
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd apps/api && uv run pytest tests/test_single_tenant_deps.py tests/test_single_tenant.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Verify nothing imports a deleted symbol**

Run: `cd apps/api && uv run python -c "import pencheff_api.main"`
Expected: imports succeed. If an `ImportError` names a deleted helper, that importing module is in the Phase 2 strip list — fix in Phase 2; for now only `auth/deps.py` consumers matter.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/auth/deps.py apps/api/tests/test_single_tenant_deps.py
git commit -m "feat(auth): bypass tokens, resolve seeded tenant in deps"
```

### Task 4: Seed on API startup

**Files:**

- Modify: `apps/api/pencheff_api/main.py` (add a startup hook near the existing `@app.on_event("startup")` block, ~line 169)

**Interfaces:**

- Consumes: `db.base.SessionLocal`, `single_tenant.ensure_single_tenant`.

- [ ] **Step 1: Add the startup hook**

Add after the existing `_production_safety_check` startup hook in `main.py`:

```python
@app.on_event("startup")
async def _seed_single_tenant() -> None:
    from .auth.single_tenant import ensure_single_tenant
    from .db.base import SessionLocal

    async with SessionLocal() as session:
        await ensure_single_tenant(session)
    log.info("single-tenant seed ensured")
```

- [ ] **Step 2: Verify it boots against a live DB**

```bash
cd /Users/balasriharsha/BalaSriharsha/Magadha/pencheff-ce
docker compose up -d postgres redis
cd apps/api && uv run alembic upgrade head
uv run uvicorn pencheff_api.main:app --port 8000 &
sleep 5
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/targets
```

Expected: `200` (not `401`). Stop the server (`kill %1`) afterwards.

- [ ] **Step 3: Commit**

```bash
git add apps/api/pencheff_api/main.py
git commit -m "feat(api): seed single tenant on startup"
```

---

## Phase 2 — Strip SaaS routers (backend)

Outcome: SaaS-only routers and their wiring are gone; the API imports and boots clean.

### Task 5: Remove SaaS router registrations and modules

**Files:**

- Modify: `apps/api/pencheff_api/main.py` (the `from .routers import (...)` block ~line 19 and the `app.include_router(...)` calls ~lines 239–288)
- Delete: `apps/api/pencheff_api/routers/{auth,orgs,billing,branding,api_keys,engagements,security_lake}.py`
- Delete: `apps/api/pencheff_api/auth/{clerk,oauth_google,jwt,password,api_key,scopes}.py`
- Delete corresponding tests under `apps/api/tests/` (see Step 3)

- [ ] **Step 1: Remove `include_router` lines and imports**

In `main.py`, delete these registrations: `auth.router`, `orgs.router`, `orgs.invite_router`, `billing.router`, `branding.router`, `api_keys.router`, `engagements.router`, `engagements.handshake_router`, `security_lake.router`. Remove the matching names from the `from .routers import (...)` block. (Leave `workspaces.router` — it is stubbed in Task 6, not removed.)

- [ ] **Step 2: Delete the stripped router + auth modules**

```bash
cd /Users/balasriharsha/BalaSriharsha/Magadha/pencheff-ce/apps/api/pencheff_api
git rm routers/auth.py routers/orgs.py routers/billing.py routers/branding.py \
       routers/api_keys.py routers/engagements.py routers/security_lake.py
git rm auth/clerk.py auth/oauth_google.py auth/jwt.py auth/password.py \
       auth/api_key.py auth/scopes.py
```

- [ ] **Step 3: Delete tests for stripped modules**

```bash
cd /Users/balasriharsha/BalaSriharsha/Magadha/pencheff-ce/apps/api
git rm -f tests/test_api_keys.py tests/test_api_key_auth_flow.py \
          tests/test_desktop_oauth_flow.py tests/test_security_lake_router.py \
          tests/test_orgs_allow_private_targets.py tests/test_orgs_security_lake_toggle.py 2>/dev/null || true
```

(If any filename does not exist, ignore — the `|| true` keeps the step green. List is derived from the stripped modules.)

- [ ] **Step 4: Find and fix dangling imports of stripped modules**

```bash
cd /Users/balasriharsha/BalaSriharsha/Magadha/pencheff-ce/apps/api
grep -rnE "routers\.(auth|orgs|billing|branding|api_keys|engagements|security_lake)|auth\.(clerk|oauth_google|jwt|password|api_key|scopes)" pencheff_api || echo "NO DANGLING IMPORTS"
```

Expected: `NO DANGLING IMPORTS`. For each hit, remove the import and the (now-unreachable) code that used it. Note: `services/` modules referencing `engagements`/`security_lake` data are gated/removed in Task 7 — record any such hits for that task rather than deleting service logic here.

- [ ] **Step 5: Verify import + targeted boot**

Run: `cd apps/api && uv run python -c "import pencheff_api.main"`
Expected: imports succeed (no `ImportError`).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: strip SaaS routers (auth, orgs, billing, branding, api_keys, engagements, security_lake)"
```

### Task 6: Stub the `workspaces` router to the single workspace

**Files:**

- Modify: `apps/api/pencheff_api/routers/workspaces.py`
- Test: `apps/api/tests/test_workspaces_stub.py`

**Interfaces:**

- The frontend `workspace-context` calls the list endpoint and expects an array containing the one workspace. Keep the existing route path and response schema; the handler returns only the seeded workspace.

- [ ] **Step 1: Inspect the current list handler**

```bash
cd /Users/balasriharsha/BalaSriharsha/Magadha/pencheff-ce/apps/api
grep -nE "@router|def |response_model" pencheff_api/routers/workspaces.py
```

Note the list route's path, function name, and response model.

- [ ] **Step 2: Write the failing test**

```python
# apps/api/tests/test_workspaces_stub.py
"""The CE workspaces list returns exactly the one seeded workspace."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pencheff_api.auth.single_tenant as st
from pencheff_api.db.models import Workspace
from pencheff_api.routers import workspaces as ws_router


class FakeSession:
    def __init__(self, ws):
        self._ws = ws

    async def get(self, model, pk):
        return self._ws if pk == self._ws.id else None


def setup_function():
    st._seed_ids.update(org_id="org-1", user_id="user-1", workspace_id="ws-1")


def teardown_function():
    st._seed_ids.clear()


def test_list_returns_single_workspace():
    ws = Workspace(id="ws-1", org_id="org-1", name="Default", slug="default")
    user = SimpleNamespace(id="user-1")
    result = asyncio.run(ws_router.list_workspaces(user=user, session=FakeSession(ws)))
    items = result if isinstance(result, list) else result.items
    assert len(items) == 1
    assert items[0].id == "ws-1"
```

(Adjust `list_workspaces` and the result-unwrap line to match the names found in Step 1.)

- [ ] **Step 3: Run test to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_workspaces_stub.py -v`
Expected: FAIL (current handler queries by membership / returns differently).

- [ ] **Step 4: Replace the list handler body**

Rewrite the list handler to return only the seeded workspace:

```python
from ..auth.single_tenant import seed_ids

# inside the list handler (keep its decorator, name, and response_model):
async def list_workspaces(user=Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    ids = await seed_ids(session)
    ws = await session.get(Workspace, ids["workspace_id"])
    return [ws]
```

Remove any other workspace-mutation routes (create/delete/switch) in this file — the CE has one fixed workspace.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_workspaces_stub.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/routers/workspaces.py apps/api/tests/test_workspaces_stub.py
git commit -m "feat: stub workspaces router to the single seeded workspace"
```

### Task 7: Env-gate paid integrations + observability ingest

**Files:**

- Modify: `apps/api/pencheff_api/main.py` (conditional `include_router`)
- Modify: `apps/api/pencheff_api/config.py` (add gate flags)

**Interfaces:**

- Produces config flags (default `False`): `integrations_enabled` (alias `INTEGRATIONS_ENABLED`), `observability_ingest_enabled` (alias `OBSERVABILITY_INGEST_ENABLED`).

- [ ] **Step 1: Add gate flags to `Settings`**

In `config.py`, inside the `Settings` class:

```python
integrations_enabled: bool = Field(False, alias="INTEGRATIONS_ENABLED")
observability_ingest_enabled: bool = Field(False, alias="OBSERVABILITY_INGEST_ENABLED")
```

- [ ] **Step 2: Wrap the optional router registrations**

In `main.py`, replace the unconditional includes for `integrations.router`, `github_webhooks.router`, `otlp_ingest.router`, and `observability_router.router` with:

```python
if settings.integrations_enabled:
    app.include_router(integrations.router)
    app.include_router(github_webhooks.router)
if settings.observability_ingest_enabled:
    app.include_router(otlp_ingest.router)
    app.include_router(observability_router.router)
```

- [ ] **Step 3: Verify default boot omits the gated routes**

```bash
cd apps/api && uv run python - <<'PY'
from pencheff_api.main import app
paths = {r.path for r in app.routes}
assert not any(p.startswith("/integrations") for p in paths), "integrations leaked"
print("gated routers off by default OK")
PY
```

Expected: `gated routers off by default OK`.

- [ ] **Step 4: Commit**

```bash
git add apps/api/pencheff_api/main.py apps/api/pencheff_api/config.py
git commit -m "feat: env-gate paid integrations and observability ingest (off by default)"
```

### Task 8: Prune SaaS settings from `config.py`

**Files:**

- Modify: `apps/api/pencheff_api/config.py`

- [ ] **Step 1: Remove Clerk/Stripe/Google-OAuth settings**

Delete these fields from `Settings`: `clerk_publishable_key`, `clerk_secret_key`, `clerk_jwks_url`, `stripe_secret_key`, `stripe_webhook_secret`, `stripe_price_pro`, `stripe_price_team`, `google_client_id`, `google_client_secret`, `google_redirect_uri`. Leave `jwt_secret`/`jwt_algorithm` (other code may import them) and `fernet_key` (credential encryption — Phase 4 auto-generates it).

- [ ] **Step 2: Verify nothing references the removed settings**

```bash
cd apps/api && grep -rnE "settings\.(clerk|stripe|google)_" pencheff_api || echo "NO REFS"
```

Expected: `NO REFS`. Fix any straggler hits.

- [ ] **Step 3: Verify import**

Run: `cd apps/api && uv run python -c "import pencheff_api.main"`
Expected: success.

- [ ] **Step 4: Run the full backend suite (expect green minus deletions)**

Run: `cd apps/api && uv run pytest -q -m "not live"`
Expected: the suite collects and passes; failures, if any, must be in tests tied to stripped modules — delete those tests (record them) and re-run until green.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/config.py
git commit -m "chore(config): remove Clerk/Stripe/Google OAuth settings"
```

---

## Phase 3 — De-auth the frontend + cull pages

Outcome: the web app loads with no Clerk, no login, landing on the dashboard.

### Task 9: Replace the Clerk provider with a pass-through

**Files:**

- Modify: `apps/web/components/clerk-provider.tsx`
- Modify: `apps/web/package.json` (remove `@clerk/*` deps)

- [ ] **Step 1: Make the provider a no-op wrapper**

Replace the contents of `components/clerk-provider.tsx` with:

```tsx
"use client";
import type { ReactNode } from "react";

export function AppClerkProvider({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
```

- [ ] **Step 2: Remove Clerk dependencies**

```bash
cd /Users/balasriharsha/BalaSriharsha/Magadha/pencheff-ce/apps/web
npm pkg delete dependencies.@clerk/nextjs dependencies.@clerk/react dependencies.@clerk/shared 2>/dev/null || true
grep -nE "@clerk" package.json || echo "NO CLERK DEPS"
```

Expected: `NO CLERK DEPS` (delete any remaining `@clerk/*` lines by hand if listed).

- [ ] **Step 3: Find remaining Clerk imports**

```bash
cd apps/web && grep -rlnE "@clerk/|ClerkProvider|useAuth|useUser|SignIn|SignedIn|SignedOut" app components lib | grep -v node_modules || echo "NONE"
```

Record the hits — they are fixed in Tasks 10–11 (api client, workspace context) and Task 12 (page deletions).

- [ ] **Step 4: Commit**

```bash
git add apps/web/components/clerk-provider.tsx apps/web/package.json
git commit -m "feat(web): replace Clerk provider with pass-through"
```

### Task 10: Strip token logic from the API client

**Files:**

- Modify: `apps/web/lib/api.ts`

- [ ] **Step 1: Remove the bearer-token plumbing**

In `lib/api.ts`: delete the `getToken` type/param and every call that fetches a Clerk session token (`clerk.session?.getToken?.()`); stop setting the `Authorization` header. Keep the `X-Workspace-Id` header logic (harmless) and the base-URL constants. The fetch should send no `Authorization` header.

- [ ] **Step 2: Verify no Clerk references remain in the client**

```bash
cd apps/web && grep -nE "getToken|Authorization|@clerk|clerk\." lib/api.ts || echo "CLEAN"
```

Expected: `CLEAN` (or only the `X-Workspace-Id` lines, no auth).

- [ ] **Step 3: Commit**

```bash
git add apps/web/lib/api.ts
git commit -m "feat(web): drop bearer-token auth from API client"
```

### Task 11: Make the workspace context auth-free

**Files:**

- Modify: `apps/web/lib/workspace-context.tsx`

- [ ] **Step 1: Remove `useAuth` and treat the user as signed in**

In `workspace-context.tsx`: delete `import { useAuth } from "@clerk/react"` and the `isSignedIn`/`isLoaded` gating; always fetch the workspace list from the stub endpoint on mount and select the single returned workspace.

- [ ] **Step 2: Verify**

```bash
cd apps/web && grep -nE "@clerk|useAuth|isSignedIn" lib/workspace-context.tsx || echo "CLEAN"
```

Expected: `CLEAN`.

- [ ] **Step 3: Commit**

```bash
git add apps/web/lib/workspace-context.tsx
git commit -m "feat(web): make workspace context auth-free"
```

### Task 12: Delete SaaS/marketing pages and add a dashboard redirect

**Files:**

- Delete: `apps/web/app/{login,signup,onboarding,billing,org,invite,oauth,enquiries,company,solutions,support,terms,privacy,methodology,process,resources}/`
- Modify/Replace: `apps/web/app/page.tsx` (marketing landing → redirect to `/dashboard`)
- Delete: `apps/web/app/page.tsx.bak`

- [ ] **Step 1: Delete SaaS + marketing route folders**

```bash
cd /Users/balasriharsha/BalaSriharsha/Magadha/pencheff-ce/apps/web/app
git rm -r login signup onboarding billing org invite oauth \
        enquiries company solutions support terms privacy methodology process resources
git rm -f page.tsx.bak
```

(If a folder does not exist, drop it from the command.)

- [ ] **Step 2: Replace the landing page with a redirect**

Replace `apps/web/app/page.tsx` with:

```tsx
import { redirect } from "next/navigation";

export default function Home() {
  redirect("/dashboard");
}
```

- [ ] **Step 3: Find dangling links/imports to deleted pages**

```bash
cd apps/web && grep -rlnE "/(login|signup|onboarding|billing|invite|oauth|enquiries|company|solutions|support|methodology|process|resources)\b" app components lib | grep -v node_modules || echo "NONE"
```

Record hits (likely nav/footer components) and remove those links. Keep `/terms` and `/privacy` references only if a footer needs them — otherwise remove the links too.

- [ ] **Step 4: Verify the build compiles**

```bash
cd apps/web && npm install && npm run build
```

Expected: build succeeds. Fix any `Module not found` from deleted Clerk imports or removed pages until green.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(web): remove SaaS/marketing pages, redirect root to dashboard"
```

---

## Phase 4 — Infra: one-command up

Outcome: `docker compose up` brings up a working single-user app.

### Task 13: Trim `docker-compose.yml`

**Files:**

- Modify: `docker-compose.yml`

- [ ] **Step 1: Remove the `docs` and `blog` services**

Delete the `docs:` and `blog:` service blocks (and any `depends_on`/volume references to them). Keep `postgres`, `redis`, `api`, `worker`, `web`.

- [ ] **Step 2: Validate the compose file**

```bash
cd /Users/balasriharsha/BalaSriharsha/Magadha/pencheff-ce
docker compose config >/dev/null && echo "COMPOSE VALID"
```

Expected: `COMPOSE VALID`.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "chore(infra): trim compose to postgres/redis/api/worker/web"
```

### Task 14: Rewrite `.env.example` and auto-generate `fernet_key`

**Files:**

- Modify: `.env.example` (root) and `apps/api/.env.example`
- Modify: `apps/api/pencheff_api/config.py` (auto-generate `fernet_key` when unset)
- Modify: `apps/web/.env.local.example`

- [ ] **Step 1: Strip SaaS keys from env examples**

In all three example files, remove `CLERK_*`, `STRIPE_*`, `GOOGLE_*`, and `NEXT_PUBLIC_CLERK_*` entries. Keep `DATABASE_URL`, `REDIS_URL`, optional `LLM_API_KEY`/`LLM_BASE_URL`/`LLM_MODEL`, and `NEXT_PUBLIC_API_URL`. Add the Phase 2 gate flags (`INTEGRATIONS_ENABLED=false`, `OBSERVABILITY_INGEST_ENABLED=false`) commented out.

- [ ] **Step 2: Auto-generate `fernet_key` on first boot when blank**

In `config.py`, after the `Settings` instance is created, add:

```python
if not settings.fernet_key:
    from cryptography.fernet import Fernet
    settings.fernet_key = Fernet.generate_key().decode()
```

(Place this where `settings` is instantiated/exported. A regenerated key per boot only invalidates previously stored encrypted credentials, which is acceptable for a fresh self-host; persisting it is the user's option via `.env`.)

- [ ] **Step 3: Verify boot with no secrets set**

```bash
cd apps/api && env -u FERNET_KEY uv run python -c "from pencheff_api.config import settings; assert settings.fernet_key; print('fernet auto-generated OK')"
```

Expected: `fernet auto-generated OK`.

- [ ] **Step 4: Commit**

```bash
git add .env.example apps/api/.env.example apps/web/.env.local.example apps/api/pencheff_api/config.py
git commit -m "chore(infra): OSS env examples + auto-generate fernet key"
```

---

## Phase 5 — AI graceful degradation, end-to-end smoke, docs

### Task 15: Guard AI features when `LLM_API_KEY` is unset

**Files:**

- Modify: `apps/api/pencheff_api/config.py` (remove paid default endpoints)
- Test: `apps/api/tests/test_ai_disabled_without_key.py`

**Interfaces:**

- Produces: `settings.ai_available -> bool` property (`bool(settings.llm_api_key)`).

- [ ] **Step 1: Write the failing test**

```python
# apps/api/tests/test_ai_disabled_without_key.py
from pencheff_api.config import Settings


def test_ai_unavailable_without_key():
    s = Settings(llm_api_key="")
    assert s.ai_available is False


def test_ai_available_with_key():
    s = Settings(llm_api_key="sk-test")
    assert s.ai_available is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && uv run pytest tests/test_ai_disabled_without_key.py -v`
Expected: FAIL — `AttributeError: ai_available`.

- [ ] **Step 3: Add the property and blank paid defaults**

In `config.py`, blank the paid default endpoints/keys (`llm_base_url`, `llm_model`, `agentic_fix_base_url`, `fix_llm_base_url`, `agent_llm_base_url`, etc. default to `""`) and add:

```python
@property
def ai_available(self) -> bool:
    return bool(self.llm_api_key)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && uv run pytest tests/test_ai_disabled_without_key.py -v`
Expected: PASS.

- [ ] **Step 5: Surface availability to the web app**

Confirm the dashboard/AI panels read an availability flag (e.g. via an existing capabilities/config endpoint). If one exists, have it return `ai_available`; the frontend already conditionally renders AI panels — point them at this flag. If no such endpoint exists, add `GET /capabilities/ai` returning `{"available": settings.ai_available}` and render a "configure an LLM key to enable" state when false. Verify scans still create with AI off:

```bash
cd apps/api && uv run python - <<'PY'
from pencheff_api.config import Settings
print("ai_available:", Settings(llm_api_key="").ai_available)
PY
```

Expected: `ai_available: False` and no exception.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/config.py apps/api/tests/test_ai_disabled_without_key.py
git commit -m "feat: AI features gated on LLM_API_KEY, no paid defaults"
```

### Task 16: End-to-end smoke script

**Files:**

- Create: `scripts/smoke.sh`

- [ ] **Step 1: Write the smoke script**

```bash
#!/usr/bin/env bash
# scripts/smoke.sh — verify the CE boots with no auth and serves the app.
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose up -d --build
echo "waiting for API health..."
for i in $(seq 1 60); do
  if curl -sf http://localhost:8000/targets >/dev/null; then break; fi
  sleep 3
done

code_targets=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/targets)
code_dash=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/dashboard)

echo "GET /targets (no token) -> $code_targets"
echo "GET /dashboard         -> $code_dash"
[ "$code_targets" = "200" ] || { echo "FAIL: targets not 200"; exit 1; }
[ "$code_dash" = "200" ] || { echo "FAIL: dashboard not 200"; exit 1; }
echo "SMOKE OK"
```

- [ ] **Step 2: Make it executable and run it**

```bash
chmod +x scripts/smoke.sh
./scripts/smoke.sh
```

Expected: ends with `SMOKE OK`. (Requires Docker running; this is the end-to-end gate that also validates the Task 4 seed and Task 3 token bypass against a real DB.)

- [ ] **Step 3: Commit**

```bash
git add scripts/smoke.sh
git commit -m "test: end-to-end no-auth smoke script"
```

### Task 17: License, README, NOTICE

**Files:**

- Modify: `LICENSE` (Apache-2.0 full text)
- Modify: `README.md` (community-edition README)
- Modify: `NOTICE`

- [ ] **Step 1: Set the license to Apache-2.0**

Replace `LICENSE` with the full Apache License 2.0 text (https://www.apache.org/licenses/LICENSE-2.0.txt) and a copyright line. Keep `THIRD_PARTY_NOTICES.md` as-is.

- [ ] **Step 2: Rewrite `README.md` for the CE**

Replace the enterprise README with a concise CE README: what it is (open-source, single-user security scanning platform), quickstart (`cp .env.example .env`, `docker compose up`, open `http://localhost:3000`), the optional `LLM_API_KEY` note, the env gate flags for integrations/observability, and an explicit "no auth / single tenant" statement. Remove enterprise/SaaS/marketing sections.

- [ ] **Step 3: Update `NOTICE`**

Trim `NOTICE` to the CE name and Apache-2.0 attribution; remove enterprise-only product/trademark claims that no longer apply.

- [ ] **Step 4: Commit**

```bash
git add LICENSE README.md NOTICE
git commit -m "docs: Apache-2.0 license + community-edition README/NOTICE"
```

---

## Self-Review

**Spec coverage:**

- §2 single-tenant shim → Tasks 2–4. §3 new repo/license → Tasks 1, 17. §4.1 seed + deps rewrite + dead-code delete → Tasks 2, 3, 4, 5, 8. §4.2 keep/strip/stub/gate → Tasks 5, 6, 7. §5 frontend de-auth + page cull → Tasks 9–12. §6 infra → Tasks 13, 14. §7 AI graceful degradation → Task 15. §8 testing (shim test, smoke) → Tasks 2, 3, 16. §9 phasing → mirrored by Phases 1–5. §10 non-goals → respected (no query rewrites, columns kept).
- Gap check: `engagements`/`api_keys` confirmed in the strip list (Task 5) per the approved spec.

**Placeholder scan:** No "TBD/TODO/implement later". The two adapt-to-local-names notes (Task 6 handler name, Task 15 capabilities endpoint) include the exact discovery command and fallback code, so they are actionable, not placeholders.

**Type consistency:** `ensure_single_tenant`/`seed_ids`/`_seed_ids` names and the `{"org_id","user_id","workspace_id"}` key set are used identically across Tasks 2, 3, 4, 6. Dependency signatures in Task 3 match the originals in `deps.py` so the 39 routers keep importing them unchanged.
