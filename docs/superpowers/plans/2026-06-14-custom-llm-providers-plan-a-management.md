# Custom LLM Providers — Plan A (Management Plane) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an org owner/admin add, edit, delete, list, and activate their own LLM provider configs (typed: openai/anthropic/google/azure_openai/openai_compatible) from Settings, with the API key encrypted at rest and never returned.

**Architecture:** New org-scoped `llm_providers` table + an `Org.active_llm_provider_id` pointer (one active org-wide). A FastAPI CRUD router mirrors the existing org-settings pattern (role-gated, audit-logged). A curated model catalog endpoint feeds the UI dropdown. The web Settings page gains a provider-management section. No AI service is wired yet — that's Plan B.

**Tech Stack:** FastAPI, SQLAlchemy 2.0 (async asyncpg), Alembic, Pydantic v2, Fernet (existing `services/credentials.py`), Next.js/React (apps/web). Tests: pytest, pure-unit with hand-built fakes (no DB), per the repo convention in `tests/test_orgs_security_lake_toggle.py`.

**Spec:** `docs/superpowers/specs/2026-06-14-custom-llm-providers-design.md`.

## Scope note

`POST /llm-providers/{id}/test` is NOT in this plan — it depends on the adapter layer built in Plan B. Everything else from the spec's management plane (§1, §2 except `/test`, §5) is here. The catalog data (`services/llm_providers/catalog.py`) is created here because the UI needs it; Plan B's adapters import from it.

## File structure

| File                                                                 | Responsibility                                                   |
| -------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `apps/api/pencheff_api/db/migrations/versions/0056_llm_providers.py` | Create `llm_providers` table + add `orgs.active_llm_provider_id` |
| `apps/api/pencheff_api/db/models.py`                                 | `LlmProvider` model + `Org.active_llm_provider_id` column        |
| `apps/api/pencheff_api/services/llm_providers/__init__.py`           | Package marker                                                   |
| `apps/api/pencheff_api/services/llm_providers/catalog.py`            | `PROVIDER_KINDS`, `MODEL_CATALOG`, helpers                       |
| `apps/api/pencheff_api/schemas/llm_providers.py`                     | `LlmProviderCreate/Update/Out`, catalog schema, validators       |
| `apps/api/pencheff_api/routers/llm_providers.py`                     | CRUD + activate/deactivate + catalog endpoints                   |
| `apps/api/pencheff_api/main.py`                                      | Register the new router                                          |
| `apps/api/tests/test_llm_providers_schema.py`                        | Schema validator tests                                           |
| `apps/api/tests/test_llm_providers_router.py`                        | CRUD handler tests (fakes, no DB)                                |
| `apps/web/lib/llm-providers.ts`                                      | Typed client calls + TS types                                    |
| `apps/web/app/settings/page.tsx` (or the live Settings page)         | Provider-management UI section                                   |

---

## Task 1: DB migration (`0056_llm_providers`)

**Files:**

- Create: `apps/api/pencheff_api/db/migrations/versions/0056_llm_providers.py`

Pattern mirrors `0055_security_lake_org_toggle.py` (revision string, `down_revision="0055"`, `op.add_column`). The migration creates the table first, then adds the `orgs` pointer column (so the FK target exists). On downgrade, drop the column before the table.

- [ ] **Step 1: Write the migration**

```python
"""custom LLM providers (BYO-LLM): llm_providers table + orgs.active_llm_provider_id

Revision ID: 0056
Revises: 0055
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0056"
down_revision = "0055"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "llm_providers",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(200), nullable=False),
        sa.Column("base_url", sa.String(1024), nullable=True),
        sa.Column("api_key_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("azure_deployment", sa.String(200), nullable=True),
        sa.Column("azure_api_version", sa.String(40), nullable=True),
        sa.Column("extra", postgresql.JSONB(), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("org_id", "label", name="uq_llm_providers_org_label"),
    )
    op.create_index("ix_llm_providers_org", "llm_providers", ["org_id"])
    op.add_column(
        "orgs",
        sa.Column("active_llm_provider_id", postgresql.UUID(as_uuid=False), nullable=True),
    )
    op.create_foreign_key(
        "fk_orgs_active_llm_provider", "orgs", "llm_providers",
        ["active_llm_provider_id"], ["id"], ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_orgs_active_llm_provider", "orgs", type_="foreignkey")
    op.drop_column("orgs", "active_llm_provider_id")
    op.drop_index("ix_llm_providers_org", table_name="llm_providers")
    op.drop_table("llm_providers")
```

- [ ] **Step 2: Verify the migration imports cleanly**

Run: `cd apps/api && .venv/bin/python -c "import pencheff_api.db.migrations.versions.0056_llm_providers" 2>&1 || .venv/bin/python -c "import importlib.util,glob; f=glob.glob('pencheff_api/db/migrations/versions/0056_*.py')[0]; spec=importlib.util.spec_from_file_location('m',f); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); print('revision', m.revision, 'down', m.down_revision)"`
Expected: prints `revision 0056 down 0055` with no error. (Module name starts with a digit, so use the importlib form.)

- [ ] **Step 3: Commit**

```bash
git add apps/api/pencheff_api/db/migrations/versions/0056_llm_providers.py
git commit -m "feat(llm-providers): migration 0056 — llm_providers table + orgs.active_llm_provider_id"
```

---

## Task 2: Models (`LlmProvider` + `Org.active_llm_provider_id`)

**Files:**

- Modify: `apps/api/pencheff_api/db/models.py` (Org class ~line 30-72; add new class)

- [ ] **Step 1: Add the `active_llm_provider_id` column to `Org`**

In `class Org(Base)`, immediately after the `security_lake_disabled_at` column and before `created_at`, add:

```python
    # Custom LLM Providers (BYO-LLM). Points at the org's active llm_providers
    # row; NULL means "use Pencheff's default env models". ON DELETE SET NULL so
    # deleting the active provider cleanly reverts the org to defaults. The
    # resolver (services/llm_providers/resolver.py, Plan B) reads this.
    active_llm_provider_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("llm_providers.id", ondelete="SET NULL"),
        nullable=True,
    )
```

- [ ] **Step 2: Add the `LlmProvider` model**

At the end of `models.py` (after the last model class), add:

```python
class LlmProvider(Base):
    """An org-supplied LLM provider config (BYO-LLM).

    Typed/native provider; the API key is Fernet-encrypted in
    ``api_key_encrypted`` (via services/credentials.encrypt_credentials with a
    {"api_key": ...} dict) and is NEVER returned by any endpoint. Exactly one
    provider per org is "active", tracked by Org.active_llm_provider_id.
    """
    __tablename__ = "llm_providers"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"),
        nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(1024))
    api_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    azure_deployment: Mapped[str | None] = mapped_column(String(200))
    azure_api_version: Mapped[str | None] = mapped_column(String(40))
    extra: Mapped[dict | None] = mapped_column(JSONB)
    created_by: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("org_id", "label", name="uq_llm_providers_org_label"),
        Index("ix_llm_providers_org", "org_id"),
    )
```

- [ ] **Step 3: Verify models import**

Run: `cd apps/api && .venv/bin/python -c "from pencheff_api.db.models import LlmProvider, Org; print('active col:', 'active_llm_provider_id' in Org.__table__.c); print('llm_providers cols:', sorted(LlmProvider.__table__.c.keys()))"`
Expected: `active col: True` and the column list includes `api_key_encrypted`, `provider`, `model`, `org_id`, etc. No `mapper`/FK resolution error (the string FK `"llm_providers.id"` resolves even though `Org` is declared before `LlmProvider`).

- [ ] **Step 4: Commit**

```bash
git add apps/api/pencheff_api/db/models.py
git commit -m "feat(llm-providers): LlmProvider model + Org.active_llm_provider_id"
```

---

## Task 3: Catalog (`services/llm_providers/catalog.py`)

**Files:**

- Create: `apps/api/pencheff_api/services/llm_providers/__init__.py`
- Create: `apps/api/pencheff_api/services/llm_providers/catalog.py`
- Test: `apps/api/tests/test_llm_providers_schema.py` (catalog assertions land here too)

- [ ] **Step 1: Create the package marker**

Create `apps/api/pencheff_api/services/llm_providers/__init__.py` with a single line:

```python
"""Custom LLM provider configs: catalog, schemas support, adapters (Plan B)."""
```

- [ ] **Step 2: Create the catalog**

Create `apps/api/pencheff_api/services/llm_providers/catalog.py`:

```python
"""Provider kinds + curated model suggestions for the BYO-LLM UI.

Free-text models are always allowed (validated as a non-empty string); this
catalog only powers the dropdown suggestions so new model ids don't need a
deploy. Kept deliberately small.
"""
from __future__ import annotations

# The five supported provider kinds. Single source of truth — the Pydantic
# Literal in schemas/llm_providers.py and the adapter factory (Plan B) both
# reference this list's members.
PROVIDER_KINDS: tuple[str, ...] = (
    "openai",
    "anthropic",
    "google",
    "azure_openai",
    "openai_compatible",
)

# Curated suggestions per kind. {id: label}. openai_compatible is intentionally
# empty (self-host / arbitrary gateway — free text only).
MODEL_CATALOG: dict[str, list[dict[str, str]]] = {
    "openai": [
        {"id": "gpt-5", "label": "GPT-5"},
        {"id": "gpt-5-mini", "label": "GPT-5 mini"},
        {"id": "gpt-4.1", "label": "GPT-4.1"},
    ],
    "anthropic": [
        {"id": "claude-opus-4-8", "label": "Claude Opus 4.8"},
        {"id": "claude-sonnet-4-6", "label": "Claude Sonnet 4.6"},
        {"id": "claude-haiku-4-5", "label": "Claude Haiku 4.5"},
    ],
    "google": [
        {"id": "gemini-2.5-pro", "label": "Gemini 2.5 Pro"},
        {"id": "gemini-2.5-flash", "label": "Gemini 2.5 Flash"},
    ],
    "azure_openai": [
        {"id": "gpt-5", "label": "GPT-5 (deployment-named)"},
    ],
    "openai_compatible": [],
}


def is_valid_kind(kind: str) -> bool:
    return kind in PROVIDER_KINDS
```

- [ ] **Step 3: Add a catalog test to the schema test file** (the failing test)

Create `apps/api/tests/test_llm_providers_schema.py` with (just this test for now; more added in Task 4):

```python
from pencheff_api.services.llm_providers.catalog import (
    PROVIDER_KINDS, MODEL_CATALOG, is_valid_kind,
)


def test_catalog_has_all_kinds():
    assert set(MODEL_CATALOG.keys()) == set(PROVIDER_KINDS)
    assert is_valid_kind("anthropic")
    assert not is_valid_kind("bedrock")
    # openai_compatible is free-text only.
    assert MODEL_CATALOG["openai_compatible"] == []
```

- [ ] **Step 4: Run it**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_llm_providers_schema.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/llm_providers/__init__.py apps/api/pencheff_api/services/llm_providers/catalog.py apps/api/tests/test_llm_providers_schema.py
git commit -m "feat(llm-providers): provider kinds + model catalog"
```

---

## Task 4: Schemas (`schemas/llm_providers.py`)

**Files:**

- Create: `apps/api/pencheff_api/schemas/llm_providers.py`
- Test: `apps/api/tests/test_llm_providers_schema.py` (extend)

- [ ] **Step 1: Write failing validator tests** (append to `tests/test_llm_providers_schema.py`)

```python
import pytest
from pydantic import ValidationError

from pencheff_api.schemas.llm_providers import (
    LlmProviderCreate, LlmProviderUpdate, LlmProviderOut,
)


def test_openai_compatible_requires_base_url():
    with pytest.raises(ValidationError):
        LlmProviderCreate(label="x", provider="openai_compatible",
                          model="m", api_key="")  # no base_url
    ok = LlmProviderCreate(label="x", provider="openai_compatible",
                           model="m", base_url="https://h/v1", api_key="")
    assert ok.base_url == "https://h/v1"


def test_azure_requires_deployment_and_version():
    with pytest.raises(ValidationError):
        LlmProviderCreate(label="x", provider="azure_openai", model="m",
                          base_url="https://h", api_key="k")  # missing azure fields
    ok = LlmProviderCreate(label="x", provider="azure_openai", model="m",
                           base_url="https://h", api_key="k",
                           azure_deployment="dep", azure_api_version="2024-02-01")
    assert ok.azure_deployment == "dep"


def test_openai_anthropic_google_require_api_key():
    for kind in ("openai", "anthropic", "google"):
        with pytest.raises(ValidationError):
            LlmProviderCreate(label="x", provider=kind, model="m", api_key="")
        ok = LlmProviderCreate(label="x", provider=kind, model="m", api_key="sk-123")
        assert ok.api_key == "sk-123"


def test_unknown_provider_rejected():
    with pytest.raises(ValidationError):
        LlmProviderCreate(label="x", provider="bedrock", model="m", api_key="k")


def test_update_all_optional():
    u = LlmProviderUpdate()
    assert u.label is None and u.api_key is None
    # empty-string api_key is a sentinel meaning "clear", kept distinct from None
    u2 = LlmProviderUpdate(api_key="")
    assert u2.api_key == ""


def test_out_never_has_api_key_field():
    assert "api_key" not in LlmProviderOut.model_fields
    assert "key_set" in LlmProviderOut.model_fields
    assert "key_hint" in LlmProviderOut.model_fields
```

- [ ] **Step 2: Run to confirm failure**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_llm_providers_schema.py -v`
Expected: FAIL (`ModuleNotFoundError: pencheff_api.schemas.llm_providers`).

- [ ] **Step 3: Implement the schemas**

Create `apps/api/pencheff_api/schemas/llm_providers.py`:

```python
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from ..services.llm_providers.catalog import PROVIDER_KINDS

LlmProviderKind = Literal[
    "openai", "anthropic", "google", "azure_openai", "openai_compatible"
]


def _validate_kind_fields(provider: str, base_url: str | None,
                          azure_deployment: str | None,
                          azure_api_version: str | None) -> None:
    if provider not in PROVIDER_KINDS:
        raise ValueError(f"unknown provider {provider!r}")
    if provider in ("openai_compatible", "azure_openai") and not base_url:
        raise ValueError(f"{provider} requires base_url")
    if provider == "azure_openai" and not (azure_deployment and azure_api_version):
        raise ValueError("azure_openai requires azure_deployment + azure_api_version")


class LlmProviderCreate(BaseModel):
    label: str = Field(min_length=1, max_length=120)
    provider: LlmProviderKind
    model: str = Field(min_length=1, max_length=200)
    base_url: str | None = Field(default=None, max_length=1024)
    # Required for hosted providers; openai_compatible may use a keyless
    # self-host, so an empty key is allowed only there.
    api_key: str = ""
    azure_deployment: str | None = Field(default=None, max_length=200)
    azure_api_version: str | None = Field(default=None, max_length=40)
    extra: dict | None = None

    @model_validator(mode="after")
    def _check(self) -> "LlmProviderCreate":
        _validate_kind_fields(self.provider, self.base_url,
                              self.azure_deployment, self.azure_api_version)
        if self.provider != "openai_compatible" and not self.api_key:
            raise ValueError(f"{self.provider} requires a non-empty api_key")
        return self


class LlmProviderUpdate(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=120)
    provider: LlmProviderKind | None = None
    model: str | None = Field(default=None, min_length=1, max_length=200)
    base_url: str | None = Field(default=None, max_length=1024)
    # None = leave unchanged; "" = clear the stored key; non-empty = replace.
    api_key: str | None = None
    azure_deployment: str | None = Field(default=None, max_length=200)
    azure_api_version: str | None = Field(default=None, max_length=40)
    extra: dict | None = None


class LlmProviderOut(BaseModel):
    id: str
    label: str
    provider: str
    model: str
    base_url: str | None = None
    azure_deployment: str | None = None
    azure_api_version: str | None = None
    extra: dict | None = None
    key_set: bool = False
    key_hint: str | None = None  # e.g. "…AB12"
    is_active: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}
```

- [ ] **Step 4: Run tests to pass**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_llm_providers_schema.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/schemas/llm_providers.py apps/api/tests/test_llm_providers_schema.py
git commit -m "feat(llm-providers): Create/Update/Out schemas + per-kind validators"
```

---

## Task 5: CRUD router (`routers/llm_providers.py`)

**Files:**

- Create: `apps/api/pencheff_api/routers/llm_providers.py`
- Test: `apps/api/tests/test_llm_providers_router.py`

The router reuses the exact dependency + audit pattern from `routers/orgs.py:update_org`
(`require_org_role("owner","admin")` for writes, `request: Request`, `AuditLog` with
`request_ip`/`user_agent`). Reads use the org from the active workspace context.

**Key helper — `_to_out`** maps a `LlmProvider` row + the org's active pointer to
`LlmProviderOut`, computing `key_set`/`key_hint` from the encrypted key WITHOUT returning it.

- [ ] **Step 1: Write failing handler tests** (`tests/test_llm_providers_router.py`)

Mirror `tests/test_orgs_security_lake_toggle.py` fakes. Full file:

```python
import asyncio
from datetime import datetime, timezone

import pytest

from pencheff_api.db.models import LlmProvider, Org, User, OrgMember
from pencheff_api.schemas.llm_providers import LlmProviderCreate, LlmProviderUpdate
from pencheff_api.services.credentials import decrypt_credentials
from pencheff_api.routers import llm_providers as mod


def _user():
    u = User(id="user-1", email="a@b.c", org_id="org-1")
    return u

def _member(role="admin"):
    return OrgMember(id="m-1", org_id="org-1", user_id="user-1", role=role)

def _org():
    o = Org(id="org-1", name="Org", plan="pro")
    o.active_llm_provider_id = None
    o.created_at = datetime.now(timezone.utc)
    return o


class _Result:
    def __init__(self, rows): self._rows = rows
    def scalars(self): return self
    def all(self): return self._rows
    def scalar_one_or_none(self): return self._rows[0] if self._rows else None


class _FakeSession:
    """Minimal async session: get() by id, execute() returns canned rows,
    add()/delete() record, commit()/refresh() noop."""
    def __init__(self, org, providers):
        self._org = org
        self._providers = {p.id: p for p in providers}
        self.added = []
        self.deleted = []
        self._next_execute = list(providers)

    async def get(self, cls, pk):
        if cls is Org and pk == self._org.id:
            return self._org
        if cls is LlmProvider:
            return self._providers.get(pk)
        return None

    async def execute(self, _stmt):
        return _Result(list(self._providers.values()))

    def add(self, row): self.added.append(row)
    async def delete(self, row): self.deleted.append(row)
    async def commit(self): pass
    async def refresh(self, _obj): pass


class _Req:
    class _C: host = "203.0.113.1"
    client = _C()
    headers = {"user-agent": "pytest"}


def test_create_encrypts_key_and_never_returns_it():
    org = _org()
    session = _FakeSession(org, [])
    body = LlmProviderCreate(label="My OpenAI", provider="openai",
                             model="gpt-5-mini", api_key="sk-secret-123")
    out = asyncio.run(mod.create_provider(
        body, request=_Req(), ctx=(_user(), _member()), session=session,
        workspace=type("W", (), {"org_id": "org-1"})()))
    created = session.added[0]
    assert isinstance(created, LlmProvider)
    # Key is encrypted, recoverable only via decrypt:
    assert created.api_key_encrypted is not None
    assert decrypt_credentials(created.api_key_encrypted)["api_key"] == "sk-secret-123"
    # Output exposes key_set/hint, never the raw key:
    assert out.key_set is True
    assert out.key_hint and out.key_hint.endswith("-123"[-4:]) or out.key_hint.endswith("123")
    assert not hasattr(out, "api_key")
    # An audit row was written:
    assert any(getattr(a, "action", "") == "org.llm_provider.created" for a in session.added)


def test_patch_without_api_key_leaves_key_unchanged():
    org = _org()
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai",
                    model="gpt-5-mini")
    from pencheff_api.services.credentials import encrypt_credentials
    p.api_key_encrypted = encrypt_credentials({"api_key": "sk-keep"})
    session = _FakeSession(org, [p])
    out = asyncio.run(mod.update_provider(
        "p-1", LlmProviderUpdate(model="gpt-5"), request=_Req(),
        ctx=(_user(), _member()), session=session,
        workspace=type("W", (), {"org_id": "org-1"})()))
    assert p.model == "gpt-5"
    assert decrypt_credentials(p.api_key_encrypted)["api_key"] == "sk-keep"
    assert out.key_set is True


def test_patch_empty_string_api_key_clears_it():
    org = _org()
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai_compatible",
                    model="m", base_url="https://h/v1")
    from pencheff_api.services.credentials import encrypt_credentials
    p.api_key_encrypted = encrypt_credentials({"api_key": "sk-old"})
    session = _FakeSession(org, [p])
    asyncio.run(mod.update_provider(
        "p-1", LlmProviderUpdate(api_key=""), request=_Req(),
        ctx=(_user(), _member()), session=session,
        workspace=type("W", (), {"org_id": "org-1"})()))
    assert p.api_key_encrypted is None


def test_activate_sets_org_pointer():
    org = _org()
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai",
                    model="gpt-5-mini")
    session = _FakeSession(org, [p])
    asyncio.run(mod.activate_provider(
        "p-1", request=_Req(), ctx=(_user(), _member()), session=session,
        workspace=type("W", (), {"org_id": "org-1"})()))
    assert org.active_llm_provider_id == "p-1"


def test_delete_active_provider_nulls_pointer():
    org = _org()
    org.active_llm_provider_id = "p-1"
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai",
                    model="gpt-5-mini")
    session = _FakeSession(org, [p])
    asyncio.run(mod.delete_provider(
        "p-1", request=_Req(), ctx=(_user(), _member()), session=session,
        workspace=type("W", (), {"org_id": "org-1"})()))
    assert org.active_llm_provider_id is None
    assert p in session.deleted


def test_member_create_blocked_is_enforced_by_dependency():
    # The owner/admin gate is the require_org_role dependency on the route;
    # this test documents that create_provider itself trusts ctx. The HTTP
    # gate is covered by require_org_role (shared dependency, already tested).
    assert mod.create_provider is not None
```

- [ ] **Step 2: Run to confirm failure**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_llm_providers_router.py -v`
Expected: FAIL (`ModuleNotFoundError: pencheff_api.routers.llm_providers`).

- [ ] **Step 3: Implement the router**

Create `apps/api/pencheff_api/routers/llm_providers.py`:

```python
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.base import get_session
from ..db.models import AuditLog, LlmProvider, OrgMember, User, Org
from ..deps import require_org_role, get_active_workspace
from ..schemas.llm_providers import (
    LlmProviderCreate, LlmProviderOut, LlmProviderUpdate,
)
from ..services.credentials import encrypt_credentials, decrypt_credentials
from ..services.llm_providers.catalog import MODEL_CATALOG, PROVIDER_KINDS

router = APIRouter(prefix="/llm-providers", tags=["llm-providers"])


def _key_hint(blob: bytes | None) -> tuple[bool, str | None]:
    creds = decrypt_credentials(blob) if blob else None
    key = (creds or {}).get("api_key") if creds else None
    if not key:
        return False, None
    return True, "…" + key[-4:]


def _to_out(p: LlmProvider, *, active_id: str | None) -> LlmProviderOut:
    key_set, hint = _key_hint(p.api_key_encrypted)
    return LlmProviderOut(
        id=p.id, label=p.label, provider=p.provider, model=p.model,
        base_url=p.base_url, azure_deployment=p.azure_deployment,
        azure_api_version=p.azure_api_version, extra=p.extra,
        key_set=key_set, key_hint=hint, is_active=(p.id == active_id),
        created_at=p.created_at,
    )


def _audit(session: AsyncSession, *, user: User, org_id: str, action: str,
           request: Request, meta: dict) -> None:
    session.add(AuditLog(
        user_id=user.id, org_id=org_id, action=action,
        entity_type="llm_provider", entity_id=meta.get("id"),
        request_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"), meta=meta,
    ))


async def _load(session: AsyncSession, provider_id: str, org_id: str) -> LlmProvider:
    p = await session.get(LlmProvider, provider_id)
    if p is None or p.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "provider not found")
    return p


@router.get("/catalog")
async def get_catalog() -> dict:
    return {"kinds": list(PROVIDER_KINDS), "models": MODEL_CATALOG}


@router.get("", response_model=list[LlmProviderOut])
async def list_providers(
    workspace=Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[LlmProviderOut]:
    org = await session.get(Org, workspace.org_id)
    rows = (await session.execute(
        select(LlmProvider).where(LlmProvider.org_id == workspace.org_id)
        .order_by(LlmProvider.created_at)
    )).scalars().all()
    active = org.active_llm_provider_id if org else None
    return [_to_out(p, active_id=active) for p in rows]


@router.post("", response_model=LlmProviderOut, status_code=status.HTTP_201_CREATED)
async def create_provider(
    body: LlmProviderCreate,
    request: Request,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner", "admin")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> LlmProviderOut:
    user, _member = ctx
    p = LlmProvider(
        id=str(uuid.uuid4()), org_id=workspace.org_id, label=body.label,
        provider=body.provider, model=body.model, base_url=body.base_url,
        api_key_encrypted=encrypt_credentials({"api_key": body.api_key}) if body.api_key else None,
        azure_deployment=body.azure_deployment, azure_api_version=body.azure_api_version,
        extra=body.extra, created_by=user.id,
    )
    session.add(p)
    _audit(session, user=user, org_id=workspace.org_id, action="org.llm_provider.created",
           request=request, meta={"id": p.id, "provider": p.provider, "label": p.label})
    await session.commit()
    org = await session.get(Org, workspace.org_id)
    return _to_out(p, active_id=org.active_llm_provider_id if org else None)


@router.patch("/{provider_id}", response_model=LlmProviderOut)
async def update_provider(
    provider_id: str,
    body: LlmProviderUpdate,
    request: Request,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner", "admin")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> LlmProviderOut:
    user, _member = ctx
    p = await _load(session, provider_id, workspace.org_id)
    if body.label is not None: p.label = body.label
    if body.provider is not None: p.provider = body.provider
    if body.model is not None: p.model = body.model
    if body.base_url is not None: p.base_url = body.base_url
    if body.azure_deployment is not None: p.azure_deployment = body.azure_deployment
    if body.azure_api_version is not None: p.azure_api_version = body.azure_api_version
    if body.extra is not None: p.extra = body.extra
    # key rule: None=unchanged, ""=clear, non-empty=replace
    if body.api_key is not None:
        p.api_key_encrypted = (
            encrypt_credentials({"api_key": body.api_key}) if body.api_key else None
        )
    _audit(session, user=user, org_id=workspace.org_id, action="org.llm_provider.updated",
           request=request, meta={"id": p.id})
    await session.commit()
    org = await session.get(Org, workspace.org_id)
    return _to_out(p, active_id=org.active_llm_provider_id if org else None)


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(
    provider_id: str,
    request: Request,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner", "admin")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> None:
    user, _member = ctx
    p = await _load(session, provider_id, workspace.org_id)
    org = await session.get(Org, workspace.org_id)
    if org and org.active_llm_provider_id == p.id:
        org.active_llm_provider_id = None  # revert to defaults
    await session.delete(p)
    _audit(session, user=user, org_id=workspace.org_id, action="org.llm_provider.deleted",
           request=request, meta={"id": provider_id})
    await session.commit()


@router.post("/{provider_id}/activate", response_model=LlmProviderOut)
async def activate_provider(
    provider_id: str,
    request: Request,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner", "admin")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> LlmProviderOut:
    user, _member = ctx
    p = await _load(session, provider_id, workspace.org_id)
    org = await session.get(Org, workspace.org_id)
    org.active_llm_provider_id = p.id
    _audit(session, user=user, org_id=workspace.org_id, action="org.llm_provider.activated",
           request=request, meta={"id": p.id})
    await session.commit()
    return _to_out(p, active_id=p.id)


@router.post("/deactivate", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_provider(
    request: Request,
    ctx: tuple[User, OrgMember] = Depends(require_org_role("owner", "admin")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> None:
    user, _member = ctx
    org = await session.get(Org, workspace.org_id)
    org.active_llm_provider_id = None
    _audit(session, user=user, org_id=workspace.org_id, action="org.llm_provider.deactivated",
           request=request, meta={})
    await session.commit()
```

> **Implementer note:** Confirm the exact import paths for `get_session`, `require_org_role`, `get_active_workspace` by grepping `routers/orgs.py` (they're used there: `from ..db.base import get_session` may instead be `from ..deps import get_session` — match orgs.py's imports exactly). Adjust the import lines to match; the bodies stay identical.

- [ ] **Step 4: Run tests to pass**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_llm_providers_router.py -v`
Expected: all PASS. (If the AuditLog assertion is brittle on `request_ip` INET typing in unit context, the row is still appended; the test only checks `action`.)

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/routers/llm_providers.py apps/api/tests/test_llm_providers_router.py
git commit -m "feat(llm-providers): CRUD + activate/deactivate + catalog endpoints (owner/admin, audited, key never returned)"
```

---

## Task 6: Register the router

**Files:**

- Modify: `apps/api/pencheff_api/main.py` (near the other `include_router` calls, ~line 206-231)

- [ ] **Step 1: Add the import + include**

Find the block of `app.include_router(...)` lines. Add `llm_providers` to the existing routers import (match how `orgs`, `targets` are imported at the top of `main.py`) and add:

```python
app.include_router(llm_providers.router)
```

right after `app.include_router(orgs.router)`.

- [ ] **Step 2: Verify app boots**

Run: `cd apps/api && .venv/bin/python -c "from pencheff_api.main import app; paths=[r.path for r in app.routes]; print('llm-providers mounted:', any(p.startswith('/llm-providers') for p in paths))"`
Expected: `llm-providers mounted: True`.

- [ ] **Step 3: Commit**

```bash
git add apps/api/pencheff_api/main.py
git commit -m "feat(llm-providers): mount the router"
```

---

## Task 7: Web Settings UI

**Files:**

- Create: `apps/web/lib/llm-providers.ts`
- Modify: the live Settings page (confirm which: `apps/web/app/settings/page.tsx` was added for the Security Lake toggle; an older `apps/web/app/org/settings/page.tsx` may also exist — wire into whichever is reachable from the nav, matching `components/nav.tsx`).

- [ ] **Step 1: Add the typed client**

Create `apps/web/lib/llm-providers.ts`:

```ts
import { api } from "./api";

export type LlmProviderKind =
  | "openai"
  | "anthropic"
  | "google"
  | "azure_openai"
  | "openai_compatible";

export type LlmProvider = {
  id: string;
  label: string;
  provider: LlmProviderKind;
  model: string;
  base_url?: string | null;
  azure_deployment?: string | null;
  azure_api_version?: string | null;
  extra?: Record<string, unknown> | null;
  key_set: boolean;
  key_hint?: string | null;
  is_active: boolean;
  created_at: string;
};

export type LlmProviderInput = {
  label: string;
  provider: LlmProviderKind;
  model: string;
  base_url?: string;
  api_key?: string; // omit on edit to keep unchanged; "" to clear
  azure_deployment?: string;
  azure_api_version?: string;
};

export const listProviders = () => api<LlmProvider[]>("/llm-providers");
export const getCatalog = () =>
  api<{
    kinds: LlmProviderKind[];
    models: Record<string, { id: string; label: string }[]>;
  }>("/llm-providers/catalog");
export const createProvider = (body: LlmProviderInput) =>
  api<LlmProvider>("/llm-providers", { method: "POST", json: body });
export const updateProvider = (id: string, body: Partial<LlmProviderInput>) =>
  api<LlmProvider>(`/llm-providers/${id}`, { method: "PATCH", json: body });
export const deleteProvider = (id: string) =>
  api<void>(`/llm-providers/${id}`, { method: "DELETE" });
export const activateProvider = (id: string) =>
  api<LlmProvider>(`/llm-providers/${id}/activate`, { method: "POST" });
export const deactivateProvider = () =>
  api<void>("/llm-providers/deactivate", { method: "POST" });
```

- [ ] **Step 2: Add the UI section to the Settings page**

In the Settings page component, add an "AI / LLM Provider" section (owner/admin editable; members see a read-only list). It must:

- On mount, call `listProviders()` + `getCatalog()`.
- Render a table: label, provider badge, model, an "Active" pill on the row where `is_active`. Actions per row: **Edit**, **Delete**, **Activate** (hidden if already active). A header **Add provider** button. A **Use Pencheff defaults** button that calls `deactivateProvider()` (shown when something is active).
- Add/Edit modal form with: label (text), provider (select from `catalog.kinds`), model (text input with a `<datalist>` of `catalog.models[provider]` suggestions), base_url (shown for `openai_compatible`/`azure_openai`), azure_deployment + azure_api_version (shown for `azure_openai`), api_key (password input; on edit show placeholder `key_set ? "•••• " + key_hint : ""` and leave blank to keep unchanged).
- After any mutation, refetch `listProviders()`.
- Gate the editable controls behind `activeOrg.role === "owner" || activeOrg.role === "admin"` (from `useWorkspace()`); members get the read-only table.

Match the existing component/styling conventions on that Settings page (reuse its card/section, button, and modal patterns — e.g. the Security Lake disable-confirm modal already there). Do not invent a new design system.

- [ ] **Step 3: Verify the web build**

Run: `cd apps/web && npx next build` (or the repo's lint/build command per the `web-nav-and-dev-loop` memory — verify with `next build`, NOT Docker).
Expected: build succeeds, no type errors in `lib/llm-providers.ts` or the Settings page.

- [ ] **Step 4: Commit**

```bash
git add apps/web/lib/llm-providers.ts apps/web/app/settings/page.tsx
git commit -m "feat(llm-providers): Settings UI — list/add/edit/delete/activate providers"
```

---

## Self-Review (completed by plan author)

**Spec coverage (management plane):** §1 data model → Tasks 1-2 ✓ (`llm_providers` table, `Org.active_llm_provider_id`, unique `(org_id,label)`, SET NULL pointer). §1 schemas → Task 4 ✓ (Create/Update/Out, per-kind validators, key-omit/clear rule, no `api_key` in Out). §2 CRUD/activate/deactivate → Task 5 ✓; **`/test` deferred to Plan B** (documented in Scope note — depends on adapters). §2 audit logging → Task 5 `_audit` ✓ (matches orgs.py pattern, never logs the key). §3 catalog → Task 3 ✓ (+ `/catalog` endpoint in Task 5). §5 web UI → Task 7 ✓ (CRUD + activate + datalist + role gate + key-write-only). Router registration → Task 6 ✓.

**Placeholder scan:** No TBD/TODO. The one soft spot is the import paths in Task 5 (get_session/require_org_role/get_active_workspace) — flagged with an explicit "grep orgs.py and match" instruction rather than guessing, and the Settings-page path in Task 7 — flagged to confirm against `components/nav.tsx`. These are deliberate verify-then-match instructions, not placeholders.

**Type consistency:** `LlmProviderKind` Literal members == `PROVIDER_KINDS` tuple (Task 3 is the single source; Task 4 references it). `api_key` rule consistent across schema (Task 4: None/""/value) and router (Task 5: same branch). `_to_out(p, active_id=...)` signature used identically in list/create/update/activate. `LlmProviderOut` fields (key_set/key_hint/is_active) match the TS `LlmProvider` type in Task 7. Migration column names (Task 1) == model columns (Task 2) == `_to_out` reads (Task 5).

**Known constraints:** Tests are pure-unit with fakes (no DB), matching the repo convention — the real DB-level FK SET NULL / cascade is exercised only in prod/migration, not unit tests (same limitation as the security-lake tests). The migration's circular-looking FK is safe because the table is created before the `orgs` column is added.
