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
    member = next(r for r in session.added if isinstance(r, OrgMember))
    assert member.org_id is not None
    assert member.user_id is not None
    assert member.role == "owner"


def test_idempotent_when_rows_exist():
    org = Org(id="org-1", name=st.DEFAULT_ORG_NAME, plan="self_hosted")
    user = User(id="user-1", email=st.DEFAULT_USER_EMAIL, name=st.DEFAULT_USER_NAME)
    ws = Workspace(id="ws-1", org_id="org-1", name=st.DEFAULT_WORKSPACE_NAME, slug=st.DEFAULT_WORKSPACE_SLUG)
    session = FakeSession([org, user, ws])
    ids = asyncio.run(st.ensure_single_tenant(session))
    assert session.added == []  # nothing created
    assert ids == {"org_id": "org-1", "user_id": "user-1", "workspace_id": "ws-1"}


def test_seed_ids_caches_after_first_call():
    ids1 = asyncio.run(st.seed_ids(FakeSession([None, None, None])))
    # second call must NOT re-query — pass an exhausted session; cache should serve it
    ids2 = asyncio.run(st.seed_ids(FakeSession([])))
    assert ids1 == ids2
    assert set(ids2) == {"org_id", "user_id", "workspace_id"}
