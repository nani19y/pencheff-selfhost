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


def test_require_role_allows_any():
    user = User(id="user-1", email=st.DEFAULT_USER_EMAIL)
    ws = Workspace(id="ws-1", org_id="org-1", name="Default", slug="default")
    dep = deps.require_role("owner")
    out_user, out_ws = asyncio.run(dep(user, ws))
    assert out_user is user and out_ws is ws


def test_require_org_role_allows_any():
    user = User(id="user-1", email=st.DEFAULT_USER_EMAIL)
    dep = deps.require_org_role("owner")
    out_user, member = asyncio.run(dep("org-1", user))
    assert out_user is user and member.role == "owner"


def test_get_current_user_populates_request_state_for_audit():
    user = User(id="user-1", email=st.DEFAULT_USER_EMAIL)
    session = FakeSession({(User, "user-1"): user})
    request = _request_without_auth()
    asyncio.run(deps.get_current_user(request, session))
    assert request.state.user_id == "user-1"
    assert request.state.org_id == "org-1"
    assert request.state.api_key_id is None
    assert request.state.auth_kind == "session"
