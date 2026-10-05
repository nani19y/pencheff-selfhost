import asyncio
from datetime import datetime, timezone

import pytest

from pencheff_api.db.models import LlmProvider, Org, User, OrgMember
from pencheff_api.schemas.llm_providers import LlmProviderCreate, LlmProviderUpdate
from pencheff_api.services.credentials import decrypt_credentials, encrypt_credentials
from pencheff_api.routers import llm_providers as mod


def _user():
    return User(id="user-1", email="a@b.c", org_id="org-1")

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


class _FakeSession:
    def __init__(self, org, providers):
        self._org = org
        self._providers = {p.id: p for p in providers}
        self.added = []
        self.deleted = []

    async def get(self, cls, pk):
        if cls is Org and pk == self._org.id: return self._org
        if cls is LlmProvider: return self._providers.get(pk)
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

def _ws():
    return type("W", (), {"org_id": "org-1"})()


def test_create_encrypts_key_and_never_returns_it():
    org = _org()
    session = _FakeSession(org, [])
    body = LlmProviderCreate(label="My OpenAI", provider="openai",
                             model="gpt-5-mini", api_key="sk-secret-123")
    out = asyncio.run(mod.create_provider(
        body, request=_Req(), ctx=(_user(), _member()), session=session, workspace=_ws()))
    created = [a for a in session.added if isinstance(a, LlmProvider)][0]
    assert created.api_key_encrypted is not None
    assert decrypt_credentials(created.api_key_encrypted)["api_key"] == "sk-secret-123"
    assert out.key_set is True
    assert out.key_hint and out.key_hint.endswith("123")
    assert not hasattr(out, "api_key")
    assert any(getattr(a, "action", "") == "org.llm_provider.created" for a in session.added)


def test_patch_without_api_key_leaves_key_unchanged():
    org = _org()
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai", model="gpt-5-mini")
    p.created_at = datetime.now(timezone.utc)
    p.api_key_encrypted = encrypt_credentials({"api_key": "sk-keep"})
    session = _FakeSession(org, [p])
    out = asyncio.run(mod.update_provider(
        "p-1", LlmProviderUpdate(model="gpt-5"), request=_Req(),
        ctx=(_user(), _member()), session=session, workspace=_ws()))
    assert p.model == "gpt-5"
    assert decrypt_credentials(p.api_key_encrypted)["api_key"] == "sk-keep"
    assert out.key_set is True


def test_patch_empty_string_api_key_clears_it():
    org = _org()
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai_compatible",
                    model="m", base_url="https://h/v1")
    p.created_at = datetime.now(timezone.utc)
    p.api_key_encrypted = encrypt_credentials({"api_key": "sk-old"})
    session = _FakeSession(org, [p])
    asyncio.run(mod.update_provider(
        "p-1", LlmProviderUpdate(api_key=""), request=_Req(),
        ctx=(_user(), _member()), session=session, workspace=_ws()))
    assert p.api_key_encrypted is None


def test_activate_sets_org_pointer():
    org = _org()
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai", model="gpt-5-mini")
    p.created_at = datetime.now(timezone.utc)
    session = _FakeSession(org, [p])
    asyncio.run(mod.activate_provider(
        "p-1", request=_Req(), ctx=(_user(), _member()), session=session, workspace=_ws()))
    assert org.active_llm_provider_id == "p-1"


def test_delete_active_provider_nulls_pointer():
    org = _org(); org.active_llm_provider_id = "p-1"
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai", model="gpt-5-mini")
    session = _FakeSession(org, [p])
    asyncio.run(mod.delete_provider(
        "p-1", request=_Req(), ctx=(_user(), _member()), session=session, workspace=_ws()))
    assert org.active_llm_provider_id is None
    assert p in session.deleted


def test_list_marks_active():
    org = _org(); org.active_llm_provider_id = "p-1"
    p1 = LlmProvider(id="p-1", org_id="org-1", label="A", provider="openai", model="m")
    p1.created_at = datetime.now(timezone.utc)
    p2 = LlmProvider(id="p-2", org_id="org-1", label="B", provider="anthropic", model="m")
    p2.created_at = datetime.now(timezone.utc)
    session = _FakeSession(org, [p1, p2])
    out = asyncio.run(mod.list_providers(workspace=_ws(), session=session))
    active = {o.id: o.is_active for o in out}
    assert active["p-1"] is True and active["p-2"] is False


def test_test_endpoint_returns_ok_on_success(monkeypatch):
    import asyncio
    from pencheff_api.routers import llm_providers as mod
    from pencheff_api.db.models import LlmProvider, Org

    org = Org(id="org-1", name="o", plan="pro"); org.active_llm_provider_id = None
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai",
                    model="gpt-5-mini", base_url="https://h/v1")
    from pencheff_api.services.credentials import encrypt_credentials
    p.api_key_encrypted = encrypt_credentials({"api_key": "k"})

    class _S:
        async def get(self, cls, pk):
            return org if cls is Org else (p if pk == "p-1" else None)

    class _FakeClient:
        provider = "openai"; model = "gpt-5-mini"
        async def chat(self, *a, **k):
            from pencheff_api.services.llm_providers.base import ChatResult
            return ChatResult(text="ok")

    monkeypatch.setattr(mod, "build_client", lambda _p: _FakeClient())
    out = asyncio.run(mod.test_provider(
        "p-1", ctx=(type("U", (), {"id": "u"})(), type("W", (), {"org_id": "org-1"})()),
        session=_S(), workspace=type("W", (), {"org_id": "org-1"})()))
    assert out["ok"] is True and out["model"] == "gpt-5-mini"


def test_test_endpoint_returns_error_on_failure(monkeypatch):
    import asyncio
    from pencheff_api.routers import llm_providers as mod
    from pencheff_api.db.models import LlmProvider, Org
    org = Org(id="org-1", name="o", plan="pro")
    p = LlmProvider(id="p-1", org_id="org-1", label="L", provider="openai",
                    model="m", base_url="https://h/v1")
    class _S:
        async def get(self, cls, pk): return org if cls is Org else p
    class _Boom:
        provider="openai"; model="m"
        async def chat(self, *a, **k): raise RuntimeError("bad key")
    monkeypatch.setattr(mod, "build_client", lambda _p: _Boom())
    out = asyncio.run(mod.test_provider(
        "p-1", ctx=(type("U", (), {"id": "u"})(), type("W", (), {"org_id": "org-1"})()),
        session=_S(), workspace=type("W", (), {"org_id": "org-1"})()))
    assert out["ok"] is False and "bad key" in out["error"]
