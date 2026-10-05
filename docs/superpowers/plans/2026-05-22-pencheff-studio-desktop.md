# Pencheff Studio Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a native macOS SwiftUI app, "Pencheff Studio," that signs the user in with Google via the system browser and renders the Pencheff product against `https://api.pencheff.com`. Mirror the web app's nav surface; deliver a tiered build (Wired / Skeleton / Placeholder) so the build is always green even if session time runs out.

**Architecture:** RFC 8252 loopback OAuth via a one-shot `NWListener`; access + refresh JWTs in macOS Keychain; `actor APIClient` for all HTTP with auto-refresh-on-401; two-column `NavigationSplitView` with per-section internal `NavigationStack`. Two small additive API changes in `apps/api` make the existing native JWT path actually authenticate and let the OAuth callback redirect to a loopback URL.

**Tech Stack:** Swift 6 / SwiftUI / `Network` / `Security` / `Foundation` / `AppKit`. Xcode 26, macOS 26.4 target. No external Swift packages. Python / FastAPI / authlib on the API side.

**Spec:** `docs/superpowers/specs/2026-05-22-pencheff-studio-desktop-design.md`

> ⚠️ **Commit policy — read once, apply everywhere:** the user has explicitly forbidden commits or pushes in this work. Every task below ends with **"Stage for review (do not commit)"** in place of a normal `git commit` step. **Never run `git add`, `git commit`, `git push`, `git stash`, or any destructive git operation.** The end-of-plan task prints a files-touched summary that the user reviews and stages manually.

---

## File Structure

### `apps/api/` (2 files modified, 1 test file added)

- Modify: `apps/api/pencheff_api/auth/deps.py` — fallback to native JWT decode in `_user_from_token`.
- Modify: `apps/api/pencheff_api/routers/auth.py` — `desktop_redirect` query param on `/auth/oauth/google/start`, alternate redirect target in `/auth/oauth/google/callback`.
- Create: `apps/api/tests/test_desktop_oauth_flow.py` — covers both changes.

### `pencheff-studio/pencheff-studio/` (new app code)

Xcode uses **synchronized folders** (`PBXFileSystemSynchronizedRootGroup` — verified in `pencheff-studio.xcodeproj/project.pbxproj`). New files dropped into `pencheff-studio/pencheff-studio/` are picked up by the build automatically — no manual `pbxproj` editing.

```
pencheff-studio/pencheff-studio/
  PencheffStudioApp.swift                   (modify — existing skeleton)
  ContentView.swift                         (delete — replaced by RootView)
  Info.plist                                (create — bundle config + entitlements declarations)
  pencheff-studio.entitlements              (create — app sandbox + network)

  Assets.xcassets/
    PencheffLogo.imageset/                  (new)
    Colors/                                 (new — pencheff/accent, surface, severity*)
    AppIcon.appiconset/                     (modify — replace placeholder)

  Auth/
    AuthCoordinator.swift                   (create)
    AuthService.swift                       (create)
    KeychainStore.swift                     (create)
    LoopbackServer.swift                    (create)
    SignedInUserSnapshot.swift              (create — small struct cached during auth)

  Networking/
    APIBaseURL.swift                        (create)
    APIClient.swift                         (create — actor)
    APIError.swift                          (create — enum)
    JSONDecoding.swift                      (create — shared decoder factory)
    Endpoints/
      AuthEndpoints.swift                   (create — /auth/me, /auth/refresh)
      DashboardEndpoints.swift              (create)
      TargetsEndpoints.swift                (create)
      ScansEndpoints.swift                  (create)
      FindingsEndpoints.swift               (create)
      ReportsEndpoints.swift                (create)
      EngagementsEndpoints.swift            (create)
      ReposEndpoints.swift                  (create)
    Models/
      Me.swift                              (create)
      DashboardSummary.swift                (create)
      Target.swift                          (create)
      Scan.swift                            (create)
      Finding.swift                         (create)
      Report.swift                          (create)
      Engagement.swift                      (create)
      Repo.swift                            (create)
      PagedResponse.swift                   (create — generic wrapper)

  UI/
    Root/
      RootView.swift                        (create)
      LoginView.swift                       (create)
      MainView.swift                        (create)
      SidebarView.swift                     (create)
      Route.swift                           (create — Hashable enum)
    Components/
      LogoView.swift                        (create)
      AccountChip.swift                     (create)
      SearchField.swift                     (create)
      EmptyStateView.swift                  (create)
      ErrorStateView.swift                  (create)
      LoadingView.swift                     (create)
      ComingSoonView.swift                  (create)
      SeverityBadge.swift                   (create)
      StatusBadge.swift                     (create)
      WorkspaceRequiredView.swift           (create)
    Wired/
      Dashboard/
        DashboardView.swift                 (create)
        DashboardViewModel.swift            (create)
      Targets/
        TargetsListView.swift               (create)
        TargetDetailView.swift              (create)
        TargetsViewModel.swift              (create)
      Scans/                                (same shape)
      Findings/                             (same shape)
      Reports/                              (same shape)
      Engagements/                          (same shape)
      Repos/                                (same shape)
      Account/
        AccountView.swift                   (create)
        AccountViewModel.swift              (create)
    Skeleton/
      SchedulesView.swift                   (create)
      IntegrationsView.swift                (create)
      ApiKeysView.swift                     (create)
      AdvisoriesView.swift                  (create)
      SBOMsView.swift                       (create)
      DependenciesView.swift                (create)
      WorkspacesView.swift                  (create)

  Theme/
    Color+Pencheff.swift                    (create)
```

### `pencheff-studio/pencheff-studioTests/` (Swift unit tests)

- `KeychainStoreTests.swift`
- `LoopbackServerTests.swift`
- `APIClientTests.swift`
- `JSONDecodingTests.swift`

---

## Recipes (referenced by later tasks)

### Recipe A — "Wired list+detail section"

Used by: Targets, Scans, Findings, Reports, Engagements, Repos.

Inputs: `Section` (e.g., `Targets`), `Model` (e.g., `Target`), `endpoint` (e.g., `GET /targets`), `route` (e.g., `Route.targets`).

Outputs four files: `{Section}ListView.swift`, `{Section}DetailView.swift`, `{Section}ViewModel.swift`, `{Section}Endpoints.swift`.

Code template (engineer substitutes literal names; nothing inferred):

```swift
// Networking/Endpoints/{Section}Endpoints.swift
import Foundation
extension APIClient {
    func {section}List(limit: Int = 50, cursor: String? = nil) async throws -> PagedResponse<{Model}> {
        var query: [URLQueryItem] = [.init(name: "limit", value: String(limit))]
        if let cursor { query.append(.init(name: "cursor", value: cursor)) }
        return try await get("/{section-plural-lowercase}", query: query)
    }
    func {section}Detail(id: String) async throws -> {Model} {
        return try await get("/{section-plural-lowercase}/\(id)")
    }
}

// UI/Wired/{Section}/{Section}ViewModel.swift
@MainActor @Observable final class {Section}ViewModel {
    enum State { case loading, loaded([{Model}]), empty, error(APIError) }
    private(set) var state: State = .loading
    private let api: APIClient
    init(api: APIClient) { self.api = api }
    func load() async {
        state = .loading
        do {
            let page = try await api.{section}List()
            state = page.items.isEmpty ? .empty : .loaded(page.items)
        } catch let err as APIError { state = .error(err) }
        catch { state = .error(.unknown(error)) }
    }
}

// UI/Wired/{Section}/{Section}ListView.swift
struct {Section}ListView: View {
    @State private var vm: {Section}ViewModel
    init(api: APIClient) { _vm = State(initialValue: .init(api: api)) }
    var body: some View {
        Group {
            switch vm.state {
            case .loading: LoadingView()
            case .empty: EmptyStateView(title: "No {section-plural-lowercase} yet")
            case .error(let e):
                if case .workspaceRequired = e { WorkspaceRequiredView() }
                else { ErrorStateView(error: e, retry: { Task { await vm.load() } }) }
            case .loaded(let items):
                List(items, id: \.id) { item in
                    NavigationLink(value: item.id) { {Section}Row(item: item) }
                }
                .navigationDestination(for: String.self) { id in
                    {Section}DetailView(api: vm.api, id: id)
                }
            }
        }
        .navigationTitle("{Section-Title}")
        .task { await vm.load() }
    }
}

// UI/Wired/{Section}/{Section}DetailView.swift
struct {Section}DetailView: View {
    let api: APIClient
    let id: String
    @State private var item: {Model}?
    @State private var error: APIError?
    var body: some View {
        Group {
            if let item { {Section}DetailContent(item: item) }
            else if let error { ErrorStateView(error: error, retry: load) }
            else { LoadingView() }
        }
        .task(id: id) { await load() }
    }
    private func load() async {
        do { item = try await api.{section}Detail(id: id) }
        catch let e as APIError { error = e } catch { error = .unknown(error) }
    }
    private func load() { Task { await load() } }   // sync entry for .retry
}
```

Verification per Recipe-A section:
- Build (⌘B). No errors.
- Run, sign in, navigate to {Section} in sidebar. List shows rows or empty state.
- Tap a row. Detail loads.
- Pull power on the wifi mid-load → ErrorStateView with retry.

### Recipe B — "Skeleton section"

Used by: Schedules, Integrations, API Keys, Advisories, SBOMs, Dependencies, Workspaces.

One file: `UI/Skeleton/{Section}View.swift`.

```swift
struct {Section}View: View {
    private let seed: [SkeletonRow] = [
        SkeletonRow(title: "Sample {Section-singular} A", subtitle: "Status: example"),
        SkeletonRow(title: "Sample {Section-singular} B", subtitle: "Status: example"),
        SkeletonRow(title: "Sample {Section-singular} C", subtitle: "Status: example"),
    ]
    var body: some View {
        VStack(spacing: 0) {
            SkeletonBanner(text: "{Section} is read-only on desktop in this release. Use app.pencheff.com to make changes.")
            List(seed, id: \.title) { row in
                VStack(alignment: .leading) {
                    Text(row.title).font(.headline)
                    Text(row.subtitle).font(.subheadline).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("{Section-Title}")
    }
}
```

### Recipe C — "Placeholder section"

Used by: Org & Members, Billing, Settings, Support.

Wired directly in `SidebarView.swift` — no per-section file. Each sidebar row routes to `ComingSoonView(title:, blurb:, webURL:)`.

---

## Phase 0 — Preconditions

### Task 0: Verify environment

**Files:** none.

- [ ] **Step 1: Confirm Xcode + macOS target**

```bash
xcodebuild -version
sw_vers
```

Expected: Xcode 26.x, macOS 26.x (any minor — target is 26.4).

- [ ] **Step 2: Confirm the Xcode project opens cleanly**

```bash
xcodebuild -project pencheff-studio/pencheff-studio.xcodeproj -list
```

Expected output lists target `pencheff-studio` and configurations `Debug`, `Release`.

- [ ] **Step 3: Confirm API test runner works**

```bash
cd apps/api && uv run pytest tests/test_api_key_auth_flow.py -q
```

Expected: tests pass (or skip gracefully). If `uv` is missing, install: `brew install uv`.

- [ ] **Step 4: Confirm Python `re` and `authlib` are importable in the api venv**

```bash
cd apps/api && uv run python -c "import re; from authlib.integrations.starlette_client import OAuth; print('ok')"
```

Expected: `ok`.

---

## Phase 1 — API changes (`apps/api`)

### Task 1: Native JWT fallback in `auth/deps.py`

**Files:**
- Modify: `apps/api/pencheff_api/auth/deps.py` (function `_user_from_token`, lines ~140–174).
- Test: `apps/api/tests/test_desktop_oauth_flow.py` (new file).

- [ ] **Step 1: Write the failing tests**

Create `apps/api/tests/test_desktop_oauth_flow.py`:

```python
"""Tests for the desktop-OAuth + native-JWT additions.

Mirrors test_api_key_auth_flow.py style: mock AsyncSession + Request,
exercise the dependency directly. No FastAPI TestClient — Pencheff's
ORM has Postgres-only column types.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
import pytest
from fastapi import HTTPException
from pencheff_api.auth import jwt as native_jwt
from pencheff_api.auth.deps import _user_from_token
from pencheff_api.db.models import User


def _make_user(id_: str = "u1", active: bool = True) -> User:
    u = User(id=id_, email=f"{id_}@example.com", name=id_, is_active=active)
    return u


def _scalar_session(user: User | None) -> AsyncMock:
    session = AsyncMock()
    async def _get(model, _id):
        return user
    session.get.side_effect = _get
    # execute() is used by the Clerk path; return empty so that path falls through.
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = None
    session.execute.return_value = exec_result
    return session


@pytest.mark.asyncio
async def test_native_access_token_resolves_user(monkeypatch):
    user = _make_user("u1")
    session = _scalar_session(user)
    request = SimpleNamespace(state=SimpleNamespace(), headers={}, query_params={})

    # Force Clerk decode to fail so the native fallback is exercised.
    import pencheff_api.auth.deps as deps
    import jwt as pyjwt
    def _bad_clerk(_): raise pyjwt.InvalidTokenError("not clerk")
    monkeypatch.setattr(deps, "decode_clerk_jwt", _bad_clerk)

    token = native_jwt.make_access_token("u1", "org1")
    out = await _user_from_token(session, token)
    assert out.id == "u1"


@pytest.mark.asyncio
async def test_native_refresh_token_rejected(monkeypatch):
    session = _scalar_session(_make_user("u1"))
    import pencheff_api.auth.deps as deps
    import jwt as pyjwt
    monkeypatch.setattr(deps, "decode_clerk_jwt",
                        lambda _: (_ for _ in ()).throw(pyjwt.InvalidTokenError("not clerk")))
    token = native_jwt.make_refresh_token("u1", "org1")
    with pytest.raises(HTTPException) as exc:
        await _user_from_token(session, token)
    assert exc.value.status_code == 401
    assert "access" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_native_token_for_inactive_user(monkeypatch):
    user = _make_user("u1", active=False)
    session = _scalar_session(user)
    import pencheff_api.auth.deps as deps
    import jwt as pyjwt
    monkeypatch.setattr(deps, "decode_clerk_jwt",
                        lambda _: (_ for _ in ()).throw(pyjwt.InvalidTokenError("not clerk")))
    token = native_jwt.make_access_token("u1", "org1")
    with pytest.raises(HTTPException) as exc:
        await _user_from_token(session, token)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_garbage_token_rejected(monkeypatch):
    session = _scalar_session(None)
    import pencheff_api.auth.deps as deps
    import jwt as pyjwt
    monkeypatch.setattr(deps, "decode_clerk_jwt",
                        lambda _: (_ for _ in ()).throw(pyjwt.InvalidTokenError("not clerk")))
    with pytest.raises(HTTPException) as exc:
        await _user_from_token(session, "not.a.jwt")
    assert exc.value.status_code == 401
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
cd apps/api && uv run pytest tests/test_desktop_oauth_flow.py -v
```

Expected: all four tests FAIL (function still only handles Clerk).

- [ ] **Step 3: Implement the fallback**

Open `apps/api/pencheff_api/auth/deps.py`. Find `_user_from_token` (starts around line 140). Modify it so that when `decode_clerk_jwt` raises `InvalidTokenError`, the function falls through to the native decoder before giving up.

```python
async def _user_from_token(session: AsyncSession, token: str) -> User:
    try:
        payload = decode_clerk_jwt(token)
    except jwt.InvalidTokenError:
        return await _user_from_native_token(session, token)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token verification failed")

    clerk_user_id = payload.get("sub")
    if not clerk_user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token claims")

    plan = _plan_from_claims(payload)
    if plan is None:
        _log.info(
            "no plan claim in Clerk JWT; payload keys=%s — falling back to backend API",
            sorted(payload.keys()),
        )
        try:
            raw_plan = fetch_clerk_subscription_plan(clerk_user_id)
        except Exception as exc:
            _log.warning("Clerk subscription lookup failed for %s: %s", clerk_user_id, exc)
            raw_plan = None
        plan = _CLERK_PLAN_TO_LOCAL.get(raw_plan or "", "free")

    user = (
        await session.execute(select(User).where(User.google_sub == clerk_user_id))
    ).scalar_one_or_none()
    if user is None:
        user = await _provision_user_from_clerk(session, clerk_user_id)
    await _sync_plan_for_user(session, user, plan)

    if not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user is inactive")
    return user


async def _user_from_native_token(session: AsyncSession, token: str) -> User:
    """Validate a JWT issued by ``auth.jwt.make_access_token``.

    The native token path (signup / login / OAuth via ``routers/auth.py``)
    issues HS-signed JWTs that the Clerk verifier cannot accept. We try
    Clerk first (the web app's primary identity); if that fails, fall
    through here. The native flow already provisions an Org on signup
    via ``_provision_tenancy``, so no plan sync is needed.
    """
    from .jwt import decode_token  # local import to keep module load order
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")
    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not an access token")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token claims")
    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    return user
```

- [ ] **Step 4: Run tests, verify they pass**

```bash
cd apps/api && uv run pytest tests/test_desktop_oauth_flow.py -v
```

Expected: all four tests PASS.

- [ ] **Step 5: Run the existing auth tests to confirm no regression**

```bash
cd apps/api && uv run pytest tests/test_api_key_auth_flow.py -q
```

Expected: all PASS, count unchanged.

- [ ] **Step 6: Stage for review (do not commit)**

Print:
```
Modified: apps/api/pencheff_api/auth/deps.py
Created:  apps/api/tests/test_desktop_oauth_flow.py
```
Do not run `git add`, `git commit`, or any git mutation.

### Task 2: `desktop_redirect` support in `routers/auth.py`

**Files:**
- Modify: `apps/api/pencheff_api/routers/auth.py` (functions `google_start` and `google_callback`).
- Test: `apps/api/tests/test_desktop_oauth_flow.py` (extend the file from Task 1).

- [ ] **Step 1: Add failing tests to `test_desktop_oauth_flow.py`**

Append to the test file:

```python
import re
import pytest
from starlette.requests import Request
from starlette.responses import RedirectResponse
from pencheff_api.routers import auth as auth_router


def _mk_request_with_session(session_dict: dict | None = None) -> Request:
    """Build a minimal Starlette Request with a mutable session dict."""
    scope = {
        "type": "http",
        "method": "GET",
        "headers": [],
        "session": session_dict if session_dict is not None else {},
        "path_params": {},
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_google_start_stores_loopback_redirect(monkeypatch):
    captured = {}
    async def fake_redirect(request, _uri):
        captured["session"] = dict(request.session)
        return RedirectResponse(url="https://accounts.google.com/o/oauth2/auth?stub")
    monkeypatch.setattr(auth_router.oauth, "_registry", {"google": object()})
    monkeypatch.setattr(auth_router.oauth, "google",
                        SimpleNamespace(authorize_redirect=fake_redirect))
    req = _mk_request_with_session()
    resp = await auth_router.google_start(
        request=req,
        desktop_redirect="http://127.0.0.1:54123/callback",
        state="abc123",
    )
    assert resp.status_code == 307 or resp.status_code == 302
    assert captured["session"]["desktop_redirect"] == "http://127.0.0.1:54123/callback"
    assert captured["session"]["desktop_state"] == "abc123"


@pytest.mark.asyncio
async def test_google_start_rejects_non_loopback(monkeypatch):
    monkeypatch.setattr(auth_router.oauth, "_registry", {"google": object()})
    monkeypatch.setattr(auth_router.oauth, "google",
                        SimpleNamespace(authorize_redirect=AsyncMock()))
    req = _mk_request_with_session()
    with pytest.raises(HTTPException) as exc:
        await auth_router.google_start(
            request=req,
            desktop_redirect="https://evil.com/callback",
            state=None,
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_google_start_rejects_loopback_wrong_path(monkeypatch):
    monkeypatch.setattr(auth_router.oauth, "_registry", {"google": object()})
    monkeypatch.setattr(auth_router.oauth, "google",
                        SimpleNamespace(authorize_redirect=AsyncMock()))
    req = _mk_request_with_session()
    with pytest.raises(HTTPException) as exc:
        await auth_router.google_start(
            request=req,
            desktop_redirect="http://127.0.0.1:54123/something-else",
            state=None,
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_google_start_without_desktop_redirect_clears_session(monkeypatch):
    captured = {}
    async def fake_redirect(request, _uri):
        captured["session"] = dict(request.session)
        return RedirectResponse(url="https://accounts.google.com/x")
    monkeypatch.setattr(auth_router.oauth, "_registry", {"google": object()})
    monkeypatch.setattr(auth_router.oauth, "google",
                        SimpleNamespace(authorize_redirect=fake_redirect))
    req = _mk_request_with_session({"desktop_redirect": "stale", "desktop_state": "stale"})
    await auth_router.google_start(request=req, desktop_redirect=None, state=None)
    assert "desktop_redirect" not in captured["session"]
    assert "desktop_state" not in captured["session"]


def test_loopback_regex_matches_only_localhost():
    """Sanity check the regex literal in google_start."""
    pat = re.compile(r"^http://127\.0\.0\.1:\d{4,5}/callback$")
    assert pat.fullmatch("http://127.0.0.1:1024/callback")
    assert pat.fullmatch("http://127.0.0.1:65535/callback")
    assert not pat.fullmatch("http://127.0.0.1/callback")
    assert not pat.fullmatch("https://127.0.0.1:54123/callback")
    assert not pat.fullmatch("http://localhost:54123/callback")
    assert not pat.fullmatch("http://127.0.0.1:54123/callback?x=1")
```

- [ ] **Step 2: Run tests — they should fail**

```bash
cd apps/api && uv run pytest tests/test_desktop_oauth_flow.py -v
```

Expected: 4 of the 5 new tests FAIL (the regex sanity check passes; the others fail because `google_start` doesn't accept the param yet).

- [ ] **Step 3: Modify `google_start` in `routers/auth.py`**

Open `apps/api/pencheff_api/routers/auth.py`. At the top of the file, add to the existing import block:

```python
import re
```

Replace the existing `google_start` function with:

```python
_LOOPBACK_RE = re.compile(r"^http://127\.0\.0\.1:\d{4,5}/callback$")


@router.get("/oauth/google/start")
async def google_start(
    request: Request,
    desktop_redirect: str | None = None,
    state: str | None = None,
):
    if "google" not in oauth._registry:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, "google oauth not configured")
    if desktop_redirect is not None:
        if not _LOOPBACK_RE.fullmatch(desktop_redirect):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid desktop_redirect")
        request.session["desktop_redirect"] = desktop_redirect
        request.session["desktop_state"] = state or ""
    else:
        request.session.pop("desktop_redirect", None)
        request.session.pop("desktop_state", None)
    return await oauth.google.authorize_redirect(request, settings.google_redirect_uri)
```

- [ ] **Step 4: Modify `google_callback` in the same file**

Replace the final two lines of `google_callback` (the ones that build `redirect` and return `RedirectResponse(url=redirect)`) with:

```python
    desktop_redirect = request.session.pop("desktop_redirect", None)
    desktop_state = request.session.pop("desktop_state", "")
    if desktop_redirect:
        # Loopback — these query params never leave the user's machine.
        url = (
            f"{desktop_redirect}"
            f"?access_token={access}"
            f"&refresh_token={refresh_token}"
            f"&state={desktop_state}"
        )
        return RedirectResponse(url=url)
    redirect = (
        f"{settings.web_base_url}/oauth/callback"
        f"#access_token={access}&refresh_token={refresh_token}"
    )
    return RedirectResponse(url=redirect)
```

- [ ] **Step 5: Run tests, verify all pass**

```bash
cd apps/api && uv run pytest tests/test_desktop_oauth_flow.py -v
```

Expected: all 9 tests PASS (4 from Task 1 + 5 from Task 2).

- [ ] **Step 6: Add a callback-redirect-target test**

Append to `test_desktop_oauth_flow.py`:

```python
@pytest.mark.asyncio
async def test_callback_redirects_to_loopback_when_set(monkeypatch):
    """The callback should redirect to the loopback URL with tokens in query when
    desktop_redirect was stashed by google_start; otherwise to web with hash."""
    from pencheff_api.auth.jwt import make_access_token, make_refresh_token
    # Stub all the DB side effects.
    fake_session = AsyncMock()
    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = None
    fake_session.execute.return_value = exec_result
    fake_session.flush = AsyncMock()
    fake_session.commit = AsyncMock()

    async def fake_authorize_access_token(_req):
        return {"userinfo": {"sub": "g123", "email": "a@b.com", "name": "A"}}
    monkeypatch.setattr(auth_router.oauth, "_registry", {"google": object()})
    monkeypatch.setattr(auth_router.oauth, "google",
                        SimpleNamespace(
                            authorize_access_token=fake_authorize_access_token,
                            userinfo=AsyncMock(return_value={}),
                        ))

    req = _mk_request_with_session({
        "desktop_redirect": "http://127.0.0.1:54123/callback",
        "desktop_state": "xyz",
    })
    resp = await auth_router.google_callback(request=req, session=fake_session)
    loc = resp.headers["location"]
    assert loc.startswith("http://127.0.0.1:54123/callback?access_token=")
    assert "&refresh_token=" in loc
    assert loc.endswith("&state=xyz")
```

- [ ] **Step 7: Run all tests in the file**

```bash
cd apps/api && uv run pytest tests/test_desktop_oauth_flow.py -v
```

Expected: 10 tests PASS.

- [ ] **Step 8: Run the broader auth suite for regression**

```bash
cd apps/api && uv run pytest tests/test_api_key_auth_flow.py tests/test_desktop_oauth_flow.py -q
```

Expected: all PASS.

- [ ] **Step 9: Stage for review (do not commit)**

Print the running files-touched list. Do not run any git command.

---

## Phase 2 — Mac app foundation

### Task 3: Replace the Hello-World skeleton

**Files:**
- Modify: `pencheff-studio/pencheff-studio/PencheffStudioApp.swift`
- Delete: `pencheff-studio/pencheff-studio/ContentView.swift`

- [ ] **Step 1: Rewrite the app entry**

Open `pencheff-studio/pencheff-studio/pencheff_studioApp.swift` (Xcode-generated name) and replace its contents with:

```swift
import SwiftUI

@main
struct PencheffStudioApp: App {
    @State private var coordinator = AuthCoordinator()

    var body: some Scene {
        WindowGroup("Pencheff Studio") {
            RootView()
                .environment(coordinator)
                .frame(minWidth: 900, minHeight: 600)
        }
        .defaultSize(width: 1280, height: 800)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Pencheff Studio") { /* no-op for now */ }
            }
            CommandGroup(after: .appInfo) {
                Divider()
                Button("Sign Out") { coordinator.signOut() }
                    .keyboardShortcut("q", modifiers: [.command, .shift])
            }
        }
    }
}
```

- [ ] **Step 2: Delete the placeholder ContentView**

Remove `pencheff-studio/pencheff-studio/ContentView.swift`.

```bash
rm pencheff-studio/pencheff-studio/ContentView.swift
```

- [ ] **Step 3: Don't build yet**

`RootView` and `AuthCoordinator` don't exist yet. The next tasks create them. After Task 11 the project compiles again.

- [ ] **Step 4: Stage for review (do not commit)**

### Task 4: Entitlements + Info.plist

**Files:**
- Create: `pencheff-studio/pencheff-studio/pencheff-studio.entitlements`
- Create: `pencheff-studio/pencheff-studio/Info.plist`

- [ ] **Step 1: Write the entitlements file**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.network.server</key>
    <true/>
</dict>
</plist>
```

- [ ] **Step 2: Write Info.plist**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>Pencheff Studio</string>
    <key>CFBundleExecutable</key>
    <string>$(EXECUTABLE_NAME)</string>
    <key>CFBundleIdentifier</key>
    <string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Pencheff Studio</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>26.4</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © 2026 Pencheff. All rights reserved.</string>
    <key>PencheffAPIBaseURL</key>
    <string>https://api.pencheff.com</string>
</dict>
</plist>
```

- [ ] **Step 3: Wire Info.plist + entitlements into the build settings**

Open `pencheff-studio/pencheff-studio.xcodeproj/project.pbxproj`. In each of the four `XCBuildConfiguration` blocks for the `pencheff-studio` target (Debug + Release), add:

```
INFOPLIST_FILE = "pencheff-studio/Info.plist";
CODE_SIGN_ENTITLEMENTS = "pencheff-studio/pencheff-studio.entitlements";
INFOPLIST_KEY_LSApplicationCategoryType = "public.app-category.developer-tools";
```

(Insert near the existing `INFOPLIST_KEY_*` block. Do not delete other generated INFOPLIST_KEY entries — they coexist with the explicit file.)

- [ ] **Step 4: Stage for review (do not commit)**

### Task 5: `Theme/Color+Pencheff.swift` + asset-catalog colors

**Files:**
- Create: `pencheff-studio/pencheff-studio/Theme/Color+Pencheff.swift`
- Create: 9 color sets in `pencheff-studio/pencheff-studio/Assets.xcassets/Colors/`

- [ ] **Step 1: Create the asset-catalog color sets**

For each of the colors below, create `Assets.xcassets/Colors/<name>.colorset/Contents.json` with two appearance variants (light + dark).

Names + hex values (dark variant in parentheses):

| Name | Light hex | Dark hex |
| --- | --- | --- |
| `accent` | `#7C3AED` | `#A78BFA` |
| `surface` | `#FFFFFF` | `#0B0F19` |
| `surfaceHigh` | `#F4F4F5` | `#1A1F2E` |
| `text` | `#0B0F19` | `#F4F4F5` |
| `textMuted` | `#6B7280` | `#9CA3AF` |
| `severityCritical` | `#B91C1C` | `#F87171` |
| `severityHigh` | `#C2410C` | `#FB923C` |
| `severityMedium` | `#A16207` | `#FBBF24` |
| `severityLow` | `#1D4ED8` | `#60A5FA` |
| `severityInfo` | `#4B5563` | `#9CA3AF` |

`Contents.json` template (the engineer copies this once per color, substituting hex):

```json
{
  "colors": [
    {
      "color": {
        "color-space": "srgb",
        "components": { "alpha": "1.000", "red": "0xFF", "green": "0xFF", "blue": "0xFF" }
      },
      "idiom": "universal"
    },
    {
      "appearances": [{ "appearance": "luminosity", "value": "dark" }],
      "color": {
        "color-space": "srgb",
        "components": { "alpha": "1.000", "red": "0x0B", "green": "0x0F", "blue": "0x19" }
      },
      "idiom": "universal"
    }
  ],
  "info": { "author": "xcode", "version": 1 }
}
```

(Engineer converts each hex `#RRGGBB` to `0xRR 0xGG 0xBB`. Light variant goes in the first object, dark in the second.)

- [ ] **Step 2: Create `Color+Pencheff.swift`**

```swift
import SwiftUI

extension Color {
    enum Pencheff {
        static let accent = Color("accent")
        static let surface = Color("surface")
        static let surfaceHigh = Color("surfaceHigh")
        static let text = Color("text")
        static let textMuted = Color("textMuted")

        enum Severity {
            static let critical = Color("severityCritical")
            static let high = Color("severityHigh")
            static let medium = Color("severityMedium")
            static let low = Color("severityLow")
            static let info = Color("severityInfo")
        }
    }
}
```

- [ ] **Step 3: Stage for review (do not commit)**

### Task 6: `Networking/APIBaseURL.swift`

**Files:**
- Create: `pencheff-studio/pencheff-studio/Networking/APIBaseURL.swift`

- [ ] **Step 1: Implement**

```swift
import Foundation

enum APIBaseURL {
    /// Resolution order:
    ///   1. UserDefaults key ``PencheffAPIBaseURL`` (lets dev override via
    ///      ``defaults write com.pencheff.pencheff-studio PencheffAPIBaseURL …``)
    ///   2. Info.plist ``PencheffAPIBaseURL``
    ///   3. Hard-coded prod default
    static let current: URL = {
        if let s = UserDefaults.standard.string(forKey: "PencheffAPIBaseURL"),
           let u = URL(string: s) { return u }
        if let s = Bundle.main.object(forInfoDictionaryKey: "PencheffAPIBaseURL") as? String,
           let u = URL(string: s) { return u }
        return URL(string: "https://api.pencheff.com")!
    }()
}
```

- [ ] **Step 2: Stage for review (do not commit)**

### Task 7: `Auth/KeychainStore.swift` + XCTest

**Files:**
- Create: `pencheff-studio/pencheff-studio/Auth/KeychainStore.swift`
- Create: `pencheff-studio/pencheff-studioTests/KeychainStoreTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
@testable import pencheff_studio

final class KeychainStoreTests: XCTestCase {
    private let service = "com.pencheff.pencheff-studio.test"
    private var store: KeychainStore!

    override func setUp() {
        super.setUp()
        store = KeychainStore(service: service)
        try? store.delete(account: "k1")
    }

    override func tearDown() {
        try? store.delete(account: "k1")
        super.tearDown()
    }

    func test_set_then_get_returns_value() throws {
        try store.set("hello", account: "k1")
        XCTAssertEqual(try store.get(account: "k1"), "hello")
    }

    func test_get_missing_returns_nil() throws {
        XCTAssertNil(try store.get(account: "k1"))
    }

    func test_overwrite_replaces_value() throws {
        try store.set("a", account: "k1")
        try store.set("b", account: "k1")
        XCTAssertEqual(try store.get(account: "k1"), "b")
    }

    func test_delete_removes_value() throws {
        try store.set("x", account: "k1")
        try store.delete(account: "k1")
        XCTAssertNil(try store.get(account: "k1"))
    }
}
```

- [ ] **Step 2: Implement `KeychainStore`**

```swift
import Foundation
import Security

struct KeychainStore {
    let service: String

    enum Error: Swift.Error { case unexpectedStatus(OSStatus) }

    init(service: String = "com.pencheff.pencheff-studio") { self.service = service }

    func get(account: String) throws -> String? {
        var q = baseQuery(account: account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw Error.unexpectedStatus(status) }
        guard let data = item as? Data, let s = String(data: data, encoding: .utf8) else { return nil }
        return s
    }

    func set(_ value: String, account: String) throws {
        let data = Data(value.utf8)
        let query = baseQuery(account: account)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        switch updateStatus {
        case errSecSuccess: return
        case errSecItemNotFound:
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            let status = SecItemAdd(addQuery as CFDictionary, nil)
            guard status == errSecSuccess else { throw Error.unexpectedStatus(status) }
        default:
            throw Error.unexpectedStatus(updateStatus)
        }
    }

    func delete(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Error.unexpectedStatus(status)
        }
    }

    private func baseQuery(account: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

enum KeychainAccount {
    static let accessToken = "access_token"
    static let refreshToken = "refresh_token"
}
```

- [ ] **Step 3: Run tests in Xcode**

In Xcode: ⌘U. Expect: 4 PASS in `KeychainStoreTests`.

- [ ] **Step 4: Stage for review (do not commit)**

### Task 8: `Networking/APIError.swift`

**Files:**
- Create: `pencheff-studio/pencheff-studio/Networking/APIError.swift`

- [ ] **Step 1: Implement**

```swift
import Foundation

enum APIError: Error, LocalizedError {
    case unauthorized
    case workspaceRequired
    case server(status: Int, message: String)
    case network(URLError)
    case decoding(Error)
    case unknown(Error)

    var errorDescription: String? {
        switch self {
        case .unauthorized: "Your session expired. Please sign in again."
        case .workspaceRequired:
            "Pencheff Studio v1 only supports single-workspace accounts. Use app.pencheff.com to pick a workspace; workspace selection on desktop ships in a later release."
        case .server(let s, let m): "Server error \(s): \(m)"
        case .network(let e): "Network error: \(e.localizedDescription)"
        case .decoding(let e): "Couldn't read response: \(e.localizedDescription)"
        case .unknown(let e): e.localizedDescription
        }
    }
}
```

- [ ] **Step 2: Stage for review (do not commit)**

### Task 9: `Networking/JSONDecoding.swift` + XCTest

**Files:**
- Create: `pencheff-studio/pencheff-studio/Networking/JSONDecoding.swift`
- Create: `pencheff-studio/pencheff-studioTests/JSONDecodingTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
@testable import pencheff_studio

final class JSONDecodingTests: XCTestCase {
    func test_decodes_iso8601_with_fractional_seconds() throws {
        let json = #"{"ts":"2026-05-22T10:00:00.123456Z"}"#.data(using: .utf8)!
        struct P: Decodable { let ts: Date }
        let p = try JSONDecoding.decoder.decode(P.self, from: json)
        XCTAssertEqual(Int(p.ts.timeIntervalSince1970), 1779789600)
    }

    func test_decodes_iso8601_without_fractional_seconds() throws {
        let json = #"{"ts":"2026-05-22T10:00:00Z"}"#.data(using: .utf8)!
        struct P: Decodable { let ts: Date }
        let p = try JSONDecoding.decoder.decode(P.self, from: json)
        XCTAssertEqual(Int(p.ts.timeIntervalSince1970), 1779789600)
    }
}
```

- [ ] **Step 2: Implement**

```swift
import Foundation

enum JSONDecoding {
    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { decoder in
            let s = try decoder.singleValueContainer().decode(String.self)
            let withFracs = ISO8601DateFormatter()
            withFracs.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = withFracs.date(from: s) { return date }
            let plain = ISO8601DateFormatter()
            plain.formatOptions = [.withInternetDateTime]
            if let date = plain.date(from: s) { return date }
            throw DecodingError.dataCorruptedError(
                in: try decoder.singleValueContainer(),
                debugDescription: "Unrecognized ISO8601 string: \(s)"
            )
        }
        return d
    }()
    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }()
}
```

- [ ] **Step 3: Run tests** — ⌘U. Both PASS.

- [ ] **Step 4: Stage for review (do not commit)**

### Task 10: `Networking/Models/Me.swift` and `PagedResponse.swift`

**Files:**
- Create: `pencheff-studio/pencheff-studio/Networking/Models/Me.swift`
- Create: `pencheff-studio/pencheff-studio/Networking/Models/PagedResponse.swift`

- [ ] **Step 1: Write `Me.swift`**

```swift
import Foundation

struct Me: Codable, Equatable, Sendable {
    let id: String
    let email: String
    let name: String?
    let orgId: String
    let orgName: String
    let plan: String

    enum CodingKeys: String, CodingKey {
        case id, email, name
        case orgId = "org_id"
        case orgName = "org_name"
        case plan
    }
}
```

- [ ] **Step 2: Write `PagedResponse.swift`**

```swift
import Foundation

struct PagedResponse<T: Decodable & Sendable>: Decodable, Sendable {
    let items: [T]
    let nextCursor: String?

    enum CodingKeys: String, CodingKey {
        case items
        case nextCursor = "next_cursor"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.items = (try? c.decode([T].self, forKey: .items)) ?? []
        self.nextCursor = try? c.decodeIfPresent(String.self, forKey: .nextCursor)
    }
}
```

- [ ] **Step 3: Stage for review (do not commit)**

---

## Phase 3 — Auth flow

### Task 11: `Auth/LoopbackServer.swift` + XCTest

**Files:**
- Create: `pencheff-studio/pencheff-studio/Auth/LoopbackServer.swift`
- Create: `pencheff-studio/pencheff-studioTests/LoopbackServerTests.swift`

- [ ] **Step 1: Implement `LoopbackServer`**

```swift
import Foundation
import Network

actor LoopbackServer {
    enum ServerError: Error { case bindFailed, timedOut, cancelled }

    private var listener: NWListener?
    private var port: UInt16?
    private var continuation: CheckedContinuation<URLComponents, Error>?
    private var timeoutTask: Task<Void, Never>?

    /// Starts an HTTP/1.1 listener on 127.0.0.1 with an OS-assigned port.
    /// Returns the bound port. Call ``waitForCallback`` to receive the request URL.
    func start() async throws -> UInt16 {
        let params = NWParameters.tcp
        params.requiredInterfaceType = .loopback
        let listener = try NWListener(using: params, on: .any)
        self.listener = listener

        listener.newConnectionHandler = { [weak self] conn in
            Task { await self?.handle(conn) }
        }

        let portCont: CheckedContinuation<UInt16, Error> = await withCheckedContinuation { _ in }
        // The block above is illustrative; use NWListener.stateUpdateHandler to resolve.
        return try await withCheckedThrowingContinuation { cont in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    guard let port = listener.port?.rawValue else {
                        cont.resume(throwing: ServerError.bindFailed); return
                    }
                    cont.resume(returning: port)
                case .failed:
                    cont.resume(throwing: ServerError.bindFailed)
                default: break
                }
            }
            listener.start(queue: .global(qos: .userInitiated))
        }
    }

    /// Suspends until either the listener receives a /callback request or the
    /// 10-minute timeout fires. Returns the parsed URL components.
    func waitForCallback() async throws -> URLComponents {
        return try await withCheckedThrowingContinuation { cont in
            self.continuation = cont
            self.timeoutTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 600 * 1_000_000_000)
                await self?.fire(.failure(ServerError.timedOut))
            }
        }
    }

    func stop() {
        timeoutTask?.cancel()
        listener?.cancel()
        listener = nil
    }

    // MARK: - Internals

    private func handle(_ conn: NWConnection) {
        conn.start(queue: .global(qos: .userInitiated))
        conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, _, _ in
            guard let self, let data, let req = String(data: data, encoding: .utf8) else {
                conn.cancel(); return
            }
            // Parse the request line: "GET /callback?... HTTP/1.1"
            let line = req.split(separator: "\r\n").first.map(String.init) ?? ""
            let parts = line.split(separator: " ")
            guard parts.count >= 2 else { conn.cancel(); return }
            let path = String(parts[1])
            let urlString = "http://127.0.0.1\(path)"
            guard let comps = URLComponents(string: urlString) else { conn.cancel(); return }

            let body = Self.successHTML
            let response = """
            HTTP/1.1 200 OK\r
            Content-Type: text/html; charset=utf-8\r
            Cache-Control: no-store\r
            Content-Length: \(body.utf8.count)\r
            Connection: close\r
            \r
            \(body)
            """
            conn.send(content: response.data(using: .utf8), completion: .contentProcessed { _ in
                conn.cancel()
            })
            Task { await self.fire(.success(comps)) }
        }
    }

    private func fire(_ result: Result<URLComponents, Error>) {
        timeoutTask?.cancel()
        timeoutTask = nil
        guard let cont = continuation else { return }
        continuation = nil
        cont.resume(with: result)
    }

    static let successHTML = """
    <!doctype html>
    <html><head><meta charset="utf-8"><title>Pencheff Studio</title>
    <script>history.replaceState(null, '', '/');</script>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, system-ui; background:#0B0F19; color:#F4F4F5; display:grid; place-items:center; height:100vh; margin:0; }
      .card { text-align:center; padding:32px 40px; border-radius:14px; background:#1A1F2E; max-width:420px; }
      h1 { margin: 0 0 8px; font-size: 22px; }
      p { margin: 0; opacity: 0.75; }
    </style>
    </head>
    <body><div class="card">
      <h1>Signed in to Pencheff Studio</h1>
      <p>You can close this tab and return to the app.</p>
    </div></body></html>
    """
}
```

- [ ] **Step 2: Write the XCTest**

```swift
import XCTest
@testable import pencheff_studio

final class LoopbackServerTests: XCTestCase {
    func test_start_returns_port_and_callback_parses_query() async throws {
        let server = LoopbackServer()
        let port = try await server.start()
        XCTAssertGreaterThan(port, 0)

        // Fire a request at the listener after a tiny delay.
        Task {
            try? await Task.sleep(nanoseconds: 100_000_000)
            let url = URL(string: "http://127.0.0.1:\(port)/callback?access_token=a&refresh_token=r&state=s")!
            _ = try? await URLSession.shared.data(from: url)
        }

        let comps = try await server.waitForCallback()
        XCTAssertEqual(comps.path, "/callback")
        let items = Dictionary(uniqueKeysWithValues: (comps.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        XCTAssertEqual(items["access_token"], "a")
        XCTAssertEqual(items["refresh_token"], "r")
        XCTAssertEqual(items["state"], "s")
        await server.stop()
    }
}
```

- [ ] **Step 3: Run tests** — ⌘U. PASS.

- [ ] **Step 4: Stage for review (do not commit)**

### Task 12: `Auth/AuthService.swift`

**Files:**
- Create: `pencheff-studio/pencheff-studio/Auth/AuthService.swift`
- Create: `pencheff-studio/pencheff-studio/Auth/SignedInUserSnapshot.swift`

- [ ] **Step 1: Create the snapshot model**

```swift
import Foundation
struct SignedInUserSnapshot: Equatable, Sendable {
    let accessToken: String
    let refreshToken: String
}
```

- [ ] **Step 2: Implement `AuthService`**

```swift
import Foundation
import AppKit
import CryptoKit

actor AuthService {
    enum AuthError: Error { case userCancelled, stateMismatch, missingTokens(String), notConfigured }

    private let baseURL: URL
    private let keychain: KeychainStore
    private var inFlightServer: LoopbackServer?

    init(baseURL: URL = APIBaseURL.current, keychain: KeychainStore = KeychainStore()) {
        self.baseURL = baseURL
        self.keychain = keychain
    }

    func beginGoogleSignIn() async throws -> SignedInUserSnapshot {
        let server = LoopbackServer()
        inFlightServer = server
        defer {
            Task { await server.stop() }
            inFlightServer = nil
        }
        let port = try await server.start()
        let redirect = "http://127.0.0.1:\(port)/callback"
        let state = Self.makeState()
        var startURL = URLComponents(url: baseURL.appendingPathComponent("auth/oauth/google/start"),
                                     resolvingAgainstBaseURL: false)!
        startURL.queryItems = [
            .init(name: "desktop_redirect", value: redirect),
            .init(name: "state", value: state),
        ]
        guard let openable = startURL.url else { throw AuthError.notConfigured }
        await MainActor.run { NSWorkspace.shared.open(openable) }

        let callback = try await server.waitForCallback()
        let items = Dictionary(uniqueKeysWithValues: (callback.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        guard items["state"] == state else { throw AuthError.stateMismatch }
        guard let access = items["access_token"], !access.isEmpty else {
            throw AuthError.missingTokens("access_token")
        }
        guard let refresh = items["refresh_token"], !refresh.isEmpty else {
            throw AuthError.missingTokens("refresh_token")
        }
        try keychain.set(access, account: KeychainAccount.accessToken)
        try keychain.set(refresh, account: KeychainAccount.refreshToken)
        return SignedInUserSnapshot(accessToken: access, refreshToken: refresh)
    }

    func cancel() async {
        await inFlightServer?.stop()
        inFlightServer = nil
    }

    func signOut() {
        try? keychain.delete(account: KeychainAccount.accessToken)
        try? keychain.delete(account: KeychainAccount.refreshToken)
    }

    private static func makeState() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
```

- [ ] **Step 3: Stage for review (do not commit)**

### Task 13: `Auth/AuthCoordinator.swift`

**Files:**
- Create: `pencheff-studio/pencheff-studio/Auth/AuthCoordinator.swift`

- [ ] **Step 1: Implement**

```swift
import Foundation
import Observation

@MainActor @Observable final class AuthCoordinator {
    enum State {
        case bootstrapping
        case signedOut
        case signingIn
        case signedIn(Me)
    }

    private(set) var state: State = .bootstrapping
    private(set) var lastError: String?

    private let auth: AuthService
    private let keychain: KeychainStore
    private(set) var apiClient: APIClient?

    init(auth: AuthService = AuthService(), keychain: KeychainStore = KeychainStore()) {
        self.auth = auth
        self.keychain = keychain
        Task { await bootstrap() }
    }

    func bootstrap() async {
        guard let access = try? keychain.get(account: KeychainAccount.accessToken),
              let refresh = try? keychain.get(account: KeychainAccount.refreshToken),
              !access.isEmpty, !refresh.isEmpty else {
            state = .signedOut; return
        }
        // Try to fetch /auth/me to confirm we're still valid.
        let client = APIClient(coordinator: self)
        apiClient = client
        do {
            let me: Me = try await client.get("/auth/me")
            state = .signedIn(me)
        } catch {
            apiClient = nil
            state = .signedOut
        }
    }

    func beginGoogleSignIn() {
        Task { await runSignIn() }
    }

    private func runSignIn() async {
        state = .signingIn
        lastError = nil
        do {
            _ = try await auth.beginGoogleSignIn()
            await bootstrap()
        } catch AuthService.AuthError.stateMismatch {
            lastError = "Sign-in was tampered with. Please try again."
            state = .signedOut
        } catch AuthService.AuthError.userCancelled {
            state = .signedOut
        } catch {
            lastError = error.localizedDescription
            state = .signedOut
        }
    }

    func cancelSignIn() { Task { await auth.cancel() } }

    func signOut() {
        auth.signOut()
        apiClient = nil
        state = .signedOut
    }
}
```

- [ ] **Step 2: Stage for review (do not commit)**

### Task 14: `Networking/APIClient.swift`

**Files:**
- Create: `pencheff-studio/pencheff-studio/Networking/APIClient.swift`
- Create: `pencheff-studio/pencheff-studio/Networking/Endpoints/AuthEndpoints.swift`

- [ ] **Step 1: Implement `APIClient`**

```swift
import Foundation

actor APIClient {
    private let baseURL: URL
    private let keychain: KeychainStore
    private weak var coordinator: AuthCoordinator?
    private let session: URLSession
    private var refreshing: Task<Void, Error>?

    init(baseURL: URL = APIBaseURL.current,
         keychain: KeychainStore = KeychainStore(),
         coordinator: AuthCoordinator,
         session: URLSession = .shared) {
        self.baseURL = baseURL
        self.keychain = keychain
        self.coordinator = coordinator
        self.session = session
    }

    func get<T: Decodable>(_ path: String, query: [URLQueryItem] = []) async throws -> T {
        return try await request(.init(method: "GET", path: path, query: query, body: nil))
    }

    func post<T: Decodable, B: Encodable>(_ path: String, body: B) async throws -> T {
        let data = try JSONDecoding.encoder.encode(body)
        return try await request(.init(method: "POST", path: path, query: [], body: data))
    }

    struct RequestSpec {
        let method: String
        let path: String
        let query: [URLQueryItem]
        let body: Data?
    }

    private func request<T: Decodable>(_ spec: RequestSpec, retried: Bool = false) async throws -> T {
        var comps = URLComponents(url: baseURL.appendingPathComponent(spec.path),
                                  resolvingAgainstBaseURL: false)!
        if !spec.query.isEmpty { comps.queryItems = spec.query }
        guard let url = comps.url else { throw APIError.unknown(URLError(.badURL)) }
        var req = URLRequest(url: url)
        req.httpMethod = spec.method
        req.httpBody = spec.body
        if spec.body != nil { req.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        if let access = try? keychain.get(account: KeychainAccount.accessToken), !access.isEmpty {
            req.setValue("Bearer \(access)", forHTTPHeaderField: "Authorization")
        }

        let (data, resp): (Data, URLResponse)
        do { (data, resp) = try await session.data(for: req) }
        catch let e as URLError { throw APIError.network(e) }
        catch { throw APIError.unknown(error) }

        guard let http = resp as? HTTPURLResponse else { throw APIError.unknown(URLError(.badServerResponse)) }

        if http.statusCode == 401 && !retried {
            try await refreshOnce()
            return try await request(spec, retried: true)
        }
        if http.statusCode == 401 {
            await coordinator?.signOut()
            throw APIError.unauthorized
        }
        if http.statusCode == 400 {
            let body = String(data: data, encoding: .utf8) ?? ""
            if body.contains("X-Workspace-Id") {
                throw APIError.workspaceRequired
            }
        }
        guard (200..<300).contains(http.statusCode) else {
            let message = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["detail"] as? String
                ?? String(data: data, encoding: .utf8)
                ?? "Unknown error"
            throw APIError.server(status: http.statusCode, message: message)
        }
        if T.self == EmptyResponse.self { return EmptyResponse() as! T }
        do { return try JSONDecoding.decoder.decode(T.self, from: data) }
        catch { throw APIError.decoding(error) }
    }

    private func refreshOnce() async throws {
        if let t = refreshing { try await t.value; return }
        let task = Task { try await performRefresh() }
        refreshing = task
        defer { refreshing = nil }
        try await task.value
    }

    private func performRefresh() async throws {
        guard let refresh = try? keychain.get(account: KeychainAccount.refreshToken), !refresh.isEmpty else {
            throw APIError.unauthorized
        }
        struct Body: Encodable { let refresh_token: String }
        struct Pair: Decodable { let access_token: String; let refresh_token: String }
        let url = baseURL.appendingPathComponent("auth/refresh")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONDecoding.encoder.encode(Body(refresh_token: refresh))
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw APIError.unauthorized
        }
        let pair = try JSONDecoding.decoder.decode(Pair.self, from: data)
        try keychain.set(pair.access_token, account: KeychainAccount.accessToken)
        try keychain.set(pair.refresh_token, account: KeychainAccount.refreshToken)
    }
}

struct EmptyResponse: Decodable, Sendable {}
```

- [ ] **Step 2: Implement `AuthEndpoints.swift`**

```swift
import Foundation

extension APIClient {
    func me() async throws -> Me {
        return try await get("/auth/me")
    }
}
```

- [ ] **Step 3: Stage for review (do not commit)**

### Task 15: `UI/Components/LogoView.swift` + `LoadingView.swift` + `ErrorStateView.swift` + `EmptyStateView.swift`

**Files:**
- Create: `pencheff-studio/pencheff-studio/UI/Components/LogoView.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Components/LoadingView.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Components/ErrorStateView.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Components/EmptyStateView.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Components/WorkspaceRequiredView.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Components/ComingSoonView.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Components/SeverityBadge.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Components/StatusBadge.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Components/AccountChip.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Components/SearchField.swift`

- [ ] **Step 1: LogoView**

```swift
import SwiftUI
struct LogoView: View {
    var size: CGFloat = 28
    var body: some View {
        Image("PencheffLogo")
            .resizable().scaledToFit()
            .frame(width: size, height: size)
            .accessibilityLabel("Pencheff")
    }
}
```

- [ ] **Step 2: LoadingView**

```swift
import SwiftUI
struct LoadingView: View {
    var body: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("Loading…").foregroundStyle(Color.Pencheff.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
```

- [ ] **Step 3: ErrorStateView**

```swift
import SwiftUI
struct ErrorStateView: View {
    let error: APIError
    var retry: (() -> Void)? = nil
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.largeTitle).foregroundStyle(Color.Pencheff.Severity.high)
            Text("Something went wrong").font(.headline)
            Text(error.localizedDescription)
                .font(.subheadline).foregroundStyle(Color.Pencheff.textMuted)
                .multilineTextAlignment(.center).padding(.horizontal)
            if let retry { Button("Try again", action: retry).buttonStyle(.borderedProminent) }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
```

- [ ] **Step 4: EmptyStateView**

```swift
import SwiftUI
struct EmptyStateView: View {
    let title: String
    var subtitle: String? = nil
    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: "tray").font(.largeTitle).foregroundStyle(Color.Pencheff.textMuted)
            Text(title).font(.headline)
            if let subtitle { Text(subtitle).font(.subheadline).foregroundStyle(Color.Pencheff.textMuted) }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
```

- [ ] **Step 5: WorkspaceRequiredView**

```swift
import SwiftUI
struct WorkspaceRequiredView: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "rectangle.stack").font(.largeTitle).foregroundStyle(Color.Pencheff.accent)
            Text("Choose a workspace in the web app").font(.headline)
            Text(APIError.workspaceRequired.errorDescription ?? "")
                .font(.subheadline).foregroundStyle(Color.Pencheff.textMuted)
                .multilineTextAlignment(.center).padding(.horizontal)
            Link("Open app.pencheff.com", destination: URL(string: "https://app.pencheff.com")!)
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
```

- [ ] **Step 6: ComingSoonView**

```swift
import SwiftUI
struct ComingSoonView: View {
    let title: String
    let blurb: String
    let webURL: URL?
    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "sparkles").font(.largeTitle).foregroundStyle(Color.Pencheff.accent)
            Text(title).font(.title2.bold())
            Text(blurb).font(.subheadline).foregroundStyle(Color.Pencheff.textMuted)
                .multilineTextAlignment(.center).padding(.horizontal)
            if let webURL {
                Link("Open in browser", destination: webURL).buttonStyle(.borderedProminent)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
```

- [ ] **Step 7: SeverityBadge**

```swift
import SwiftUI
struct SeverityBadge: View {
    let value: String
    var body: some View {
        Text(value.uppercased())
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
    }
    private var color: Color {
        switch value.lowercased() {
        case "critical": Color.Pencheff.Severity.critical
        case "high": Color.Pencheff.Severity.high
        case "medium": Color.Pencheff.Severity.medium
        case "low": Color.Pencheff.Severity.low
        default: Color.Pencheff.Severity.info
        }
    }
}
```

- [ ] **Step 8: StatusBadge**

```swift
import SwiftUI
struct StatusBadge: View {
    let value: String
    var body: some View {
        Text(value)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(Color.Pencheff.surfaceHigh, in: Capsule())
            .foregroundStyle(Color.Pencheff.text)
    }
}
```

- [ ] **Step 9: AccountChip**

```swift
import SwiftUI
struct AccountChip: View {
    let me: Me
    let onSignOut: () -> Void
    var body: some View {
        Menu {
            Text(me.email)
            Divider()
            Button("Sign out", role: .destructive, action: onSignOut)
        } label: {
            HStack(spacing: 8) {
                Circle().fill(Color.Pencheff.accent)
                    .frame(width: 24, height: 24)
                    .overlay(Text(initials(me.name ?? me.email))
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.white))
                Text(me.name ?? me.email).lineLimit(1)
            }
        }
        .menuStyle(.borderlessButton)
    }
    private func initials(_ s: String) -> String {
        let parts = s.split(whereSeparator: { " @.".contains($0) }).prefix(2)
        return parts.compactMap { $0.first }.map(String.init).joined()
    }
}
```

- [ ] **Step 10: SearchField**

```swift
import SwiftUI
struct SearchField: View {
    @Binding var text: String
    var placeholder: String = "Search"
    var body: some View {
        HStack {
            Image(systemName: "magnifyingglass").foregroundStyle(Color.Pencheff.textMuted)
            TextField(placeholder, text: $text).textFieldStyle(.plain)
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background(Color.Pencheff.surfaceHigh, in: RoundedRectangle(cornerRadius: 8))
        .frame(maxWidth: 320)
    }
}
```

- [ ] **Step 11: Stage for review (do not commit)**

### Task 16: `UI/Root/LoginView.swift`

**Files:**
- Create: `pencheff-studio/pencheff-studio/UI/Root/LoginView.swift`

- [ ] **Step 1: Implement**

```swift
import SwiftUI

struct LoginView: View {
    @Environment(AuthCoordinator.self) private var coordinator

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            LogoView(size: 64)
            VStack(spacing: 6) {
                Text("Pencheff Studio").font(.largeTitle.bold())
                Text("Sign in to access your assessments.")
                    .foregroundStyle(Color.Pencheff.textMuted)
            }
            VStack(spacing: 12) {
                if case .signingIn = coordinator.state {
                    ProgressView()
                    Text("Waiting for browser sign-in…").foregroundStyle(Color.Pencheff.textMuted)
                    Button("Cancel") { coordinator.cancelSignIn() }
                } else {
                    Button {
                        coordinator.beginGoogleSignIn()
                    } label: {
                        HStack {
                            Image(systemName: "g.circle.fill")
                            Text("Continue with Google")
                        }
                        .frame(minWidth: 220)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                }
            }
            if let err = coordinator.lastError {
                Text(err).foregroundStyle(Color.Pencheff.Severity.high).font(.callout)
            }
            Spacer()
            Text("By signing in you agree to the Pencheff terms.")
                .font(.caption).foregroundStyle(Color.Pencheff.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.Pencheff.surface)
        .padding()
    }
}
```

- [ ] **Step 2: Stage for review (do not commit)**

### Task 17: `UI/Root/Route.swift`, `SidebarView.swift`, `MainView.swift`, `RootView.swift`

**Files:**
- Create: `pencheff-studio/pencheff-studio/UI/Root/Route.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Root/SidebarView.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Root/MainView.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Root/RootView.swift`

- [ ] **Step 1: `Route.swift`**

```swift
import Foundation

enum Route: Hashable, Identifiable, CaseIterable {
    case dashboard, engagements, scans, findings, reports
    case targets, repos, sboms, dependencies
    case schedules, integrations, apiKeys
    case advisories
    case workspaces, orgMembers, billing, settings, support

    var id: Self { self }

    var title: String {
        switch self {
        case .dashboard: "Dashboard"
        case .engagements: "Engagements"
        case .scans: "Scans"
        case .findings: "Findings"
        case .reports: "Reports"
        case .targets: "Targets"
        case .repos: "Repos"
        case .sboms: "SBOMs"
        case .dependencies: "Dependencies"
        case .schedules: "Schedules"
        case .integrations: "Integrations"
        case .apiKeys: "API Keys"
        case .advisories: "Advisories"
        case .workspaces: "Workspaces"
        case .orgMembers: "Org & Members"
        case .billing: "Billing"
        case .settings: "Settings"
        case .support: "Support"
        }
    }

    var symbol: String {
        switch self {
        case .dashboard: "rectangle.grid.2x2"
        case .engagements: "person.2"
        case .scans: "magnifyingglass"
        case .findings: "exclamationmark.shield"
        case .reports: "doc.text"
        case .targets: "scope"
        case .repos: "chevron.left.forwardslash.chevron.right"
        case .sboms: "shippingbox"
        case .dependencies: "cube.box"
        case .schedules: "calendar"
        case .integrations: "puzzlepiece"
        case .apiKeys: "key"
        case .advisories: "megaphone"
        case .workspaces: "rectangle.stack"
        case .orgMembers: "building.2"
        case .billing: "creditcard"
        case .settings: "gearshape"
        case .support: "lifepreserver"
        }
    }
}

enum RouteGroup: String, CaseIterable, Identifiable {
    case work = "Work"
    case assets = "Assets"
    case pipeline = "Pipeline"
    case advisories = "Advisories"
    case admin = "Admin"

    var id: String { rawValue }

    var routes: [Route] {
        switch self {
        case .work: [.dashboard, .engagements, .scans, .findings, .reports]
        case .assets: [.targets, .repos, .sboms, .dependencies]
        case .pipeline: [.schedules, .integrations, .apiKeys]
        case .advisories: [.advisories]
        case .admin: [.workspaces, .orgMembers, .billing, .settings, .support]
        }
    }
}
```

- [ ] **Step 2: `SidebarView.swift`**

```swift
import SwiftUI

struct SidebarView: View {
    @Binding var selection: Route?
    var body: some View {
        List(selection: $selection) {
            ForEach(RouteGroup.allCases) { group in
                Section(group.rawValue) {
                    ForEach(group.routes) { route in
                        NavigationLink(value: route) {
                            Label(route.title, systemImage: route.symbol)
                        }
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .navigationTitle("Pencheff Studio")
    }
}
```

- [ ] **Step 3: `MainView.swift`**

```swift
import SwiftUI

struct MainView: View {
    @Environment(AuthCoordinator.self) private var coordinator
    let me: Me
    @State private var selection: Route? = .dashboard

    var body: some View {
        NavigationSplitView {
            SidebarView(selection: $selection)
                .navigationSplitViewColumnWidth(min: 220, ideal: 250, max: 320)
        } detail: {
            DetailHost(route: selection ?? .dashboard, api: coordinator.apiClient!)
                .toolbar {
                    ToolbarItem(placement: .navigation) { LogoView(size: 22) }
                    ToolbarItemGroup(placement: .primaryAction) {
                        Text(me.orgName).font(.callout).foregroundStyle(Color.Pencheff.textMuted)
                        AccountChip(me: me, onSignOut: { coordinator.signOut() })
                    }
                }
        }
        .background(Color.Pencheff.surface)
    }
}

private struct DetailHost: View {
    let route: Route
    let api: APIClient

    var body: some View {
        NavigationStack {
            content
        }
    }

    @ViewBuilder private var content: some View {
        switch route {
        case .dashboard:    DashboardView(api: api)
        case .targets:      TargetsListView(api: api)
        case .scans:        ScansListView(api: api)
        case .findings:     FindingsListView(api: api)
        case .reports:      ReportsListView(api: api)
        case .engagements:  EngagementsListView(api: api)
        case .repos:        ReposListView(api: api)

        case .schedules:    SchedulesView()
        case .integrations: IntegrationsView()
        case .apiKeys:      ApiKeysView()
        case .advisories:   AdvisoriesView()
        case .sboms:        SBOMsView()
        case .dependencies: DependenciesView()
        case .workspaces:   WorkspacesView()

        case .orgMembers:
            ComingSoonView(
                title: "Org & Members",
                blurb: "Manage seats, roles, and SSO from the web for now.",
                webURL: URL(string: "https://app.pencheff.com/org"))
        case .billing:
            ComingSoonView(
                title: "Billing",
                blurb: "Plans, invoices, and payment methods stay in the web app in this release.",
                webURL: URL(string: "https://app.pencheff.com/billing"))
        case .settings:
            ComingSoonView(
                title: "Settings",
                blurb: "Org and personal settings are managed in the web app for now.",
                webURL: URL(string: "https://app.pencheff.com/settings"))
        case .support:
            ComingSoonView(
                title: "Support",
                blurb: "Pencheff support sits in the web app. We'll bring it native in a later release.",
                webURL: URL(string: "https://app.pencheff.com/support"))
        }
    }
}
```

- [ ] **Step 4: `RootView.swift`**

```swift
import SwiftUI

struct RootView: View {
    @Environment(AuthCoordinator.self) private var coordinator

    var body: some View {
        switch coordinator.state {
        case .bootstrapping:
            VStack(spacing: 16) { LogoView(size: 56); ProgressView() }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color.Pencheff.surface)
        case .signedOut, .signingIn:
            LoginView()
        case .signedIn(let me):
            MainView(me: me)
        }
    }
}
```

- [ ] **Step 5: Build the project**

In Xcode: ⌘B.

Expected: many "Cannot find type 'DashboardView' in scope" errors — those views still need to be created. As of this task the project should NOT yet build. That's fine; we'll add stubs before running.

To unblock, create empty stubs in the next task.

- [ ] **Step 6: Stage for review (do not commit)**

### Task 18: Stub-out every Wired/Skeleton view referenced by `MainView` so the project compiles

This task adds minimal `View` types so MainView resolves. They get replaced in Phase 6/7.

**Files:**
- Create one-liner stub for each: `DashboardView`, `TargetsListView`, `ScansListView`, `FindingsListView`, `ReportsListView`, `EngagementsListView`, `ReposListView`, `SchedulesView`, `IntegrationsView`, `ApiKeysView`, `AdvisoriesView`, `SBOMsView`, `DependenciesView`, `WorkspacesView`.

- [ ] **Step 1: Drop each stub into the right folder**

For each Wired section, e.g., `UI/Wired/Dashboard/DashboardView.swift`:

```swift
import SwiftUI
struct DashboardView: View {
    let api: APIClient
    var body: some View { Text("Dashboard — stub").navigationTitle("Dashboard") }
}
```

Repeat verbatim for `TargetsListView`, `ScansListView`, `FindingsListView`, `ReportsListView`, `EngagementsListView`, `ReposListView` — each placed under `UI/Wired/<Section>/`, with the section's name as the navigationTitle and the body text.

For each Skeleton section, e.g., `UI/Skeleton/SchedulesView.swift`:

```swift
import SwiftUI
struct SchedulesView: View {
    var body: some View { Text("Schedules — stub").navigationTitle("Schedules") }
}
```

Repeat for `IntegrationsView`, `ApiKeysView`, `AdvisoriesView`, `SBOMsView`, `DependenciesView`, `WorkspacesView`.

- [ ] **Step 2: Build and run**

⌘B + ⌘R.

Expected: app launches into bootstrap → since no tokens are in Keychain → `LoginView` with the "Continue with Google" button.

- [ ] **Step 3: Stage for review (do not commit)**

### Task 19: Manual smoke test — full sign-in dance against a working API

**Files:** none — manual verification.

**Preconditions:** API instance reachable. Either:
- `https://api.pencheff.com` with `GOOGLE_CLIENT_ID` configured, OR
- local `apps/api` running on port 8000 with a working `.env` (Google OAuth creds set).

If using local, set the API base URL once before launching the app:

```bash
defaults write com.pencheff.pencheff-studio PencheffAPIBaseURL http://localhost:8000
```

(To return to prod: `defaults delete com.pencheff.pencheff-studio PencheffAPIBaseURL`.)

- [ ] **Step 1: Run the app, click "Continue with Google"**

Expected:
1. Default browser opens `https://api.pencheff.com/auth/oauth/google/start?desktop_redirect=http://127.0.0.1:<port>/callback&state=...`.
2. Google sign-in completes.
3. Browser shows the "Signed in to Pencheff Studio" card.
4. App window flips from `LoginView` → `MainView` with sidebar.

- [ ] **Step 2: Confirm tokens are in Keychain**

```bash
security find-generic-password -s com.pencheff.pencheff-studio -a access_token -w
```

Expected: a JWT token printed. (`security` may prompt for Keychain access — allow.)

- [ ] **Step 3: Confirm `/auth/me` works**

App should display the user's name in the top-right `AccountChip`. If you see the email instead, `name` is null in the response — acceptable.

- [ ] **Step 4: Click sidebar items**

All 19 routes should switch without crashing. Each shows the stub text.

- [ ] **Step 5: Sign out via the AccountChip menu**

App returns to LoginView.

- [ ] **Step 6: Sign back in and quit / relaunch**

Expected: app starts in `.bootstrapping`, reads Keychain, calls `/auth/me`, jumps to `MainView` without showing LoginView.

- [ ] **Step 7: If any step failed, debug now**

Common issues:
- 501 from `/auth/oauth/google/start` → `GOOGLE_CLIENT_ID` unset on the API instance you're hitting.
- Listener doesn't fire → check macOS Firewall isn't blocking 127.0.0.1.
- `/auth/me` returns 401 → Task 1's `_user_from_native_token` not wired correctly; re-run pytest.

- [ ] **Step 8: Stage for review (do not commit)**

End of Phase 3. Auth + plumbing works end-to-end. Subsequent phases promote stubs to real views.

---

## Phase 4 — Wired sections (data-rendering views)

Each task below applies **Recipe A** (at the top of this document) for one section. After each, build + smoke-test that section's list and detail.

### Task 20: Dashboard (Recipe A — fully spelled out, others reference back)

**Files:**
- Create: `pencheff-studio/pencheff-studio/Networking/Models/DashboardSummary.swift`
- Create: `pencheff-studio/pencheff-studio/Networking/Endpoints/DashboardEndpoints.swift`
- Modify: `pencheff-studio/pencheff-studio/UI/Wired/Dashboard/DashboardView.swift` (replace stub)
- Create: `pencheff-studio/pencheff-studio/UI/Wired/Dashboard/DashboardViewModel.swift`

The Dashboard isn't list+detail — it's an aggregate summary. Spelled out in full here so subsequent recipe-A tasks have a fully-completed reference.

- [ ] **Step 1: Inspect the existing endpoint shape**

```bash
grep -n "@router.get\|@router.post" /Users/balasriharsha/BalaSriharsha/pencheff/apps/api/pencheff_api/routers/dashboard.py | head -30
```

Identify the primary GET — likely `GET /dashboard/summary` or `GET /dashboard`. Read the response schema in `apps/api/pencheff_api/schemas/`. Map every field used to a Swift property.

- [ ] **Step 2: `DashboardSummary.swift`**

```swift
import Foundation

struct DashboardSummary: Decodable, Sendable {
    let openFindings: Int
    let criticalFindings: Int
    let scansThisWeek: Int
    let targetsCount: Int
    let recentScans: [RecentScan]

    struct RecentScan: Decodable, Sendable, Identifiable {
        let id: String
        let target: String
        let status: String
        let createdAt: Date
        enum CodingKeys: String, CodingKey { case id, target, status; case createdAt = "created_at" }
    }

    enum CodingKeys: String, CodingKey {
        case openFindings = "open_findings"
        case criticalFindings = "critical_findings"
        case scansThisWeek = "scans_this_week"
        case targetsCount = "targets_count"
        case recentScans = "recent_scans"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.openFindings = (try? c.decodeIfPresent(Int.self, forKey: .openFindings)) ?? 0
        self.criticalFindings = (try? c.decodeIfPresent(Int.self, forKey: .criticalFindings)) ?? 0
        self.scansThisWeek = (try? c.decodeIfPresent(Int.self, forKey: .scansThisWeek)) ?? 0
        self.targetsCount = (try? c.decodeIfPresent(Int.self, forKey: .targetsCount)) ?? 0
        self.recentScans = (try? c.decodeIfPresent([RecentScan].self, forKey: .recentScans)) ?? []
    }
}
```

If the API's field names differ, adjust `CodingKeys`. The defensive `decodeIfPresent` means unknown / renamed fields render as zeros.

- [ ] **Step 3: `DashboardEndpoints.swift`**

```swift
import Foundation

extension APIClient {
    func dashboardSummary() async throws -> DashboardSummary {
        return try await get("/dashboard/summary")
    }
}
```

- [ ] **Step 4: `DashboardViewModel.swift`**

```swift
import Foundation
import Observation

@MainActor @Observable final class DashboardViewModel {
    enum State { case loading, loaded(DashboardSummary), error(APIError) }
    private(set) var state: State = .loading
    private let api: APIClient
    init(api: APIClient) { self.api = api }
    func load() async {
        state = .loading
        do { state = .loaded(try await api.dashboardSummary()) }
        catch let e as APIError { state = .error(e) }
        catch { state = .error(.unknown(error)) }
    }
}
```

- [ ] **Step 5: Replace the stub `DashboardView.swift`**

```swift
import SwiftUI

struct DashboardView: View {
    @State private var vm: DashboardViewModel
    init(api: APIClient) { _vm = State(initialValue: .init(api: api)) }

    var body: some View {
        Group {
            switch vm.state {
            case .loading: LoadingView()
            case .error(let e):
                if case .workspaceRequired = e { WorkspaceRequiredView() }
                else { ErrorStateView(error: e) { Task { await vm.load() } } }
            case .loaded(let s):
                ScrollView {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), spacing: 16)], spacing: 16) {
                        StatCard(title: "Open findings", value: "\(s.openFindings)")
                        StatCard(title: "Critical", value: "\(s.criticalFindings)",
                                 tint: Color.Pencheff.Severity.critical)
                        StatCard(title: "Scans this week", value: "\(s.scansThisWeek)")
                        StatCard(title: "Targets", value: "\(s.targetsCount)")
                    }
                    .padding()
                    Section {
                        ForEach(s.recentScans) { scan in
                            HStack {
                                Text(scan.target).font(.headline)
                                Spacer()
                                StatusBadge(value: scan.status)
                                Text(scan.createdAt, style: .relative)
                                    .font(.caption).foregroundStyle(Color.Pencheff.textMuted)
                            }
                            .padding(.horizontal).padding(.vertical, 8)
                            Divider()
                        }
                    } header: {
                        Text("Recent scans").font(.headline)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal)
                    }
                }
            }
        }
        .navigationTitle("Dashboard")
        .task { await vm.load() }
    }
}

private struct StatCard: View {
    let title: String
    let value: String
    var tint: Color = Color.Pencheff.accent
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.caption).foregroundStyle(Color.Pencheff.textMuted)
            Text(value).font(.system(size: 32, weight: .semibold, design: .rounded))
                .foregroundStyle(tint)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.Pencheff.surfaceHigh, in: RoundedRectangle(cornerRadius: 12))
    }
}
```

- [ ] **Step 6: Build and run, click Dashboard in sidebar**

Expected: real numbers render. If the API returned a 400 about workspaces → `WorkspaceRequiredView`. If 500 → `ErrorStateView`.

- [ ] **Step 7: Verify the response shape matches**

If StatCard values are all zero, the field names in the API response don't match. Open Web Inspector on the running web app, navigate to dashboard, check the network response, update `CodingKeys` in `DashboardSummary.swift` accordingly.

- [ ] **Step 8: Stage for review (do not commit)**

### Tasks 21–26: Apply Recipe A to remaining wired sections

For each section below, follow Recipe A (top of this document). Substitute the values listed. For each section, also create a `Networking/Models/<Section>.swift` with these fields (defensive `decodeIfPresent`):

| Section | endpoint | model fields |
| --- | --- | --- |
| Targets | `GET /targets` | `id: String`, `name: String?`, `hostname: String?`, `kind: String?`, `createdAt: Date?` |
| Scans | `GET /scans` | `id: String`, `targetName: String?` (mapping `target_name`), `status: String`, `createdAt: Date?`, `findingsCount: Int?` |
| Findings | `GET /findings` | `id: String`, `title: String`, `severity: String`, `status: String`, `scanId: String?`, `createdAt: Date?` |
| Reports | `GET /reports` | `id: String`, `title: String?`, `kind: String?`, `createdAt: Date?`, `downloadUrl: String?` (mapping `download_url`) |
| Engagements | `GET /engagements` | `id: String`, `name: String`, `status: String?`, `createdAt: Date?` |
| Repos | `GET /repos` | `id: String`, `provider: String?`, `fullName: String?` (mapping `full_name`), `defaultBranch: String?` (mapping `default_branch`) |

Each gets four files following Recipe A. The row sub-view (`{Section}Row`) should be a small `HStack` with the primary field on the left, a status / severity badge on the right where applicable. Detail content (`{Section}DetailContent`) is a `Form` with one `LabeledContent` per field — engineer adds fields verbatim from the model.

- [ ] **Task 21: Targets** — Apply Recipe A. Use `SeverityBadge` only where applicable (Targets has no severity → skip badge).
- [ ] **Task 22: Scans** — Apply Recipe A. Show `StatusBadge(value: scan.status)` in the row.
- [ ] **Task 23: Findings** — Apply Recipe A. Show `SeverityBadge(value: finding.severity)` in the row.
- [ ] **Task 24: Reports** — Apply Recipe A. Detail view adds a "Download" button that opens `report.downloadUrl` via `NSWorkspace.shared.open` if set.
- [ ] **Task 25: Engagements** — Apply Recipe A.
- [ ] **Task 26: Repos** — Apply Recipe A. Row shows `provider/full_name`.

Per-task end: build, run, click into the section, verify list + detail. **Stage for review (do not commit)** between sections.

### Task 27: Account (Wired but different shape)

**Files:**
- Create: `pencheff-studio/pencheff-studio/UI/Wired/Account/AccountView.swift`
- Create: `pencheff-studio/pencheff-studio/UI/Wired/Account/AccountViewModel.swift`
- Modify: `pencheff-studio/pencheff-studio/UI/Root/Route.swift` — add `.account` between `.support` and the end, plus to the Admin group as the **last** entry.
- Modify: `pencheff-studio/pencheff-studio/UI/Root/MainView.swift` — add `.account` to the `DetailHost` switch.

- [ ] **Step 1: Extend Route**

In `Route.swift`, add `case account`, give it title `"Account"` and symbol `"person.crop.circle"`. Append to `RouteGroup.admin.routes`.

- [ ] **Step 2: ViewModel + View**

```swift
@MainActor @Observable final class AccountViewModel {
    enum State { case loading, loaded(Me), error(APIError) }
    private(set) var state: State = .loading
    private let api: APIClient
    init(api: APIClient) { self.api = api }
    func load() async {
        do { state = .loaded(try await api.me()) }
        catch let e as APIError { state = .error(e) }
        catch { state = .error(.unknown(error)) }
    }
}

struct AccountView: View {
    @Environment(AuthCoordinator.self) private var coordinator
    @State private var vm: AccountViewModel
    init(api: APIClient) { _vm = State(initialValue: .init(api: api)) }
    var body: some View {
        Group {
            switch vm.state {
            case .loading: LoadingView()
            case .error(let e): ErrorStateView(error: e) { Task { await vm.load() } }
            case .loaded(let me):
                Form {
                    Section("Identity") {
                        LabeledContent("Name", value: me.name ?? "—")
                        LabeledContent("Email", value: me.email)
                    }
                    Section("Organization") {
                        LabeledContent("Org", value: me.orgName)
                        LabeledContent("Plan", value: me.plan)
                    }
                    Section {
                        Button("Sign out", role: .destructive) { coordinator.signOut() }
                    }
                }
                .formStyle(.grouped)
            }
        }
        .navigationTitle("Account")
        .task { await vm.load() }
    }
}
```

- [ ] **Step 3: Wire into MainView's `DetailHost`**

```swift
case .account: AccountView(api: api)
```

- [ ] **Step 4: Build, run, navigate to Account**

Form shows identity + org + plan. Sign-out returns to LoginView.

- [ ] **Step 5: Stage for review (do not commit)**

---

## Phase 5 — Skeleton sections

### Task 28: Apply Recipe B to each Skeleton section

**Files (replace existing stubs):**
- `UI/Skeleton/SchedulesView.swift`
- `UI/Skeleton/IntegrationsView.swift`
- `UI/Skeleton/ApiKeysView.swift`
- `UI/Skeleton/AdvisoriesView.swift`
- `UI/Skeleton/SBOMsView.swift`
- `UI/Skeleton/DependenciesView.swift`
- `UI/Skeleton/WorkspacesView.swift`

- [ ] **Step 1: Define the shared SkeletonRow + SkeletonBanner helpers**

Create `pencheff-studio/pencheff-studio/UI/Skeleton/SkeletonShared.swift`:

```swift
import SwiftUI

struct SkeletonRow: Identifiable, Hashable {
    var id: String { title }
    let title: String
    let subtitle: String
}

struct SkeletonBanner: View {
    let text: String
    var body: some View {
        Text(text)
            .font(.callout)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.Pencheff.accent.opacity(0.12))
            .foregroundStyle(Color.Pencheff.accent)
    }
}
```

- [ ] **Step 2: Replace each skeleton stub**

For `SchedulesView.swift` (others follow the same shape — substitute `Schedules` → `Integrations`, etc.):

```swift
import SwiftUI

struct SchedulesView: View {
    private let seed = [
        SkeletonRow(title: "Weekly scan — staging.example.com", subtitle: "Sun 02:00 UTC · Next run in 4d"),
        SkeletonRow(title: "Nightly scan — api.example.com", subtitle: "Daily 03:00 UTC · Next run in 8h"),
        SkeletonRow(title: "Compliance audit — production", subtitle: "1st of month · Next run in 14d"),
    ]
    var body: some View {
        VStack(spacing: 0) {
            SkeletonBanner(text: "Schedules are read-only on desktop in this release. Use app.pencheff.com to create or edit.")
            List(seed) { row in
                VStack(alignment: .leading, spacing: 4) {
                    Text(row.title).font(.headline)
                    Text(row.subtitle).font(.subheadline).foregroundStyle(Color.Pencheff.textMuted)
                }
                .padding(.vertical, 4)
            }
        }
        .navigationTitle("Schedules")
    }
}
```

Per-section seed content (engineer copies and adapts the three sample rows so they read like real Pencheff data):

| View | Sample row titles |
| --- | --- |
| IntegrationsView | "GitHub — magadhaapps/pencheff", "Jira — PENCH project", "Slack — #security-alerts" |
| ApiKeysView | "Production CI key — created 2026-04-12", "Staging deploy key — created 2026-05-01", "Local dev key — created 2026-05-20" |
| AdvisoriesView | "PNC-2026-0014 — Path traversal in legacy uploader", "PNC-2026-0013 — Outdated openssl pin", "PNC-2026-0012 — Permissive CORS in /api/internal" |
| SBOMsView | "magadhaapps/pencheff — main", "magadhaapps/pencheff — release/1.4", "internal/charts/k8s-admission — v0.9" |
| DependenciesView | "fastapi 0.118.0 — high risk", "sqlalchemy 2.0.41 — medium risk", "authlib 1.6.5 — low risk" |
| WorkspacesView | "Default", "Customer A — assessments", "Customer B — pentest 2026-Q2" |

- [ ] **Step 3: Build and click through each skeleton in the sidebar**

Expected: banner + three rows. No crashes.

- [ ] **Step 4: Stage for review (do not commit)**

---

## Phase 6 — Logos and app icon

### Task 29: Copy Pencheff logo into asset catalog

**Files:**
- Create: `pencheff-studio/pencheff-studio/Assets.xcassets/PencheffLogo.imageset/Contents.json`
- Copy:   `apps/web/public/logo.png` → `pencheff-studio/pencheff-studio/Assets.xcassets/PencheffLogo.imageset/logo.png`

- [ ] **Step 1: Create the imageset folder**

```bash
mkdir -p pencheff-studio/pencheff-studio/Assets.xcassets/PencheffLogo.imageset
cp apps/web/public/logo.png pencheff-studio/pencheff-studio/Assets.xcassets/PencheffLogo.imageset/logo.png
```

- [ ] **Step 2: Write `Contents.json`**

```json
{
  "images": [
    { "idiom": "universal", "filename": "logo.png", "scale": "1x" }
  ],
  "info": { "author": "xcode", "version": 1 }
}
```

- [ ] **Step 3: Build, run** — LoginView and toolbar should show the real Pencheff logo.

- [ ] **Step 4: Stage for review (do not commit)**

### Task 30: App icon

**Files:**
- Modify: `pencheff-studio/pencheff-studio/Assets.xcassets/AppIcon.appiconset/Contents.json`
- Copy: `apps/web/public/icon-192.png` (and downsized variants if needed) into the appiconset.

- [ ] **Step 1: Generate the required macOS app-icon sizes**

macOS expects: 16, 32, 64, 128, 256, 512, 1024 at @1x and @2x. Use `sips` to resize once-per-size from the largest source (`apple-icon.png` is 28K so it's higher-resolution than `icon-192.png`):

```bash
SRC=apps/web/public/apple-icon.png
DEST=pencheff-studio/pencheff-studio/Assets.xcassets/AppIcon.appiconset
for SIZE in 16 32 64 128 256 512 1024; do
  sips -Z $SIZE "$SRC" --out "$DEST/icon_${SIZE}.png"
  sips -Z $((SIZE * 2)) "$SRC" --out "$DEST/icon_${SIZE}@2x.png"
done
```

(`sips` is preinstalled on macOS. `-Z` resizes preserving aspect.)

- [ ] **Step 2: Write `Contents.json`**

```json
{
  "images": [
    { "size": "16x16", "idiom": "mac", "filename": "icon_16.png", "scale": "1x" },
    { "size": "16x16", "idiom": "mac", "filename": "icon_16@2x.png", "scale": "2x" },
    { "size": "32x32", "idiom": "mac", "filename": "icon_32.png", "scale": "1x" },
    { "size": "32x32", "idiom": "mac", "filename": "icon_32@2x.png", "scale": "2x" },
    { "size": "128x128", "idiom": "mac", "filename": "icon_128.png", "scale": "1x" },
    { "size": "128x128", "idiom": "mac", "filename": "icon_128@2x.png", "scale": "2x" },
    { "size": "256x256", "idiom": "mac", "filename": "icon_256.png", "scale": "1x" },
    { "size": "256x256", "idiom": "mac", "filename": "icon_256@2x.png", "scale": "2x" },
    { "size": "512x512", "idiom": "mac", "filename": "icon_512.png", "scale": "1x" },
    { "size": "512x512", "idiom": "mac", "filename": "icon_512@2x.png", "scale": "2x" }
  ],
  "info": { "author": "xcode", "version": 1 }
}
```

(The 1024 you generated isn't referenced for macOS — it's available if you later want App Store distribution.)

- [ ] **Step 3: Build and run.** App icon appears in the Dock.

- [ ] **Step 4: Stage for review (do not commit)**

---

## Phase 7 — End-to-end verification + handoff

### Task 31: End-to-end smoke test against api.pencheff.com

**Files:** none. Manual.

- [ ] **Step 1: Ensure we're pointing at prod**

```bash
defaults delete com.pencheff.pencheff-studio PencheffAPIBaseURL 2>/dev/null || true
```

- [ ] **Step 2: Run the app, sign in with Google**

Verify: browser opens, you sign in, app flips to MainView.

- [ ] **Step 3: Walk every sidebar item**

For each of the 19 routes, click it and observe:

| Section | Expected |
| --- | --- |
| Dashboard | 4 stat cards + recent scans list (real numbers) |
| Engagements | List of engagement rows (real) |
| Scans | List of scan rows with StatusBadge (real) |
| Findings | List of finding rows with SeverityBadge (real) |
| Reports | List of report rows; click → detail with "Download" button if `download_url` present |
| Targets | List of target rows (real) |
| Repos | List of repo rows showing `provider/full_name` (real) |
| SBOMs | Skeleton: banner + 3 placeholder rows |
| Dependencies | Skeleton |
| Schedules | Skeleton |
| Integrations | Skeleton |
| API Keys | Skeleton |
| Advisories | Skeleton |
| Workspaces | Skeleton |
| Org & Members | Placeholder + "Open in browser" |
| Billing | Placeholder + "Open in browser" |
| Settings | Placeholder + "Open in browser" |
| Support | Placeholder + "Open in browser" |
| Account | Real Me data + Sign out |

- [ ] **Step 4: Force a token-refresh path**

```bash
security delete-generic-password -s com.pencheff.pencheff-studio -a access_token
```

Click sidebar → reload current section. Expected: APIClient detects 401, hits `/auth/refresh` using the still-valid refresh token, retries, renders data. App does NOT bounce to LoginView.

- [ ] **Step 5: Force a full sign-out path**

```bash
security delete-generic-password -s com.pencheff.pencheff-studio -a refresh_token
security delete-generic-password -s com.pencheff.pencheff-studio -a access_token
```

Click sidebar. Expected: 401 → refresh fails → app bounces to LoginView.

- [ ] **Step 6: Verify web sign-in still works (regression)**

Open `https://app.pencheff.com/login` in browser. Sign in via Clerk's Google flow. Expected: works exactly as before — our API changes are additive.

- [ ] **Step 7: Run all API tests once more**

```bash
cd apps/api && uv run pytest tests/test_desktop_oauth_flow.py tests/test_api_key_auth_flow.py -q
```

Expected: all PASS.

- [ ] **Step 8: Stage for review (do not commit)**

### Task 32: Files-touched summary

**Files:** none — output only.

- [ ] **Step 1: Print every file the engineer created or modified**

```bash
git -C /Users/balasriharsha/BalaSriharsha/pencheff status
```

Capture the output verbatim. Print it back to the user under the header "## Files touched — review and stage manually".

- [ ] **Step 2: Confirm nothing was committed**

```bash
git -C /Users/balasriharsha/BalaSriharsha/pencheff log -1 --oneline
```

Expected: the topmost commit hash is `203d92d` (or whatever was current at session start) — proof we didn't slip a commit in.

- [ ] **Step 3: End the session**

Output a short summary:
- What works end-to-end (auth, wired sections enumerated).
- What's skeleton vs placeholder.
- What needs the user's attention before shipping (e.g., GOOGLE_CLIENT_ID env on prod API, app icon polish, signing identity for distribution).
- Reminder that nothing was committed.

- [ ] **Step 4: Do NOT stage anything**

End.

---

## Self-Review

**1. Spec coverage** — every spec section maps to at least one task:
- §3 (auth flow): Tasks 11–19.
- §4.1 (`deps.py` change): Task 1.
- §4.2–4.3 (`routers/auth.py` changes): Task 2.
- §5 (Mac app architecture): Tasks 3–18.
- §5.4 (workspace handling): Task 8 (`APIError.workspaceRequired`), Task 14 (mapping in APIClient), Task 15 (`WorkspaceRequiredView`).
- §6 (build/run/env): Tasks 4, 6, 19, 31.
- §7 (risks): each row covered by a task — `desktop_redirect` regex (Task 2), loopback timeout (Task 11), workspace error (Task 14/15), 401 refresh + sign-out (Task 14/31).
- §8 (out of scope): none — explicitly deferred.
- §9 (DoD): Task 31 walks all 10 points.

**2. Placeholder scan** — no `TBD`, `TODO`, or "fill in" instructions. Each step contains the actual code or command. The Recipe-A reference tasks (21–26) list exact substitutions per section instead of vague "similar to" instructions.

**3. Type consistency** — `APIClient`, `AuthCoordinator`, `KeychainStore`, `Me`, `PagedResponse`, `APIError`, `Route`, `RouteGroup` are referenced with consistent names across tasks. `APIError.workspaceRequired` is defined in Task 8 and referenced in Tasks 14, 15. `KeychainAccount.accessToken` / `.refreshToken` defined in Task 7 and referenced in 12, 13, 14. No name drift detected.

**4. Scope check** — single coherent deliverable. Phases (API → foundation → auth → wired → skeleton → assets → verification) are sequential and each phase has a green build at its end (except the intentional mid-Task-17 broken state that Task 18 immediately resolves).
