# Pencheff Studio — native macOS desktop app

**Status:** Approved design. Implementation plan to follow.
**Date:** 2026-05-22
**Owner:** balasriharsha
**Repos touched:** `pencheff-studio/` (existing SwiftUI Xcode skeleton) + `apps/api/` (two small auth changes)
**Commit policy:** **Do not commit or push anything in this work.** Files are written, build artifacts are inspectable, but `git add` / `git commit` / `git push` are out of scope.

---

## 1. Goal

Ship a native macOS app, "Pencheff Studio", that mirrors the Pencheff web app for enterprise users who prefer a desktop client. Login is "Continue with Google" handed off to the user's default browser (RFC 8252 loopback redirect). After login, every screen is a SwiftUI native view that reads/writes via `https://api.pencheff.com`.

The Xcode skeleton already exists at `pencheff-studio/pencheff-studio.xcodeproj` (SwiftUI, macOS 26.4, bundle `com.pencheff.pencheff-studio`).

## 2. Scope decision

The web app has 30+ sections. Full native parity in one session is not realistic. Scope is explicitly tiered:

- **Wired (real data):** Dashboard, Targets, Scans, Findings, Reports, Engagements, Repos, Account/Me.
- **Skeleton (real navigation, placeholder rows from typed seeds):** Schedules, Integrations, API Keys, Advisories, SBOMs, Dependencies, Workspaces.
- **Placeholder (`ComingSoonView` + "Open in browser" deep link):** Org & Members, Billing, Settings, Support.

If the session ends mid-tier, anything not built slides down to the next tier. **The build never breaks.** Subsequent sessions promote Skeleton → Wired and Placeholder → Skeleton.

## 3. Identity / auth path

### 3.1 The constraint

The web app authenticates via Clerk. `apps/api/pencheff_api/auth/deps.py::get_current_user` only validates Clerk JWTs and API keys. The API's *native* auth path (`/auth/login`, `/auth/oauth/google/*`, `/auth/refresh`, `make_access_token`) issues JWTs that no other endpoint currently accepts — dead-end code as shipped.

### 3.2 The decision

Use the native API JWT path and teach `get_current_user` to validate native JWTs as a fallback after Clerk fails. Desktop app stays independent of Clerk. ~15 lines of API change.

### 3.3 The auth flow (RFC 8252 loopback)

```
Mac App                          Default Browser              api.pencheff.com         accounts.google.com

1. user taps "Continue with Google"
2. generate state nonce (CryptoKit, 32 bytes base64url)
3. start http://127.0.0.1:<random-port>/callback listener (Network.framework)
4. NSWorkspace.shared.open(.../auth/oauth/google/start?desktop_redirect=…&state=…)
                              ─────────────────────►
                                                        5. validates loopback URI regex
                                                        6. stashes redirect + state in request.session
                                                        7. 302 ──────────────────►
                                                                                    8. Google auth UI (user signs in)
                                                        9. 302 with code  ◄──────
                                                        10. exchanges code, provisions user
                                                        11. issues access + refresh JWTs
                                                        12. 302 to http://127.0.0.1:<port>/callback?access_token=…&refresh_token=…&state=…
                              ◄─────────────────────────
13. local listener captures, validates state matches the one it sent
14. writes tokens to Keychain
15. serves a small HTML page: "Signed in. You can close this tab." (history.replaceState clears the URL)
16. closes listener, transitions UI to MainView
```

API calls thereafter:

```
Mac App ──Authorization: Bearer <access>──► api.pencheff.com
         ◄── 200 / 401 ──
On 401: POST /auth/refresh → persist new pair → retry once. On 2nd 401 → sign out.
```

### 3.4 Token storage

macOS Keychain via `Security` framework. `kSecClassGenericPassword`. Service `com.pencheff.pencheff-studio`. Two accounts: `access_token`, `refresh_token`. Attribute `kSecAttrAccessibleAfterFirstUnlock`. Bundle-scoped (no Keychain access group sharing).

## 4. API changes (`apps/api/`)

### 4.1 `auth/deps.py::_user_from_token` — fallback to native JWTs

In `_user_from_token`, after the Clerk decode raises `InvalidTokenError`, try the native path:

```python
try:
    payload = decode_clerk_jwt(token)
    # … existing Clerk path (lookup by google_sub, sync plan)
except jwt.InvalidTokenError:
    try:
        native = decode_token(token)   # from auth.jwt
    except Exception:
        raise HTTPException(401, "invalid or expired token")
    if native.get("type") != "access":
        raise HTTPException(401, "not an access token")
    user = await session.get(User, native["sub"])
    if user is None or not user.is_active:
        raise HTTPException(401, "user not found")
    request.state.auth_kind = "session"
    return user
```

No plan sync for native users — their `Org` row already has a plan from `_provision_tenancy` in `google_callback`. `request.state.auth_kind` stays `"session"` so `session_only` endpoints work.

### 4.2 `routers/auth.py::google_start` — `desktop_redirect` query param

```python
@router.get("/oauth/google/start")
async def google_start(
    request: Request,
    desktop_redirect: str | None = None,
    state: str | None = None,
):
    if "google" not in oauth._registry:
        raise HTTPException(501, "google oauth not configured")
    if desktop_redirect is not None:
        if not re.fullmatch(r"http://127\.0\.0\.1:\d{4,5}/callback", desktop_redirect):
            raise HTTPException(400, "invalid desktop_redirect")
        request.session["desktop_redirect"] = desktop_redirect
        request.session["desktop_state"] = state or ""
    else:
        request.session.pop("desktop_redirect", None)
        request.session.pop("desktop_state", None)
    return await oauth.google.authorize_redirect(request, settings.google_redirect_uri)
```

Loopback-only regex is strict. Any other value → 400.

### 4.3 `routers/auth.py::google_callback` — alternate redirect target

Inside the existing callback, after `make_access_token` / `make_refresh_token`:

```python
desktop_redirect = request.session.pop("desktop_redirect", None)
desktop_state = request.session.pop("desktop_state", "")
if desktop_redirect:
    # Loopback — query params stay on the user's machine.
    url = (f"{desktop_redirect}?access_token={access}"
           f"&refresh_token={refresh_token}"
           f"&state={desktop_state}")
    return RedirectResponse(url=url)
# existing fragment-redirect to web stays for browser users
redirect = f"{settings.web_base_url}/oauth/callback#access_token={access}&refresh_token={refresh_token}"
return RedirectResponse(url=redirect)
```

### 4.4 What does NOT change

- `SessionMiddleware` is already configured in `apps/api/pencheff_api/main.py:68` with `secret_key=settings.jwt_secret`. No middleware change needed.
- `authlib` already registered. No new dependency.
- Web auth flow (Clerk path) untouched — same code paths, same JWT validation, same `/oauth/callback` redirect when `desktop_redirect` is absent.

## 5. Mac app architecture (`pencheff-studio/`)

### 5.1 Window structure

- One `WindowGroup` rendered by `RootView`. State machine in `AuthCoordinator` (`@Observable`):
  - `.bootstrapping` → splash while Keychain is read
  - `.signedOut` → `LoginView`
  - `.signingIn` → `LoginView` with progress + cancel
  - `.signedIn(Me)` → `MainView`
- `MainView` = two-column `NavigationSplitView` (sidebar 250pt min, detail flexible). Sections that need list+detail (Targets, Scans, Findings, Reports, Engagements, Repos) host their own internal `NavigationStack` inside the detail column, so the master-list and detail stack within one section without leaving an empty middle column on non-list sections like Dashboard.
- Toolbar: logo (left), search field (center, ⌘F), workspace label pill (read-only in v1; clickable picker comes when Workspaces is promoted from Skeleton → Wired), account chip with avatar/initials (right).
- Menu bar: Pencheff Studio → About / Settings… / Sign out. File → New Scan / New Target. View → toggles per section.

### 5.2 Sidebar (mirrors web nav)

```
WORK         Dashboard, Engagements, Scans, Findings, Reports
ASSETS       Targets, Repos, SBOMs, Dependencies
PIPELINE     Schedules, Integrations, API Keys
ADVISORIES   Advisories
ADMIN        Workspaces, Org & Members, Billing, Settings, Support
```

Each row is `NavigationLink(value: Route.foo)`. `Route` is a `Hashable` enum.

### 5.3 Folder layout

```
pencheff-studio/pencheff-studio/
  PencheffStudioApp.swift
  Info.plist                          (no URL schemes; loopback only)
  Assets.xcassets/
  Auth/
    AuthCoordinator.swift
    AuthService.swift                 (Google OAuth dance)
    KeychainStore.swift
    LoopbackServer.swift              (Network.framework HTTP listener)
  Networking/
    APIClient.swift                   (actor; auto-refresh on 401)
    APIError.swift
    APIBaseURL.swift                  (Info.plist / UserDefaults override)
    Endpoints/
      AuthEndpoints.swift             (/auth/me, /auth/refresh)
      DashboardEndpoints.swift
      TargetsEndpoints.swift
      ScansEndpoints.swift
      FindingsEndpoints.swift
      ReportsEndpoints.swift
      EngagementsEndpoints.swift
      ReposEndpoints.swift
    Models/
      Me.swift, Target.swift, Scan.swift, Finding.swift, Report.swift,
      Engagement.swift, Repo.swift, …
  UI/
    Root/
      RootView.swift, LoginView.swift, MainView.swift, SidebarView.swift
    Components/
      LogoView.swift, AccountChip.swift, SearchField.swift,
      EmptyStateView.swift, ErrorStateView.swift, LoadingView.swift,
      SeverityBadge.swift, StatusBadge.swift
    Wired/
      Dashboard/ DashboardView.swift, DashboardViewModel.swift
      Targets/   TargetsListView.swift, TargetDetailView.swift, TargetsViewModel.swift
      Scans/, Findings/, Reports/, Engagements/, Repos/, Account/
    Skeleton/
      Schedules/, Integrations/, ApiKeys/, Advisories/, SBOMs/, Dependencies/, Workspaces/
    Placeholder/
      ComingSoonView.swift
```

### 5.4 Networking layer

`APIClient` is a Swift `actor`. Responsibilities:

- Hold the base `URL` (from `APIBaseURL.swift`).
- Sign every outbound request with `Authorization: Bearer <access>` from Keychain.
- On 401, call `POST /auth/refresh` with the refresh token, persist new pair, retry the original request **once**.
- On second 401 (or refresh failure), publish `AuthCoordinator.signOut()` and propagate `APIError.unauthorized`.
- Map non-2xx to `APIError.server(status:, message:)`.
- Decode bodies with `JSONDecoder(.iso8601withFractionalSeconds)`; all models use `decodeIfPresent` defensively so unknown / renamed fields don't crash the app.

**Workspace header (`X-Workspace-Id`) in v1:** the client does **not** send this header. The API (`auth/deps.py::_resolve_active_workspace`) auto-falls-back to the user's sole workspace when they belong to exactly one org with exactly one workspace, which covers the typical first-time Google sign-up that `_provision_tenancy` creates. Users with multiple orgs / workspaces will receive a 400 "missing X-Workspace-Id header" — `APIClient` maps that specific 400 to `APIError.workspaceRequired`, and Wired list views render an explicit error: *"Pencheff Studio v1 only supports single-workspace accounts. Use app.pencheff.com to pick a workspace; workspace selection on desktop ships in a later release."* A real switcher arrives when Workspaces is promoted to Wired.

```swift
actor APIClient {
    private let baseURL: URL
    private let keychain: KeychainStore
    private let coordinator: AuthCoordinator
    private let urlSession: URLSession

    func get<T: Decodable>(_ path: String, query: [URLQueryItem] = []) async throws -> T
    func post<T: Decodable>(_ path: String, body: Encodable) async throws -> T
    // patch, delete same shape
}
```

### 5.5 Styling

- Custom `Color` extension reading asset-catalog color sets named `pencheff/accent`, `pencheff/surface`, `pencheff/surfaceHigh`, `pencheff/text`, `pencheff/textMuted`, `pencheff/severity{critical|high|medium|low|info}`.
- Dark-by-default to match the web dashboard. Light mode follows system via appearance variants in the catalog.
- System fonts (SF Pro Display on macOS 26). No custom fonts shipped.

## 6. Build, run, env

### 6.1 Toolchain

- Xcode 26, target macOS 26.4 (already in `project.pbxproj`).
- No external Swift packages. Frameworks used: `SwiftUI`, `Network`, `Security`, `Foundation`, `AppKit` (for `NSWorkspace.shared.open`).

### 6.2 Entitlements

- `com.apple.security.app-sandbox = true`
- `com.apple.security.network.client = true` (outbound HTTPS)
- `com.apple.security.network.server = true` (loopback OAuth listener)
- Hardened runtime default. Keychain access group: bundle ID only.

### 6.3 API base URL

- **Build default:** `https://api.pencheff.com` baked into `APIBaseURL.swift`.
- **`Info.plist` override:** key `PencheffAPIBaseURL` (string). QA builds aimed at staging.
- **User defaults override:** `defaults write com.pencheff.pencheff-studio PencheffAPIBaseURL http://localhost:8000` for local dev against the docker stack — no rebuild needed.

### 6.4 No `.env` file

Explicit: the desktop app ships with **no secrets**. No Clerk publishable key, no LLM key, no DB URL. The only configurable value is the API base URL (above), pulled from `apps/api/.env.example` documentation, baked into the Swift binary at build time. If a `.env` file is wanted later for some specific reason, that's a follow-up.

### 6.5 Logos

Copied from `apps/web/public/`:
- `logo.png` → `Assets.xcassets/PencheffLogo.imageset/` (used in toolbar + login screen).
- `icon-192.png`, `icon-64.png`, `icon-32.png` → `Assets.xcassets/AppIcon.appiconset/`, expanded to the macOS sizes Xcode expects (16/32/64/128/256/512/1024 @1x/@2x). Where no clean source size exists, scale `icon-192.png` with sharp interpolation; the user can swap in hand-tuned art later.

## 7. Risk register

| Risk | Trigger | Mitigation |
| --- | --- | --- |
| Prod `GOOGLE_CLIENT_ID` unset | First sign-in returns 501 | Spec flags this. Operator sets the env var on api.pencheff.com or runs the app against `localhost:8000`. |
| `JWT_SECRET` rotation | All desktop sessions invalidated | Acceptable — same blast radius as Clerk session-cookie rotation. |
| Loopback port already bound | Picked port collides with another process | OS-assigned random port (`NWListener` with port `nil`). On bind failure, surface "Couldn't start sign-in listener — try again." |
| User closes browser mid-flow | Listener idle | 10-minute timeout. On expiry the listener cancels and UI returns to `.signedOut`. |
| Tokens visible in browser history | `?access_token=` in loopback URL | Loopback — never leaves the user's machine, but the served HTML calls `history.replaceState(null, '', '/')` on load and sets `Cache-Control: no-store`. |
| Out-of-time mid-build | Session ends before all Wired sections compile | Tier ordering Wired → Skeleton → Placeholder. Unfinished sections demote to Placeholder. Build never breaks. |
| Web app API schemas drift | Renamed / removed fields | All `Codable` models use `decodeIfPresent`; unknown fields ignored. |
| Existing web flow regressed | Anyone signing in via web | API change is additive: `desktop_redirect` defaults `None`; the existing fragment-redirect path runs unchanged. |
| User belongs to multiple orgs / workspaces | Wired sections hit 400 "missing X-Workspace-Id" | `APIClient` maps to `APIError.workspaceRequired`; the affected list view renders a clear message pointing the user to `app.pencheff.com`. No crash; rest of app still works. Real fix is promoting Workspaces to Wired in a later release. |

## 8. Out of scope (deferred to later sessions)

- App auto-update (Sparkle).
- Notifications (`UNUserNotificationCenter`) for scan completion events.
- Background SSE / WebSocket listening for live scan progress.
- Settings UI for changing API base URL / signing out other devices.
- macOS share extension for "Pentest this URL" from Safari.
- Notarization / distribution (DMG, Developer ID signing) — local-build only for v1.
- iOS / iPad / watchOS / visionOS targets.

## 9. Definition of done

At session end:

1. Open `pencheff-studio.xcodeproj`, build, run — clean build, no warnings introduced.
2. "Continue with Google" → default browser opens to `https://api.pencheff.com/auth/oauth/google/start?desktop_redirect=…&state=…`.
3. Sign in with Google → browser shows "Signed in. You can close this tab." → main window appears.
4. Dashboard renders real data from `api.pencheff.com`.
5. Targets / Scans / Findings / Reports / Engagements / Repos lists render real rows; detail views render real data.
6. Account chip → "Sign out" clears Keychain, returns to `LoginView`.
7. Skeleton sections (Schedules, Integrations, …) open without crashing; placeholder rows + "Available in a future release" banner.
8. Placeholder sections (Billing, Settings, …) show `ComingSoonView` + "Open in browser" link.
9. Two API changes verified: web sign-in flow still works (Clerk JWTs validated normally) AND desktop flow works (native JWTs accepted; loopback redirect honored).
10. **Nothing committed, nothing pushed.** End-of-session summary lists every file touched, in both `pencheff-studio/` and `apps/api/`, for the user to review and stage themselves.
