# Security Lake Toggle — Desktop (macOS) Reflection — Design

**Date:** 2026-06-14
**Status:** Approved design (pre-implementation)
**Builds on:** the web/backend Security Lake enable/disable feature (`2026-06-13-security-lake-enable-disable-design.md`).

## Summary

Reflect the org-level Security Lake enable/disable setting in the **macOS app** (`pencheff-studio`) with an **editable toggle** at parity with the web Settings page: owner/admin can flip it, disabling shows a 7-day-deletion confirmation. The Windows/Electron app is tracked as a follow-up (its source isn't available in this workspace). The backend gating is server-side and already applies to all clients — this work is purely the desktop UI + the two model fields needed to read/write the flag.

## Confirmed decisions

| Decision   | Choice                                                                            |
| ---------- | --------------------------------------------------------------------------------- |
| App        | **macOS (`pencheff-studio`, Swift/SwiftUI)** now; Electron = documented follow-up |
| UX         | **Editable toggle** (web parity), not read-only                                   |
| Permission | Owner/admin only; members see it read-only/disabled                               |
| Disable UX | Confirmation dialog warning lake data is deleted after 7 days                     |
| Repo       | `~/BalaSriharsha/pencheff-studio` (its own git repo — own branch/commit/push)     |
| Docs       | spec/plan live in the monorepo `docs/superpowers/` (Security Lake doc family)     |

## Backend contract (already shipped)

- `GET /orgs/{id}` / orgs list → `OrgOut.security_lake_enabled: bool`.
- `PATCH /orgs/{id}` body `{ "security_lake_enabled": true|false }` (owner/admin) flips it; disabling starts a 7-day purge clock server-side.
- `/security-lake/*` returns 403 when disabled. The macOS app does **not** call those endpoints today (only `/findings`, `/scans`, `/repos/...`), so no client-side gating/error handling is needed beyond the toggle.

## 1. `Networking/Models/Org.swift`

Add `securityLakeEnabled: Bool`, mirroring the existing `allowPrivateTargets` decode exactly:

- new stored prop `let securityLakeEnabled: Bool`
- `CodingKeys`: `case securityLakeEnabled = "security_lake_enabled"`
- in `init(from:)`: `self.securityLakeEnabled = (try? c.decodeIfPresent(Bool.self, forKey: .securityLakeEnabled)) ?? false`

(Update the doc-comment that says the compliance toggles are "surfaced read-only" — security_lake is now editable.)

## 2. `Networking/Models/OrgUpdate.swift`

Add the optional field so PATCH can send it (nil-omitted on encode, like `name`):

- `let securityLakeEnabled: Bool?`
- `CodingKeys`: add `case securityLakeEnabled = "security_lake_enabled"`
- Existing callers construct `OrgUpdate(name:)` — add `securityLakeEnabled: nil` default OR make the initializer's params defaulted (`init(name: String? = nil, securityLakeEnabled: Bool? = nil)`) so the existing `OrgUpdate(name:)` call site in `SettingsView.saveOrg()` keeps compiling. Encoding must omit nil keys (use `encodeIfPresent` in an explicit `encode(to:)`, or rely on the default Codable behavior — match how `name` is currently encoded; if the struct uses synthesized Codable, add an explicit `encode(to:)` that only encodes non-nil fields so a name-only save doesn't send `security_lake_enabled: null`).

## 3. `UI/Wired/Settings/SettingsView.swift` — the toggle

In the **Organization** section, add a Security Lake control:

- **State:** a `@State private var securityLakeEnabled: Bool` buffer, initialised from `org.securityLakeEnabled` when the view loads/`org` changes (mirror how `orgName` is seeded from `org.name`).
- **Owner/admin gate:** `let canManage = org.role == "owner" || org.role == "admin"`. For members, render a read-only `LabeledContent("Security Lake", value: enabled ? "Enabled" : "Disabled")` (consistent with the existing read-only flag rows). For owner/admin, render the editable `Toggle`.
- **Toggle behavior** (owner/admin): a SwiftUI `Toggle("Security Lake", isOn: …)` driven through a custom `Binding` (or `.onChange`) so we can intercept the _disable_ transition:
  - **Enable (off→on):** call `saveSecurityLake(true)` directly.
  - **Disable (on→off):** do NOT save immediately — set `showDisableConfirm = true` and keep the toggle visually on until confirmed; a `.confirmationDialog`/`.alert` titled "Disable Security Lake?" warns that ingestion stops and **lake data is deleted after 7 days unless re-enabled**, with a destructive "Disable" button → `saveSecurityLake(false)`, and a "Cancel" that leaves it enabled.
- **`saveSecurityLake(_ value: Bool)`** (async, mirrors the existing `saveOrg()`):
  - `let updated = try await api.updateOrg(id: me.orgId, body: OrgUpdate(securityLakeEnabled: value))`
  - on success: `org = updated`; sync the `securityLakeEnabled` buffer from `updated.securityLakeEnabled`.
  - on failure: revert the buffer to the previous value and surface the error via the existing error-presentation mechanism used by `saveOrg`/`MutationButton`.
- A short caption under the control: what the Security Lake does + "Disabled by default; disabling deletes lake data after 7 days."

Reuse the section's existing async/error affordances (`MutationButton` pattern or the same error state `saveOrg` uses) rather than inventing a new one.

## 4. Verification

No full Xcode in this workspace (Command Line Tools only) — **cannot `xcodebuild` the app target here**. Verification is therefore:

- Match the existing Swift patterns exactly (Org/OrgUpdate/SettingsView).
- `swiftc -parse` the standalone model files (`Org.swift`, `OrgUpdate.swift`) where the imports resolve, as a syntax check.
- **Final build/run is done by the user in Xcode.** No success claim beyond the syntax check + pattern review.

## 5. Electron (`pencheff-studio-windows`) — follow-up (not built here)

Source not in this workspace. The equivalent changes, to apply in that repo separately:

- Add `security_lake_enabled?: boolean` to the TS `Org` type.
- Add an editable toggle to the org/settings screen (owner/admin gated) that `PATCH`es `/orgs/{id}` with `{ security_lake_enabled }` and refreshes.
- Replicate the disable-confirm dialog (7-day deletion warning).
- No lake-query UI exists, so no 403 handling needed.

A short follow-up note will capture this for the Windows repo.

## Out of scope

- Any lake-viewing UI in desktop (none exists; not adding one here).
- Client-side handling of `/security-lake/*` 403 (desktop doesn't call those endpoints).
- Changing the backend (done) or the web app (done).
