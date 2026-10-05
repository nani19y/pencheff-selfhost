# Security Lake Toggle — macOS Desktop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an editable, owner/admin-gated Security Lake enable/disable toggle (with a 7-day-deletion disable confirmation) to the macOS app's Settings, at parity with the web.

**Architecture:** Two model fields (`Org.securityLakeEnabled` read; `OrgUpdate.securityLakeEnabled` write) + a SwiftUI `Toggle` in `SettingsView`'s Organization section that PATCHes `/orgs/{id}` via the existing `APIClient`. Backend gating is server-side and already live — this is desktop UI + the two Codable fields only.

**Tech Stack:** Swift 6 / SwiftUI, Xcode project (`pencheff-studio`). The generic `APIClient.patch` + `updateOrg(id:body:)` already exist.

**Spec:** `docs/superpowers/specs/2026-06-14-security-lake-desktop-design.md`.

## ⚠️ Repo + verification constraints (read first)

- **This work is in a SEPARATE repo:** `/Users/balasriharsha/BalaSriharsha/pencheff-studio` (NOT the monorepo). Create a branch there: `git -C /Users/balasriharsha/BalaSriharsha/pencheff-studio checkout -b feat/security-lake-toggle`. All commits in Tasks 1–2 happen in that repo. (The plan/spec docs stay in the monorepo.)
- **No full Xcode in this workspace** (Command Line Tools only) → `xcodebuild` cannot build the app. Verification per task is: `swiftc -parse <file>` (syntax check — confirmed working for these files) + exact pattern-matching against the existing code. **Final build/run is the user's, in Xcode.** Do NOT claim the app builds.

## File structure (all under `pencheff-studio/pencheff-studio/`)

| File                                   | Change                                                |
| -------------------------------------- | ----------------------------------------------------- |
| `Networking/Models/Org.swift`          | + `securityLakeEnabled: Bool` (decode, default false) |
| `Networking/Models/OrgUpdate.swift`    | + `securityLakeEnabled: Bool?` + defaulted init       |
| `UI/Wired/Settings/SettingsView.swift` | Security Lake toggle + confirm + `saveSecurityLake`   |

---

## Task 1: Model fields (`Org` + `OrgUpdate`)

**Repo:** `/Users/balasriharsha/BalaSriharsha/pencheff-studio` (branch `feat/security-lake-toggle`).

- [ ] **Step 1: Edit `Networking/Models/Org.swift`**

Add the stored property after `allowPrivateTargets`:

```swift
    let securityLakeEnabled: Bool
```

Add to `CodingKeys` (after the `allowPrivateTargets` case):

```swift
        case securityLakeEnabled = "security_lake_enabled"
```

Add to `init(from:)` (after the `allowPrivateTargets` decode line):

```swift
        self.securityLakeEnabled = (try? c.decodeIfPresent(Bool.self, forKey: .securityLakeEnabled)) ?? false
```

Update the type's doc-comment: change the note so it no longer implies _all_ org flags are read-only — `security_lake_enabled` is editable from the Mac app now (the deterministic/private-targets flags remain read-only).

- [ ] **Step 2: Edit `Networking/Models/OrgUpdate.swift`**

Replace the struct body so it gains the optional field AND a defaulted initializer (so the existing `OrgUpdate(name: trimmed)` call keeps compiling):

```swift
struct OrgUpdate: Codable, Sendable {
    let name: String?
    let securityLakeEnabled: Bool?

    init(name: String? = nil, securityLakeEnabled: Bool? = nil) {
        self.name = name
        self.securityLakeEnabled = securityLakeEnabled
    }

    enum CodingKeys: String, CodingKey {
        case name
        case securityLakeEnabled = "security_lake_enabled"
    }
}
```

(Swift's synthesized encoder uses `encodeIfPresent` for optionals, so a nil field is omitted from the JSON body — `OrgUpdate(name:)` sends only `name`, `OrgUpdate(securityLakeEnabled:)` sends only `security_lake_enabled`. Even if a null were sent, the backend's `update_org` skips `None` fields, so it's harmless either way.)

- [ ] **Step 3: Syntax-check both files**

Run (from `/Users/balasriharsha/BalaSriharsha/pencheff-studio`):

```bash
swiftc -parse pencheff-studio/Networking/Models/Org.swift && echo "Org OK"
swiftc -parse pencheff-studio/Networking/Models/OrgUpdate.swift && echo "OrgUpdate OK"
```

Expected: both print OK, no parse errors. (This is syntax-only; full typecheck happens in Xcode.)

- [ ] **Step 4: Commit (in the pencheff-studio repo)**

```bash
git -C /Users/balasriharsha/BalaSriharsha/pencheff-studio add pencheff-studio/Networking/Models/Org.swift pencheff-studio/Networking/Models/OrgUpdate.swift
git -C /Users/balasriharsha/BalaSriharsha/pencheff-studio commit -m "feat(security-lake): Org.security_lake_enabled read + OrgUpdate write field"
```

---

## Task 2: Settings toggle (`SettingsView.swift`)

**File:** `pencheff-studio/pencheff-studio/UI/Wired/Settings/SettingsView.swift`.

- [ ] **Step 1: Add state vars**

After the existing editable-buffer `@State` vars (near `orgName`/`workspaceName`), add:

```swift
    @State private var securityLakeEnabled: Bool = false
    @State private var securityLakeSaving = false
    @State private var showSecurityLakeDisableConfirm = false
```

- [ ] **Step 2: Seed the buffer in `load()`**

In `load()`, right after `orgName = o.name`, add:

```swift
            securityLakeEnabled = o.securityLakeEnabled
```

- [ ] **Step 3: Add the control to `organizationSection`**

Inside the `Section("Organization")`, after the `allowPrivateTargets` `LabeledContent` block and before the `MutationButton(label: "Save organization")`, insert:

```swift
                if org.role == "owner" || org.role == "admin" {
                    Toggle("Security Lake", isOn: Binding(
                        get: { securityLakeEnabled },
                        set: { newValue in
                            if newValue {
                                securityLakeEnabled = true                 // optimistic
                                Task { await saveSecurityLake(true, revertTo: false) }
                            } else {
                                showSecurityLakeDisableConfirm = true      // confirm before disabling
                            }
                        }
                    ))
                    .disabled(securityLakeSaving)
                } else {
                    LabeledContent("Security Lake", value: securityLakeEnabled ? "Enabled" : "Disabled")
                }
```

Then update the section's trailing caption `Text(...)` to mention the lake, e.g. append a sentence:

```swift
                Text("Only owners and admins can rename the org or toggle the Security Lake. The Security Lake is disabled by default; disabling it stops ingestion and deletes your lake data after 7 days unless you re-enable. Compliance toggles (deterministic mode, private targets) live in the web admin app.")
                    .font(.caption)
                    .foregroundStyle(Color.Pencheff.textMuted)
```

- [ ] **Step 4: Attach the disable-confirm dialog**

Attach a `.confirmationDialog` to the `organizationSection`'s `Section` (mirror the `localDataSection` clear-confirm pattern). Add these modifiers to the `Section("Organization") { ... }`:

```swift
            .confirmationDialog(
                "Disable Security Lake?",
                isPresented: $showSecurityLakeDisableConfirm,
                titleVisibility: .visible
            ) {
                Button("Disable", role: .destructive) {
                    securityLakeEnabled = false                          // optimistic
                    Task { await saveSecurityLake(false, revertTo: true) }
                }
                Button("Cancel", role: .cancel) { }
            } message: {
                Text("New findings stop ingesting and the Security Lake is turned off for your org. Your lake data is permanently deleted 7 days from now unless you re-enable before then.")
            }
```

- [ ] **Step 5: Add the `saveSecurityLake` method**

Next to `saveOrg()`, add:

```swift
    private func saveSecurityLake(_ value: Bool, revertTo: Bool) async {
        securityLakeSaving = true
        defer { securityLakeSaving = false }
        do {
            let updated = try await api.updateOrg(
                id: me.orgId,
                body: OrgUpdate(securityLakeEnabled: value)
            )
            org = updated
            securityLakeEnabled = updated.securityLakeEnabled
        } catch {
            securityLakeEnabled = revertTo                              // roll back the optimistic flip
            mutationErrorMessage = "Couldn't update Security Lake: \(error)"
            showMutationError = true
        }
    }
```

(`mutationErrorMessage`/`showMutationError` already drive the `.alert("Couldn't save")` in `body`, so the failure surfaces through the existing alert.)

- [ ] **Step 6: Syntax-check**

Run (from the repo root): `swiftc -parse pencheff-studio/UI/Wired/Settings/SettingsView.swift && echo "SettingsView OK"` — expect OK (syntax-only; SwiftUI symbol resolution + the full build happen in Xcode).

- [ ] **Step 7: Commit**

```bash
git -C /Users/balasriharsha/BalaSriharsha/pencheff-studio add pencheff-studio/UI/Wired/Settings/SettingsView.swift
git -C /Users/balasriharsha/BalaSriharsha/pencheff-studio commit -m "feat(security-lake): editable Security Lake toggle in Settings (owner/admin, disable-confirm)"
```

- [ ] **Step 8: Hand off for Xcode verification**

Print the explicit manual-verification checklist for the user (cannot run here): open in Xcode → build → Settings → Organization: toggle ON enables (PATCH succeeds, persists on reload); toggle OFF shows the 7-day warning, confirming disables; a member (non-owner/admin) account sees the read-only "Enabled/Disabled" row; a failed PATCH shows the "Couldn't save" alert and reverts the toggle.

---

## Task 3: Electron follow-up note

**File (monorepo):** `docs/superpowers/specs/2026-06-14-security-lake-desktop-electron-followup.md`.

- [ ] **Step 1: Write the follow-up note**

Create the file documenting the equivalent change for `pencheff-studio-windows` (source not in this workspace): add `security_lake_enabled?: boolean` to the TS `Org` type; add an owner/admin-gated toggle to the org/settings screen that `PATCH`es `/orgs/{id}` with `{ security_lake_enabled }` and refreshes; replicate the disable-confirm (7-day deletion warning); no lake-query UI exists so no 403 handling. Note the backend contract is already live and the macOS app (this plan) is the reference implementation.

- [ ] **Step 2: Commit (in the monorepo)**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add docs/superpowers/specs/2026-06-14-security-lake-desktop-electron-followup.md
git commit -m "docs(security-lake): Electron desktop toggle follow-up note"
```

---

## Self-review (completed by plan author)

**Spec coverage:** §1 Org.swift → Task 1 ✓. §2 OrgUpdate.swift → Task 1 ✓. §3 SettingsView toggle (owner/admin gate, enable-direct, disable-confirm with 7-day warning, saveSecurityLake + error revert, caption) → Task 2 ✓. §4 verification (swiftc -parse + Xcode handoff) → Tasks 1/2 steps ✓. §5 Electron follow-up → Task 3 ✓.

**Placeholder scan:** No TBD/TODO. All Swift is complete and matches the existing file patterns (decode via `decodeIfPresent ?? false`; `MutationButton`/confirmationDialog/alert conventions). The "update the doc-comment" instruction is concrete.

**Type consistency:** `securityLakeEnabled` (camelCase Swift) ↔ `security_lake_enabled` (JSON CodingKey) used consistently in Org + OrgUpdate. `saveSecurityLake(_ value: Bool, revertTo: Bool)` signature matches both call sites (enable: `(true, revertTo: false)`; disable: `(false, revertTo: true)`). `OrgUpdate(securityLakeEnabled:)` and the existing `OrgUpdate(name:)` both compile via the defaulted init. `mutationErrorMessage`/`showMutationError` are the existing state vars wired to the existing alert.

**Known limitation (documented):** the macOS app cannot be built in this workspace (no Xcode); Tasks 1–2 are syntax-checked + pattern-matched, with a manual Xcode verification checklist handed to the user. The Electron app is a documented follow-up only.
