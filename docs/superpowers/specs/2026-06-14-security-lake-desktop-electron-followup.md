# Security Lake Toggle — Electron (Windows) Desktop — Follow-up

**Date:** 2026-06-14
**Status:** Follow-up (not implemented — source repo not in this workspace)
**Repo to apply in:** `MagadhaApps/pencheff-studio-windows` (Electron/TypeScript)
**Reference implementation:** the macOS app (`pencheff-studio`, branch `feat/security-lake-toggle`) — see `docs/superpowers/specs/2026-06-14-security-lake-desktop-design.md`.

## Why this is a follow-up

The Windows/Electron app's source isn't checked out in this workspace (only built `.exe` artifacts are present), so it couldn't be changed in the session that shipped the macOS toggle. The **backend contract is already live**, so this is purely a UI/model change in the Electron app.

## Backend contract (already shipped, no changes needed)

- `GET /orgs/{id}` / orgs list → `OrgOut.security_lake_enabled: boolean`.
- `PATCH /orgs/{id}` body `{ "security_lake_enabled": true | false }` (owner/admin only, session auth) flips it; disabling starts a server-side 7-day purge clock.
- `/security-lake/*` returns **403** when disabled. The Electron app does not call those endpoints today, so no 403/disabled handling is required.

## Changes to make in `pencheff-studio-windows`

Mirror the macOS implementation:

1. **Org type:** add `security_lake_enabled?: boolean` to the TypeScript `Org` type/interface used for `GET /orgs`.
2. **Org-update payload:** ensure the `PATCH /orgs/{id}` request type allows `{ security_lake_enabled?: boolean }` (omit when not set, like the existing `name` update).
3. **Settings/org screen — editable toggle:**
   - **Owner/admin only** (gate on the org `role`); members see a read-only "Enabled/Disabled" indicator.
   - **Enable** (off→on): `PATCH /orgs/{id}` with `{ security_lake_enabled: true }`, then refresh the org.
   - **Disable** (on→off): show a **confirmation dialog** first, warning that ingestion stops and **lake data is permanently deleted after 7 days unless re-enabled**; on confirm, `PATCH … { security_lake_enabled: false }`, then refresh. On cancel, leave it enabled.
   - On PATCH failure, revert the toggle and surface the error.
   - Caption: what the Security Lake does + "Disabled by default; disabling deletes lake data after 7 days."
4. **No lake-viewing UI** exists in the Electron app, so there is nothing to gate on 403 beyond the toggle.

## Verification (in the Electron repo)

- Type-check / lint the changed files.
- Run the app; confirm: enable persists across reload; disable shows the 7-day warning and turns it off; a non-owner/admin sees the read-only indicator; a failed PATCH reverts the toggle + shows the error.

## Out of scope

- Backend or web changes (done).
- Any new lake-querying UI in the desktop app.
