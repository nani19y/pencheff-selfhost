# Security Lake — Enable/Disable Setting (+ 7-day retention purge) — Design

**Date:** 2026-06-13
**Status:** Approved design (pre-implementation)
**Builds on:** the deployed Security Lake (Slices 1–5; `security-lake-deploy.md`).

## Summary

Give orgs an explicit **enable/disable** control for the Security Lake, **disabled by default**, surfaced on a new **Settings page**. When disabled: new findings stop ingesting, the query/export endpoints return 403, and the org's lake data is **purged 7 days** after a user-initiated disable (a grace period — re-enabling cancels it).

## Confirmed decisions

| Decision              | Choice                                                                                                |
| --------------------- | ----------------------------------------------------------------------------------------------------- |
| Scope of the toggle   | **Org-level** (matches the lake's `org_id` tenancy)                                                   |
| Default               | **Disabled** (`security_lake_enabled = False`)                                                        |
| What "disabled" gates | Ingestion **and** query/export endpoints (full off)                                                   |
| Data on disable       | Retained, then **purged 7 days** after a user-initiated disable; re-enable cancels                    |
| Migration default     | existing orgs → `enabled=False`, `disabled_at=NULL` (purge clock NOT running)                         |
| UI                    | New **"Settings"** sidebar entry → page with a Security Lake section (toggle + disable-confirm modal) |
| Auth                  | Owner/admin only, session-auth (the `orgs` settings surface is session-only; no API-key access)       |

## 1. Data model

Add two columns to `Org` (`apps/api/pencheff_api/db/models.py`), following the existing
`allow_private_targets` boolean pattern:

```python
security_lake_enabled: Mapped[bool] = mapped_column(
    Boolean, nullable=False, server_default="false", default=False)
security_lake_disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
```

- `security_lake_enabled` — the on/off flag. Default **off**.
- `security_lake_disabled_at` — the purge clock. Set to _now_ on an **enable→disable**
  transition; cleared to `NULL` on **disable→enable**. `NULL` ⇒ no purge pending.

**Alembic migration `0055`** (`down_revision = "0054"`): add both columns. Existing rows
get `enabled=False`, `disabled_at=NULL` — the clock does **not** start from the migration,
only from an explicit user disable. So the already-backfilled org keeps its data until the
user toggles it on and later off.

## 2. Settings API

Extend `PATCH /orgs/{org_id}` (`routers/orgs.py`; `require_org_role("owner","admin")`):

- Accept `security_lake_enabled: bool | None` on `OrgUpdate`.
- On change (before != after):
  - set `org.security_lake_enabled = after`
  - if turning **off**: `org.security_lake_disabled_at = now()`
  - if turning **on**: `org.security_lake_disabled_at = None`
  - write an `AuditLog` row: action `org.security_lake_enabled.toggle`, meta `{before, after, actor_role}`.
- Surface `security_lake_enabled` (and optionally `security_lake_disabled_at`) on `OrgOut`.

No new RBAC scope — org settings are session-only (owner/admin), enforced by `require_org_role`.

## 3. Gating — what "disabled" turns off

A single helper resolves the flag from an org id. Both paths consult it:

- **Ingestion** (`tasks/security_lake_ingest_task.py`): `ingest_repo_scan` / `ingest_dast_scan`
  load the scan's org and, if `security_lake_enabled` is False, return
  `{"ok": True, "skipped": "disabled"}` without touching the lake. The guarded enqueue
  helpers (`enqueue_repo_ingest` / `enqueue_dast_ingest`) also short-circuit on the flag to
  avoid pointless worker dispatch (best-effort; the task is the authoritative gate).
- **Query/export** (`routers/security_lake.py`): a dependency checks
  `get_active_workspace().org_id`'s flag; when disabled, the endpoints raise
  `HTTP 403 "Security Lake is disabled for this organization"`. Applies to
  `/findings`, `/trends`, `/correlate`, `/export`.

The org flag is the single source of truth; no behavior depends on client input.

## 4. Retention purge (7-day grace)

A **daily periodic task** `security_lake_retention` (registered via the existing periodic-task
mechanism — exact wiring confirmed in the plan):

1. Select orgs where `security_lake_enabled = False AND security_lake_disabled_at IS NOT NULL
AND security_lake_disabled_at < now() − interval '7 days'`.
2. For each, purge its lake data: `table.delete(EqualTo("org_id", <org_id>))` on the
   `pencheff.findings` Iceberg table (`org_id` is a partition column → prunes to that org's
   partition). Then clear `security_lake_disabled_at = NULL` (purge done; don't re-purge).
3. Re-enabling before day 7 clears `disabled_at`, so the org is never selected → no purge.

**Verification gate (implementation):** confirm `table.delete(EqualTo("org_id", …))` works
against real R2 and removes only the target org's rows (same live-verify approach used for
append). **Fallback** if pyiceberg delete is problematic: delete the org's
`data/org_id=<org>/` object prefix from R2 **and** rewrite table metadata to drop those data
files (never delete files without updating metadata, or reads break).

## 5. Frontend

- **Nav:** add a `{ href: "/settings", label: "Settings", icon: <SettingsIcon /> }` entry to
  `SETTINGS_NAV` in `components/nav.tsx`.
- **Page:** `app/settings/page.tsx` (`"use client"`) with a **Security Lake** section:
  - The `role="switch"` toggle (existing `allow_private_targets` pattern) bound to
    `activeOrg.security_lake_enabled`.
  - Enabling: `api('/orgs/{id}', { method: 'PATCH', json: { security_lake_enabled: true } })` → `refresh()`.
  - Disabling: a **confirm modal** (data-loss warning: "findings stop ingesting; lake data is
    deleted after 7 days unless you re-enable") before the PATCH.
  - Short copy explaining what the Security Lake does + the disabled-by-default note.
- **Context:** add `security_lake_enabled?: boolean` to the `Org` type in
  `lib/workspace-context.tsx` so the toggle reflects current state.

## 6. Testing

- **Gating (hermetic):** ingest task returns `skipped: disabled` when the org flag is False;
  query/export raise 403 when disabled — both with a fake/seeded org flag, no real R2.
- **Retention:** the selection query picks only orgs past the 7-day window and skips
  re-enabled ones (`disabled_at` cleared); the per-org delete removes only that org's rows
  (verified on a local catalog with two orgs, then confirmed against real R2 during deploy).
- **Settings API:** PATCH flips `security_lake_enabled`, sets/clears `security_lake_disabled_at`
  on the right transitions, and writes the audit row.

## Out of scope

- Workspace-level (sub-org) granularity — the lake has no `workspace_id` column; org is the boundary.
- A manual "delete my lake data now" action (separate from the 7-day auto-purge).
- Changing the lake storage/architecture (Postgres catalog + R2) — unchanged.
