# Admin Web and Database-Backed RBAC

## Goal

Build an Admin Web on the `adminweb` branch that lets authorized Pencheff administrators manage application users, reusable permission sets, and assignments without editing Python role maps. Keep this branch separate; do not merge it into the authentication/RBAC branch.

## Current implementation

- `apps/api/pencheff_api/auth/permissions.py` defines a static permission catalog and static `ROLE_PERMISSIONS` mapping.
- `permissions_for_claims()` reads Keycloak realm/client role and group claims and resolves them into permissions.
- `apps/api/pencheff_api/auth/deps.py::require_permission()` checks the resulting request-state set.
- OIDC user identity is matched to the Pencheff `users` row by immutable `sub` stored in `google_sub`, with email as a fallback.
- `/auth/me`, `/auth/permissions/catalog`, and `/auth/permissions/check` expose authorization information.
- Authentication and existing route dependencies must remain functional during migration.

## Target behavior

1. Keycloak remains the identity provider. Pencheff never stores IDP passwords.
2. The permission catalog remains a controlled list of capabilities defined by backend routes. The admin UI displays this catalog; it does not invent arbitrary permission strings or change what an API route requires.
3. Administrators create named permission sets and select allowed permissions from the catalog.
4. Administrators assign permission sets to Pencheff users. Effective permissions are loaded from the database on the server for each request (or via a safe, invalidatable cache), not trusted from browser state.
5. A new user has no application permissions until an authorized administrator assigns a permission set. No administrative permission set is assigned by default.
6. Access to user administration, permission-set management, and assignment APIs is server-side protected. Hiding a UI link is not an authorization boundary.
7. A bootstrap procedure must be explicit and safe so the first administrator can be established without making every Keycloak user an administrator. Prefer an operator-configured immutable OIDC subject or a one-time bootstrap command; do not grant admin based on an unverified email alone.
8. All permission-set and assignment changes produce audit records with actor, action, target, timestamp, and changed values.
9. Enforce organization/workspace boundaries for all users, permission sets, and assignments.
10. Removing or changing an assignment must affect authorization promptly; token claims must not retain stale application permissions.

## Suggested data model

- `permission_sets`: id, org_id, name, description, created_by, created_at, updated_at.
- `permission_set_permissions`: permission_set_id, permission_name; unique pair and FK to permission set. Validate every permission against the server catalog.
- `user_permission_set_assignments`: org_id, user_id, permission_set_id, assigned_by, created_at; unique or explicitly documented multi-assignment semantics.
- Use existing users/org membership and audit facilities where possible instead of duplicating identity records.

Whether permission sets are global or organization-scoped must be explicit. Default to organization-scoped permission sets to prevent cross-tenant leakage.

## Admin Web pages

- `/admin/users`: list/search users and membership status; create an invitation or link an existing OIDC identity; assign/revoke permission sets.
- `/admin/permission-sets`: list/create/edit/delete permission sets.
- `/admin/permission-sets/new` and `/admin/permission-sets/[id]`: name, description, catalog grouped by category and risk, permission checkboxes, save/cancel.
- `/admin/audit`: inspect permission and assignment changes.
- Admin navigation and page access are conditional on effective admin-management permissions, but every API endpoint independently enforces them.

## Migration and compatibility plan

1. Add schema migration and tests before switching authorization reads.
2. Seed only the permission catalog (not a universal admin assignment). Preserve existing API capability names and descriptions.
3. Define an explicit bootstrap path for the first administrator.
4. Add read-only effective-permission resolution from database assignments.
5. Keep existing OIDC role-based resolution behind a documented temporary compatibility flag while data is migrated. Do not silently union untrusted/old role claims with database grants, because that could bypass admin revocation.
6. Switch `require_permission()` to database-backed resolution only after bootstrap, migration, and regression tests pass.
7. Add authenticated admin APIs and the UI using the existing API client and design conventions.
8. Test role/permission denial on real protected routes, not only the introspection endpoint.

## Required tests

- Catalog contains only known capabilities; unknown permission strings are rejected.
- New user has no effective permissions by default.
- Admin bootstrap works only for the configured subject/one-time procedure.
- Non-admin cannot list/create/update/delete permission sets or assign permissions by direct API call.
- Admin can create a custom permission set and assign it to a user.
- Assigned user gets exactly the assigned permissions; revocation takes effect promptly.
- Read-only user cannot write or run scans; write user can only perform assigned operations.
- Cross-organization user/permission-set access is denied.
- Existing authentication, targets, scans, findings, reports, uploads, and remediation routes continue to work.
- Migration upgrade and downgrade are tested against the supported PostgreSQL version.

## Implementation safety rules

- Do not merge this branch into any other branch.
- Do not remove or weaken existing route-level authorization dependencies.
- Do not give administrative permissions to every authenticated user or use a frontend-only check.
- Do not rewrite unrelated files or discard local changes.
- Run API tests, frontend type/build checks, and authorization regression tests before calling the feature complete.
