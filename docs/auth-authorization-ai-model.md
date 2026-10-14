# Authentication, authorization, and AI operating model

## 1. Identity

Pencheff uses an external OIDC identity provider (Keycloak-compatible). The
identity provider owns passwords, MFA, account lifecycle, direct user role
assignments, and group membership.

The browser uses the Keycloak JavaScript adapter with Authorization Code +
PKCE. Access/refresh tokens remain in browser memory and are attached as
Bearer tokens to API calls; they are not persisted to localStorage.

## 2. Authorization

Pencheff keeps an explicit permission catalog in
`apps/api/pencheff_api/auth/permissions.py`.

Administrators first inspect the catalog, then assign the corresponding
Pencheff roles directly to a user or to an IDP group. Group role mappings are
inherited by group members. Direct user role mappings are also supported.

Recommended roles:

| Role | Purpose |
|---|---|
| pencheff-admin | Full administration and security operations |
| pencheff-security-admin | Security operations + remediation approval/execution |
| pencheff-security | Register targets, scan, investigate and propose fixes |
| pencheff-readonly | Read-only findings/report access |
| pencheff-ai-agent | AI can read permitted data, register targets, scan and propose remediation; it cannot approve or execute remediation |

The API maps route requirements such as `targets:write` and
`remediation:approve` to these effective roles and returns HTTP 403 when the
required permission is absent.

## 3. Target / AI workflow

The intended workflow is:

1. User authenticates with the IDP.
2. Pencheff validates the signed access token.
3. User/group roles become effective permissions.
4. User or an authorized AI agent can register an explicitly allowed target.
5. The AI orchestrator reads only the workspace/target data allowed by its
   permissions and the target's configured scope.
6. The AI starts the appropriate scan workflow.
7. Findings are stored and reported to the human operator.
8. AI can create a remediation proposal/diff.
9. A human with `remediation:approve` explicitly approves it.
10. Execution requires the separate `remediation:execute` permission.
11. Execution creates the controlled Git/PR change; AI never receives the
    approval permission.

## 4. Data exposure boundary

The AI service should receive only the minimum data required for the current
operation. Secrets such as repository PATs, API credentials and encrypted
target credentials must stay server-side. The AI may request a permitted
operation through a controlled tool/API instead of receiving raw secrets.

For production, add an explicit per-workspace/target AI policy layer on top of
RBAC (allowed targets, allowed data classes, allowed scan types, and whether
AI registration is permitted). That policy must be checked server-side, never
only in the UI.

## 5. Remediation safety

A proposal and its execution are separate operations. The current proposal
flow now has an explicit `approved` state and the apply endpoint requires
`remediation:execute`; approval itself requires `remediation:approve`.

The server-side Agentic Fix worker still needs to be refactored to use the same
approval boundary before it creates/pushes a PR. That is a separate phase
because its current worker loop edits a temporary checkout and finalizes the
PR in one asynchronous run.

## 6. Keycloak setup

Create a public OIDC client for the Pencheff web application, configure exact
redirect URIs and web origins, and expose the user's effective roles/groups in
the access token. Configure the API with the OIDC issuer, audience/client ID
and optional JWKS URL.

Do not put an IDP client secret in the browser.

## 7. Security principle

Authentication answers **who are you?**

Authorization answers **what are you allowed to do?**

AI delegation answers **what may the AI do on your behalf?**

Human approval answers **what high-impact change may actually be executed?**

These four decisions should remain separate.
