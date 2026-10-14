# Keycloak / OIDC authentication

This guide applies to the `feature/keycloak-rbac-ai-authorization` line and
branches based on it. The default Community Edition remains single-user and
unauthenticated when `OIDC_ENABLED=false`.

## Required settings

Set the following in the root `.env` before building the web container:

- `OIDC_ENABLED=true`
- `OIDC_ISSUER`: exact realm issuer URL, e.g. `https://id.example/realms/pencheff`
- `OIDC_AUDIENCE`: audience expected by the API. Configure a Keycloak audience
  mapper/client scope so access tokens include this audience.
- `NEXT_PUBLIC_OIDC_URL`: Keycloak base URL, e.g. `https://id.example`
- `NEXT_PUBLIC_OIDC_REALM`: realm name
- `NEXT_PUBLIC_OIDC_CLIENT_ID`: public browser client ID

`OIDC_CLIENT_ID` is the backend-side client setting; configure it to match
your intended Keycloak client. `OIDC_JWKS_URL` is optional if standard OIDC
discovery is reachable from the API.

The `NEXT_PUBLIC_*` values are compiled into the frontend image. Rebuild the
web image after changing them. Never put a client secret in a `NEXT_PUBLIC_*`
variable or in browser code.

## User provisioning

New users are denied by default. Create/link users through the deployment's
approved provisioning process. Set `OIDC_AUTO_PROVISION_USERS=true` only when
you explicitly want unknown authenticated identities added to the first
configured organization as basic members. Do not use auto-provisioning as a
substitute for organization invitation or approval policy in a shared deployment.

Existing users can be linked by an exact verified email claim only when their
account is not already linked to a different OIDC subject. Keep Keycloak email
verification enabled. An existing OIDC subject remains the stable identity key.

## Authorization checks before production

1. Confirm a valid access token with the configured audience succeeds.
2. Confirm expired, unsigned, wrong-issuer, and wrong-audience tokens return 401.
3. Confirm an unprovisioned user is denied when auto-provisioning is disabled.
4. Confirm an ordinary user cannot call admin-only API routes, even by directly
   calling the API rather than using the frontend.
5. Confirm workspace IDs belonging to another organization are denied.
6. Confirm uploads and downloads include the bearer token and workspace header.
7. Check streaming/SSE routes separately: browser `EventSource` cannot attach
   an Authorization header. Do not solve this by placing long-lived bearer
   tokens in URLs, where they can leak through logs and browser history.

## Important

The Keycloak role/group names must match the mapping in
`apps/api/pencheff_api/auth/permissions.py`. A successful login does not mean
the user has any application permissions; authorization must be tested on API
routes. Do not expose the API publicly until these checks and the project test
suite pass.
