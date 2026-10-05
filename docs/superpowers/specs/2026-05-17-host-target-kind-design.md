# Host target kind + UI + consent gate — design

**Date:** 2026-05-17
**Sub-project:** A (of a 6-part Mythos-style OS exploitation ladder: A → B → C → D → E → F)
**Status:** Implemented on branch `seo` (2026-05-17). Commits `c988bb3..f30ef53` plus subsequent frontend tasks.
**Owner:** balasriharsha

---

## Context

Anthropic's April 2026 Claude Mythos Preview demonstrated autonomous discovery and exploitation of OS-level zero-days. Mythos itself is invite-only (Project Glasswing), so Pencheff cannot route to it directly — but the **capability** (find OS-level vulnerabilities in a target and prove exploitation with real exfil + screenshot evidence) is what users want from the platform.

The full capability decomposes into six independently-shippable sub-projects. This spec covers only the first.

| # | Sub-project | What it ships | Depends on |
|---|---|---|---|
| **A (this spec)** | `host` target kind + UI + consent gate | New `Target.kind = "host"`, multi-host list input, RFC1918 opt-in, consent disclosure action, scan-disabled-until-B | nothing |
| B | OSExploitAgent breaker | nmap → service version → CVE match → public-exploit run → evidence capture | A |
| C | Evidence + session-management subsystem | msf RPC client, session lifecycle, evidence storage table, redaction, auto-cleanup | A |
| D | HostBehindURLAgent breaker | On URL targets, resolve host, scan its OS surface, reuse B+C machinery | B, C |
| E | SandboxExploitAgent for package/repo | Spin ephemeral container matching detected version, exploit in sandbox | C |
| F | Chain integration | Wire OS findings into `exploit_chain_suggest` + new chain templates | B, D |

## Decisions captured from brainstorming

- **Target shape:** multi-host list per Target (FQDN or IPv4/IPv6), capped at 50 hosts.
- **Authorization gate:** consent attestation only (matches existing URL-target pattern). No callback challenge, no Letter-of-Authorization upload in v1.
- **Private-IP policy:** RFC1918 / loopback / link-local / CGNAT / IPv6 ULA blocked by default; per-Org `allow_private_targets` opt-in flag.
- **Scan execution in A:** disabled with HTTP 409 + UI tooltip; lands when B ships.
- **Storage:** hosts ride in existing `Target.kind_config` JSONB (added by migration 0044). One new `Org.allow_private_targets` Boolean.

## Scope

**In scope:**

- New `Target.kind = "host"` end-to-end: Pydantic `TargetKind` Literal, DB column accepts it, frontend `SupportedKind` TS type, `TYPES_BY_ID` entry.
- Multi-host input stored as `Target.kind_config.hosts: list[str]`.
- Per-host server-side validation: FQDN regex, IPv4/IPv6 parse via `ipaddress` stdlib, de-dup (case-insensitive), list-size cap = 50, whitespace strip, control-character rejection.
- DNS resolution at create/PATCH time. Resolution failure → 422 per offending host.
- Private-IP detection on resolved IPs. Helper `_is_private_host(s)` covers RFC1918, loopback (127/8, ::1), link-local (169.254/16, fe80::/10), CGNAT (100.64/10), IPv6 ULA (fc00::/7).
- New `Org.allow_private_targets` Boolean column (default `false`).
- New consent action ID `host_os_exploitation`, wired into `REQUIRED_ACTION_IDS_BY_KIND["host"]` alongside `passive_recon` and `active_recon`.
- Strong-attestation disclosure modal when flipping `allow_private_targets` ON.
- `Scan.consent_payload` bumped to v2 — adds `authorized_hosts`, `acknowledged_at`, `acknowledged_by_user_id`, `acknowledged_from_ip`, `acknowledged_user_agent`. v1 payloads still readable.
- `POST /scans` against host-kind Targets returns HTTP 409 `host_kind_scanning_not_yet_available` until sub-project B removes the gate.
- Frontend `HostFormSection` for target creation, with per-line validation chips, private-IP warning chips for IP entries, 50-host counter.
- Scan button on host Targets disabled with tooltip in `app/targets/[id]/page.tsx` and `app/targets/page.tsx`.
- Org admin permissions panel exposing the `allow_private_targets` switch with disclosure modal on flip-on.
- Audit logs: every host-Target create, every `allow_private_targets` flip, with actor + IP + user-agent + prior/new value.

**Out of scope (deferred):**

- OSExploitAgent itself, `KIND_TO_BREAKER_NAMES["host"]`, dispatch routing → B
- nmap / searchsploit / msfvenom / msfconsole integration, evidence capture → B + C
- Per-host findings shape, msf session lifecycle, screenshot/exfil pipeline → C
- URL-target host-behind-the-web-app scanning → D
- Package/repo sandbox exploitation → E
- Cross-kind chain templates linking OS to web findings → F

## Data model

### Migration 0047 — `apps/api/pencheff_api/db/migrations/versions/0047_host_kind_target.py`

```python
def upgrade() -> None:
    op.add_column(
        "orgs",
        sa.Column(
            "allow_private_targets",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

def downgrade() -> None:
    op.drop_column("orgs", "allow_private_targets")
```

No new tables. Host list rides in the existing `Target.kind_config` JSONB column added by migration 0044.

### Pydantic schema — `apps/api/pencheff_api/schemas/targets.py`

```python
TargetKind = Literal[
    "url", "repo", "llm",
    "web_app", "rest_api", "graphql", "websocket", "grpc",
    "source_code", "cicd_pipeline", "iac",
    "container_image", "k8s_cluster",
    "package_registry", "sbom",
    "host",  # new
]

class HostKindConfig(BaseModel):
    hosts: list[str] = Field(min_length=1, max_length=50)
    is_private_target: bool = False  # SERVER-SET — client value is ignored

    @field_validator("hosts")
    @classmethod
    def validate_hosts(cls, raw: list[str]) -> list[str]:
        # Strip whitespace, reject empty / control-char / scheme-prefixed entries,
        # validate FQDN regex or ipaddress.ip_address(), dedup case-insensitive.
        ...
```

`HostKindConfig` plugs into `TargetCreate.kind_config` the same way Feature-001 per-kind configs do.

### `Org.allow_private_targets` semantics

- Default `false` for every existing and new Org.
- Server-side gate at `POST /targets` and `PATCH /targets/{id}`: if `any(is_private)` across resolved hosts AND `Org.allow_private_targets == False` → 422.
- Flag flip false → true via `PATCH /orgs/{id}` requires Org admin + body `private_targets_disclosure_ack: true`.
- Flag flip true → false has no disclosure (downgrade is freely allowed).
- Targets created while the flag was ON keep working when the flag flips OFF (no retro-invalidation). PATCH attempts that *add* a new private host while flag is OFF do fail.

## API contract

No new endpoints. Per-kind branching at the router layer follows the established Feature-001 pattern.

### `POST /targets` — host-kind branch (`routers/targets.py`)

```jsonc
// Request
{
  "name": "example.com prod boxes",
  "kind": "host",
  "kind_config": {
    "hosts": ["box1.example.com", "1.2.3.4", "203.0.113.10"]
  }
}
```

Server flow:

1. Parse + validate via `HostKindConfig` (per-host format, dedup, max-50).
2. Resolve FQDNs once via `socket.getaddrinfo` (or async equivalent). Resolution failure → 422 with per-host detail.
3. Classify resolved IP for each entry — public / RFC1918 / loopback / CGNAT / link-local / ULA.
4. If `any(is_private)` AND `org.allow_private_targets is False` → HTTP 422:
   ```jsonc
   {
     "error": "host_kind_private_targets_disabled",
     "message": "Your org does not permit private-IP host targets. Ask an admin to enable allow_private_targets, or remove the private hosts.",
     "offending_hosts": ["10.0.0.5", "192.168.1.10"]
   }
   ```
5. Set `kind_config.is_private_target = any(is_private)` server-side. Strip any client-supplied value.
6. Persist Target. Write audit-log row (actor, IP, user-agent, host list, is_private_target).
7. Return canonical record.

### `POST /scans` — host-kind 409 gate (`routers/scans.py`)

When `Target.kind == "host"`, the router short-circuits before any consent / dispatch logic:

```jsonc
{
  "error": "host_kind_scanning_not_yet_available",
  "message": "Scanning host targets requires the OSExploitAgent (shipping in v2 of this feature). Target creation is supported now; scanning is not.",
  "eta_reference": "sub-project B"
}
```

No `Scan` row is created. No Celery task enqueued. Removed in sub-project B.

### `PATCH /targets/{id}`

Editing the host list re-runs the validation pipeline including DNS resolution and the RFC1918 gate. Existing public hosts stay; adding a new private host while `allow_private_targets == False` is rejected.

### `PATCH /orgs/{id}` — extend existing route

`allow_private_targets` flip is gated:

- Requester must be Org admin.
- Flip false → true: body must include `private_targets_disclosure_ack: true`. Without it → 422.
- Flip true → false: no disclosure required.
- Every flip writes to `audit_logs` with actor, IP, user-agent, prior + new value.

## Consent disclosure

### Action catalogue — `apps/web/lib/consent-disclosures.ts`

```typescript
{
  id: "host_os_exploitation",
  displayName: "Host operating-system exploitation",
  description:
    "Run remote and local exploits against the operating systems and exposed services of the listed hosts. " +
    "On a successful compromise, Pencheff will execute read-only reconnaissance commands (hostname, current user, " +
    "directory listings, kernel/version banners), capture one screenshot of the active session, and exfiltrate up to " +
    "256 KB of evidence per host to demonstrate impact. Pencheff will NOT modify, delete, or persist anything on the " +
    "target; sessions are torn down immediately after evidence capture. By authorizing this action you attest that " +
    "you own these hosts or hold written authorization from the owner.",
  upcoming: false,
}
```

### Required action IDs

```typescript
REQUIRED_ACTION_IDS_BY_KIND["host"] = [
  "passive_recon",
  "active_recon",
  "host_os_exploitation",
];
```

### `Scan.consent_payload` v2

```jsonc
{
  "version": 2,
  "acknowledged": true,
  "disclosed_actions": ["passive_recon", "active_recon", "host_os_exploitation"],
  "authorization_text": "<full disclosure text rendered to the user, copied verbatim>",
  "authorized_hosts": ["box1.example.com", "1.2.3.4", "203.0.113.10"],
  "acknowledged_at": "2026-05-17T10:44:33Z",
  "acknowledged_by_user_id": "user_3CrNc…",
  "acknowledged_from_ip": "203.0.113.42",
  "acknowledged_user_agent": "Mozilla/5.0…"
}
```

All consumers of `Scan.consent_payload` route through a single typed loader `load_consent_payload(raw_json) -> ConsentPayload` that v1-tolerates and v2-emits. v1 payloads are read with the new fields nullable.

### Strong-attestation disclosure for `allow_private_targets` flip-on

Modal text:

> "Enabling private-IP host targets allows users in this org to register and (once OSExploitAgent ships) exploit hosts inside RFC1918, loopback, link-local, CGNAT, and IPv6 ULA ranges. You attest that this org operates or holds written authorization to test these networks. Pencheff logs every host target created under this flag for post-hoc abuse review."

User checks "I attest…" → admin UI sends `PATCH /orgs/{id}` with `private_targets_disclosure_ack: true`.

### Why a new action ID instead of reusing `exploitation`?

URL-kind `exploitation` blast radius is "the web app at this URL". Host-kind `host_os_exploitation` blast radius is "the operating system kernel of physical or virtual machines." Two different consent surfaces deserve two different IDs. Future kill-switching ("disable host exploitation but keep web exploitation") requires them as separate switchable units.

## Frontend

### Catalogue entry — `apps/web/components/register-target/target-types.ts`

```typescript
host: {
  id: "host",
  label: "Host / IP",
  group: "infrastructure",
  description: "Operating-system-level scanning + exploitation of one or more hosts (FQDN or IP).",
  icon: "Server",
  comingSoon: false,
}
```

`SupportedKind` Literal extended with `"host"`.

### `HostFormSection` — `apps/web/components/register-target/host-form-section.tsx`

- Single textarea, placeholder `"One host per line — FQDN or IP\nbox1.example.com\n203.0.113.10"`.
- On blur / debounce, per-line validation: FQDN regex OR IP parse. Inline ❌ chips per offending line with specific error.
- Client-side RFC1918 detection on IP entries only (no DNS-over-fetch). Yellow chip "Private IP — requires org admin to enable allow_private_targets".
- Live counter `12 / 50 hosts`. Submit disabled at >50.
- Dedup detection with a "remove duplicates" button.
- Server-side error mapping: per-host errors from the 422 response bind back to the offending lines as ❌ chips.

### `app/targets/new/page.tsx` — branch

```typescript
{selectedKinds.has("host") && (
  <HostFormSection
    value={hostKindConfig}
    onChange={setHostKindConfig}
    allowPrivateTargets={org.allow_private_targets}
  />
)}
```

Tooltip on the submit button when `allowPrivateTargets === false` AND any private chip is showing: "Your org doesn't allow private-IP targets. Ask an admin to enable it under Org settings → Permissions."

### Scan-disabled until B — `app/targets/[id]/page.tsx` + `app/targets/page.tsx`

The Run-scan button's existing `disabled` expression is `OR`-ed with one new clause for host kind. Example shape:

```tsx
const isHostKindUntilB = target.kind === "host";  // remove this line in sub-project B
<Button
  disabled={existingDisabledExpr || isHostKindUntilB}
  title={isHostKindUntilB
    ? "Host-target scanning ships in OSExploitAgent v2 (coming soon)."
    : undefined}>
  Run scan
</Button>
```

The flag's removal is the only surface area sub-project B touches in these files.

### Org admin permissions panel

New section in `apps/web/app/org/settings/page.tsx` (the existing org-settings page):

- Switch: "Allow host targets that resolve to private IP space (RFC1918, loopback, link-local, CGNAT, IPv6 ULA)".
- Off by default.
- Flip-on opens the strong-attestation modal (above). The user must check "I attest…" before the PATCH fires with `private_targets_disclosure_ack: true`.
- Flip-off is one click, no disclosure.
- Below the switch, a small "Last changed on `2026-05-14 by ada@example.com`" line, sourced from the most-recent audit row.

### Commission-scan modal

`apps/web/components/commission-scan-modal.tsx` consumes `getKindDisclosures(kind, kindConfig)`. The new action ID flows in automatically once the catalogue change ships. Modal-side work in A: when `kind === "host"`, render `kind_config.hosts` as a bulleted block above the action descriptions. Roughly ten lines.

## Validation rules

Single helper module `apps/api/pencheff_api/services/host_validation.py`:

- `_is_private_host(addr: str) -> bool` — IP-classification using `ipaddress.ip_address(addr)` for `.is_private` / `.is_loopback` / `.is_link_local`, plus explicit CGNAT check (`100.64.0.0/10`).
- `_resolve_host(host: str) -> str` — synchronous (or async) DNS lookup returning the first resolved IP. Raises `HostResolutionError` on failure.
- `_validate_host_format(host: str) -> None` — strip whitespace, reject empty / control-char / scheme-prefixed entries, validate against FQDN regex OR IP parse.
- `classify_host_list(hosts: list[str]) -> HostClassification` — orchestrates the three above, returns per-host status (`valid`, `private`, `invalid`, `unresolvable`) for the router to consume.

## Testing

### Unit — `apps/api/tests/`

| Path | Coverage |
|---|---|
| `services/test_host_validation.py` | `_is_private_host` correctness across RFC1918, loopback, link-local, CGNAT, IPv6 ULA, public; DNS resolve helper mocks success + failure; format validator catches scheme prefixes, control chars, empty entries. |
| `schemas/test_host_kind_config.py` | Valid list accepted; dedup case-insensitive; max-50 enforced; empty / control-char / scheme-prefixed rejected with field-pointing errors; `is_private_target` is server-set (client value ignored). |
| `routers/test_targets_host_kind.py` | `POST /targets` happy path (public hosts); all-private + `allow_private_targets=false` → 422 + `offending_hosts`; with `allow_private_targets=true` → 201 + `is_private_target=true`; PATCH adding a new private host with flag off → 422; PATCH adding a public host on a previously-private Target → 200; audit row written. |
| `routers/test_orgs_allow_private_targets.py` | Admin flip false→true with disclosure ack → 200; without ack → 422; non-admin → 403; audit row records prior + new value. |
| `routers/test_scans_host_kind_gate.py` | `POST /scans` against host Target → 409 `host_kind_scanning_not_yet_available`; no `Scan` row written; no Celery task enqueued. |

### Frontend — match existing repo convention

| Test | Coverage |
|---|---|
| `HostFormSection.test.tsx` | Per-line invalid chip; private-IP chip on RFC1918 entries; submit disabled at >50; dedup button removes dupes; server-error mapping. |
| Extend `targets-new-page.test.tsx` | Selecting "Host / IP" renders `HostFormSection`. |
| `org-permissions.test.tsx` | Allow-private switch shows modal on flip-on, no modal on flip-off, PATCH carries the ack. |

### End-to-end

One Playwright (or equivalent) scenario: create org → flip `allow_private_targets` ON with disclosure ack → create a host Target with mixed public + private hosts → see `is_private_target=true` in the Target detail page → click "Run scan" → see the disabled tooltip "host-target scanning ships in OSExploitAgent v2".

### Migration

Extend existing alembic test pattern: upgrade + downgrade reversible and idempotent; existing rows get `allow_private_targets=false`; v1 `consent_payload` rows still parse under the v2 reader.

## Rollout

1. Migration 0047 lands. Defaults preserve existing behavior for every org.
2. Backend code lands without a feature flag — host-kind validation is additive, the 409 gate is more restrictive than today's enum error. No need for staged rollout.
3. Frontend lands. The "Host / IP" tile appears in the target-type selector for every user. Existing flows untouched.
4. Org admins flip `allow_private_targets` as needed.
5. Sub-project B PR opens with the OSExploitAgent and a one-line removal of the 409 gate.

## Risks

- **Split-horizon DNS:** an FQDN resolves publicly on Pencheff infra but internally resolves to a private IP. We let the Target through based on public resolution; the agent in B resolves again at scan time and may end up against a different IP. Documented in the field-help text. Not a v1 blocker.
- **`consent_payload` v1 readers everywhere:** every consumer needs to be v2-tolerant. Mitigated by routing all reads through a single typed loader with backward-compatible defaults.
- **Audit-log volume:** every host-Target create writes an audit row. Existing `audit_logs` table is partitioned and pruned, so growth is bounded.

## Non-goals to keep in mind during implementation

- Don't speculate about B/C/D/E/F interfaces — let the next sub-project's brainstorm shape them.
- Don't add SSH/SMB credential storage in `kind_credentials_encrypted` yet. B decides whether the agent needs stored creds.
- Don't pre-build session-management or evidence storage tables. C designs those after B's needs are known.
- Don't wire `KIND_TO_BREAKER_NAMES["host"]` yet. B does that when the OSExploitAgent ships.

---

*Next: sub-project B (OSExploitAgent breaker) gets its own brainstorm → spec → plan cycle after this ships.*
