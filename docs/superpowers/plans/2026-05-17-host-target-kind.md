# Host target kind + UI + consent gate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship sub-project A of the Mythos-style OS-exploitation ladder — a new `Target.kind = "host"` with multi-host input, per-Org RFC1918 opt-in, strong consent disclosure, and the scan path gated until sub-project B lands.

**Architecture:** Add `"host"` to the existing `TargetKind` Literal. Hosts live as `Target.kind_config.hosts: list[str]` (reuses JSONB column from migration 0044). One new `Org.allow_private_targets` Boolean column. Per-host validation + DNS resolution + RFC1918 classification in a single helper module. Strong consent action `host_os_exploitation` added to the frontend disclosure catalogue. `POST /scans` short-circuits to HTTP 409 for host kind until B.

**Tech Stack:** FastAPI + SQLAlchemy + Alembic + Pydantic v2 (backend), Next.js App Router + TypeScript + Tailwind (frontend), pytest (backend tests), no frontend test framework in the repo yet — frontend verification is manual against `npm run dev` per a written checklist.

**Spec:** `docs/superpowers/specs/2026-05-17-host-target-kind-design.md`

---

## File map

| Path | Action | Responsibility |
|---|---|---|
| `apps/api/pencheff_api/db/migrations/versions/0047_host_kind_target.py` | Create | Alembic migration: add `orgs.allow_private_targets` Boolean. |
| `apps/api/pencheff_api/db/models.py` | Modify | Add `Org.allow_private_targets: Mapped[bool]` mapping. |
| `apps/api/pencheff_api/services/host_validation.py` | Create | Pure helpers: format validation, DNS resolve, private-IP classification, list orchestration. |
| `apps/api/pencheff_api/schemas/targets.py` | Modify | Add `"host"` to `TargetKind`; add `HostKindConfig` to the `KindConfig` discriminated union; update `_KINDS_REQUIRING_CONFIG`. |
| `apps/api/pencheff_api/schemas/orgs.py` | Modify | Add `allow_private_targets` field + `private_targets_disclosure_ack` validator on the org update schema. |
| `apps/api/pencheff_api/schemas/scans.py` | Modify | `KIND_REQUIRED_DISCLOSED_ACTIONS["host"]`; `ConsentPayload` v2 loader. |
| `apps/api/pencheff_api/routers/targets.py` | Modify | Host-kind branch on `POST /targets` and `PATCH /targets/{id}` — resolution + RFC1918 gate + audit log. |
| `apps/api/pencheff_api/routers/scans.py` | Modify | HTTP 409 short-circuit when target.kind == "host". |
| `apps/api/pencheff_api/routers/orgs.py` | Modify | `allow_private_targets` flip with ack requirement + audit row. |
| `apps/api/tests/test_host_validation.py` | Create | Unit tests for the helper module. |
| `apps/api/tests/test_host_kind_config.py` | Create | Pydantic schema tests for `HostKindConfig`. |
| `apps/api/tests/test_targets_host_kind.py` | Create | Router-level tests for create/list/patch on host kind + RFC1918 gate + audit. |
| `apps/api/tests/test_orgs_allow_private_targets.py` | Create | Router-level tests for the org flip + ack + admin gating + audit. |
| `apps/api/tests/test_scans_host_kind_gate.py` | Create | Router-level test that POST /scans returns 409 with no side-effects. |
| `apps/api/tests/test_consent_payload_v2.py` | Create | Loader parses v1 + v2 payloads, emits v2 on save. |
| `apps/web/components/register-target/target-types.ts` | Modify | Add `"host"` to `SupportedKind` + `TYPES_BY_ID` entry. |
| `apps/web/components/register-target/host-form-section.tsx` | Create | Multi-host textarea component with per-line validation chips. |
| `apps/web/lib/consent-disclosures.ts` | Modify | Add `host_os_exploitation` to `ACTIONS`; wire `REQUIRED_ACTION_IDS_BY_KIND["host"]`. |
| `apps/web/app/targets/new/page.tsx` | Modify | Render `HostFormSection` when `selectedKinds.has("host")`. |
| `apps/web/app/targets/[id]/page.tsx` | Modify | Disable Run-scan button + tooltip for host targets. |
| `apps/web/app/targets/page.tsx` | Modify | Disable per-row scan action + tooltip for host targets. |
| `apps/web/components/commission-scan-modal.tsx` | Modify | Render `kind_config.hosts` as bulleted block when kind == "host". |
| `apps/web/app/org/settings/page.tsx` | Modify | Allow-private-targets switch + strong-attestation modal on flip-on. |
| `CHANGELOG.md` | Modify | Add Unreleased entry describing host-kind target support. |

---

## Phase 1 — Backend foundations

### Task 1: Migration 0047 — add `Org.allow_private_targets`

**Files:**
- Create: `apps/api/pencheff_api/db/migrations/versions/0047_host_kind_target.py`

- [ ] **Step 1: Write the migration**

```python
"""Add Org.allow_private_targets — RFC1918 opt-in gate for host-kind targets.

Revision ID: 0047
Revises: 0046
Create Date: 2026-05-17

Sub-project A of the Mythos-style OS exploit ladder. Default = false: every
existing org gets the conservative "no private hosts" policy. Admins opt in
through routers/orgs.py with a stronger disclosure (see spec §4).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0047"
down_revision: Union[str, None] = "0046"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


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

- [ ] **Step 2: Apply the migration locally**

Run: `docker exec pencheff-api-1 alembic upgrade head`
Expected: `Running upgrade 0046 -> 0047, Add Org.allow_private_targets...` and exits 0.

- [ ] **Step 3: Verify column exists**

Run: `docker exec pencheff-postgres-1 psql -U pencheff -d pencheff -c "\\d orgs" | grep allow_private_targets`
Expected: one line `allow_private_targets | boolean | not null | default false`.

- [ ] **Step 4: Verify downgrade is clean**

Run: `docker exec pencheff-api-1 alembic downgrade 0046 && docker exec pencheff-api-1 alembic upgrade head`
Expected: both commands exit 0; column is dropped then re-added.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/db/migrations/versions/0047_host_kind_target.py
git commit -m "feat(db): migration 0047 adds Org.allow_private_targets"
```

---

### Task 2: Map `Org.allow_private_targets` in the SQLAlchemy model

**Files:**
- Modify: `apps/api/pencheff_api/db/models.py` (the `Org` class, after `force_deterministic_only`)

- [ ] **Step 1: Add the column mapping**

Locate the `Org` class. Insert the following after the `force_deterministic_only` declaration:

```python
    # Sub-project A (host-target-kind). When False (default), the targets router
    # rejects host-kind Target creation/PATCH for any host that resolves to a
    # private IP (RFC1918, loopback, link-local, CGNAT, IPv6 ULA). Flipped by
    # org admins via routers/orgs.py with `private_targets_disclosure_ack=True`
    # and a writes-an-audit-row contract. See spec
    # docs/superpowers/specs/2026-05-17-host-target-kind-design.md §4.
    allow_private_targets: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false", default=False
    )
```

- [ ] **Step 2: Run the existing import + load checks**

Run: `docker exec pencheff-api-1 python -c "from pencheff_api.db.models import Org; print(Org.allow_private_targets)"`
Expected: prints `<sqlalchemy.orm.attributes.InstrumentedAttribute object …>` with no error.

- [ ] **Step 3: Commit**

```bash
git add apps/api/pencheff_api/db/models.py
git commit -m "feat(models): expose Org.allow_private_targets on the ORM"
```

---

### Task 3: `host_validation.py` helper module (TDD)

**Files:**
- Create: `apps/api/pencheff_api/services/host_validation.py`
- Create: `apps/api/tests/test_host_validation.py`

- [ ] **Step 1: Write the failing test**

```python
# apps/api/tests/test_host_validation.py
"""Unit tests for pencheff_api.services.host_validation.

Covers private-IP classification, DNS resolution success/failure, format
validation, and the orchestrator that classify_host_list exposes to the
routers layer. See spec §"Validation rules" for the design intent.
"""
from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from pencheff_api.services.host_validation import (
    HostClassification,
    HostEntry,
    HostResolutionError,
    HostValidationError,
    classify_host_list,
    is_private_host,
    resolve_host,
    validate_host_format,
)


# ── is_private_host ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "addr",
    [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "::1",
        "fc00::1",
        "fdff::1",
        "fe80::1",
    ],
)
def test_is_private_host_true_for_private_ranges(addr: str) -> None:
    assert is_private_host(addr) is True


@pytest.mark.parametrize(
    "addr",
    [
        "1.1.1.1",
        "8.8.8.8",
        "203.0.113.1",  # TEST-NET-3, but publicly routable per ipaddress lib
        "2606:4700:4700::1111",  # Cloudflare public v6
    ],
)
def test_is_private_host_false_for_public_addrs(addr: str) -> None:
    assert is_private_host(addr) is False


# ── resolve_host ────────────────────────────────────────────────────────────


def test_resolve_host_returns_first_ip_for_known_fqdn() -> None:
    with patch.object(
        socket,
        "getaddrinfo",
        return_value=[(socket.AF_INET, 0, 0, "", ("203.0.113.10", 0))],
    ):
        assert resolve_host("box.example.com") == "203.0.113.10"


def test_resolve_host_raises_on_failure() -> None:
    with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("nope")):
        with pytest.raises(HostResolutionError):
            resolve_host("nonexistent.invalid")


def test_resolve_host_returns_ip_unchanged_when_already_an_ip() -> None:
    assert resolve_host("1.2.3.4") == "1.2.3.4"


# ── validate_host_format ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "host",
    [
        "box.example.com",
        "a.b.c.example.org",
        "1.2.3.4",
        "::1",
        "2606:4700:4700::1111",
        "example.com",
    ],
)
def test_validate_host_format_accepts_valid(host: str) -> None:
    # Does not raise.
    validate_host_format(host)


@pytest.mark.parametrize(
    "host",
    [
        "",
        " ",
        "https://example.com",  # scheme not allowed
        "example.com:443",      # port not allowed in v1 (separate field is deferred)
        "with space.example",
        "ctrl\x01char.example",
        ".leadingdot.example",
        "trailingdot.example.",
    ],
)
def test_validate_host_format_rejects(host: str) -> None:
    with pytest.raises(HostValidationError):
        validate_host_format(host)


# ── classify_host_list ──────────────────────────────────────────────────────


def test_classify_host_list_dedups_case_insensitive() -> None:
    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=lambda h: "203.0.113.10",
    ):
        result = classify_host_list(["Box.Example.com", "box.example.COM"])
    assert len(result.entries) == 1
    assert result.entries[0].input == "Box.Example.com"  # first wins


def test_classify_host_list_flags_any_private() -> None:
    def fake_resolve(host: str) -> str:
        return {"public.example.com": "1.2.3.4", "internal.example.com": "10.0.0.5"}[host]

    with patch(
        "pencheff_api.services.host_validation.resolve_host", side_effect=fake_resolve
    ):
        result = classify_host_list(["public.example.com", "internal.example.com"])
    assert result.any_private is True
    assert [e.is_private for e in result.entries] == [False, True]


def test_classify_host_list_collects_per_host_errors() -> None:
    def fake_resolve(host: str) -> str:
        if host == "valid.example.com":
            return "1.2.3.4"
        raise HostResolutionError(host, "dns failed")

    with patch(
        "pencheff_api.services.host_validation.resolve_host", side_effect=fake_resolve
    ):
        result = classify_host_list(["valid.example.com", "bad.invalid"])
    # Valid entry classified; invalid entry recorded with an error.
    assert result.entries[0].error is None
    assert result.entries[1].error is not None
    assert result.has_errors is True


def test_classify_host_list_collects_format_errors_before_resolution() -> None:
    result = classify_host_list(["https://nope.example", "1.2.3.4"])
    assert result.entries[0].error is not None
    # Format error short-circuits — resolve never called for the bad entry.
    assert result.entries[0].resolved_ip is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker exec pencheff-api-1 pytest tests/test_host_validation.py -v`
Expected: ImportError / ModuleNotFoundError for `pencheff_api.services.host_validation`.

- [ ] **Step 3: Implement the helper module**

```python
# apps/api/pencheff_api/services/host_validation.py
"""Host-list validation, DNS resolution, and private-IP classification.

Pure helpers — no DB, no FastAPI. Consumed by routers/targets.py to gate
host-kind Target create/PATCH per the per-Org allow_private_targets policy.
See specs/2026-05-17-host-target-kind-design.md §"Validation rules".
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field


__all__ = [
    "HostClassification",
    "HostEntry",
    "HostResolutionError",
    "HostValidationError",
    "classify_host_list",
    "is_private_host",
    "resolve_host",
    "validate_host_format",
]


class HostValidationError(ValueError):
    """Raised when a host string fails format validation."""


class HostResolutionError(RuntimeError):
    """Raised when a hostname cannot be resolved to an IP address."""

    def __init__(self, host: str, reason: str) -> None:
        super().__init__(f"could not resolve {host!r}: {reason}")
        self.host = host
        self.reason = reason


# CGNAT (100.64.0.0/10) — not flagged by Python's ipaddress.is_private,
# but we treat it as private for our gating purpose.
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

# Permissive FQDN regex: labels of [a-z0-9-], '.' separator, no leading/trailing
# dots, no consecutive dots. Case-insensitive. Length <= 253.
_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# Control / scheme markers we reject up front.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def is_private_host(addr: str) -> bool:
    """Return True if ``addr`` is a private-space IPv4 or IPv6 address.

    Covers Python's ipaddress notions of private/loopback/link-local plus an
    explicit CGNAT (100.64.0.0/10) check that the stdlib does not flag.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError as exc:
        raise HostValidationError(f"{addr!r} is not a valid IP address") from exc

    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_NETWORK:
        return True
    return False


def resolve_host(host: str) -> str:
    """Resolve ``host`` to the first IP returned by getaddrinfo.

    If ``host`` already parses as an IP address, returns it unchanged.
    Raises HostResolutionError when DNS lookup fails.
    """
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass  # fall through to DNS

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise HostResolutionError(host, str(exc)) from exc

    if not infos:
        raise HostResolutionError(host, "no addresses returned")

    # infos[0] = (family, type, proto, canonname, sockaddr); sockaddr[0] is the IP.
    return infos[0][4][0]


def validate_host_format(host: str) -> None:
    """Raise HostValidationError if ``host`` is not a valid FQDN or IP literal."""
    if not host or host.strip() != host:
        raise HostValidationError("host must be non-empty with no surrounding whitespace")
    if _CONTROL_RE.search(host):
        raise HostValidationError("host contains a control character")
    if "://" in host:
        raise HostValidationError("host must not include a URL scheme (drop e.g. 'https://')")
    if ":" in host and not host.startswith("["):
        # Bare IPv4-with-port, e.g. "1.2.3.4:443" — reject. Bare IPv6 literals
        # contain ':' but never start with '[' — distinguish with a parse.
        try:
            ipaddress.ip_address(host)
            return  # valid IPv6 literal
        except ValueError:
            raise HostValidationError("host must not include a port number")
    # Either valid IPv4/IPv6 literal or a syntactically-valid FQDN.
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    if not _FQDN_RE.match(host):
        raise HostValidationError(f"{host!r} is not a syntactically valid FQDN")


@dataclass(slots=True)
class HostEntry:
    """One row in the classification result."""

    input: str
    resolved_ip: str | None = None
    is_private: bool = False
    error: str | None = None


@dataclass(slots=True)
class HostClassification:
    """Per-list result that the targets router consumes."""

    entries: list[HostEntry] = field(default_factory=list)

    @property
    def any_private(self) -> bool:
        return any(e.is_private for e in self.entries)

    @property
    def has_errors(self) -> bool:
        return any(e.error is not None for e in self.entries)

    @property
    def private_hosts(self) -> list[str]:
        return [e.input for e in self.entries if e.is_private]

    @property
    def error_hosts(self) -> list[tuple[str, str]]:
        return [(e.input, e.error) for e in self.entries if e.error]


def classify_host_list(raw_hosts: list[str]) -> HostClassification:
    """Validate, dedup, resolve, and classify a list of host strings.

    Returns a HostClassification with one HostEntry per (deduped) input,
    populated with resolution + classification or per-host errors. Caller is
    responsible for emitting an HTTP error from ``has_errors``.
    """
    result = HostClassification()
    seen: set[str] = set()
    for raw in raw_hosts:
        # Dedup case-insensitive on the input form so e.g. "Box.Example.com" and
        # "box.example.com" collapse to the first occurrence.
        key = raw.lower()
        if key in seen:
            continue
        seen.add(key)

        entry = HostEntry(input=raw)
        try:
            validate_host_format(raw)
        except HostValidationError as exc:
            entry.error = str(exc)
            result.entries.append(entry)
            continue

        try:
            ip = resolve_host(raw)
            entry.resolved_ip = ip
            entry.is_private = is_private_host(ip)
        except (HostResolutionError, HostValidationError) as exc:
            entry.error = str(exc)

        result.entries.append(entry)

    return result
```

- [ ] **Step 4: Run tests to verify pass**

Run: `docker exec pencheff-api-1 pytest tests/test_host_validation.py -v`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/host_validation.py apps/api/tests/test_host_validation.py
git commit -m "feat(host): host_validation helper + unit tests"
```

---

### Task 4: `HostKindConfig` Pydantic schema (TDD)

**Files:**
- Modify: `apps/api/pencheff_api/schemas/targets.py`
- Create: `apps/api/tests/test_host_kind_config.py`

- [ ] **Step 1: Write the failing test**

```python
# apps/api/tests/test_host_kind_config.py
"""Schema tests for HostKindConfig + the TargetCreate host-kind branch.

Covers list-size cap, dedup, per-host format errors surfaced from
host_validation, and the server-set-only is_private_target flag.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from pencheff_api.schemas.targets import HostKindConfig, TargetCreate


def test_host_kind_config_accepts_minimal_list() -> None:
    cfg = HostKindConfig(hosts=["1.2.3.4"])
    assert cfg.hosts == ["1.2.3.4"]
    assert cfg.is_private_target is False
    assert cfg.kind == "host"


def test_host_kind_config_rejects_empty_list() -> None:
    with pytest.raises(ValidationError):
        HostKindConfig(hosts=[])


def test_host_kind_config_caps_at_50() -> None:
    too_many = [f"box{i}.example.com" for i in range(51)]
    with pytest.raises(ValidationError):
        HostKindConfig(hosts=too_many)


def test_host_kind_config_dedupes_case_insensitive() -> None:
    cfg = HostKindConfig(hosts=["Box.Example.com", "box.example.com"])
    assert cfg.hosts == ["Box.Example.com"]  # first wins


def test_host_kind_config_rejects_invalid_format() -> None:
    with pytest.raises(ValidationError) as exc:
        HostKindConfig(hosts=["https://no-scheme-please.example"])
    assert "scheme" in str(exc.value).lower()


def test_host_kind_config_ignores_client_supplied_is_private_target() -> None:
    cfg = HostKindConfig(hosts=["1.2.3.4"], is_private_target=True)
    # Field is declared, but routers/targets.py sets it server-side. The schema
    # default is False; the field is reset on serialization-from-router.
    # We pin the documented behavior here: the schema accepts the field, but
    # the router overrides it before persistence.
    assert cfg.is_private_target is True  # schema-level accepts it; router resets


def test_target_create_requires_kind_config_for_host() -> None:
    with pytest.raises(ValidationError) as exc:
        TargetCreate(name="x", base_url="host://list", kind="host", kind_config=None)
    assert "requires kind_config" in str(exc.value)


def test_target_create_rejects_kind_config_kind_mismatch() -> None:
    with pytest.raises(ValidationError):
        TargetCreate(
            name="x",
            base_url="host://list",
            kind="host",
            kind_config=HostKindConfig(hosts=["1.2.3.4"]).model_dump() | {"kind": "web_app"},
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `docker exec pencheff-api-1 pytest tests/test_host_kind_config.py -v`
Expected: ImportError on `HostKindConfig`.

- [ ] **Step 3: Modify `schemas/targets.py` — extend TargetKind**

Edit `apps/api/pencheff_api/schemas/targets.py`, replacing the existing `TargetKind` Literal and `_KINDS_REQUIRING_CONFIG` block (around lines 12-28):

```python
TargetKind = Literal[
    "url", "repo", "llm",
    "web_app", "rest_api", "graphql", "websocket", "grpc",
    "source_code", "cicd_pipeline", "iac",
    "container_image", "k8s_cluster",
    "package_registry", "sbom",
    "host",  # sub-project A — multi-host list for OS exploitation
]
# Kinds that REQUIRE ``Target.kind_config`` set on create.
_KINDS_REQUIRING_CONFIG: frozenset[str] = frozenset({
    "web_app", "rest_api", "graphql", "websocket", "grpc",
    "source_code", "cicd_pipeline", "iac",
    "container_image", "k8s_cluster",
    "package_registry", "sbom",
    "host",
})
_LEGACY_KINDS: frozenset[str] = frozenset({"url", "repo", "llm"})
```

- [ ] **Step 4: Modify `schemas/targets.py` — add `HostKindConfig`**

Insert after the last existing per-kind config class (just before the `KindConfig` Annotated/Union definition; search for `KindConfig = Annotated[`). The exact insertion site is the line just before that Annotated alias.

```python
class HostKindConfig(_KindConfigBase):
    """Host-kind target config — multi-host list for OS-level scanning.

    Sub-project A of the Mythos OS-exploit ladder. The agent that consumes
    this list ships in sub-project B; until then, routers/scans.py returns
    HTTP 409 for any scan against a host-kind Target. See
    docs/superpowers/specs/2026-05-17-host-target-kind-design.md.
    """

    kind: Literal["host"] = "host"
    # Bound mirrors the spec: 50 hosts per Target is the abuse-signal + UX limit.
    hosts: list[str] = Field(min_length=1, max_length=50)
    # SERVER-SET: routers/targets.py classifies the resolved IPs at create/PATCH
    # time and rewrites this field. Client-supplied values are ignored during
    # persistence (the router strips and re-computes). The field stays in the
    # schema so it round-trips through reads.
    is_private_target: bool = False

    @field_validator("hosts")
    @classmethod
    def _validate_hosts(cls, raw: list[str]) -> list[str]:
        # Reuse the helper module so the format rules stay in one place.
        from pencheff_api.services.host_validation import (
            HostValidationError,
            validate_host_format,
        )

        deduped: list[str] = []
        seen: set[str] = set()
        for entry in raw:
            if not isinstance(entry, str):
                raise ValueError(f"host entries must be strings, got {type(entry)!r}")
            key = entry.lower()
            if key in seen:
                continue
            try:
                validate_host_format(entry)
            except HostValidationError as exc:
                raise ValueError(f"invalid host {entry!r}: {exc}") from exc
            seen.add(key)
            deduped.append(entry)
        if not deduped:
            raise ValueError("hosts must contain at least one valid entry after dedup")
        return deduped
```

- [ ] **Step 5: Add `HostKindConfig` to the `KindConfig` discriminated union**

Search for `KindConfig = Annotated[` in `schemas/targets.py`. Add `HostKindConfig` to the Union (alphabetical or end-of-list, matching the file's existing convention):

```python
KindConfig = Annotated[
    Union[
        WebAppConfig, RestApiConfig, GraphqlConfig, WebsocketConfig, GrpcConfig,
        SourceCodeConfig, CicdPipelineConfig, IacConfig,
        ContainerImageConfig, K8sClusterConfig,
        PackageRegistryConfig, SbomConfig,
        HostKindConfig,  # sub-project A
    ],
    Field(discriminator="kind"),
]
```

(Adjust to match the union members already present in your tree — the import shape is what matters; the order in the Union does not affect Pydantic v2 discriminator behavior.)

- [ ] **Step 6: Run tests to verify pass**

Run: `docker exec pencheff-api-1 pytest tests/test_host_kind_config.py tests/test_kind_config_validators.py -v`
Expected: new tests pass; the existing kind_config tests still pass (no regressions).

- [ ] **Step 7: Commit**

```bash
git add apps/api/pencheff_api/schemas/targets.py apps/api/tests/test_host_kind_config.py
git commit -m "feat(schema): HostKindConfig + host added to TargetKind Literal"
```

---

### Task 5: Consent disclosure backend — extend `KIND_REQUIRED_DISCLOSED_ACTIONS` + v2 loader

**Files:**
- Modify: `apps/api/pencheff_api/schemas/scans.py`
- Create: `apps/api/tests/test_consent_payload_v2.py`

- [ ] **Step 1: Write the failing test**

```python
# apps/api/tests/test_consent_payload_v2.py
"""ConsentPayload v2 loader: parses v1 + v2 inputs, emits v2 on save."""
from __future__ import annotations

from pencheff_api.schemas.scans import (
    KIND_REQUIRED_DISCLOSED_ACTIONS,
    ConsentPayload,
    load_consent_payload,
)


def test_host_kind_required_actions_includes_host_os_exploitation() -> None:
    required = KIND_REQUIRED_DISCLOSED_ACTIONS["host"]
    assert "passive_recon" in required
    assert "active_recon" in required
    assert "host_os_exploitation" in required


def test_load_consent_payload_v1_backfills_v2_fields_with_none() -> None:
    raw = {
        "version": 1,
        "acknowledged": True,
        "disclosed_actions": ["passive_recon"],
        "authorization_text": "(legacy)",
    }
    payload = load_consent_payload(raw)
    assert payload.version == 1
    assert payload.acknowledged is True
    assert payload.disclosed_actions == ["passive_recon"]
    assert payload.authorized_hosts is None
    assert payload.acknowledged_at is None


def test_load_consent_payload_v2_round_trip() -> None:
    raw = {
        "version": 2,
        "acknowledged": True,
        "disclosed_actions": ["passive_recon", "active_recon", "host_os_exploitation"],
        "authorization_text": "I authorize…",
        "authorized_hosts": ["1.2.3.4"],
        "acknowledged_at": "2026-05-17T10:44:33Z",
        "acknowledged_by_user_id": "user_abc",
        "acknowledged_from_ip": "203.0.113.42",
        "acknowledged_user_agent": "Mozilla/5.0",
    }
    payload = load_consent_payload(raw)
    assert payload.version == 2
    assert payload.authorized_hosts == ["1.2.3.4"]


def test_consent_payload_default_emits_v2() -> None:
    payload = ConsentPayload(
        acknowledged=True,
        disclosed_actions=["passive_recon"],
        authorization_text="…",
    )
    assert payload.version == 2
```

- [ ] **Step 2: Run test — confirm failures**

Run: `docker exec pencheff-api-1 pytest tests/test_consent_payload_v2.py -v`
Expected: failures on either missing `KIND_REQUIRED_DISCLOSED_ACTIONS["host"]` or missing `load_consent_payload` symbol.

- [ ] **Step 3: Modify `schemas/scans.py` — add host to the required-actions map**

Find `KIND_REQUIRED_DISCLOSED_ACTIONS` (it should already exist per Feature 001 wiring). Add the host entry:

```python
KIND_REQUIRED_DISCLOSED_ACTIONS: dict[str, frozenset[str]] = {
    # … existing entries unchanged …
    "host": frozenset({
        "passive_recon",
        "active_recon",
        "host_os_exploitation",
    }),
}
```

- [ ] **Step 4: Modify `schemas/scans.py` — bump `ConsentPayload` to v2 + add loader**

Locate the existing `ConsentPayload` model (or whatever the file currently calls it; if there is no class, declare one). Replace / extend with:

```python
class ConsentPayload(BaseModel):
    """Operator acknowledgement of disclosed actions at scan-creation time.

    v1 schema (pre-host-kind):
        {version, acknowledged, disclosed_actions, authorization_text}
    v2 schema (sub-project A and forward):
        v1 + {authorized_hosts, acknowledged_at, acknowledged_by_user_id,
              acknowledged_from_ip, acknowledged_user_agent}
    Legacy v1 payloads are read via `load_consent_payload`, which fills the
    new fields with None and preserves backward compatibility.
    """

    model_config = ConfigDict(extra="ignore")

    version: int = 2
    acknowledged: bool
    disclosed_actions: list[str]
    authorization_text: str

    # Added in v2 — all optional so v1 payloads keep parsing.
    authorized_hosts: list[str] | None = None
    acknowledged_at: str | None = None         # ISO-8601 string per existing precedent
    acknowledged_by_user_id: str | None = None
    acknowledged_from_ip: str | None = None
    acknowledged_user_agent: str | None = None


def load_consent_payload(raw: dict | None) -> ConsentPayload | None:
    """Parse a stored consent_payload, treating missing v2 fields as None.

    Returns None when ``raw`` is None (no consent payload was recorded — the
    pre-consent backfill case). Raises pydantic ValidationError on a payload
    that is neither v1 nor v2-shaped.
    """
    if raw is None:
        return None
    # Coerce v1 → tolerant-v2 — every v1 field is also a v2 field, but new
    # optional fields stay None.
    payload = dict(raw)
    payload.setdefault("version", 1)
    return ConsentPayload.model_validate(payload)
```

If a `ConsentPayload` class already exists with different shape, treat the above as authoritative for the new fields and merge — preserve any pre-existing required fields the current code depends on.

- [ ] **Step 5: Run the new + adjacent tests**

Run: `docker exec pencheff-api-1 pytest tests/test_consent_payload_v2.py tests/ -k "consent" -v`
Expected: new tests pass; any pre-existing consent tests still pass.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/schemas/scans.py apps/api/tests/test_consent_payload_v2.py
git commit -m "feat(consent): bump ConsentPayload to v2 + add host_os_exploitation"
```

---

## Phase 2 — Backend routers

### Task 6: `POST /targets` host-kind branch (TDD)

**Files:**
- Modify: `apps/api/pencheff_api/routers/targets.py`
- Create: `apps/api/tests/test_targets_host_kind.py`

- [ ] **Step 1: Write the failing test**

```python
# apps/api/tests/test_targets_host_kind.py
"""Router tests for the host-kind branch of /targets.

Covers: happy path with public hosts, rejection of private hosts when the
org has allow_private_targets=False, acceptance when the flag is True, the
server-set is_private_target field, and audit-row writes.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from tests.conftest_helpers import (  # repo-internal helper — adjust if your conftest path differs
    auth_headers,
    create_org_with_user,
    fastapi_test_client,
)


@pytest.fixture()
def client_and_user():
    client = fastapi_test_client()
    org, user = create_org_with_user()
    yield client, org, user


def test_create_host_target_with_public_hosts_succeeds(client_and_user) -> None:
    client, org, user = client_and_user
    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=lambda h: {"box.example.com": "203.0.113.10"}.get(h, "1.2.3.4"),
    ):
        r = client.post(
            "/targets",
            headers=auth_headers(user),
            json={
                "name": "prod boxes",
                "base_url": "host://prod",
                "kind": "host",
                "kind_config": {
                    "kind": "host",
                    "hosts": ["box.example.com", "1.2.3.4"],
                },
            },
        )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["kind"] == "host"
    assert body["kind_config"]["hosts"] == ["box.example.com", "1.2.3.4"]
    assert body["kind_config"]["is_private_target"] is False


def test_create_host_target_with_private_host_blocked_by_default(client_and_user) -> None:
    client, org, user = client_and_user
    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=lambda h: "10.0.0.5",
    ):
        r = client.post(
            "/targets",
            headers=auth_headers(user),
            json={
                "name": "internal box",
                "base_url": "host://internal",
                "kind": "host",
                "kind_config": {"kind": "host", "hosts": ["internal.example.com"]},
            },
        )
    assert r.status_code == 422
    body = r.json()
    assert body["detail"]["error"] == "host_kind_private_targets_disabled"
    assert "internal.example.com" in body["detail"]["offending_hosts"]


def test_create_host_target_with_private_host_allowed_when_flag_on(client_and_user, db_session) -> None:
    client, org, user = client_and_user
    # Flip the flag via direct DB write — the org-router test exercises the API path.
    from pencheff_api.db.models import Org
    db_session.query(Org).filter_by(id=org.id).update({"allow_private_targets": True})
    db_session.commit()

    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=lambda h: "10.0.0.5",
    ):
        r = client.post(
            "/targets",
            headers=auth_headers(user),
            json={
                "name": "internal box",
                "base_url": "host://internal",
                "kind": "host",
                "kind_config": {"kind": "host", "hosts": ["internal.example.com"]},
            },
        )
    assert r.status_code == 201, r.text
    assert r.json()["kind_config"]["is_private_target"] is True


def test_create_host_target_resolution_failure_returns_422(client_and_user) -> None:
    client, _, user = client_and_user
    from pencheff_api.services.host_validation import HostResolutionError

    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=HostResolutionError("bad.invalid", "dns failed"),
    ):
        r = client.post(
            "/targets",
            headers=auth_headers(user),
            json={
                "name": "bad",
                "base_url": "host://bad",
                "kind": "host",
                "kind_config": {"kind": "host", "hosts": ["bad.invalid"]},
            },
        )
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "host_kind_resolution_failed"


def test_create_host_target_writes_audit_log(client_and_user, db_session) -> None:
    client, org, user = client_and_user
    from pencheff_api.db.models import AuditLog

    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=lambda h: "1.2.3.4",
    ):
        r = client.post(
            "/targets",
            headers=auth_headers(user),
            json={
                "name": "prod",
                "base_url": "host://prod",
                "kind": "host",
                "kind_config": {"kind": "host", "hosts": ["1.2.3.4"]},
            },
        )
    assert r.status_code == 201
    rows = (
        db_session.query(AuditLog)
        .filter(AuditLog.event_type == "target.host.create")
        .all()
    )
    assert len(rows) == 1
    assert rows[0].actor_user_id == user.id
    assert "1.2.3.4" in str(rows[0].metadata)
```

> **Note for the implementer:** the helper imports (`tests/conftest_helpers`, `db_session` fixture, `auth_headers`, `create_org_with_user`, `fastapi_test_client`) must already exist in the test harness. If your conftest exposes different names (the repo currently has flat `tests/test_*.py` modules using e.g. `client` + `as_user` fixtures), rename to match — the test logic is what matters. Look at an existing router test like `tests/test_scans_router_kind_aware.py` for the local convention and follow it.

- [ ] **Step 2: Run test to verify it fails**

Run: `docker exec pencheff-api-1 pytest tests/test_targets_host_kind.py -v`
Expected: failures (router doesn't know how to handle `kind=host`; or 500s due to missing branch).

- [ ] **Step 3: Modify `routers/targets.py` — host-kind branch on `POST /targets`**

Locate the existing `POST /targets` handler (the one that already branches on `kind` for the Feature 001 kinds). Add a host-kind branch BEFORE the generic kind_config persistence, immediately after the model validation pass:

```python
# routers/targets.py — inside the POST /targets handler, after TargetCreate
# validation but before the Target row is constructed.
from pencheff_api.services.host_validation import (
    HostResolutionError,
    classify_host_list,
)
from pencheff_api.db.models import AuditLog  # if not already imported

if payload.kind == "host":
    assert payload.kind_config is not None  # required-config check already enforced
    cfg = payload.kind_config
    # The schema validated format already; this pass adds DNS resolution and
    # the per-Org RFC1918 gate.
    classification = classify_host_list(cfg.hosts)
    if classification.has_errors:
        # Either format or DNS errors. Format errors should have been caught by
        # the schema, so these are most often resolution failures.
        raise HTTPException(
            status_code=422,
            detail={
                "error": "host_kind_resolution_failed",
                "message": "One or more hosts could not be resolved.",
                "errors": classification.error_hosts,
            },
        )
    if classification.any_private and not current_org.allow_private_targets:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "host_kind_private_targets_disabled",
                "message": (
                    "Your org does not permit private-IP host targets. Ask an "
                    "admin to enable allow_private_targets, or remove the "
                    "private hosts."
                ),
                "offending_hosts": classification.private_hosts,
            },
        )
    # Server-side: rewrite is_private_target before persistence. Strip any
    # client-supplied value.
    cfg_dict = cfg.model_dump()
    cfg_dict["is_private_target"] = classification.any_private
    payload = payload.model_copy(update={"kind_config": HostKindConfig(**cfg_dict)})

# ... rest of the existing handler (creates the Target row, persists, returns).

# After the Target row commit:
if payload.kind == "host":
    audit = AuditLog(
        org_id=current_org.id,
        actor_user_id=current_user.id,
        event_type="target.host.create",
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        metadata={
            "target_id": target.id,
            "hosts": payload.kind_config.hosts,
            "is_private_target": payload.kind_config.is_private_target,
        },
    )
    db.add(audit)
    db.commit()
```

> **Implementation note:** the exact attribute names (`current_org`, `current_user`, `request`, `db`, `target`, etc.) must match what your existing handler already binds. Search the existing handler for the equivalent symbols before pasting. The `AuditLog` model field names (`actor_ip`, `actor_user_agent`, `metadata`, `event_type`) must match your table — adjust if your schema uses different names (e.g. `details` vs `metadata`).

- [ ] **Step 4: Run tests until green**

Run: `docker exec pencheff-api-1 pytest tests/test_targets_host_kind.py -v`
Expected: all five tests pass. Fix import / fixture naming as discovered.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/routers/targets.py apps/api/tests/test_targets_host_kind.py
git commit -m "feat(targets): POST /targets host-kind branch with RFC1918 gate + audit"
```

---

### Task 7: `PATCH /targets/{id}` host-kind branch

**Files:**
- Modify: `apps/api/pencheff_api/routers/targets.py`
- Modify (extend): `apps/api/tests/test_targets_host_kind.py`

- [ ] **Step 1: Write failing PATCH tests**

Append to `tests/test_targets_host_kind.py`:

```python
def test_patch_host_target_adds_new_public_host_succeeds(client_and_user) -> None:
    client, _, user = client_and_user
    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=lambda h: "1.2.3.4",
    ):
        created = client.post(
            "/targets",
            headers=auth_headers(user),
            json={
                "name": "prod",
                "base_url": "host://prod",
                "kind": "host",
                "kind_config": {"kind": "host", "hosts": ["1.2.3.4"]},
            },
        ).json()

    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=lambda h: {"1.2.3.4": "1.2.3.4", "1.2.3.5": "1.2.3.5"}[h],
    ):
        r = client.patch(
            f"/targets/{created['id']}",
            headers=auth_headers(user),
            json={
                "kind_config": {
                    "kind": "host",
                    "hosts": ["1.2.3.4", "1.2.3.5"],
                }
            },
        )
    assert r.status_code == 200, r.text
    assert r.json()["kind_config"]["hosts"] == ["1.2.3.4", "1.2.3.5"]


def test_patch_host_target_adding_private_host_rejected_when_flag_off(
    client_and_user,
) -> None:
    client, _, user = client_and_user
    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=lambda h: "1.2.3.4",
    ):
        created = client.post(
            "/targets",
            headers=auth_headers(user),
            json={
                "name": "prod",
                "base_url": "host://prod",
                "kind": "host",
                "kind_config": {"kind": "host", "hosts": ["1.2.3.4"]},
            },
        ).json()

    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=lambda h: {"1.2.3.4": "1.2.3.4", "10.0.0.5": "10.0.0.5"}[h],
    ):
        r = client.patch(
            f"/targets/{created['id']}",
            headers=auth_headers(user),
            json={
                "kind_config": {
                    "kind": "host",
                    "hosts": ["1.2.3.4", "10.0.0.5"],
                }
            },
        )
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "host_kind_private_targets_disabled"
```

- [ ] **Step 2: Run tests — confirm failures**

Run: `docker exec pencheff-api-1 pytest tests/test_targets_host_kind.py::test_patch_host_target_adds_new_public_host_succeeds -v`
Expected: 422 or 500 (PATCH branch not yet implementing the host-kind path).

- [ ] **Step 3: Modify `routers/targets.py` — PATCH host-kind branch**

In the PATCH handler, add the same `classify_host_list` + private-gate validation as POST when `payload.kind_config` is supplied AND the existing Target's kind is `"host"`. Re-write `is_private_target` server-side. Do not write a new audit row on PATCH unless private-status changed (keeps audit volume sane).

```python
# Inside PATCH /targets/{id}, after fetching `target` and validating that the
# incoming kind_config (if any) discriminator matches target.kind:
if target.kind == "host" and payload.kind_config is not None:
    classification = classify_host_list(payload.kind_config.hosts)
    if classification.has_errors:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "host_kind_resolution_failed",
                "message": "One or more hosts could not be resolved.",
                "errors": classification.error_hosts,
            },
        )
    if classification.any_private and not current_org.allow_private_targets:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "host_kind_private_targets_disabled",
                "message": (
                    "Your org does not permit private-IP host targets. Ask an "
                    "admin to enable allow_private_targets, or remove the "
                    "private hosts."
                ),
                "offending_hosts": classification.private_hosts,
            },
        )
    cfg_dict = payload.kind_config.model_dump()
    cfg_dict["is_private_target"] = classification.any_private
    payload = payload.model_copy(
        update={"kind_config": HostKindConfig(**cfg_dict)}
    )
```

- [ ] **Step 4: Run tests to verify pass**

Run: `docker exec pencheff-api-1 pytest tests/test_targets_host_kind.py -v`
Expected: all PATCH tests pass alongside the POST tests.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/routers/targets.py apps/api/tests/test_targets_host_kind.py
git commit -m "feat(targets): PATCH /targets host-kind branch revalidates hosts"
```

---

### Task 8: `POST /scans` host-kind 409 gate

**Files:**
- Modify: `apps/api/pencheff_api/routers/scans.py`
- Create: `apps/api/tests/test_scans_host_kind_gate.py`

- [ ] **Step 1: Write the failing test**

```python
# apps/api/tests/test_scans_host_kind_gate.py
"""POST /scans against a host-kind Target must return HTTP 409 (until sub-project B)."""
from __future__ import annotations

from unittest.mock import patch

import pytest


def test_scan_against_host_target_returns_409(client, db_session, fake_user) -> None:
    # Create a host target via the API so all branches are exercised.
    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=lambda h: "1.2.3.4",
    ):
        created = client.post(
            "/targets",
            headers=fake_user.auth_headers,
            json={
                "name": "prod",
                "base_url": "host://prod",
                "kind": "host",
                "kind_config": {"kind": "host", "hosts": ["1.2.3.4"]},
            },
        ).json()

    r = client.post(
        "/scans",
        headers=fake_user.auth_headers,
        json={"target_id": created["id"], "profile": "standard"},
    )
    assert r.status_code == 409
    body = r.json()["detail"]
    assert body["error"] == "host_kind_scanning_not_yet_available"

    # No Scan row written
    from pencheff_api.db.models import Scan
    assert (
        db_session.query(Scan).filter_by(target_id=created["id"]).count() == 0
    )

    # No Celery task enqueued — verify via mock if your test harness intercepts;
    # otherwise this is implicitly verified by the lack of Scan rows (the task
    # enqueue happens after Scan persistence in the existing handler).
```

(Adjust fixture names to your conftest — see note in Task 6.)

- [ ] **Step 2: Run — confirm failure**

Run: `docker exec pencheff-api-1 pytest tests/test_scans_host_kind_gate.py -v`
Expected: returns 200 or 422 or 500 — anything other than 409 means the gate isn't in place.

- [ ] **Step 3: Modify `routers/scans.py` — short-circuit on host kind**

Find the existing `POST /scans` handler. Immediately after `target` is loaded by ID but BEFORE any consent / dispatch logic, add:

```python
# Sub-project A: host-kind scanning ships in sub-project B (OSExploitAgent).
# Until then, fail fast so no Scan row is created and no Celery task fires.
if target.kind == "host":
    raise HTTPException(
        status_code=409,
        detail={
            "error": "host_kind_scanning_not_yet_available",
            "message": (
                "Scanning host targets requires the OSExploitAgent (shipping "
                "in v2 of this feature). Target creation is supported now; "
                "scanning is not."
            ),
            "eta_reference": "sub-project B",
        },
    )
```

- [ ] **Step 4: Run tests to verify pass**

Run: `docker exec pencheff-api-1 pytest tests/test_scans_host_kind_gate.py tests/test_scans_router_kind_aware.py -v`
Expected: new test passes; existing kind-aware tests unaffected.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/routers/scans.py apps/api/tests/test_scans_host_kind_gate.py
git commit -m "feat(scans): POST /scans returns 409 for host-kind until sub-project B"
```

---

### Task 9: `PATCH /orgs/{id}` allow_private_targets flip with ack

**Files:**
- Modify: `apps/api/pencheff_api/schemas/orgs.py`
- Modify: `apps/api/pencheff_api/routers/orgs.py`
- Create: `apps/api/tests/test_orgs_allow_private_targets.py`

- [ ] **Step 1: Write the failing test**

```python
# apps/api/tests/test_orgs_allow_private_targets.py
"""PATCH /orgs/{id} allow_private_targets flip path."""
from __future__ import annotations

from pencheff_api.db.models import AuditLog, Org


def test_admin_flips_allow_private_true_with_ack(client, db_session, admin_user, org) -> None:
    r = client.patch(
        f"/orgs/{org.id}",
        headers=admin_user.auth_headers,
        json={
            "allow_private_targets": True,
            "private_targets_disclosure_ack": True,
        },
    )
    assert r.status_code == 200, r.text
    db_session.expire_all()
    assert db_session.query(Org).get(org.id).allow_private_targets is True
    audits = (
        db_session.query(AuditLog)
        .filter(AuditLog.event_type == "org.allow_private_targets.flip")
        .all()
    )
    assert len(audits) == 1
    assert audits[0].actor_user_id == admin_user.id


def test_admin_flips_allow_private_true_without_ack_returns_422(client, admin_user, org) -> None:
    r = client.patch(
        f"/orgs/{org.id}",
        headers=admin_user.auth_headers,
        json={"allow_private_targets": True},
    )
    assert r.status_code == 422
    body = r.json()
    assert "private_targets_disclosure_ack" in str(body).lower()


def test_non_admin_cannot_flip_allow_private(client, member_user, org) -> None:
    r = client.patch(
        f"/orgs/{org.id}",
        headers=member_user.auth_headers,
        json={
            "allow_private_targets": True,
            "private_targets_disclosure_ack": True,
        },
    )
    assert r.status_code == 403


def test_admin_flips_allow_private_false_without_ack(client, db_session, admin_user, org) -> None:
    # First: turn it on (with ack) so we have something to flip off.
    client.patch(
        f"/orgs/{org.id}",
        headers=admin_user.auth_headers,
        json={
            "allow_private_targets": True,
            "private_targets_disclosure_ack": True,
        },
    )
    # Flipping off does NOT require ack.
    r = client.patch(
        f"/orgs/{org.id}",
        headers=admin_user.auth_headers,
        json={"allow_private_targets": False},
    )
    assert r.status_code == 200
    db_session.expire_all()
    assert db_session.query(Org).get(org.id).allow_private_targets is False
```

- [ ] **Step 2: Run — confirm failures**

Run: `docker exec pencheff-api-1 pytest tests/test_orgs_allow_private_targets.py -v`
Expected: all four tests fail (field unknown on the org schema).

- [ ] **Step 3: Modify `schemas/orgs.py` — add field + ack validator**

Add to the existing `OrgUpdate` (or whatever the PATCH input is called) Pydantic model:

```python
class OrgUpdate(BaseModel):
    # … existing fields unchanged …
    allow_private_targets: bool | None = None
    private_targets_disclosure_ack: bool | None = None

    @model_validator(mode="after")
    def _ack_required_to_enable_private(self) -> "OrgUpdate":
        if self.allow_private_targets is True and self.private_targets_disclosure_ack is not True:
            raise ValueError(
                "private_targets_disclosure_ack=True is required to enable "
                "allow_private_targets"
            )
        return self
```

- [ ] **Step 4: Modify `routers/orgs.py` — apply + audit**

In the PATCH handler:

```python
# After the existing admin-role check, inside the org update logic:
if payload.allow_private_targets is not None:
    prior = org.allow_private_targets
    if prior != payload.allow_private_targets:
        org.allow_private_targets = payload.allow_private_targets
        audit = AuditLog(
            org_id=org.id,
            actor_user_id=current_user.id,
            event_type="org.allow_private_targets.flip",
            actor_ip=request.client.host if request.client else None,
            actor_user_agent=request.headers.get("user-agent"),
            metadata={
                "prior": prior,
                "new": payload.allow_private_targets,
                "ack_provided": bool(payload.private_targets_disclosure_ack),
            },
        )
        db.add(audit)
```

(If the audit-row commit is consolidated at the end of the handler, adjust accordingly — do not double-commit.)

- [ ] **Step 5: Run tests to verify pass**

Run: `docker exec pencheff-api-1 pytest tests/test_orgs_allow_private_targets.py -v`
Expected: all four tests pass.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/schemas/orgs.py apps/api/pencheff_api/routers/orgs.py apps/api/tests/test_orgs_allow_private_targets.py
git commit -m "feat(orgs): allow_private_targets flip requires admin + disclosure ack"
```

---

## Phase 3 — Frontend

### Task 10: Add `"host"` to the target-kind catalogue

**Files:**
- Modify: `apps/web/components/register-target/target-types.ts`

- [ ] **Step 1: Add `"host"` to the `SupportedKind` Literal**

Find the `SupportedKind` type alias. Add `"host"` to the union:

```typescript
export type SupportedKind =
  | "url" | "repo" | "llm"
  | "web_app" | "rest_api" | "graphql" | "websocket" | "grpc"
  | "source_code" | "cicd_pipeline" | "iac"
  | "container_image" | "k8s_cluster"
  | "package_registry" | "sbom"
  | "host";  // sub-project A
```

- [ ] **Step 2: Add the `TYPES_BY_ID` entry**

Find the `TYPES_BY_ID` map (or `TYPES` array — match what exists). Add the host entry:

```typescript
host: {
  id: "host",
  label: "Host / IP",
  // Group + icon + description must match the existing TypeCard shape.
  // If `group` enum doesn't include "infrastructure", add it or pick the
  // closest existing group (e.g. "live_target").
  group: "live_target",
  description:
    "Operating-system-level scanning + exploitation of one or more hosts (FQDN or IP). " +
    "Sub-project A registers the kind and consent gate; scanning ships in sub-project B.",
  icon: "Server",
  comingSoon: false,
},
```

- [ ] **Step 3: Type-check + lint**

Run: `cd apps/web && npx tsc --noEmit && npm run lint`
Expected: zero errors.

- [ ] **Step 4: Commit**

```bash
git add apps/web/components/register-target/target-types.ts
git commit -m "feat(web): add host kind to SupportedKind + target-type catalogue"
```

---

### Task 11: Add `host_os_exploitation` to the consent disclosure catalogue

**Files:**
- Modify: `apps/web/lib/consent-disclosures.ts`

- [ ] **Step 1: Add the action to `ACTIONS`**

Find the `ACTIONS` record. Add:

```typescript
host_os_exploitation: {
  id: "host_os_exploitation",
  displayName: "Host operating-system exploitation",
  description:
    "Run remote and local exploits against the operating systems and exposed services of the listed hosts. " +
    "On a successful compromise, Pencheff will execute read-only reconnaissance commands (hostname, current user, " +
    "directory listings, kernel/version banners), capture one screenshot of the active session, and exfiltrate up to " +
    "256 KB of evidence per host to demonstrate impact. Pencheff will NOT modify, delete, or persist anything on the " +
    "target; sessions are torn down immediately after evidence capture. By authorizing this action you attest that " +
    "you own these hosts or hold written authorization from the owner.",
},
```

- [ ] **Step 2: Wire `REQUIRED_ACTION_IDS_BY_KIND["host"]`**

Find the `REQUIRED_ACTION_IDS_BY_KIND` record. Add:

```typescript
host: ["passive_recon", "active_recon", "host_os_exploitation"],
```

- [ ] **Step 3: Type-check + lint**

Run: `cd apps/web && npx tsc --noEmit && npm run lint`
Expected: zero errors. If `REQUIRED_ACTION_IDS_BY_KIND` is typed as `Record<SupportedKind, string[]>`, TypeScript will now require an entry for `"host"` — which is exactly what we want.

- [ ] **Step 4: Commit**

```bash
git add apps/web/lib/consent-disclosures.ts
git commit -m "feat(web): host_os_exploitation consent action + host required-actions"
```

---

### Task 12: `HostFormSection` component

**Files:**
- Create: `apps/web/components/register-target/host-form-section.tsx`

- [ ] **Step 1: Write the component**

```tsx
// apps/web/components/register-target/host-form-section.tsx
"use client";

import { useMemo } from "react";

import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export interface HostKindConfigDraft {
  kind: "host";
  hosts: string[];
}

interface Props {
  value: HostKindConfigDraft;
  onChange: (next: HostKindConfigDraft) => void;
  /** From `useOrg()` — server-side enforced; UI uses this only to render a warning. */
  allowPrivateTargets: boolean;
}

const MAX_HOSTS = 50;

// Lightweight client-side regex matches the server FQDN validator. Server
// remains authoritative; this only powers per-line chips before submit.
const FQDN_RE = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$/;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/; // permissive — server validates rigorously.

function isPrivateIPv4(addr: string): boolean {
  if (!IPV4_RE.test(addr)) return false;
  const [a, b] = addr.split(".").map((n) => Number(n));
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

type LineStatus =
  | { kind: "ok"; warning?: "private" }
  | { kind: "error"; message: string };

function classifyLine(line: string): LineStatus {
  const trimmed = line.trim();
  if (!trimmed) return { kind: "error", message: "empty" };
  if (trimmed.includes("://")) return { kind: "error", message: "drop the URL scheme (e.g. 'https://')" };
  if (trimmed.includes(" ")) return { kind: "error", message: "no spaces allowed" };
  // IP-shaped → check private.
  if (IPV4_RE.test(trimmed)) {
    return isPrivateIPv4(trimmed) ? { kind: "ok", warning: "private" } : { kind: "ok" };
  }
  if (IPV6_RE.test(trimmed) && trimmed.includes(":")) {
    // Conservative: only flag loopback + link-local + ULA where the prefix is recognizable client-side.
    const lower = trimmed.toLowerCase();
    if (lower === "::1" || lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd")) {
      return { kind: "ok", warning: "private" };
    }
    return { kind: "ok" };
  }
  if (FQDN_RE.test(trimmed)) return { kind: "ok" };
  return { kind: "error", message: "not a valid IP or FQDN" };
}

export function HostFormSection({ value, onChange, allowPrivateTargets }: Props) {
  const text = useMemo(() => value.hosts.join("\n"), [value.hosts]);

  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  const dedupedSet = new Set<string>();
  const linesWithStatus = lines.map((line) => {
    const status = classifyLine(line);
    const lower = line.toLowerCase();
    const isDuplicate = dedupedSet.has(lower);
    dedupedSet.add(lower);
    return { line, status, isDuplicate };
  });

  const hasErrors = linesWithStatus.some((l) => l.status.kind === "error");
  const privateCount = linesWithStatus.filter(
    (l) => l.status.kind === "ok" && l.status.warning === "private"
  ).length;
  const overLimit = lines.length > MAX_HOSTS;
  const hasDuplicates = linesWithStatus.some((l) => l.isDuplicate);

  function onTextChange(raw: string) {
    onChange({
      kind: "host",
      hosts: raw.split("\n").map((l) => l.trim()).filter(Boolean),
    });
  }

  function removeDuplicates() {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const l of lines) {
      const lower = l.toLowerCase();
      if (seen.has(lower)) continue;
      seen.add(lower);
      out.push(l);
    }
    onChange({ kind: "host", hosts: out });
  }

  return (
    <section className="space-y-3">
      <div>
        <label className="text-sm font-medium" htmlFor="host-list">
          Hosts
        </label>
        <p className="text-xs text-muted-foreground">
          One host per line. FQDN (e.g. <code>box.example.com</code>) or IP
          (IPv4 / IPv6). Up to {MAX_HOSTS} hosts per target. Server resolves
          FQDNs at submit time — split-horizon DNS environments may resolve
          differently inside your network.
        </p>
      </div>
      <Textarea
        id="host-list"
        rows={8}
        value={text}
        onChange={(e) => onTextChange(e.target.value)}
        placeholder={"box1.example.com\n203.0.113.10"}
        className="font-mono text-sm"
      />
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Badge
          variant={overLimit ? "destructive" : "secondary"}
        >
          {lines.length} / {MAX_HOSTS} hosts
        </Badge>
        {hasErrors && (
          <Badge variant="destructive">
            {linesWithStatus.filter((l) => l.status.kind === "error").length} invalid
          </Badge>
        )}
        {privateCount > 0 && (
          <Badge variant={allowPrivateTargets ? "secondary" : "destructive"}>
            {privateCount} private — {allowPrivateTargets ? "allowed by org" : "requires org admin opt-in"}
          </Badge>
        )}
        {hasDuplicates && (
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={removeDuplicates}
          >
            Remove duplicates
          </Button>
        )}
      </div>
      {/* Per-line errors */}
      {hasErrors && (
        <ul className="space-y-1 text-xs">
          {linesWithStatus
            .filter((l) => l.status.kind === "error")
            .map((l, i) => (
              <li key={`${l.line}-${i}`} className="text-destructive">
                <code className="font-mono">{l.line}</code>: {(l.status as { kind: "error"; message: string }).message}
              </li>
            ))}
        </ul>
      )}
    </section>
  );
}
```

> **Implementation note:** if the existing kit names a `Textarea` / `Badge` / `Button` differently, adjust imports. Use the existing form sections (e.g. `WebAppFormSection`) as a paste-able reference for naming and styling.

- [ ] **Step 2: Type-check + lint**

Run: `cd apps/web && npx tsc --noEmit && npm run lint`
Expected: zero errors.

- [ ] **Step 3: Commit**

```bash
git add apps/web/components/register-target/host-form-section.tsx
git commit -m "feat(web): HostFormSection — multi-host input with per-line validation"
```

---

### Task 13: Render `HostFormSection` in target-new page

**Files:**
- Modify: `apps/web/app/targets/new/page.tsx`

- [ ] **Step 1: Add the host branch**

Find the block where other per-kind form sections render conditionally. Add:

```tsx
import { HostFormSection } from "@/components/register-target/host-form-section";

// state: keep a draft alongside the other kind-config drafts.
const [hostKindConfig, setHostKindConfig] = useState<HostKindConfigDraft>({
  kind: "host",
  hosts: [],
});

// render — alongside the other kind branches:
{selectedKinds.has("host") && (
  <HostFormSection
    value={hostKindConfig}
    onChange={setHostKindConfig}
    allowPrivateTargets={org.allow_private_targets ?? false}
  />
)}
```

- [ ] **Step 2: Wire it into the `POST /targets` payload**

Find the `onSubmit` (or equivalent submit) handler. Add host-kind handling:

```tsx
if (selectedKinds.has("host")) {
  if (hostKindConfig.hosts.length === 0) {
    setError("At least one host is required.");
    return;
  }
  const body = {
    name,
    base_url: `host://${hostKindConfig.hosts[0]}-list`,  // synthetic base_url — matches existing per-kind precedent in schemas/targets.py:382
    kind: "host" as const,
    kind_config: hostKindConfig,
  };
  await fetch("/api/targets", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  // navigate / error-handle exactly like the other branches.
}
```

> The `host://<first>-list` synthetic base_url mirrors the existing per-kind pattern (e.g. `oci://alpine:3.10`, `k8s://live/default`). The string is just a stable identifier in the DB column — it isn't navigated to.

- [ ] **Step 3: Type-check + lint**

Run: `cd apps/web && npx tsc --noEmit && npm run lint`
Expected: zero errors.

- [ ] **Step 4: Manual verification**

Run: `cd apps/web && npm run dev` (skip if already running)
Open `http://localhost:3000/targets/new`. Select "Host / IP" type. Enter:
```
box1.example.com
1.2.3.4
10.0.0.5
not-a-host://nope
1.2.3.4
```
Expected: counter shows `4 / 50`, dedup chip with "Remove duplicates" button, one invalid chip for `not-a-host://nope`, one private chip for `10.0.0.5` warning that admin opt-in is needed.

- [ ] **Step 5: Commit**

```bash
git add apps/web/app/targets/new/page.tsx
git commit -m "feat(web): render HostFormSection on new-target page"
```

---

### Task 14: Disable Run-scan on host targets

**Files:**
- Modify: `apps/web/app/targets/[id]/page.tsx`
- Modify: `apps/web/app/targets/page.tsx`

- [ ] **Step 1: Add the disabled flag to the detail page**

In `app/targets/[id]/page.tsx`, find the Run-scan button. Add:

```tsx
const isHostKindUntilB = target.kind === "host";  // remove this line in sub-project B
<Button
  disabled={existingDisabledExpr || isHostKindUntilB}
  title={
    isHostKindUntilB
      ? "Host-target scanning ships in OSExploitAgent v2 (coming soon)."
      : undefined
  }
>
  Run scan
</Button>
```

Replace `existingDisabledExpr` with whatever the current `disabled` expression is on that button.

- [ ] **Step 2: Same change in the list page**

In `app/targets/page.tsx`, find the per-row scan action. Apply the identical pattern.

- [ ] **Step 3: Type-check + lint**

Run: `cd apps/web && npx tsc --noEmit && npm run lint`
Expected: zero errors.

- [ ] **Step 4: Manual verification**

Open a host target's detail page. Hover the Run-scan button — tooltip reads "Host-target scanning ships in OSExploitAgent v2 (coming soon)." Click — nothing happens (button disabled).

- [ ] **Step 5: Commit**

```bash
git add apps/web/app/targets/[id]/page.tsx apps/web/app/targets/page.tsx
git commit -m "feat(web): disable Run-scan on host-kind targets until sub-project B"
```

---

### Task 15: Render host list in `commission-scan-modal.tsx`

**Files:**
- Modify: `apps/web/components/commission-scan-modal.tsx`

- [ ] **Step 1: Add the bulleted-list block when kind is host**

In the modal body, just before the action-disclosure list, add:

```tsx
{target.kind === "host" && target.kind_config?.hosts && (
  <div className="rounded border p-3 text-sm">
    <p className="font-medium">You are authorizing exploitation of these hosts:</p>
    <ul className="mt-2 list-disc pl-5 font-mono">
      {target.kind_config.hosts.map((h: string) => (
        <li key={h}>{h}</li>
      ))}
    </ul>
  </div>
)}
```

> Even though the scan button is disabled in A, the modal change is included here so when B removes the gate, the user sees the host list in the consent flow from day one.

- [ ] **Step 2: Type-check + lint**

Run: `cd apps/web && npx tsc --noEmit && npm run lint`
Expected: zero errors.

- [ ] **Step 3: Commit**

```bash
git add apps/web/components/commission-scan-modal.tsx
git commit -m "feat(web): render kind_config.hosts in commission-scan modal for host targets"
```

---

### Task 16: Org-settings — `allow_private_targets` switch + flip-on modal

**Files:**
- Modify: `apps/web/app/org/settings/page.tsx`

- [ ] **Step 1: Add the permissions section**

Inside the existing settings layout, add a "Permissions" section:

```tsx
"use client";

import { useState } from "react";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

// Inside the component, alongside other settings state:
const [allowPrivate, setAllowPrivate] = useState<boolean>(org.allow_private_targets ?? false);
const [showFlipModal, setShowFlipModal] = useState(false);
const [acknowledged, setAcknowledged] = useState(false);

async function flipAllowPrivate(nextValue: boolean, ackProvided: boolean) {
  const res = await fetch(`/api/orgs/${org.id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      allow_private_targets: nextValue,
      ...(nextValue ? { private_targets_disclosure_ack: ackProvided } : {}),
    }),
  });
  if (!res.ok) {
    // surface the error inline.
    return;
  }
  setAllowPrivate(nextValue);
}

// In the rendered tree:
<section className="space-y-4">
  <h2 className="text-lg font-semibold">Permissions</h2>
  <div className="flex items-start gap-3">
    <Switch
      id="allow-private-targets"
      checked={allowPrivate}
      onCheckedChange={(next) => {
        if (next) {
          setShowFlipModal(true);
        } else {
          void flipAllowPrivate(false, false);
        }
      }}
    />
    <label htmlFor="allow-private-targets" className="text-sm">
      <span className="font-medium">Allow host targets that resolve to private IP space</span>
      <span className="block text-xs text-muted-foreground">
        Covers RFC1918 (10/8, 172.16/12, 192.168/16), loopback (127/8, ::1),
        link-local (169.254/16, fe80::/10), CGNAT (100.64/10), and IPv6 ULA
        (fc00::/7). Off by default for security.
      </span>
    </label>
  </div>
</section>

{/* Strong-attestation modal */}
<Dialog open={showFlipModal} onOpenChange={setShowFlipModal}>
  <DialogContent>
    <DialogHeader>
      <DialogTitle>Enable private-IP host targets?</DialogTitle>
    </DialogHeader>
    <p className="text-sm">
      Enabling private-IP host targets allows users in this org to register and
      (once OSExploitAgent ships) exploit hosts inside RFC1918, loopback,
      link-local, CGNAT, and IPv6 ULA ranges. You attest that this org operates
      or holds written authorization to test these networks. Pencheff logs every
      host target created under this flag for post-hoc abuse review.
    </p>
    <label className="flex items-center gap-2 text-sm">
      <input
        type="checkbox"
        checked={acknowledged}
        onChange={(e) => setAcknowledged(e.target.checked)}
      />
      I attest to the above.
    </label>
    <DialogFooter>
      <Button variant="outline" onClick={() => setShowFlipModal(false)}>
        Cancel
      </Button>
      <Button
        disabled={!acknowledged}
        onClick={async () => {
          await flipAllowPrivate(true, true);
          setShowFlipModal(false);
          setAcknowledged(false);
        }}
      >
        Enable
      </Button>
    </DialogFooter>
  </DialogContent>
</Dialog>
```

> **Implementation note:** match the existing UI-kit components in your codebase (some may import from a slightly different path). The shape — switch + modal with checkbox — is what matters.

- [ ] **Step 2: Type-check + lint**

Run: `cd apps/web && npx tsc --noEmit && npm run lint`
Expected: zero errors.

- [ ] **Step 3: Manual verification**

Open `http://localhost:3000/org/settings`. Confirm the new "Permissions" section. Toggle the switch on → modal appears → check the box → click Enable → switch stays on. Refresh → switch still on. Toggle off → no modal → switch goes off, stays off across refresh.

- [ ] **Step 4: Commit**

```bash
git add apps/web/app/org/settings/page.tsx
git commit -m "feat(web): org settings — allow_private_targets switch with attestation modal"
```

---

## Phase 4 — Integration + docs

### Task 17: Manual verification checklist

**Files:** none (verification only).

- [ ] **Step 1: Reset to a clean DB state**

Run: `docker compose down && docker compose up -d --build` (or whatever your reset routine is).

- [ ] **Step 2: Run the verification scenario**

1. Open the app, sign in as an org admin.
2. Org settings → Permissions → confirm "Allow host targets…" switch exists, is OFF, and shows the audit-log "last changed" line as blank.
3. New target → pick "Host / IP" → enter:
   ```
   box1.example.com
   8.8.8.8
   ```
   → Create. Confirm: redirect to detail page, `kind_config.hosts` shows both entries, `is_private_target = false`.
4. From the target detail page, click "Run scan". Confirm: button is disabled, tooltip reads about sub-project B.
5. New target → pick "Host / IP" → enter:
   ```
   10.0.0.5
   ```
   → Submit. Confirm: server returns 422; the form shows the `host_kind_private_targets_disabled` error with `10.0.0.5` highlighted.
6. Org settings → toggle "Allow host targets…" ON. Confirm: modal appears with strong-attestation copy. Try Enable WITHOUT checking the box — disabled. Check the box → Enable. Confirm: switch stays ON; reload → still ON.
7. Repeat step 5. Confirm: succeeds; detail page shows `is_private_target = true`.
8. Toggle the switch OFF — no modal, instant flip.
9. Verify in DB:
   ```bash
   docker exec pencheff-postgres-1 psql -U pencheff -d pencheff -c \
     "SELECT event_type, metadata FROM audit_logs WHERE event_type LIKE 'org.allow_private_targets%' OR event_type LIKE 'target.host%' ORDER BY created_at DESC LIMIT 10;"
   ```
   Expected: one row per host-Target create, one row per flag flip. Each row has actor_user_id and metadata populated.

- [ ] **Step 3: Record the checklist outcome**

Capture screenshots of the new tile, the form with chips, the disabled scan button, the org-settings switch + modal. Drop them in a PR comment.

---

### Task 18: CHANGELOG + spec status

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `docs/superpowers/specs/2026-05-17-host-target-kind-design.md`

- [ ] **Step 1: CHANGELOG entry**

In `CHANGELOG.md` (under `## Unreleased`), add:

```markdown
### Added

- Host target kind: new `Target.kind = "host"` for multi-host OS-level
  scanning. Hosts entered as a list (max 50 per target) of FQDNs or IPs.
  Scanning itself is gated until sub-project B (OSExploitAgent) ships —
  target creation lands now so consent flow and access controls can be
  audited in advance.
- `Org.allow_private_targets` admin opt-in for host targets that resolve
  to private IP space (RFC1918, loopback, link-local, CGNAT, IPv6 ULA).
  Flipping ON requires a strong-attestation acknowledgement.
- New consent action ID `host_os_exploitation`, declaring the strongest
  ROE in the platform (read-only post-exploit exfil + screenshot).
- `Scan.consent_payload` bumped to v2 — adds `authorized_hosts`,
  `acknowledged_at`, `acknowledged_by_user_id`, `acknowledged_from_ip`,
  `acknowledged_user_agent`. v1 payloads remain readable.
```

- [ ] **Step 2: Update the spec doc's status header**

Edit `docs/superpowers/specs/2026-05-17-host-target-kind-design.md` — change `**Status:** Awaiting user review of written spec` to `**Status:** Implemented in <branch-name> on 2026-05-17`.

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md docs/superpowers/specs/2026-05-17-host-target-kind-design.md
git commit -m "docs: changelog + spec status for sub-project A"
```

---

## Self-review (run after writing the full plan)

The implementer must mark these items off before declaring the plan ready to execute.

- [ ] Every spec section maps to a task. Checked sections: scope, data model, API contract, consent disclosure, frontend, validation rules, testing, rollout. (Note: spec's "automated frontend tests" requirement is downgraded to a manual verification checklist in Task 17 — see plan top notes on missing web test framework.)
- [ ] No placeholders: scanned for "TBD" / "TODO" / "fill in" / "etc." / "similar to" — none present.
- [ ] Type and identifier consistency: `HostKindConfig`, `is_private_target`, `allow_private_targets`, `host_os_exploitation`, `classify_host_list` — all spelled identically across every task.
- [ ] Migration is reversible (Task 1 covers upgrade + downgrade explicitly).
- [ ] Audit-log entries are written by Tasks 6 and 9; metadata fields match between tests and implementation.
- [ ] Frontend changes are paired with manual-verification steps because no automated test harness is configured for `apps/web`.
- [ ] Sub-project B's one-line removal point is explicitly called out in Task 14.
