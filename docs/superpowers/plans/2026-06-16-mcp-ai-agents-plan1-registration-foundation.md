# MCP / AI Agents — Plan 1: Backend Registration & Consent Foundation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the API accept and validate `kind="mcp"` target registration for all four sources (remote/stdio MCP server, agent HTTP, agent browser), wire the MCP consent vocabulary, and safely gate MCP scanning until the scanner ships.

**Architecture:** Adds `mcp` as a new wire kind (`Target.kind` is `String(16)` — no DB enum migration) with a dedicated `McpConfig` in the existing `kind_config` discriminated union, mirroring the established per-kind config + consent pattern (host/memory). A 409 gate on `POST /scans` prevents an MCP target from falling through to the URL/DAST pipeline before the real scanner exists (same pattern as the host and memory gates already in the codebase).

**Tech Stack:** Python 3, FastAPI, Pydantic v2, pytest (`.venv/bin/python -m pytest`), SQLAlchemy.

**Series context:** Plan 1 (this) = backend registration/consent. Plan 1b = frontend form. Plan 2 = MCP protocol client + static analyzers + fingerprinting. Plan 3 = transport/auth probes + dynamic fuzzing + toxic-flow + dispatch wiring (removes the gate from Task 3). Spec: `docs/superpowers/specs/2026-06-16-mcp-ai-agents-scanning-design.md`.

---

## File structure

| File                                             | Responsibility                                                                              | Change |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------- | ------ |
| `apps/api/pencheff_api/schemas/targets.py`       | `McpConfig` model; add `mcp` to `TargetKind`, `_KINDS_REQUIRING_CONFIG`, `KindConfig` union | Modify |
| `apps/api/pencheff_api/schemas/scans.py`         | `KIND_REQUIRED_DISCLOSED_ACTIONS["mcp"]` base actions                                       | Modify |
| `apps/api/pencheff_api/routers/scans.py`         | `_required_disclosed_actions` mcp extension; `start_scan` 409 gate                          | Modify |
| `apps/api/tests/test_targets_mcp_config.py`      | `McpConfig` validation tests                                                                | Create |
| `apps/api/tests/test_scans_mcp_kind_gate.py`     | scan-gating 409 tests                                                                       | Create |
| `apps/api/tests/test_scans_router_kind_aware.py` | add `mcp` to coverage + FE-mirror sets                                                      | Modify |

---

## Task 1: `McpConfig` schema + `mcp` wire kind

**Files:**

- Modify: `apps/api/pencheff_api/schemas/targets.py` (TargetKind ~line 12; `_KINDS_REQUIRING_CONFIG` ~line 24; new class before `KindConfig` ~line 408; union ~line 410-418)
- Test: `apps/api/tests/test_targets_mcp_config.py`

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/test_targets_mcp_config.py`:

```python
# apps/api/tests/test_targets_mcp_config.py
"""Validation tests for the McpConfig kind_config variant."""
from __future__ import annotations

import pytest
from pydantic import ValidationError, TypeAdapter

from pencheff_api.schemas.targets import KindConfig

_adapter = TypeAdapter(KindConfig)


def _parse(data: dict):
    return _adapter.validate_python(data)


def test_mcp_http_requires_url_and_transport():
    ok = _parse({"kind": "mcp", "source_type": "mcp_http",
                 "url": "https://mcp.example.com/sse", "transport": "sse"})
    assert ok.source_type == "mcp_http"
    with pytest.raises(ValidationError):
        _parse({"kind": "mcp", "source_type": "mcp_http"})  # no url/transport


def test_mcp_stdio_requires_command():
    ok = _parse({"kind": "mcp", "source_type": "mcp_stdio",
                 "command": ["npx", "some-mcp-server"]})
    assert ok.command == ["npx", "some-mcp-server"]
    with pytest.raises(ValidationError):
        _parse({"kind": "mcp", "source_type": "mcp_stdio"})  # no command


def test_agent_http_requires_provider():
    ok = _parse({"kind": "mcp", "source_type": "agent_http", "provider": "openai-chat"})
    assert ok.provider == "openai-chat"
    with pytest.raises(ValidationError):
        _parse({"kind": "mcp", "source_type": "agent_http"})  # no provider


def test_agent_browser_requires_url_and_selectors():
    ok = _parse({"kind": "mcp", "source_type": "agent_browser",
                 "url": "https://agent.example.com",
                 "prompt_selector": "#in", "send_selector": "#go",
                 "response_selector": "#out"})
    assert ok.prompt_selector == "#in"
    with pytest.raises(ValidationError):
        _parse({"kind": "mcp", "source_type": "agent_browser",
                "url": "https://agent.example.com"})  # missing selectors


def test_destructive_defaults_false_and_extra_forbidden():
    cfg = _parse({"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"]})
    assert cfg.dynamic_invocation is False
    assert cfg.destructive_opt_in is False
    with pytest.raises(ValidationError):
        _parse({"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"],
                "bogus_field": 1})  # extra="forbid" inherited from _KindConfigBase
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_targets_mcp_config.py -q`
Expected: FAIL — `mcp` is not a valid discriminator value in the `KindConfig` union (ValidationError on the _valid_ cases too).

- [ ] **Step 3: Add `mcp` to the wire-kind enum and required-config set**

In `apps/api/pencheff_api/schemas/targets.py`, edit `TargetKind` to add `"mcp"` after `"memory"`:

```python
TargetKind = Literal[
    "url", "repo", "llm",
    "web_app", "rest_api", "graphql", "websocket", "grpc",
    "source_code", "cicd_pipeline", "iac",
    "container_image", "k8s_cluster",
    "package_registry", "sbom",
    "host",  # sub-project A — multi-host list for OS exploitation
    "memory",  # agent memory / vector-store items, scanned via /v1/memory/scan
    "mcp",  # MCP server / AI agent — source-aware scanner (see spec 2026-06-16)
]
```

And add `"mcp"` to `_KINDS_REQUIRING_CONFIG`:

```python
_KINDS_REQUIRING_CONFIG: frozenset[str] = frozenset({
    "web_app", "rest_api", "graphql", "websocket", "grpc",
    "source_code", "cicd_pipeline", "iac",
    "container_image", "k8s_cluster",
    "package_registry", "sbom",
    "host",
    "memory",
    "mcp",
})
```

- [ ] **Step 4: Add the `McpConfig` class**

In `apps/api/pencheff_api/schemas/targets.py`, immediately before the `KindConfig = Annotated[...]` union (currently ~line 410), insert:

```python
class McpConfig(_KindConfigBase):
    """MCP server / AI agent target config (source-aware).

    One card → kind="mcp"; the four deployment sources live in ``source_type``.
    MCP-server sources (mcp_http/mcp_stdio) drive the MCP protocol client +
    static/dynamic tool analyzers; agent sources (agent_http/agent_browser)
    reuse the LlmProbe engine with the MCP/agent attack pack. Auth secrets ride
    on Target.kind_credentials_encrypted, not here. See spec 2026-06-16.
    """

    kind: Literal["mcp"] = "mcp"
    source_type: Literal["mcp_http", "mcp_stdio", "agent_http", "agent_browser"]

    # mcp_http
    url: HttpUrl | None = None
    transport: Literal["sse", "streamable_http"] | None = None

    # mcp_stdio
    command: list[str] | None = None
    env: dict[str, str] | None = None  # non-secret only; secrets via kind_credentials
    cwd: str | None = None

    # agent_http (LLM-style; reuses LlmProbe engine)
    provider: LlmProvider | None = None
    model: str | None = None
    request_template: str | None = None
    response_path: str | None = None

    # agent_browser (Playwright)
    prompt_selector: str | None = None
    send_selector: str | None = None
    response_selector: str | None = None

    # common dynamic-testing controls
    tool_allowlist: list[str] = Field(default_factory=list)
    tool_denylist: list[str] = Field(default_factory=list)
    dynamic_invocation: bool = False
    destructive_opt_in: bool = False

    @model_validator(mode="after")
    def _validate_source(self) -> "McpConfig":
        st = self.source_type
        if st == "mcp_http" and not (self.url and self.transport):
            raise ValueError("source_type='mcp_http' requires url and transport")
        if st == "mcp_stdio" and not self.command:
            raise ValueError("source_type='mcp_stdio' requires command")
        if st == "agent_http" and not self.provider:
            raise ValueError("source_type='agent_http' requires provider")
        if st == "agent_browser" and not (
            self.url and self.prompt_selector and self.send_selector
            and self.response_selector
        ):
            raise ValueError(
                "source_type='agent_browser' requires url, prompt_selector, "
                "send_selector, response_selector"
            )
        return self
```

- [ ] **Step 5: Add `McpConfig` to the `KindConfig` union**

Edit the union to include `McpConfig`:

```python
KindConfig = Annotated[
    Union[
        WebAppConfig, RestApiConfig, GraphqlConfig, WebsocketConfig, GrpcConfig,
        SourceCodeConfig, CicdPipelineConfig, IacConfig, ContainerImageConfig,
        K8sClusterConfig, PackageRegistryConfig, SbomConfig,
        HostKindConfig, MemoryKindConfig, McpConfig,
    ],
    Field(discriminator="kind"),
]
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_targets_mcp_config.py -q`
Expected: PASS (5 passed).

- [ ] **Step 7: Run the broader targets-schema suite to catch coverage tests**

Run: `cd apps/api && .venv/bin/python -m pytest tests/ -q -k "target" `
Expected: PASS. If a test asserts "every non-legacy kind has a KindConfig" or "every kind is legacy-or-requires-config", it now passes because `mcp` is in both the union and `_KINDS_REQUIRING_CONFIG`. If any such test hard-codes an expected kind set, add `"mcp"` to it (fix inline, re-run).

- [ ] **Step 8: Commit**

```bash
git add apps/api/pencheff_api/schemas/targets.py apps/api/tests/test_targets_mcp_config.py
git commit -m "feat(api): add mcp wire kind + McpConfig (source-aware registration)"
```

---

## Task 2: MCP consent vocabulary

**Files:**

- Modify: `apps/api/pencheff_api/schemas/scans.py:14-38` (`KIND_REQUIRED_DISCLOSED_ACTIONS`)
- Modify: `apps/api/pencheff_api/routers/scans.py:37-52` (`_required_disclosed_actions`)
- Modify: `apps/api/tests/test_scans_router_kind_aware.py` (coverage `expected` set + FE-mirror `_FRONTEND_DISCLOSED_ACTION_IDS_BY_KIND`)
- Test: `apps/api/tests/test_scans_router_kind_aware.py` (new cases)

- [ ] **Step 1: Write the failing test**

Append to `apps/api/tests/test_scans_router_kind_aware.py`:

```python
def test_mcp_base_required_action_is_enumerate() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions

    class _T:
        kind = "mcp"
        kind_config = {"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"]}

    actions = _required_disclosed_actions(_T())
    assert actions == {"mcp_enumerate"}


def test_mcp_dynamic_invocation_adds_tool_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions

    class _T:
        kind = "mcp"
        kind_config = {"kind": "mcp", "source_type": "mcp_stdio",
                       "command": ["x"], "dynamic_invocation": True}

    actions = _required_disclosed_actions(_T())
    assert "mcp_enumerate" in actions
    assert "mcp_tool_invocation" in actions
    assert "mcp_destructive_tool_invocation" not in actions


def test_mcp_destructive_opt_in_adds_destructive_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions

    class _T:
        kind = "mcp"
        kind_config = {"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"],
                       "dynamic_invocation": True, "destructive_opt_in": True}

    actions = _required_disclosed_actions(_T())
    assert "mcp_destructive_tool_invocation" in actions
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_scans_router_kind_aware.py -q -k mcp`
Expected: FAIL — `_required_disclosed_actions` returns `set()` for `mcp` (kind not in `KIND_REQUIRED_DISCLOSED_ACTIONS`).

- [ ] **Step 3: Add the base action set**

In `apps/api/pencheff_api/schemas/scans.py`, inside `KIND_REQUIRED_DISCLOSED_ACTIONS`, add after the `"host"` entry:

```python
    # MCP / AI agent target (spec 2026-06-16). Base = passive enumeration;
    # the router ADDS mcp_tool_invocation / mcp_destructive_tool_invocation
    # when kind_config.dynamic_invocation / destructive_opt_in are set.
    "mcp":              frozenset({"mcp_enumerate"}),
```

- [ ] **Step 4: Extend the router's per-row computation**

In `apps/api/pencheff_api/routers/scans.py`, inside `_required_disclosed_actions`, after the existing `k8s_cluster` block (right before the function returns the frozenset), add:

```python
    if target.kind == "mcp":
        if cfg.get("dynamic_invocation") is True:
            base.add("mcp_tool_invocation")
        if cfg.get("destructive_opt_in") is True:
            base.add("mcp_destructive_tool_invocation")
```

(Place it before the existing `return frozenset(base)` line.)

- [ ] **Step 5: Update the coverage + FE-mirror sets**

In `apps/api/tests/test_scans_router_kind_aware.py`:

In `test_kind_required_disclosed_actions_covers_every_target_kind`, add `"mcp"` to the `expected` set:

```python
        "host",  # sub-project A
        "mcp",   # spec 2026-06-16
    }
```

In `_FRONTEND_DISCLOSED_ACTION_IDS_BY_KIND`, add an `mcp` entry mirroring the full mcp vocabulary the FE will define (Plan 1b):

```python
    "mcp": {"mcp_enumerate", "mcp_tool_invocation", "mcp_destructive_tool_invocation"},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_scans_router_kind_aware.py -q`
Expected: PASS (all, including the 3 new mcp cases and the updated coverage test).

- [ ] **Step 7: Commit**

```bash
git add apps/api/pencheff_api/schemas/scans.py apps/api/pencheff_api/routers/scans.py apps/api/tests/test_scans_router_kind_aware.py
git commit -m "feat(api): MCP consent vocabulary (enumerate/tool/destructive disclosed actions)"
```

---

## Task 3: Gate MCP scanning until the scanner ships

**Files:**

- Modify: `apps/api/pencheff_api/routers/scans.py` (`start_scan`, near the existing `memory`/`host` gates ~line 188-200)
- Test: `apps/api/tests/test_scans_mcp_kind_gate.py`

This mirrors the existing host/memory gates. It is **removed in Plan 3** when the real `mcp` dispatch lands.

- [ ] **Step 1: Write the failing test**

Create `apps/api/tests/test_scans_mcp_kind_gate.py`:

```python
# apps/api/tests/test_scans_mcp_kind_gate.py
"""POST /scans must 409 for kind="mcp" until the MCP scanner ships (Plan 3).

Prevents an mcp target from falling through to the URL/DAST runner. Mirrors
test_scans_host_kind_gate.py / test_scans_memory_kind_gate.py.
"""
from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from pencheff_api.db.models import Scan, Target, User, Workspace
from pencheff_api.routers.scans import start_scan
from pencheff_api.schemas.scans import ConsentPayload, ScanCreate

_NOW = datetime.datetime.now(datetime.timezone.utc)
_AUTH = (
    "I confirm I have written authorization from AcmeCorp to perform "
    "an AI-assisted security assessment of the target systems listed."
)


def _ws() -> Workspace:
    return Workspace(id="ws-1", org_id="org-1", name="Default")


def _user() -> User:
    return User(id="user-1", email="t@example.com")


def _mcp_target(ws: Workspace) -> Target:
    return Target(
        id="target-mcp-1", org_id=ws.org_id, workspace_id=ws.id, user_id="user-1",
        name="My MCP", base_url="https://mcp.example.com/sse",
        scope=None, exclude_paths=[], credentials_encrypted=None,
        kind_credentials_encrypted=None, kind="mcp", llm_config=None,
        kind_config={"kind": "mcp", "source_type": "mcp_http",
                     "url": "https://mcp.example.com/sse", "transport": "sse"},
        weekly_digest_emails=None, repository_id=None, created_at=_NOW,
    )


def _body(target_id: str) -> ScanCreate:
    return ScanCreate(
        target_id=target_id, profile="standard",
        consent_payload=ConsentPayload(
            acknowledged=True, authorization_text=_AUTH,
            disclosed_actions=["mcp_enumerate"], consent_given_at=_NOW,
        ),
    )


class _FakeSession:
    def __init__(self, target):
        self._t = target
        self.added = []
        self._n = 0

    async def execute(self, stmt):
        self._n += 1
        m = MagicMock()
        if self._n == 1:
            m.scalar_one_or_none.return_value = self._t
        else:
            m.scalar_one_or_none.return_value = None
            m.scalars.return_value.all.return_value = []
        return m

    def add(self, row):
        self.added.append(row)

    async def flush(self):
        ...

    async def commit(self):
        ...

    async def refresh(self, obj):
        ...

    async def get(self, model_cls, pk):
        return None


@pytest.mark.asyncio
async def test_scan_against_mcp_target_returns_409() -> None:
    ws, user, target = _ws(), _user(), None
    target = _mcp_target(ws)
    session = _FakeSession(target)
    with patch("pencheff_api.routers.scans.run_full_scan") as task:
        task.delay = MagicMock()
        with pytest.raises(HTTPException) as ei:
            await start_scan(body=_body(target.id), user=user, workspace=ws, session=session)
    assert ei.value.status_code == 409
    assert ei.value.detail["error"] == "mcp_kind_scanning_not_yet_available"


@pytest.mark.asyncio
async def test_scan_against_mcp_target_does_not_enqueue_or_write() -> None:
    ws, user = _ws(), _user()
    target = _mcp_target(ws)
    session = _FakeSession(target)
    delay = MagicMock()
    with patch("pencheff_api.routers.scans.run_full_scan") as task:
        task.delay = delay
        with pytest.raises(HTTPException):
            await start_scan(body=_body(target.id), user=user, workspace=ws, session=session)
    delay.assert_not_called()
    assert [r for r in session.added if isinstance(r, Scan)] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_scans_mcp_kind_gate.py -q`
Expected: FAIL — no 409 gate yet; the handler proceeds past target lookup (raises a different error or no error), so `detail["error"]` assertion fails.

- [ ] **Step 3: Add the gate**

In `apps/api/pencheff_api/routers/scans.py`, in `start_scan`, immediately after the existing `host` 409 gate block (and before the `llm` `llm_config` check), add:

```python
    # MCP targets are scanned by the dedicated MCP scanner (spec 2026-06-16),
    # which ships in Plan 3. Until then, fail fast so an mcp target can never
    # fall through to the URL/DAST runner. Remove this gate when mcp dispatch
    # lands in services/scan_runner.py.
    if target.kind == "mcp":
        raise HTTPException(
            status_code=409,
            detail={
                "error": "mcp_kind_scanning_not_yet_available",
                "message": (
                    "MCP / AI-agent scanning ships shortly. Target registration "
                    "is supported now; scanning is not yet enabled."
                ),
            },
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && .venv/bin/python -m pytest tests/test_scans_mcp_kind_gate.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/routers/scans.py apps/api/tests/test_scans_mcp_kind_gate.py
git commit -m "feat(api): gate POST /scans for kind=mcp until scanner ships (Plan 3)"
```

---

## Task 4: Full-suite regression check

**Files:** none (verification only)

- [ ] **Step 1: Run the scan + target test suites**

Run: `cd apps/api && .venv/bin/python -m pytest tests/ -q -k "scan or target or consent or kind"`
Expected: PASS. Investigate any failure referencing `mcp`, `KIND_REQUIRED_DISCLOSED_ACTIONS`, or the `KindConfig` union; fix inline (most likely a hard-coded kind set needing `"mcp"` added).

- [ ] **Step 2: Commit any fixups**

```bash
git add -A apps/api
git commit -m "test(api): align kind-set fixtures with new mcp kind"
```

(Skip if Step 1 was already green.)

---

## Self-review

**Spec coverage (this plan = §5.1, §5.2 schema, §9 backend consent, §12 backend gate):**

- §5.1 wire kind added (TargetKind, \_KINDS_REQUIRING_CONFIG, KindConfig union) → Task 1 ✓
- §5.2 McpConfig with 4 source_types + dynamic controls + validation → Task 1 ✓
- §9 consent disclosed actions (mcp_enumerate / mcp_tool_invocation / mcp_destructive_tool_invocation), graduated by config → Task 2 ✓
- §12 scan gate (no fall-through) → Task 3 ✓
- Out of this plan (later): FE form (§5.3, §11) → Plan 1b; protocol client + analyzers (§6, §7) → Plan 2/3; DB migration marker (§12) → folded into Plan 3 with dispatch.

**Placeholder scan:** No TBD/TODO; every code step shows complete code. ✓

**Type consistency:** `McpConfig.kind="mcp"` matches the union discriminator and `KIND_REQUIRED_DISCLOSED_ACTIONS["mcp"]`; action IDs (`mcp_enumerate`, `mcp_tool_invocation`, `mcp_destructive_tool_invocation`) identical across scans.py, routers/scans.py, and the test FE-mirror; config keys (`dynamic_invocation`, `destructive_opt_in`, `source_type`, `command`, `url`, `transport`) identical across schema, router computation, and tests. ✓

**Note on `db/migrations`:** `Target.kind` is `String(16)` (not a PG enum), so registering `kind="mcp"` needs **no** migration. A documentation-only migration (host/memory pattern) is deferred to Plan 3 alongside the dispatch change, to keep this plan migration-free and reversible.
