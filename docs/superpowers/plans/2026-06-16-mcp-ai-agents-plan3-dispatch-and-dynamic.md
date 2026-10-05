# MCP / AI Agents — Plan 3: Pipeline Dispatch + Dynamic Probes

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** (A) Wire `kind="mcp"` into the Celery scan pipeline so registering an MCP target and commissioning a scan runs the static scanner end-to-end and persists findings — removing the Plan 1 409 gate. Then layer the dynamic surface: (B) DB migration marker, (C) transport/auth CVE probes, (D) consent-gated dynamic tool-invocation fuzzing (OAST-backed), (E) toxic-flow analysis + agent-endpoint probing.

**Architecture:** `scan_runner.run_scan` gets an `mcp` special-case branch mirroring the `llm` one (NOT `_run_kind_aware_scan`): create pencheff session with `mcp_config`, run `scan_mcp`, persist findings via the existing `_finding_to_db_row` path. The dynamic probes are new analyzers in `mcp_scan/` gated behind the `mcp_config` flags + consent (already enforced by Plan 1's `_required_disclosed_actions`). Static scanning (Tasks A/B) is independently shippable; the dynamic layer (C/D/E) extends `scan_mcp`.

**Tech Stack:** Python, FastAPI/Celery worker, pencheff plugin, mcp SDK, httpx, OAST, asyncio. API tests: `cd apps/api && .venv/bin/python -m pytest`. Plugin tests: `cd plugins/pencheff && uv run pytest`.

**Contract (from codebase map):**

- LLM dispatch is a special-case `if target.kind == "llm":` block in `run_scan` (scan_runner.py ~741-803) that runs AFTER `pencheff_create_session` and returns early; findings persisted via `_finding_to_db_row` + `DbFinding`. `mcp` mirrors this exactly. Do NOT add `mcp` to `_NON_DAST_NEW_KINDS`.
- pencheff session: `create_session(...)` in `plugins/pencheff/pencheff/core/session.py` — add an `mcp_config` field + param (parallel to `llm_config`).
- Tool bridge: in-process `import pencheff.server as srv; fn = getattr(srv, "scan_mcp"); await fn(session_id=psession.id, mcp_config=...)`.
- `scan_mcp(session_id, mcp_config=None)` already exists (Plan 2) and returns the standard `{new_findings,...}` shape; the static module runs analyzers + fingerprint.

**Series:** Plans 1, 1b, 2 done. This is the final plan.

---

## Task A: Pipeline dispatch for kind=mcp (end-to-end static) + remove 409 gate

**Files:**

- Modify `plugins/pencheff/pencheff/core/session.py` (add `mcp_config`)
- Modify `apps/api/pencheff_api/services/scan_runner.py` (session bind + `mcp` branch + `_run_mcp_scan` + `MCP_PROFILE_CAPS`)
- Modify `apps/api/pencheff_api/routers/scans.py` (remove the `mcp` 409 gate)
- Modify `apps/api/tests/test_scans_mcp_kind_gate.py` (invert: gate removed)
- Test `plugins/pencheff/tests/test_mcp_session_config.py`

- [ ] **Step 1: session.mcp_config (TDD)** — test `plugins/pencheff/tests/test_mcp_session_config.py`:

```python
from pencheff.core.session import create_session


def test_create_session_carries_mcp_config():
    cfg = {"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"]}
    s = create_session(target_url="mcp://t", depth="quick", mcp_config=cfg)
    assert s.mcp_config == cfg


def test_create_session_mcp_config_defaults_none():
    s = create_session(target_url="mcp://t", depth="quick")
    assert s.mcp_config is None
```

Run → FAIL. Then in `plugins/pencheff/pencheff/core/session.py`: add `mcp_config: dict[str, Any] | None = None` field to the `PentestSession` dataclass (next to `llm_config`), and add `mcp_config: dict[str, Any] | None = None` param to `create_session`, passing it through to the constructed `PentestSession(...)`. Run → PASS.

- [ ] **Step 2: scan_runner — bind mcp_config** — in `apps/api/pencheff_api/services/scan_runner.py`, the `pencheff_create_session(...)` call (~line 684) currently passes `llm_config=...`. Add an argument:

```python
        mcp_config=dict(target.kind_config) if (target.kind == "mcp" and target.kind_config) else None,
```

- [ ] **Step 3: scan_runner — MCP_PROFILE_CAPS + dispatch branch** — add near `LLM_PROFILE_CAPS`:

```python
MCP_PROFILE_CAPS: dict[str, int] = {"quick": 0, "standard": 50, "deep": 200}
# 0 = static only (no dynamic tool calls); >0 caps dynamic probes (Plan 3 C/D).
```

After the `if target.kind == "llm": ... return` block, add an `mcp` branch (mirror the llm persistence/grading block exactly — copy it, swapping the scan call):

```python
    if target.kind == "mcp":
        await _run_mcp_scan(scan_id=scan_id, psession=psession, profile=scan.profile, Session=Session)
        all_findings = (
            list(psession.findings.get_all(include_suppressed=True))
            if hasattr(psession.findings, "get_all") else []
        )
        if not all_findings and hasattr(psession.findings, "findings"):
            all_findings = list(psession.findings.findings)
        async with Session() as db:
            for f in all_findings:
                db.add(DbFinding(**_finding_to_db_row(scan_id, f)))
            await db.commit()
        score, grade, counts = compute_grade(
            [_DbFindingProxy(_) for _ in await _read_back_findings(scan_id, Session)],
            target_kind="mcp",
        )
        await _finalize_scan(scan_id, score, grade, counts, Session)
        return
```

NOTE: copy the EXACT persistence + grading + finalize tail from the `llm` block (the helper names `_read_back_findings`, `compute_grade`, `_finalize_scan`, `_DbFindingProxy`, `_finding_to_db_row` must match what the llm block uses — read it and replicate verbatim, only changing `target_kind="mcp"` and the scan call).

- [ ] **Step 4: `_run_mcp_scan`** — add near `_run_llm_scan` (mirror it; simpler — no payload cap needed for static):

```python
async def _run_mcp_scan(*, scan_id: str, psession, profile: str, Session) -> None:
    """Invoke the pencheff scan_mcp tool in-process (mirrors _run_llm_scan)."""
    import pencheff.server as srv
    fn = getattr(srv, "scan_mcp", None)
    if fn is None:
        log.warning("pencheff scan_mcp tool unavailable")
        return
    try:
        await asyncio.wait_for(
            fn(session_id=psession.id, mcp_config=psession.mcp_config),
            timeout=_HEARTBEAT_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        log.warning("scan_mcp timed out for scan %s", scan_id)
    except Exception as e:
        log.warning("scan_mcp failed for scan %s: %s", scan_id, e)
```

NOTE: match `_run_llm_scan`'s exact helper/timeout names (`_HEARTBEAT_TIMEOUT_S`, `log`) — read it and mirror. If `_run_llm_scan` writes a heartbeat/progress row, mirror that too.

- [ ] **Step 5: Remove the 409 gate** — in `apps/api/pencheff_api/routers/scans.py`, DELETE the `if target.kind == "mcp": raise HTTPException(409, ...)` block added in Plan 1 (the one with `error: "mcp_kind_scanning_not_yet_available"`). The consent vocabulary (mcp_enumerate etc.) added in Plan 1 stays and is now enforced for real.

- [ ] **Step 6: Invert the gate test** — replace `apps/api/tests/test_scans_mcp_kind_gate.py` contents so it asserts the gate is GONE: an mcp target no longer 409s on the `mcp_kind_scanning_not_yet_available` error. Minimal version:

```python
# apps/api/tests/test_scans_mcp_kind_gate.py
"""The mcp 409 'not yet available' gate was removed in Plan 3 (dispatch wired).
This guards against the gate being reintroduced."""
from __future__ import annotations

import inspect

from pencheff_api.routers import scans


def test_mcp_not_yet_available_gate_is_removed():
    src = inspect.getsource(scans.start_scan)
    assert "mcp_kind_scanning_not_yet_available" not in src, (
        "the temporary mcp scan gate must be removed once dispatch is wired"
    )
```

- [ ] **Step 7: Verify**
  - `cd plugins/pencheff && uv run pytest tests/test_mcp_session_config.py -q` → pass.
  - `cd apps/api && .venv/bin/python -m pytest tests/test_scans_mcp_kind_gate.py tests/test_scans_router_kind_aware.py -q` → pass.
  - `cd apps/api && .venv/bin/python -c "import pencheff_api.services.scan_runner"` → no import error.
  - `cd plugins/pencheff && uv run python -c "import pencheff.server, pencheff.core.session; print('ok')"` → ok.

- [ ] **Step 8: Commit**

```bash
git add plugins/pencheff/pencheff/core/session.py apps/api/pencheff_api/services/scan_runner.py apps/api/pencheff_api/routers/scans.py apps/api/tests/test_scans_mcp_kind_gate.py plugins/pencheff/tests/test_mcp_session_config.py
git commit -m "feat: wire kind=mcp into scan pipeline (static end-to-end), remove 409 gate"
```

After Task A: registering an MCP target and commissioning a scan runs the static scanner and persists findings end-to-end. **This is the shippable milestone.**

---

## Task B: Migration marker

**Files:** Create a new alembic migration under `apps/api/pencheff_api/db/migrations/versions/`.

- [ ] **Step 1:** Read the most recent migration for `memory`/`host` (the 0047/0048-style files) to copy the head-revision + style. `Target.kind` is `String(16)` (no enum), so no schema change is needed — this migration is a documentation/no-op marker recording that `mcp` is now a valid kind (mirrors how host/memory were added). Create `NNNN_mcp_target_kind.py` with the correct `down_revision` (current head) and empty `upgrade()`/`downgrade()` bodies plus a docstring explaining `mcp` is a `String(16)` value needing no DDL.

- [ ] **Step 2: Verify** — `cd apps/api && .venv/bin/python -m alembic history | head` (or the project's migration check) shows the new revision chains cleanly off the prior head. If the project has a "migrations form a single chain" test, run it.

- [ ] **Step 3: Commit**

```bash
git add apps/api/pencheff_api/db/migrations/versions/
git commit -m "chore(db): migration marker for mcp target kind (String(16), no DDL)"
```

---

## Task C: Transport / auth CVE probes

**Files:** Create `plugins/pencheff/pencheff/modules/mcp_scan/transport_probes.py`; test `tests/test_mcp_transport_probes.py`. Wire into `module.py`.

Active checks against an MCP HTTP endpoint. Designed for graceful degradation (a probe that errors yields no finding, not a crash). Pure-logic helpers (verdict from a response) are unit-tested; live HTTP is exercised via `httpx.MockTransport`.

- [ ] **Step 1: Failing tests** — test the verdict helpers with mocked responses:

```python
# plugins/pencheff/tests/test_mcp_transport_probes.py
from pencheff.modules.mcp_scan.manifest import McpManifest
from pencheff.modules.mcp_scan import transport_probes as tp


def _mf(**kw):
    base = dict(transport="sse", endpoint="http://localhost:9000/sse")
    base.update(kw); return McpManifest(**base)


def test_session_id_entropy_flags_pointer_like_id():
    # A pointer-cast integer string (oatpp-mcp CVE-2025-6515 pattern)
    assert tp._session_id_is_weak("140234176823920") is True
    assert tp._session_id_is_weak("0x7f3a1c2d") is True


def test_session_id_entropy_accepts_random_uuid():
    assert tp._session_id_is_weak("9f1c2e7a-3b4d-4f5e-8a9b-0c1d2e3f4a5b") is False


def test_rebind_verdict_flags_missing_host_validation():
    # No Host/Origin validation → server accepts a foreign Host header
    assert tp._accepts_foreign_host(status_code=200) is True
    assert tp._accepts_foreign_host(status_code=403) is False


def test_audience_verdict_flags_accepted_wrong_audience():
    assert tp._accepts_wrong_audience(status_code=200) is True
    assert tp._accepts_wrong_audience(status_code=401) is False


def test_only_runs_for_http_transports():
    stdio = McpManifest(transport="stdio", endpoint="stdio:x")
    # build_transport_findings returns [] for stdio (nothing to probe)
    import asyncio
    assert asyncio.run(tp.build_transport_findings(stdio, http_get=None)) == []
```

- [ ] **Step 2: FAIL**, then implement `transport_probes.py`:
  - `_session_id_is_weak(sid: str) -> bool` — true if the id looks like a pointer/integer/sequential (matches `^\d{6,}$` or `^0x[0-9a-f]+$`) rather than high-entropy (uuid/≥128-bit base64). (CVE-2025-6515.)
  - `_accepts_foreign_host(status_code) -> bool` — true if a request with a spoofed `Host`/`Origin` header was accepted (2xx) rather than rejected (4xx). (CVE-2025-66416 DNS-rebind class.)
  - `_accepts_wrong_audience(status_code) -> bool` — true if a token with a wrong `aud` was accepted (2xx) vs rejected (401/403). (MCP auth spec 2025-06-18.)
  - `async build_transport_findings(mf, http_get)` — for HTTP transports only (`mf.transport in {"sse","streamable_http"}`): perform the probes via the injected async `http_get` (so tests inject a mock; production injects an httpx client wrapper). For each weakness, emit a `Finding` (severity high, owasp LLM05/CWE as per the catalog, technique `mcp:dns-rebind` / `mcp:session-entropy` / `mcp:auth-audience`). Return `[]` for stdio. Wrap each probe in try/except → degrade to no-finding on error.
    Run → PASS.

- [ ] **Step 3: Wire into module.py** — in `McpStaticScanModule.run`, after the static analyzers, if `mf.transport` is HTTP, call `await build_transport_findings(mf, http_get=<httpx wrapper>)` and extend findings. Use a real httpx.AsyncClient wrapper in production; the module test (Plan 2) injects a fake manifest so this path is exercised separately by the transport-probe tests. Keep failures non-fatal.

- [ ] **Step 4: Commit**

```bash
git add plugins/pencheff/pencheff/modules/mcp_scan/transport_probes.py plugins/pencheff/pencheff/modules/mcp_scan/module.py plugins/pencheff/tests/test_mcp_transport_probes.py
git commit -m "feat(mcp-scan): transport/auth CVE probes (dns-rebind, session entropy, audience)"
```

---

## Task D: Consent-gated dynamic tool-invocation fuzzing

**Files:** Create `plugins/pencheff/pencheff/modules/mcp_scan/dynamic.py`; test `tests/test_mcp_dynamic.py`. Wire into `module.py` + `scan_mcp`.

Invokes tools via `tools/call` with adversarial inputs. Gated by `mcp_config.dynamic_invocation` (and `destructive_opt_in` for destructive-classed tools — classification reuses the `analyze_excessive_agency` keyword logic). OAST-backed for blind detection. The payload generator + the tool-classifier + the response analyzer are pure (unit-tested); live invocation uses a fake session in tests.

- [ ] **Step 1: Failing tests** for the pure parts:

```python
# plugins/pencheff/tests/test_mcp_dynamic.py
from pencheff.modules.mcp_scan.manifest import McpTool
from pencheff.modules.mcp_scan import dynamic as dyn


def test_classify_destructive_tool():
    assert dyn.is_destructive(McpTool(name="delete_file", description="Delete a file")) is True
    assert dyn.is_destructive(McpTool(name="get_weather", description="Return weather")) is False


def test_injection_payloads_include_oast_and_traversal():
    payloads = dyn.injection_payloads(oast_url="http://oast.example/abc")
    joined = " ".join(payloads)
    assert "oast.example" in joined          # SSRF/exfil canary
    assert any(".." in p for p in payloads)  # path traversal
    assert any(";" in p or "|" in p for p in payloads)  # command injection


def test_response_indicates_injection_on_oast_hit():
    assert dyn.response_indicates_injection("...root:x:0:0:...", oast_hit=False)  # LFI marker
    assert dyn.response_indicates_injection("ok", oast_hit=True)  # blind via OAST


def test_select_tools_respects_allow_deny_and_gating():
    tools = [McpTool(name="read_x", description="read"), McpTool(name="delete_x", description="delete")]
    # dynamic on, destructive off → only non-destructive, minus denylist
    sel = dyn.select_tools(tools, allow=[], deny=["read_x"], dynamic=True, destructive=False)
    assert sel == []  # read_x denied, delete_x destructive-excluded
    sel2 = dyn.select_tools(tools, allow=[], deny=[], dynamic=True, destructive=True)
    assert {t.name for t in sel2} == {"read_x", "delete_x"}
    assert dyn.select_tools(tools, allow=[], deny=[], dynamic=False, destructive=False) == []
```

- [ ] **Step 2: FAIL**, then implement `dynamic.py`:
  - `is_destructive(tool) -> bool` — reuse the `_DANGEROUS` keyword set from static_analyzers (import it) against name+description.
  - `injection_payloads(oast_url) -> list[str]` — command-injection (`; id`, `| id`, backticks), SSRF (the oast_url), path-traversal (`../../../../etc/passwd`), and a benign canary.
  - `response_indicates_injection(text, oast_hit) -> bool` — true if `oast_hit` OR the text matches LFI/cmd markers (`root:x:0:0`, `uid=`, etc.).
  - `select_tools(tools, allow, deny, dynamic, destructive) -> list[McpTool]` — `[]` if not `dynamic`; filter by allow (if non-empty) / deny; exclude destructive unless `destructive`.
  - `async fuzz_tools(session, tools, *, oast, allow, deny, dynamic, destructive, endpoint) -> list[Finding]` — for each selected tool, for each payload, call `session.call_tool(name, args)` (wrap per-call in try/except), analyze the response (+ poll OAST), emit a `Finding` on a hit (technique `mcp:param-injection`, severity high/critical, CWE-78/918/22 by payload class). Use a fake session in tests.
    Run → PASS.

- [ ] **Step 3: Wire** — extend `scan_mcp` (or the module) so when `mcp_config.dynamic_invocation` is set, it opens a live session (the client already opens one in `connect_and_enumerate` — refactor so the same `ClientSession` is reused for enumeration AND fuzzing, OR re-open for fuzzing) and runs `fuzz_tools` with the OAST handle (`from pencheff.core.oast import get_oast`). Respect `MCP_PROFILE_CAPS` as the max tool-call budget. Destructive only when `destructive_opt_in`. Keep all live calls non-fatal.

- [ ] **Step 4: Commit**

```bash
git add plugins/pencheff/pencheff/modules/mcp_scan/dynamic.py plugins/pencheff/pencheff/modules/mcp_scan/module.py plugins/pencheff/pencheff/server.py plugins/pencheff/tests/test_mcp_dynamic.py
git commit -m "feat(mcp-scan): consent-gated dynamic tool-invocation fuzzing (OAST-backed)"
```

---

## Task E: Toxic-flow + agent-endpoint probing

**Files:** Create `plugins/pencheff/pencheff/modules/mcp_scan/agent_probe.py`; test `tests/test_mcp_agent_probe.py`. Wire `agent_http`/`agent_browser` sources into `scan_mcp`.

- [ ] **Step 1: Failing tests** for the pure parts:
  - `lethal_trifecta_present(manifest_or_tools) -> bool` — true when the tool set combines (untrusted-input capability) + (private-data access) + (exfiltration/egress) — the confused-deputy/toxic-flow precondition. Test with a tool set that has all three vs one missing.
  - `build_agent_probe_config(mcp_config) -> dict` — maps an `agent_http`/`agent_browser` McpConfig into the `llm_config` shape the existing LlmProbe engine consumes (provider/url/request_template/response_path or browser selectors) + sets `redteam.plugins=["mcp"]` so the existing `mcp.yaml` attack pack runs.

- [ ] **Step 2: FAIL**, then implement `agent_probe.py`:
  - `lethal_trifecta_present(...)` per above (keyword-classify tools into the three buckets; true iff all three non-empty).
  - `build_agent_probe_config(...)` per above.
  - `async run_agent_probe(session, mcp_config) -> list[Finding]` — for `agent_http`/`agent_browser`: build the probe config, run the existing LlmProbe / llm_red_team `mcp` pack against it (reuse `pencheff.modules.llm_red_team`), and if `lethal_trifecta_present`, emit a high-severity toxic-flow `Finding` (technique `mcp:toxic-flow`, LLM06/CWE-441).
    Run → PASS.

- [ ] **Step 3: Wire into `scan_mcp`/module** — when `source_type in {"agent_http","agent_browser"}`, route to `run_agent_probe` instead of `connect_and_enumerate` (which only handles mcp_server sources). Findings merge into the same return.

- [ ] **Step 4: Commit**

```bash
git add plugins/pencheff/pencheff/modules/mcp_scan/agent_probe.py plugins/pencheff/pencheff/modules/mcp_scan/module.py plugins/pencheff/pencheff/server.py plugins/pencheff/tests/test_mcp_agent_probe.py
git commit -m "feat(mcp-scan): toxic-flow analysis + agent-endpoint probing (agent_http/agent_browser)"
```

---

## Task F: Full regression

- [ ] **Step 1:** `cd plugins/pencheff && uv run pytest tests/test_mcp_*.py -q` — all green.
- [ ] **Step 2:** `cd apps/api && .venv/bin/python -m pytest tests/ -q -k "scan or mcp or kind or consent"` — green.
- [ ] **Step 3:** import checks: `pencheff.server`, `pencheff_api.services.scan_runner` — clean.
- [ ] **Step 4:** Commit any fixups.

---

## Self-review

**Spec coverage (spec §4 dispatch, §7c transport probes, §7d dynamic, §7e toxic-flow/agent, §9 consent enforcement, §12 migration):** dispatch + gate removal (A) ✓; migration (B) ✓; transport/auth probes (C) ✓; dynamic fuzzing (D) ✓; toxic-flow + agent probing (E) ✓; consent already enforced via Plan 1's `_required_disclosed_actions` (A relies on it) ✓.

**Placeholder scan:** Task A dispatch + session field are complete code; B is a no-DDL marker; C/D/E specify pure unit-tested cores (verdict helpers, payload gen, tool selection, trifecta detection) with complete test contracts + concrete function specs, and live-invocation wiring described against the real client/OAST/LlmProbe seams. The live-network paths are integration surface (exercised manually / in Plan-4 e2e), consistent with how the llm path is structured.

**Type consistency:** `mcp_config` dict keys (`source_type`, `command`, `dynamic_invocation`, `destructive_opt_in`, `tool_allowlist`, `tool_denylist`) match Plan 1 `McpConfig`; `Finding`/`Severity`/`McpTool`/`McpManifest` consistent with Plan 2; scan_runner helper names (`_finding_to_db_row`, `compute_grade`, `_finalize_scan`, `_read_back_findings`, `_DbFindingProxy`, `_HEARTBEAT_TIMEOUT_S`) flagged to mirror the real `llm` block verbatim.

**Shippable checkpoint:** Task A alone delivers end-to-end static MCP scanning through the platform. C/D/E extend it with the dynamic surface; each is independently committable.

**Risk note:** the dynamic/live-network tasks (D/E) invoke real tools — they are consent-gated (Plan 1) and `destructive_opt_in`-gated, intended for sandbox targets, and all live calls are non-fatal. The fragile surface is the live `ClientSession` reuse for fuzzing and the OAST handle plumbing; the pure decision logic is unit-tested.
