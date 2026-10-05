# MCP / AI Agents — Plan 4: Live-Wiring Follow-ups

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Make the three gated/stub dynamic paths from Plan 3 actually fire: (A) a live HTTP getter so transport/auth CVE probes run against real MCP HTTP servers; (B) wire the OAST handle into dynamic fuzzing so blind SSRF/exfil is detectable; (C) harden agent-endpoint probing so it reliably drives the llm_red_team `mcp` pack and surfaces failures instead of silently returning `[]`.

**Architecture:** All three are completions of existing `mcp_scan/` code — no new design. (A) adds an httpx-backed getter closure in `module.py` and passes it to the already-built `build_transport_findings`. (B) adds a thin OAST adapter (`.url` + async `poll()`) and passes it to the already-built `fuzz_tools`. (C) ensures `session.llm_config`/endpoint are set and replaces the silent `except: pass` with logging + makes the live invocation testable.

**Tech Stack:** Python, httpx, mcp SDK, pencheff plugin. Tests: `cd plugins/pencheff && uv run pytest <file> -q`.

**Branch:** `feat/mcp-live-wiring` off `main@43c9ecc` (MCP feature already shipped). Contract facts (verified):

- `build_transport_findings(mf, http_get)` calls `await http_get(url, headers={...})` and reads `resp.status_code` + (probe 2) `getattr(resp, "session_id", None)`; returns `[]` when `http_get is None` or transport is stdio.
- `fuzz_tools(..., oast=...)` reads `oast.url` (a string) and `await oast.poll()` (returns a list; non-empty = callback hit). `OASTManager` (from `pencheff.core.oast.get_oast(session_id)`) has `new_url(label)->str` (sync) + `poll()->list` (async) but NO `.url`.
- `run_agent_probe` sets `session.llm_config = probe_cfg` then `await module.run(session, http=None, config={"llm_config": probe_cfg})` for `LLM_RED_TEAM_MODULES["LLM06"]`; proven pattern (matches `scan_llm_red_team` in server.py). Currently wrapped in `except Exception: pass`.
- httpx house style: `httpx.AsyncClient(verify=False, timeout=httpx.Timeout(...), follow_redirects=...)`.

---

## Task 1 (Fix A): Live HTTP getter for transport/auth probes

**Files:** Modify `plugins/pencheff/pencheff/modules/mcp_scan/module.py`; new `tests/test_mcp_transport_getter.py`.

The getter is the small piece that makes the (already-tested) transport probes actually probe. It runs for HTTP transports as part of the standard scan (covered by the always-disclosed `mcp_enumerate` consent — it's connection-level, no tool invocation).

- [ ] **Step 1: Failing test** — `plugins/pencheff/tests/test_mcp_transport_getter.py`:

```python
import asyncio
import httpx
from pencheff.modules.mcp_scan.module import _make_http_probe_getter


def test_getter_returns_status_and_session_id():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Mcp-Session-Id": "abc-123"}, text="ok")
    transport = httpx.MockTransport(handler)
    getter = _make_http_probe_getter(transport=transport)
    resp = asyncio.run(getter("http://localhost:9000/sse", headers={"Host": "evil.example"}))
    assert resp.status_code == 200
    assert resp.session_id == "abc-123"


def test_getter_handles_403_no_session():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")
    getter = _make_http_probe_getter(transport=httpx.MockTransport(handler))
    resp = asyncio.run(getter("http://localhost:9000/sse"))
    assert resp.status_code == 403
    assert resp.session_id is None


def test_getter_timeout_treated_as_accepted_streaming():
    # SSE endpoints stream and may not close; a read timeout means the server
    # ACCEPTED the request (began streaming) → represent as 200 for probe verdicts.
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("stream open", request=request)
    getter = _make_http_probe_getter(transport=httpx.MockTransport(handler))
    resp = asyncio.run(getter("http://localhost:9000/sse"))
    assert resp.status_code == 200  # accepted/streaming
```

- [ ] **Step 2: FAIL**, then implement in `module.py`:

```python
import httpx
from dataclasses import dataclass

@dataclass
class _ProbeResp:
    status_code: int
    session_id: str | None = None


def _make_http_probe_getter(*, transport=None):
    """Return an async http_get(url, headers=...) -> _ProbeResp for transport probes.
    A read-timeout on an SSE endpoint means the server began streaming (accepted the
    request) → reported as status 200 so the Host/audience verdicts treat it as accepted.
    `transport` is for tests (httpx.MockTransport)."""
    async def _get(url: str, **kwargs):
        headers = kwargs.get("headers") or {}
        client_kwargs = dict(verify=False, timeout=httpx.Timeout(10.0), follow_redirects=False)
        if transport is not None:
            client_kwargs["transport"] = transport
        async with httpx.AsyncClient(**client_kwargs) as client:
            try:
                resp = await client.get(url, headers=headers)
            except httpx.ReadTimeout:
                return _ProbeResp(status_code=200, session_id=None)
            sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
            return _ProbeResp(status_code=resp.status_code, session_id=sid)
    return _get
```

- [ ] **Step 3: Wire** — in `McpStaticScanModule.run`, replace the `build_transport_findings(manifest, http_get=None)` call with:

```python
        if manifest.transport in ("sse", "streamable_http"):
            try:
                getter = _make_http_probe_getter()
                findings.extend(await transport_probes.build_transport_findings(manifest, http_get=getter))
            except Exception:
                pass
```

(Keep it non-fatal. stdio transports skip — `build_transport_findings` already returns [] for non-HTTP, but guarding here avoids constructing a getter needlessly.)

- [ ] **Step 4: PASS** — `cd plugins/pencheff && uv run pytest tests/test_mcp_transport_getter.py tests/test_mcp_transport_probes.py tests/test_mcp_scan_module.py -q`.

- [ ] **Step 5: Commit**

```bash
git add plugins/pencheff/pencheff/modules/mcp_scan/module.py plugins/pencheff/tests/test_mcp_transport_getter.py
git commit -m "feat(mcp-scan): live HTTP getter — transport/auth CVE probes now fire"
```

---

## Task 2 (Fix B): Wire OAST into dynamic fuzzing

**Files:** Modify `plugins/pencheff/pencheff/modules/mcp_scan/module.py`; new `tests/test_mcp_oast_adapter.py`.

`fuzz_tools` wants `oast.url` (str) + `await oast.poll()`. `OASTManager` has `new_url()`/`poll()`. Add a thin adapter and pass it.

- [ ] **Step 1: Failing test** — `plugins/pencheff/tests/test_mcp_oast_adapter.py`:

```python
import asyncio
from pencheff.modules.mcp_scan.module import _OastAdapter


class _FakeManager:
    def __init__(self): self._polled = 0
    def new_url(self, label=""): return f"http://probe.oast.example/{label}"
    async def poll(self): self._polled += 1; return [{"hit": 1}] if self._polled > 1 else []


def test_adapter_exposes_url_and_async_poll():
    m = _FakeManager()
    a = _OastAdapter(m, label="mcp-fuzz")
    assert a.url == "http://probe.oast.example/mcp-fuzz"
    assert asyncio.run(a.poll()) == []          # first poll: no hits
    assert asyncio.run(a.poll()) == [{"hit": 1}]  # second: a hit
```

- [ ] **Step 2: FAIL**, then implement in `module.py`:

```python
class _OastAdapter:
    """Adapts pencheff OASTManager (new_url/poll) to the .url + async poll() shape
    fuzz_tools expects. Reserves one canary URL upfront for payload embedding."""
    def __init__(self, manager, *, label: str = "mcp-fuzz"):
        self._m = manager
        self.url = manager.new_url(label)
    async def poll(self):
        return await self._m.poll()
```

- [ ] **Step 3: Wire** — in `_fuzz_just_in_time`, replace `oast=None` with a best-effort adapter:

```python
    oast = None
    try:
        from pencheff.core.oast import get_oast
        sid = getattr(manifest, "session_id", None)  # not on manifest; use the pencheff session id
        # the module has the pencheff session in scope as `session` (run() arg) — thread it in:
        # change _fuzz_just_in_time to accept session and use session.id
        oast = _OastAdapter(get_oast(session.id))
    except Exception:
        oast = None
```

IMPORTANT plumbing: `_fuzz_just_in_time` currently takes `(manifest, cfg, dyn_cfg)`. Thread the pencheff `session` through so it can call `get_oast(session.id)`. Update the call site in `run` to `_fuzz_just_in_time(session, manifest, cfg, dyn_cfg)` and the signature accordingly. Then pass `oast=oast` (the adapter or None) into `fuzz_tools`. Keep non-fatal: if `get_oast`/`session.id` is unavailable, `oast=None` and fuzzing still runs with inline-only detection.

- [ ] **Step 4: PASS** — `cd plugins/pencheff && uv run pytest tests/test_mcp_oast_adapter.py tests/test_mcp_dynamic.py tests/test_mcp_scan_module.py -q`.

- [ ] **Step 5: Commit**

```bash
git add plugins/pencheff/pencheff/modules/mcp_scan/module.py plugins/pencheff/tests/test_mcp_oast_adapter.py
git commit -m "feat(mcp-scan): wire OAST into dynamic fuzzing (blind SSRF/exfil detection)"
```

---

## Task 3 (Fix C): Harden agent-endpoint probing

**Files:** Modify `plugins/pencheff/pencheff/modules/mcp_scan/agent_probe.py`; extend `tests/test_mcp_agent_probe.py`.

Make the live LLM probe reliably fire + observable (no silent swallow), and ensure the probe targets the agent endpoint.

- [ ] **Step 1: Failing test** — append to `tests/test_mcp_agent_probe.py` (a mock that proves run_agent_probe drives the LLM06 module and returns its findings):

```python
import asyncio


def test_run_agent_probe_invokes_llm_pack(monkeypatch):
    from pencheff.modules.mcp_scan import agent_probe as ap

    calls = {}

    class _FakeFinding:
        owasp_category = "LLM06"; title = "probe finding"; metadata = {}

    class _FakeModule:
        async def run(self, session, http=None, config=None):
            calls["ran"] = True
            calls["llm_config"] = getattr(session, "llm_config", None)
            return [_FakeFinding()]

    # Patch the module registry so LLM06 → our fake
    import pencheff.modules.llm_red_team as lrt
    monkeypatch.setitem(lrt.LLM_RED_TEAM_MODULES, "LLM06", _FakeModule)

    class _Sess:
        llm_config = None
        target = type("T", (), {"base_url": "http://agent.example/chat"})()

    cfg = {"kind": "mcp", "source_type": "agent_http", "provider": "openai-chat",
           "model": "gpt-4", "url": "http://agent.example/chat"}
    findings = asyncio.run(ap.run_agent_probe(_Sess(), cfg))
    assert calls.get("ran") is True
    assert calls.get("llm_config") is not None  # session.llm_config was set to probe_cfg
    assert any(f.owasp_category == "LLM06" for f in findings)
```

- [ ] **Step 2: FAIL** (if the current code path doesn't reliably run/return), then harden `run_agent_probe`:
  - Keep `session.llm_config = probe_cfg` (the engine reads the endpoint from `session.target.base_url` + this config; the scan_runner already creates the session with the agent URL as target for agent_http).
  - Replace the blanket `except Exception: pass` with `except Exception as e: log.warning("agent live-probe failed: %s", e)` (import the module logger like other modules do) so failures are observable, not silent. The static trifecta analysis still runs after (keep it outside the try).
  - Ensure `LLM_RED_TEAM_MODULES.get("LLM06")` lookup + instantiation + `await module.run(session, http=None, config={"llm_config": probe_cfg})` and that returned findings are extended into `findings`.
  - Confirm the function returns `findings` (live + trifecta).

- [ ] **Step 3: PASS** — `cd plugins/pencheff && uv run pytest tests/test_mcp_agent_probe.py -q` (the 4 existing + the new test).

- [ ] **Step 4: Commit**

```bash
git add plugins/pencheff/pencheff/modules/mcp_scan/agent_probe.py plugins/pencheff/tests/test_mcp_agent_probe.py
git commit -m "fix(mcp-scan): agent probe reliably runs llm pack + logs failures (no silent swallow)"
```

---

## Task 4: Regression + import checks

- [ ] **Step 1:** `cd plugins/pencheff && uv run pytest tests/test_mcp_*.py -q` — all green.
- [ ] **Step 2:** `uv run python -c "import pencheff.server, pencheff.modules.mcp_scan.module"` — clean.
- [ ] **Step 3:** Commit any fixups.

---

## Self-review

**Coverage:** Fix A (transport getter → probes fire) ✓; Fix B (OAST adapter → blind detection) ✓; Fix C (agent probe observable + tested) ✓. All three were the "live-wiring" gaps called out post-Plan-3.

**Placeholder scan:** getter + adapter are complete code; Fix C is a hardening of existing structurally-correct code with a new test that proves the live path runs (via a patched module registry). No TODOs.

**Type consistency:** `_ProbeResp(.status_code,.session_id)` matches what `build_transport_findings` reads; `_OastAdapter(.url, async poll())` matches what `fuzz_tools` reads; `run_agent_probe` continues to use the proven `session.llm_config` + `module.run(...)` pattern.

**Risk/limits (honest):** Fix A's getter treats an SSE read-timeout as "accepted (200)" — a heuristic for the Host/audience verdicts; acceptable but could mis-verdict a server that streams regardless of auth (conservative = more likely to flag, which is the safe direction for a scanner). Fix B's blind detection only yields hits if an interactsh-client/OAST backend is actually configured (`poll()` returns [] otherwise) — the canary URL is always embedded so an external OAST still catches callbacks. Fix C's live probe still depends on a reachable agent endpoint; failures now log instead of vanish.
