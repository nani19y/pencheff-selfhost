# Voice / Speech AI — Plan 3: Dispatch, Live Transport & Frontend

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Wire `kind="voice"` end-to-end: a best-effort httpx live transport so prod probes run, scan_runner dispatch to `scan_voice`, removal of the Plan-1 409 gate, migration marker, and the FE (`VoiceFormSection` with the graduated `audio_probes` consent, Voice card flips `llm`→`voice`).

**Architecture:** Mirror the SHIPPED ML/RAG dispatch + FE. `PentestSession` gains `voice_config`. A new `voice_scan/live_transport.py` builds httpx-backed `http_get`/`http_post`/`submit_audio` callables (best-effort, non-fatal); the `scan_voice` tool attaches them to the session so prod does real probing while unit tests (which don't attach) stay no-op. Migration `0061` is a no-DDL marker. FE adds `VoiceFormSection` + the 3-action graduated consent + flips the Voice card.

**Tech Stack:** Python (`cd apps/api && .venv/bin/python -m pytest`; `cd plugins/pencheff && uv run pytest`); Next.js 15/TS (`cd apps/web && npx tsc --noEmit` + `npx next build`). **Branch:** `feat/ml-voice-scanning` (already checked out — NO worktree, NO branch switching).

**Reference (mirror these — most are identical to ML Plan 3 with rag/ml→voice):** `core/session.py` `ml_config` (just added in ML Plan 3) for the slot pattern; scan_runner `ml_model`/`rag` dispatch blocks + `_run_ml_scan`; `routers/scans.py` voice 409 gate (Plan 1) + the rag/ml guard tests; migration `0060_ml_model_target_kind.py`; FE `rag-form-section.tsx` + the mcp graduated-consent UI (mcp-form-section has the dynamic/destructive toggles — mirror its consent toggle for `audio_probes`); `consent-disclosures.ts` mcp graduated entries; `target-types.ts` voice card (line ~329) + TargetKind union; `app/targets/new/page.tsx` + `[id]/edit/page.tsx` + `page.tsx` + `[id]/page.tsx`. Spec: `docs/superpowers/specs/2026-06-17-voice-speech-ai-scanning-design.md`.

---

## Task 1: `voice_config` slot on the pencheff session

**Files:** `plugins/pencheff/pencheff/core/session.py`; Test `plugins/pencheff/tests/test_voice_session_config.py`.

- [ ] **Step 1: Failing test** (mirror `test_ml_session_config.py`):

```python
from pencheff.core.session import create_session


def test_voice_config_round_trips():
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    s = create_session(target_url="https://h/stt", depth="quick", voice_config=cfg)
    assert s.voice_config == cfg


def test_voice_config_defaults_none():
    s = create_session(target_url="x", depth="quick")
    assert s.voice_config is None
```

- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** — add `voice_config: dict[str, Any] | None = None` field after `ml_config` in `PentestSession`; add the `voice_config` param to `create_session` (after `ml_config`) and pass it through in the constructor.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** `feat(plugin): voice_config slot on PentestSession`.

---

## Task 2: `live_transport.py` + attach in `scan_voice`

**Files:** Create `plugins/pencheff/pencheff/modules/voice_scan/live_transport.py`; modify the `scan_voice` tool in `plugins/pencheff/pencheff/server.py`; Test `plugins/pencheff/tests/test_voice_live_transport.py`.

- [ ] **Step 1: Failing test** `tests/test_voice_live_transport.py`:

```python
from pencheff.modules.voice_scan.live_transport import build_live_transport


def test_builder_returns_three_callables():
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    http_get, http_post, submit_audio = build_live_transport(cfg)
    assert callable(http_get) and callable(http_post) and callable(submit_audio)
```

- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** `live_transport.py` (best-effort httpx; non-fatal — callers already wrap in try/except and treat None responses as no-result):

```python
# pencheff/modules/voice_scan/live_transport.py
"""Best-effort httpx-backed live transport for voice probes. Returns three async
callables (http_get, http_post, submit_audio). Each returns None on failure so
the probe layers (which already handle None) degrade gracefully. v1 assumes a
simple JSON/multipart endpoint; custom shapes (request_template/response_path)
are honored when present, else a sensible default is used."""
from __future__ import annotations

import logging

import httpx

log = logging.getLogger("pencheff.modules.voice_scan.live_transport")
_TIMEOUT = 30.0


def build_live_transport(cfg: dict):
    headers = {}
    cred = (cfg.get("credentials") or {}) if isinstance(cfg, dict) else {}
    if cred.get("api_key"):
        headers["Authorization"] = f"Bearer {cred['api_key']}"

    async def http_get(url, **kw):
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=_TIMEOUT) as c:
                return await c.get(url, headers=headers, **kw)
        except Exception as e:  # noqa: BLE001
            log.warning("voice http_get failed: %s", e)
            return None

    async def http_post(url, **kw):
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=_TIMEOUT) as c:
                return await c.post(url, headers=headers, **kw)
        except Exception as e:  # noqa: BLE001
            log.warning("voice http_post failed: %s", e)
            return None

    async def submit_audio(wav_bytes: bytes, kind: str):
        """POST WAV bytes; return {status_code, text, json} (json None if not JSON)."""
        url = cfg.get("url") or ""
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=_TIMEOUT) as c:
                resp = await c.post(
                    url, headers=headers,
                    files={"audio": ("probe.wav", wav_bytes, "audio/wav")},
                )
            body = None
            try:
                body = resp.json()
            except Exception:
                body = None
            return {"status_code": resp.status_code, "text": resp.text, "json": body}
        except Exception as e:  # noqa: BLE001
            log.warning("voice submit_audio failed: %s", e)
            return None

    return http_get, http_post, submit_audio
```

Then modify the `scan_voice` tool (added in Voice Plan 2) to attach the live transport before running the module — insert right after resolving `cfg` and before `VoiceScanModule().run(...)`:

```python
    from pencheff.modules.voice_scan.live_transport import build_live_transport
    _g, _p, _s = build_live_transport(cfg)
    session.voice_http_get, session.voice_http_post, session.voice_submit_audio = _g, _p, _s
```

(Setting attributes on the session object dynamically is fine — `PentestSession` is a dataclass but Python allows attribute assignment; the module reads them via `getattr(..., None)`. If the dataclass uses `slots=True` and rejects new attrs, add `voice_http_get`/`voice_http_post`/`voice_submit_audio` as Optional fields defaulting to None on `PentestSession` instead — check and do whichever the class requires.)

- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** `feat(plugin): voice best-effort live transport + attach in scan_voice`.

---

## Task 3: scan_runner dispatch (`voice` → `scan_voice`)

**Files:** `apps/api/pencheff_api/services/scan_runner.py`; Test `apps/api/tests/test_scan_runner_voice_dispatch.py`.

- [ ] **Step 1: Failing test** (mirror `test_scan_runner_ml_dispatch.py`): patch `sys.modules["pencheff.server"]` with a fake exposing `scan_voice`; assert `_run_voice_scan` calls it with `session_id` + `voice_config`; and a missing-tool case is non-fatal.
- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3: Implement** — (a) at the `create_session(...)` call, after the `ml_config=` line add:

```python
            voice_config=dict(target.kind_config) if (target.kind == "voice" and target.kind_config) else None,
```

(b) add `_run_voice_scan` after `_run_ml_scan` (exact clone, ml→voice, tool `scan_voice`, kwarg `voice_config=psession.voice_config`).
(c) add the dispatch block after the `ml_model` block (clone it; guard `if target.kind == "voice":`, call `_run_voice_scan`, `target_kind="voice"`).
(d) verify `compute_grade` handles `target_kind="voice"` (same check as ML Plan 3 Task 2d; add `voice` alongside `rag`/`mcp`/`ml_model` if the function enumerates kinds).

- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** `feat(api): scan_runner dispatch kind=voice → scan_voice`.

---

## Task 4: Remove the Plan-1 409 gate + convert its test to a guard

**Files:** `apps/api/pencheff_api/routers/scans.py`; `apps/api/tests/test_scans_voice_kind_gate.py`.

- [ ] **Step 1:** Rewrite `test_scans_voice_kind_gate.py` as a guard (mirror the ml_model guard from ML Plan 3 Task 3): a scan for a `voice` target with `["voice_enumerate"]` disclosed must NOT return 409 `voice_kind_scanning_not_yet_available`.
- [ ] **Step 2: Run, confirm FAIL.**
- [ ] **Step 3:** Delete the `if target.kind == "voice": raise HTTPException(409, ...)` block from `start_scan`.
- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Commit** `feat(api): enable POST /scans for kind=voice (remove gate)`.

---

## Task 5: Migration marker `0061_voice_target_kind`

**Files:** Create `apps/api/pencheff_api/db/migrations/versions/0061_voice_target_kind.py`.

- [ ] **Step 1: Implement** — copy `0060_ml_model_target_kind.py`; `revision="0061"`, `down_revision="0060"`, no-DDL upgrade/downgrade, message about `voice` (`Target.kind` is `String(16)`).
- [ ] **Step 2: Verify** `.venv/bin/python -m alembic heads` shows `0061` (or the suite builds the schema cleanly).
- [ ] **Step 3: Commit** `feat(api): migration marker 0061 for voice kind`.

---

## Task 6: FE — graduated consent vocabulary + TargetKind + Voice card flip

**Files:** `apps/web/lib/consent-disclosures.ts`; `apps/web/components/register-target/target-types.ts`.

- [ ] **Step 1: consent-disclosures.ts.** Add three `ACTIONS` entries (after `ml_fetch`):

```typescript
  voice_enumerate: {
    id: "voice_enumerate",
    displayName: "Voice endpoint enumeration & transport posture",
    description:
      "Probe the voice endpoint's transport posture: reachability without auth, audio-URL SSRF surface, and oversized/malformed-audio handling. No crafted-speech submission.",
  },
  voice_audio_probe: {
    id: "voice_audio_probe",
    displayName: "Crafted-audio submission (cross-modal injection / ultrasonic)",
    description:
      "Submit synthesized audio to the endpoint to test cross-modal prompt injection and ultrasonic hidden commands. Only authorize against endpoints you own or are authorized to test.",
  },
  voice_auth_probe: {
    id: "voice_auth_probe",
    displayName: "Voice-auth spoofing (synthetic speaker audio)",
    description:
      "Submit synthetic/altered speaker audio to a voice-authentication endpoint to test anti-spoofing. Requires crafted-audio submission; only against authorized targets.",
  },
```

Add to `REQUIRED_ACTION_IDS_BY_KIND` (after `ml_model`): `voice: ["voice_enumerate"]`. Add to the optional/frontend conditional map (where mcp lists its conditional ids): `voice: ["voice_audio_probe", "voice_auth_probe"]`. Add `"voice"` to `SupportedKind` if it's a TS union.

- [ ] **Step 2: target-types.ts.** Add `"voice"` to the `TargetKind` union (after `"ml_model"`). Flip the voice card `kind` (line ~333) from `"llm"` to `"voice"`.
- [ ] **Step 3: Type-check** `cd apps/web && npx tsc --noEmit` (errors only at not-yet-written Task-7 sites are OK).
- [ ] **Step 4: Commit** `feat(web): voice graduated consent vocab + TargetKind + card kind`.

---

## Task 7: FE — `VoiceFormSection` + wire into create/edit/list/detail

**Files:** Create `apps/web/components/register-target/voice-form-section.tsx`; modify `app/targets/new/page.tsx`, `app/targets/[id]/edit/page.tsx`, `app/targets/page.tsx`, `app/targets/[id]/page.tsx`.

- [ ] **Step 1: Build `VoiceFormSection`** (copy `rag-form-section.tsx`; for the consent toggle pattern, read `mcp-form-section.tsx` where it toggles the dynamic/destructive options). Fields, emitting a `VoiceConfig` object `{ kind: "voice", source_type, url, audio_format, request_template?, response_path?, injection_phrase?, audio_probes }`:
  - `source_type` selector: `stt_endpoint` | `voice_bot` | `tts_endpoint` | `voice_auth`.
  - `url` text input (required, placeholder `https://host/transcribe`).
  - `audio_format` select: `wav|mp3|flac|ogg` (default `wav`).
  - optional `request_template` + `response_path` (advanced/collapsible; helper "custom request shape / JSONPath to read the result").
  - optional `injection_phrase` text (helper "instruction embedded in cross-modal probes; defaults to a canary").
  - `audio_probes` toggle (default off). When ON, show the graduated consent note: "Enables crafted-audio submission (cross-modal injection + ultrasonic). For voice-auth targets this also enables auth-spoofing probes. Only against endpoints you own/are authorized to test." (mirror mcp's destructive-consent inline note styling). When `source_type==="voice_auth"`, surface that auth-spoof probing is included when audio_probes is on.
    Export `export function VoiceFormSection({ ... })` with the SAME prop signature as `RagFormSection`.
- [ ] **Step 2–4: Wire** into `new/page.tsx` (import + render branch beside ML), `[id]/edit/page.tsx`, and add the `voice` kind→label (`"Voice / Speech AI"`) badge + any kind-branched config display in `page.tsx` and `[id]/page.tsx` (mirror the `ml_model` wiring from ML Plan 3 Task 6).
- [ ] **Step 5: Type-check + build** `cd apps/web && npx tsc --noEmit` clean + `npx next build` succeeds.
- [ ] **Step 6: Commit** `feat(web): VoiceFormSection + create/edit/list/detail wiring`.

---

## Task 8: Full regression (BE + plugin + FE)

- [ ] **Step 1: API** `cd apps/api && .venv/bin/python -m pytest tests/ -q -k "scan or target or kind or consent or memory or ml or voice"` → green.
- [ ] **Step 2: Plugin** `cd plugins/pencheff && uv run pytest tests/ -q -k "voice or ml or rag or mcp or smoke or sentry"` → green; `uv run python -c "import pencheff.server; print('ok')"`.
- [ ] **Step 3: FE** `cd apps/web && npx tsc --noEmit` clean + `npx next build` succeeds.
- [ ] **Step 4: Commit** any snapshot/test-list updates: `test(voice): end-to-end regression green`.

---

## Self-review

**Spec coverage (§9 dispatch + FE):** voice_config slot (T1) ✓; best-effort live transport + attach (T2) ✓; scan_runner dispatch + `_run_voice_scan` (T3) ✓; gate removed (T4) ✓; migration marker (T5) ✓; graduated consent vocab + card flip (T6) ✓; VoiceFormSection with audio_probes consent + wiring (T7) ✓; regression (T8) ✓.
**Graduated-consent parity FE↔BE:** `voice_enumerate` base; `voice_audio_probe` shown when `audio_probes`; `voice_auth_probe` nested (audio_probes + voice_auth) — matches the backend `_required_disclosed_actions` voice branch from Voice Plan 1.
**Type consistency:** session attr `voice_config`; tool kwarg `voice_config`; `target_kind="voice"`; FE config keys match `VoiceConfig` (kind/source_type/url/audio_format/request_template/response_path/injection_phrase/audio_probes); action ids match `KIND_REQUIRED_DISCLOSED_ACTIONS["voice"]`. Card kind `"voice"` matches union + required-actions map.
**Best-effort live transport:** prod gets real httpx probing via `build_live_transport`; unit tests don't attach it, so the module stays no-op/green. Non-fatal throughout.
**No migration DDL:** `Target.kind` is `String(16)`; 0061 is a marker.
