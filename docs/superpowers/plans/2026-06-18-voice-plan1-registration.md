# Voice / Speech AI — Plan 1: Backend Registration, Graduated Consent & Gate

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** API accepts/validates `kind="voice"` (sources: stt_endpoint / voice_bot / tts_endpoint / voice_auth), wires the graduated consent vocabulary (`voice_enumerate` always; `voice_audio_probe` when `audio_probes`; `voice_auth_probe` nested under audio_probes), and 409-gates scanning until the scanner ships (Plan 2/3).

**Architecture:** New wire kind `voice` + `VoiceConfig` in the `kind_config` union (mirrors the SHIPPED `McpConfig`; `Target.kind` is `String(16)` — no DB enum migration). Consent is GRADUATED like `mcp`: a base required action plus router-added conditional actions driven by `kind_config` flags. 409 gate prevents fall-through.

**Tech Stack:** Python, Pydantic v2, FastAPI, pytest (`cd apps/api && .venv/bin/python -m pytest`). **Branch:** `feat/ml-voice-scanning` (already checked out — NO worktree, NO branch switching).

**Reference (mirror these):** `McpConfig` in `apps/api/pencheff_api/schemas/targets.py`; the GRADUATED mcp consent in `apps/api/pencheff_api/schemas/scans.py` (`KIND_REQUIRED_DISCLOSED_ACTIONS["mcp"]`) + `routers/scans.py` `_required_disclosed_actions` (the mcp branch that ADDS `mcp_tool_invocation`/`mcp_destructive_tool_invocation` from `kind_config`); the memory/ml_model 409 gates in `start_scan`; tests `test_targets_mcp_config.py`, `test_scans_router_kind_aware.py`, `test_scans_ml_model_kind_gate.py`. Spec: `docs/superpowers/specs/2026-06-17-voice-speech-ai-scanning-design.md`.

---

## Task 1: `VoiceConfig` + `voice` wire kind

**Files:** `apps/api/pencheff_api/schemas/targets.py`; Test `apps/api/tests/test_targets_voice_config.py`.

- [ ] **Step 1: Write failing test** `tests/test_targets_voice_config.py`:

```python
from __future__ import annotations
import pytest
from pydantic import ValidationError, TypeAdapter
from pencheff_api.schemas.targets import KindConfig
_adapter = TypeAdapter(KindConfig)
def _parse(d): return _adapter.validate_python(d)


def test_requires_url():
    ok = _parse({"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"})
    assert ok.source_type == "stt_endpoint"
    with pytest.raises(ValidationError):
        _parse({"kind": "voice", "source_type": "stt_endpoint"})


def test_all_source_types_accepted():
    for st in ("stt_endpoint", "voice_bot", "tts_endpoint", "voice_auth"):
        cfg = _parse({"kind": "voice", "source_type": st, "url": "https://h/x"})
        assert cfg.source_type == st


def test_defaults_and_extra_forbidden():
    cfg = _parse({"kind": "voice", "source_type": "voice_bot", "url": "https://h/x"})
    assert cfg.audio_format == "wav"
    assert cfg.audio_probes is False
    with pytest.raises(ValidationError):
        _parse({"kind": "voice", "source_type": "voice_bot", "url": "https://h/x", "bogus": 1})


def test_audio_probes_flag_round_trips():
    cfg = _parse({"kind": "voice", "source_type": "voice_auth", "url": "https://h/x", "audio_probes": True})
    assert cfg.audio_probes is True
```

- [ ] **Step 2: Run, confirm FAIL.** Then add `"voice"` to `TargetKind` (after `"ml_model"`) + `_KINDS_REQUIRING_CONFIG`. Add before the `KindConfig` union:

```python
class VoiceConfig(_KindConfigBase):
    """Voice / Speech-AI endpoint target. Static transport probes always; crafted
    audio submission is consent-gated (audio_probes). See spec 2026-06-17."""
    kind: Literal["voice"] = "voice"
    source_type: Literal["stt_endpoint", "voice_bot", "tts_endpoint", "voice_auth"]
    url: str
    audio_format: Literal["wav", "mp3", "flac", "ogg"] = "wav"
    request_template: str | None = None
    response_path: str | None = None
    injection_phrase: str | None = None
    audio_probes: bool = False
```

Add `VoiceConfig` to the `KindConfig` union. (`url` is a required field, so no model_validator is needed — pydantic enforces presence.)

- [ ] **Step 3: Run, confirm PASS** (`.venv/bin/python -m pytest tests/test_targets_voice_config.py -q`, 4). Then `-k target` suite green; add `"voice"` to any hard-coded kind set if a test surfaces one.
- [ ] **Step 4: Commit** `feat(api): add voice wire kind + VoiceConfig`.

---

## Task 2: Graduated consent vocabulary

**Files:** `schemas/scans.py`, `routers/scans.py`, append to `tests/test_scans_router_kind_aware.py`.

- [ ] **Step 1: Failing tests** — append:

```python
def test_voice_base_required_is_enumerate() -> None:
    from pencheff.routers_voice_helper import _noop  # placeholder; real import below
```

(Delete that placeholder — use the real import as the other tests in this file do:)

```python
def test_voice_static_only_requires_enumerate() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "voice"
        kind_config = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/x"}
    assert _required_disclosed_actions(_T()) == {"voice_enumerate"}


def test_voice_audio_probes_adds_audio_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "voice"
        kind_config = {"kind": "voice", "source_type": "voice_bot", "url": "https://h/x", "audio_probes": True}
    assert _required_disclosed_actions(_T()) == {"voice_enumerate", "voice_audio_probe"}


def test_voice_auth_source_with_audio_probes_adds_auth_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "voice"
        kind_config = {"kind": "voice", "source_type": "voice_auth", "url": "https://h/x", "audio_probes": True}
    assert _required_disclosed_actions(_T()) == {"voice_enumerate", "voice_audio_probe", "voice_auth_probe"}
```

- [ ] **Step 2: Run, confirm FAIL.** Add to `KIND_REQUIRED_DISCLOSED_ACTIONS`: `"voice": frozenset({"voice_enumerate"})`. Then in `routers/scans.py` `_required_disclosed_actions`, add a `voice` branch MIRRORING the mcp graduated branch (read it first):

```python
    if t.kind == "voice":
        actions = set(base)  # {"voice_enumerate"}
        cfg = t.kind_config or {}
        if cfg.get("audio_probes"):
            actions.add("voice_audio_probe")
            if cfg.get("source_type") == "voice_auth":
                actions.add("voice_auth_probe")   # nested: auth-spoof needs audio_probes too
        return actions
```

(Match the exact local-variable names / accessor style the mcp branch uses — `base`, `t`, `kind_config` access. The nesting rule: `voice_auth_probe` is added ONLY when `audio_probes` is true AND source is `voice_auth`.) Add `"voice"` to the coverage `expected` set and to `_FRONTEND_DISCLOSED_ACTION_IDS_BY_KIND` the optional ids `{"voice_audio_probe", "voice_auth_probe"}` (mirroring how mcp lists its conditional ids).

- [ ] **Step 3: Run, confirm PASS** (`.venv/bin/python -m pytest tests/test_scans_router_kind_aware.py -q`).
- [ ] **Step 4: Commit** `feat(api): voice graduated consent vocabulary`.

---

## Task 3: Gate scanning + regression

**Files:** `routers/scans.py` (`start_scan`); Test `tests/test_scans_voice_kind_gate.py`.

- [ ] **Step 1: Failing test** `test_scans_voice_kind_gate.py` (copy `test_scans_ml_model_kind_gate.py` from Plan 1 — the 409 version): kind="voice", kind_config `{"kind":"voice","source_type":"stt_endpoint","url":"https://h/x"}`, disclosed `["voice_enumerate"]`, assert 409 + `detail["error"]=="voice_kind_scanning_not_yet_available"` + no enqueue / no Scan row.
- [ ] **Step 2: Run, confirm FAIL.** Add the gate in `start_scan` after the `ml_model` gate:

```python
    if target.kind == "voice":
        raise HTTPException(status_code=409, detail={
            "error": "voice_kind_scanning_not_yet_available",
            "message": "Voice/Speech-AI scanning ships shortly. Registration is supported now; scanning is not yet enabled.",
            "eta_reference": "Voice Plan 2/3",
        })
```

- [ ] **Step 3: Run, confirm PASS.**
- [ ] **Step 4: Regression** — `.venv/bin/python -m pytest tests/ -q -k "scan or target or kind or consent or memory or ml or voice"` → green.
- [ ] **Step 5: Commit** `feat(api): gate POST /scans for kind=voice until scanner ships`.

---

## Self-review

**Spec coverage (§5 schema, §8 consent, §9 gate):** wire kind + VoiceConfig (T1) ✓; graduated consent voice_enumerate/voice_audio_probe/voice_auth_probe with nesting (T2) ✓; 409 gate (T3) ✓. Scanner (§6) → Plan 2; dispatch/FE (§9) → Plan 3.
**Type consistency:** `VoiceConfig.kind="voice"` matches union + `KIND_REQUIRED_DISCLOSED_ACTIONS["voice"]`; action ids `voice_enumerate`/`voice_audio_probe`/`voice_auth_probe` consistent across scans.py + router branch + tests; config keys (source_type/url/audio_format/request_template/response_path/injection_phrase/audio_probes) match the spec §5.
**Nesting invariant:** `voice_auth_probe` requires BOTH `audio_probes=True` AND `source_type="voice_auth"` (mirrors mcp destructive-nested-in-dynamic).
**No migration:** `Target.kind` is `String(16)`; marker deferred to Plan 3 (mcp/rag/ml precedent).
