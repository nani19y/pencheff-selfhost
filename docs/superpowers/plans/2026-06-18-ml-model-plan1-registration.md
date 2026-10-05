# ML Model — Plan 1: Backend Registration & Consent Foundation

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** API accepts/validates `kind="ml_model"` (sources: file_url / huggingface / local_path), wires the `ml_fetch` consent action, and gates scanning until the scanner ships (Plan 2/3).

**Architecture:** New wire kind `ml_model` + `MlModelConfig` in the `kind_config` union, mirroring the SHIPPED `McpConfig` pattern. `Target.kind` is `String(16)` — no DB enum migration. 409 gate prevents fall-through (like host/memory/mcp).

**Tech Stack:** Python, Pydantic v2, FastAPI, pytest (`cd apps/api && .venv/bin/python -m pytest`). **Branch:** `feat/ml-voice-scanning`. **Reference (verbatim-mirror):** `McpConfig` in `apps/api/pencheff_api/schemas/targets.py`; `KIND_REQUIRED_DISCLOSED_ACTIONS["mcp"]` + `_required_disclosed_actions` mcp branch; the mcp 409 gate; `test_targets_mcp_config.py` / `test_scans_mcp_kind_gate.py`. Spec: `docs/superpowers/specs/2026-06-17-ml-model-scanning-design.md`.

---

## Task 1: `MlModelConfig` + `ml_model` wire kind

**Files:** `apps/api/pencheff_api/schemas/targets.py`; test `apps/api/tests/test_targets_ml_model_config.py`.

- [ ] **Step 1: Failing tests** — `test_targets_ml_model_config.py`:

```python
from __future__ import annotations
import pytest
from pydantic import ValidationError, TypeAdapter
from pencheff_api.schemas.targets import KindConfig
_adapter = TypeAdapter(KindConfig)
def _parse(d): return _adapter.validate_python(d)


def test_file_url_requires_url():
    ok = _parse({"kind": "ml_model", "source_type": "file_url", "url": "https://h/model.pkl"})
    assert ok.source_type == "file_url"
    with pytest.raises(ValidationError):
        _parse({"kind": "ml_model", "source_type": "file_url"})


def test_huggingface_requires_repo():
    ok = _parse({"kind": "ml_model", "source_type": "huggingface", "hf_repo": "owner/model"})
    assert ok.hf_repo == "owner/model"
    with pytest.raises(ValidationError):
        _parse({"kind": "ml_model", "source_type": "huggingface"})


def test_local_path_requires_path():
    ok = _parse({"kind": "ml_model", "source_type": "local_path", "local_path": "/models/m.pt"})
    assert ok.local_path == "/models/m.pt"
    with pytest.raises(ValidationError):
        _parse({"kind": "ml_model", "source_type": "local_path"})


def test_format_hint_default_and_extra_forbidden():
    cfg = _parse({"kind": "ml_model", "source_type": "huggingface", "hf_repo": "o/m"})
    assert cfg.format_hint == "auto"
    with pytest.raises(ValidationError):
        _parse({"kind": "ml_model", "source_type": "huggingface", "hf_repo": "o/m", "bogus": 1})
```

- [ ] **Step 2: FAIL**, then add `"ml_model"` to `TargetKind` (after the AI-cluster kinds) + `_KINDS_REQUIRING_CONFIG`. Add `MlModelConfig` before the `KindConfig` union:

```python
class MlModelConfig(_KindConfigBase):
    """ML model artifact target — STATICALLY scanned (never loaded). See spec 2026-06-17."""
    kind: Literal["ml_model"] = "ml_model"
    source_type: Literal["file_url", "huggingface", "local_path"]
    url: str | None = None
    hf_repo: str | None = None
    hf_revision: str | None = None
    local_path: str | None = None
    format_hint: Literal["auto", "pickle", "pytorch", "safetensors", "keras", "h5", "savedmodel", "gguf", "joblib"] = "auto"
    max_bytes: int = Field(default=524_288_000, ge=1, le=5_368_709_120)

    @model_validator(mode="after")
    def _validate_source(self) -> "MlModelConfig":
        st = self.source_type
        if st == "file_url" and not self.url:
            raise ValueError("source_type='file_url' requires url")
        if st == "huggingface" and not self.hf_repo:
            raise ValueError("source_type='huggingface' requires hf_repo")
        if st == "local_path" and not self.local_path:
            raise ValueError("source_type='local_path' requires local_path")
        return self
```

Add `MlModelConfig` to the `KindConfig` union.

- [ ] **Step 3: PASS** — `cd apps/api && .venv/bin/python -m pytest tests/test_targets_ml_model_config.py -q` (4). Then `-k target` suite green (add `"ml_model"` to any hard-coded kind set if needed).
- [ ] **Step 4: Commit** `feat(api): add ml_model wire kind + MlModelConfig`.

---

## Task 2: Consent vocabulary

**Files:** `schemas/scans.py`, `routers/scans.py`, `tests/test_scans_router_kind_aware.py`.

- [ ] **Step 1: Failing test** — append to `test_scans_router_kind_aware.py`:

```python
def test_ml_model_required_action_is_fetch() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "ml_model"
        kind_config = {"kind": "ml_model", "source_type": "huggingface", "hf_repo": "o/m"}
    assert _required_disclosed_actions(_T()) == {"ml_fetch"}
```

- [ ] **Step 2: FAIL**, then add to `KIND_REQUIRED_DISCLOSED_ACTIONS`: `"ml_model": frozenset({"ml_fetch"})`. (No conditional additions — ml_model is static-only, single disclosure. The router `_required_disclosed_actions` needs no ml_model branch unless a future dynamic tier is added.) Add `"ml_model"` to the coverage `expected` set + `_FRONTEND_DISCLOSED_ACTION_IDS_BY_KIND` (`{"ml_fetch"}`).
- [ ] **Step 3: PASS** — `cd apps/api && .venv/bin/python -m pytest tests/test_scans_router_kind_aware.py -q`.
- [ ] **Step 4: Commit** `feat(api): ml_model consent vocabulary (ml_fetch)`.

---

## Task 3: Gate scanning + regression

**Files:** `routers/scans.py` (`start_scan`); test `tests/test_scans_ml_model_kind_gate.py`.

- [ ] **Step 1: Failing test** — `test_scans_ml_model_kind_gate.py` (copy `test_scans_mcp_kind_gate.py`; kind="ml_model", kind_config `{"kind":"ml_model","source_type":"huggingface","hf_repo":"o/m"}`, disclosed `["ml_fetch"]`, assert 409 + `detail["error"]=="ml_model_kind_scanning_not_yet_available"` + no enqueue/no Scan row).
- [ ] **Step 2: FAIL**, then add the gate in `start_scan` after the mcp gate:

```python
    if target.kind == "ml_model":
        raise HTTPException(status_code=409, detail={
            "error": "ml_model_kind_scanning_not_yet_available",
            "message": "ML model scanning ships shortly. Registration is supported now; scanning is not yet enabled.",
            "eta_reference": "ML Plan 2/3",
        })
```

- [ ] **Step 3: PASS** — `cd apps/api && .venv/bin/python -m pytest tests/test_scans_ml_model_kind_gate.py -q`.
- [ ] **Step 4: Regression** — `cd apps/api && .venv/bin/python -m pytest tests/ -q -k "scan or target or kind or consent"` → green.
- [ ] **Step 5: Commit** `feat(api): gate POST /scans for kind=ml_model until scanner ships`.

---

## Self-review

**Spec coverage (§5 schema, §8 consent, §9 gate):** wire kind + MlModelConfig (T1) ✓; ml_fetch consent (T2) ✓; gate (T3) ✓. Scanner (§6) → Plan 2; FE/dispatch (§9) → Plan 3.
**Placeholder scan:** complete code. **Type consistency:** `MlModelConfig.kind="ml_model"` matches union + `KIND_REQUIRED_DISCLOSED_ACTIONS["ml_model"]`; action id `ml_fetch` consistent across scans.py/test FE-mirror; config keys (source_type/url/hf_repo/hf_revision/local_path/format_hint/max_bytes) match the spec.
**No migration:** `Target.kind` is `String(16)`; marker deferred to Plan 3 (mcp/rag precedent).
