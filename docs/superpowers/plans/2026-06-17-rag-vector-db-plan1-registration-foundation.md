# RAG / Vector DB — Plan R1: Backend Registration & Consent Foundation

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** API accepts + validates `kind="rag"` registration for all 4 sources (managed/self-hosted vector DB, RAG endpoint, embedding artifact), wires the RAG consent vocabulary, and safely gates RAG scanning until the scanner ships (Plan R2/R3).

**Architecture:** New wire kind `rag` (`Target.kind` is `String(16)` — no DB enum migration) + dedicated `RagConfig` in the `kind_config` discriminated union, mirroring the shipped `McpConfig` pattern exactly. A 409 gate on `POST /scans` prevents a rag target from falling through to the URL/DAST pipeline before the scanner exists (same as the host/memory/mcp gates).

**Tech Stack:** Python 3, Pydantic v2, FastAPI, pytest (`cd apps/api && .venv/bin/python -m pytest`).

**Series:** RAG is the 2nd AI target type. This is R1 (backend reg). R1b = FE form. R2 = connectors + static analyzers. R3 = dynamic probes + dispatch (removes this gate). Spec: `docs/superpowers/specs/2026-06-17-rag-vector-db-scanning-design.md`. Branch: `feat/rag-vector-db`.

**Reference (verbatim-mirror the shipped MCP equivalents):** `McpConfig` in `apps/api/pencheff_api/schemas/targets.py`; `KIND_REQUIRED_DISCLOSED_ACTIONS["mcp"]` in `schemas/scans.py`; the `mcp` branch in `_required_disclosed_actions` + the `mcp` 409 gate in `routers/scans.py`; tests `test_targets_mcp_config.py` / `test_scans_mcp_kind_gate.py`.

---

## File structure

| File                                             | Change                                                                         |
| ------------------------------------------------ | ------------------------------------------------------------------------------ |
| `apps/api/pencheff_api/schemas/targets.py`       | `rag` in TargetKind + `_KINDS_REQUIRING_CONFIG`; `RagConfig`; KindConfig union |
| `apps/api/pencheff_api/schemas/scans.py`         | `KIND_REQUIRED_DISCLOSED_ACTIONS["rag"]`                                       |
| `apps/api/pencheff_api/routers/scans.py`         | `_required_disclosed_actions` rag branch; `start_scan` 409 gate                |
| `apps/api/tests/test_targets_rag_config.py`      | RagConfig validation (create)                                                  |
| `apps/api/tests/test_scans_rag_kind_gate.py`     | 409 gate (create)                                                              |
| `apps/api/tests/test_scans_router_kind_aware.py` | rag in coverage + FE-mirror sets; rag disclosed-action tests                   |

---

## Task 1: `RagConfig` schema + `rag` wire kind

**Files:** Modify `schemas/targets.py`; test `tests/test_targets_rag_config.py`.

- [ ] **Step 1: Write the failing test** — `apps/api/tests/test_targets_rag_config.py`:

```python
# apps/api/tests/test_targets_rag_config.py
"""Validation tests for the RagConfig kind_config variant."""
from __future__ import annotations

import pytest
from pydantic import ValidationError, TypeAdapter

from pencheff_api.schemas.targets import KindConfig

_adapter = TypeAdapter(KindConfig)
def _parse(d): return _adapter.validate_python(d)


def test_managed_vdb_requires_provider_and_url():
    ok = _parse({"kind": "rag", "source_type": "managed_vdb",
                 "provider": "pinecone", "url": "https://idx.svc.pinecone.io", "index_name": "docs"})
    assert ok.provider == "pinecone"
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "managed_vdb"})


def test_self_hosted_vdb_requires_provider_and_url():
    ok = _parse({"kind": "rag", "source_type": "self_hosted_vdb",
                 "provider": "pgvector", "url": "postgresql://h/db"})
    assert ok.provider == "pgvector"
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "self_hosted_vdb", "provider": "pgvector"})  # no url


def test_rag_endpoint_requires_provider_llm():
    ok = _parse({"kind": "rag", "source_type": "rag_endpoint", "provider_llm": "openai-chat"})
    assert ok.provider_llm == "openai-chat"
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "rag_endpoint"})


def test_embedding_artifact_requires_items():
    ok = _parse({"kind": "rag", "source_type": "embedding_artifact", "items": ["chunk1", "chunk2"]})
    assert ok.items == ["chunk1", "chunk2"]
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "embedding_artifact"})


def test_poison_injection_requires_query_probes():
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "managed_vdb", "provider": "qdrant",
                "url": "https://q", "poison_injection_opt_in": True})  # query_probes False
    ok = _parse({"kind": "rag", "source_type": "managed_vdb", "provider": "qdrant",
                 "url": "https://q", "query_probes": True, "poison_injection_opt_in": True})
    assert ok.poison_injection_opt_in is True


def test_defaults_and_extra_forbidden():
    cfg = _parse({"kind": "rag", "source_type": "embedding_artifact", "items": ["x"]})
    assert cfg.query_probes is False and cfg.poison_injection_opt_in is False
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "embedding_artifact", "items": ["x"], "bogus": 1})
```

- [ ] **Step 2: Run, confirm FAIL** — `cd apps/api && .venv/bin/python -m pytest tests/test_targets_rag_config.py -q`.

- [ ] **Step 3: Add `rag` to the wire enum + required-config set** — in `schemas/targets.py`, add `"rag"` to `TargetKind` (after `"mcp"`) and to `_KINDS_REQUIRING_CONFIG`.

- [ ] **Step 4: Add `RagConfig`** — insert before the `KindConfig` union (next to `McpConfig`):

```python
RagProvider = Literal["pinecone", "weaviate", "qdrant", "chroma", "milvus", "pgvector", "redis"]


class RagConfig(_KindConfigBase):
    """RAG / vector-DB target config (source-aware). See spec 2026-06-17.
    Distinct from MemoryKindConfig (a batch of stored items) — this is the live
    retrieval system. Auth secrets ride on Target.kind_credentials_encrypted."""

    kind: Literal["rag"] = "rag"
    source_type: Literal["managed_vdb", "self_hosted_vdb", "rag_endpoint", "embedding_artifact"]

    # managed_vdb / self_hosted_vdb
    provider: RagProvider | None = None
    url: str | None = None  # endpoint or connection URL (postgresql://... allowed → not HttpUrl)
    index_name: str | None = None
    namespace: str | None = None

    # rag_endpoint (reuses LlmProbe)
    provider_llm: LlmProvider | None = None
    request_template: str | None = None
    response_path: str | None = None

    # embedding_artifact
    items: list[str] | None = None

    # common dynamic-testing controls
    query_probes: bool = False
    poison_injection_opt_in: bool = False
    canary_text: str | None = None

    @model_validator(mode="after")
    def _validate_source(self) -> "RagConfig":
        st = self.source_type
        if st in ("managed_vdb", "self_hosted_vdb") and not (self.provider and self.url):
            raise ValueError(f"source_type={st!r} requires provider and url")
        if st == "rag_endpoint" and not self.provider_llm:
            raise ValueError("source_type='rag_endpoint' requires provider_llm")
        if st == "embedding_artifact" and not self.items:
            raise ValueError("source_type='embedding_artifact' requires items")
        if self.poison_injection_opt_in and not self.query_probes:
            raise ValueError("poison_injection_opt_in requires query_probes")
        return self
```

- [ ] **Step 5: Add `RagConfig` to the `KindConfig` union** (append after `McpConfig`).

- [ ] **Step 6: Run, confirm PASS** — `cd apps/api && .venv/bin/python -m pytest tests/test_targets_rag_config.py -q` (6 passed).

- [ ] **Step 7: Broader targets suite** — `cd apps/api && .venv/bin/python -m pytest tests/ -q -k "target"`. If a hard-coded kind set fails only for missing `rag`, add it; else report.

- [ ] **Step 8: Commit**

```bash
git add apps/api/pencheff_api/schemas/targets.py apps/api/tests/test_targets_rag_config.py
git commit -m "feat(api): add rag wire kind + RagConfig (source-aware registration)"
```

---

## Task 2: RAG consent vocabulary

**Files:** Modify `schemas/scans.py`, `routers/scans.py`, `tests/test_scans_router_kind_aware.py`.

- [ ] **Step 1: Write failing tests** — append to `tests/test_scans_router_kind_aware.py`:

```python
def test_rag_base_required_action_is_enumerate() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "rag"
        kind_config = {"kind": "rag", "source_type": "managed_vdb", "provider": "qdrant", "url": "https://q"}
    assert _required_disclosed_actions(_T()) == {"rag_enumerate"}


def test_rag_query_probes_adds_query_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "rag"
        kind_config = {"kind": "rag", "source_type": "managed_vdb", "provider": "qdrant",
                       "url": "https://q", "query_probes": True}
    a = _required_disclosed_actions(_T())
    assert "rag_query_probe" in a and "rag_poison_injection" not in a


def test_rag_poison_injection_adds_destructive_action() -> None:
    from pencheff_api.routers.scans import _required_disclosed_actions
    class _T:
        kind = "rag"
        kind_config = {"kind": "rag", "source_type": "managed_vdb", "provider": "qdrant", "url": "https://q",
                       "query_probes": True, "poison_injection_opt_in": True}
    a = _required_disclosed_actions(_T())
    assert "rag_poison_injection" in a
```

- [ ] **Step 2: FAIL**, then add to `KIND_REQUIRED_DISCLOSED_ACTIONS` in `schemas/scans.py` (after `"mcp"`):

```python
    "rag":              frozenset({"rag_enumerate"}),
```

- [ ] **Step 3: Extend `_required_disclosed_actions`** in `routers/scans.py` (after the mcp branch, nested like mcp's destructive):

```python
    if target.kind == "rag":
        if cfg.get("query_probes") is True:
            base.add("rag_query_probe")
            if cfg.get("poison_injection_opt_in") is True:
                base.add("rag_poison_injection")
```

- [ ] **Step 4: Update coverage + FE-mirror sets** in `tests/test_scans_router_kind_aware.py`: add `"rag"` to the `expected` set in `test_kind_required_disclosed_actions_covers_every_target_kind`, and add `"rag": {"rag_enumerate", "rag_query_probe", "rag_poison_injection"}` to `_FRONTEND_DISCLOSED_ACTION_IDS_BY_KIND`.

- [ ] **Step 5: PASS** — `cd apps/api && .venv/bin/python -m pytest tests/test_scans_router_kind_aware.py -q`.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/schemas/scans.py apps/api/pencheff_api/routers/scans.py apps/api/tests/test_scans_router_kind_aware.py
git commit -m "feat(api): RAG consent vocabulary (enumerate/query_probe/poison_injection)"
```

---

## Task 3: Gate RAG scanning until the scanner ships

**Files:** Modify `routers/scans.py` (`start_scan`, near the mcp gate); test `tests/test_scans_rag_kind_gate.py`.

- [ ] **Step 1: Write failing test** — `apps/api/tests/test_scans_rag_kind_gate.py` (copy `test_scans_mcp_kind_gate.py` and adapt: kind="rag", kind_config a valid RagConfig dict `{"kind":"rag","source_type":"managed_vdb","provider":"qdrant","url":"https://q"}`, disclosed_actions `["rag_enumerate"]`, assert 409 + `detail["error"] == "rag_kind_scanning_not_yet_available"` + no enqueue/no Scan row). Mirror the mcp gate test's `_FakeSession`/`_make`/`_body` helpers exactly.

- [ ] **Step 2: FAIL**, then add the gate in `start_scan` (after the mcp gate, before the llm `llm_config` check):

```python
    if target.kind == "rag":
        raise HTTPException(
            status_code=409,
            detail={
                "error": "rag_kind_scanning_not_yet_available",
                "message": (
                    "RAG / vector-DB scanning ships shortly. Target registration is "
                    "supported now; scanning is not yet enabled."
                ),
                "eta_reference": "Plan R3",
            },
        )
```

- [ ] **Step 3: PASS** — `cd apps/api && .venv/bin/python -m pytest tests/test_scans_rag_kind_gate.py -q`.

- [ ] **Step 4: Commit**

```bash
git add apps/api/pencheff_api/routers/scans.py apps/api/tests/test_scans_rag_kind_gate.py
git commit -m "feat(api): gate POST /scans for kind=rag until scanner ships (Plan R3)"
```

---

## Task 4: Full-suite regression

- [ ] **Step 1:** `cd apps/api && .venv/bin/python -m pytest tests/ -q -k "scan or target or consent or kind"` → green. Fix any hard-coded kind set needing `"rag"`.
- [ ] **Step 2:** Commit any fixups.

---

## Self-review

**Spec coverage (spec §5 schema, §9 backend consent, §12 backend gate):** wire kind + RagConfig 4 sources + validation (incl. poison→query coherence) → Task 1 ✓; consent actions graduated → Task 2 ✓; scan gate → Task 3 ✓. FE (§11), connectors+analyzers (§6/§7), dispatch (§4) → Plans R1b/R2/R3.

**Placeholder scan:** complete code; no TODOs.

**Type consistency:** `RagConfig.kind="rag"` matches union discriminator + `KIND_REQUIRED_DISCLOSED_ACTIONS["rag"]`; action IDs (`rag_enumerate`/`rag_query_probe`/`rag_poison_injection`) identical across scans.py, routers/scans.py, tests; config keys (`source_type`, `provider`, `url`, `provider_llm`, `items`, `query_probes`, `poison_injection_opt_in`) consistent. `url` is `str` (not HttpUrl) to allow `postgresql://`/`redis://` connection strings.

**No migration:** `Target.kind` is `String(16)`; `"rag"` needs no DDL (marker deferred to R3 with dispatch, per the MCP precedent).
