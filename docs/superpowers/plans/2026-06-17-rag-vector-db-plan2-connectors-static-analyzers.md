# RAG / Vector DB — Plan R2: Connector Layer + Static Analyzers + Exposure Fingerprinting

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Build the static-scanning core of the RAG scanner — a vector-DB connector abstraction that normalizes any source into a `RagManifest`, pure static analyzers (exposure/missing-auth, multi-tenancy/access-control config, secrets-&-PII at rest, embedding-invertibility risk), exposure/CVE fingerprinting, and a `scan_rag` MCP tool orchestrating static-only scanning.

**Architecture:** New package `plugins/pencheff/pencheff/modules/rag_scan/`. Connectors normalize into a `RagManifest` dataclass; analyzers are **pure functions** `(RagManifest) -> list[Finding]` (no network, fully unit-testable) — exactly the decoupling that worked for MCP. `scan_rag` connects, builds the manifest, runs analyzers + fingerprinting, returns the standard `scan_*` dict. Dynamic query probes + poison injection + rag_endpoint black-box probing are **deferred to Plan R3**; R2 is static-only and safe.

**Tech Stack:** Python 3, httpx, pyyaml, asyncio, FastMCP, pencheff plugin. Tests: `cd plugins/pencheff && uv run pytest <file>`. `Finding`/`Evidence` from `pencheff.core.findings`; `Severity` from `pencheff.config`.

**Contract reuse (verified during MCP):** `Finding(title, severity, category, owasp_category, description, remediation, endpoint, parameter?, evidence=[], cwe_id?, references=[], metadata={})`; `BaseTestModule.run/get_techniques`; `@mcp.tool()` + `_require_session` + standard return; session carries no kind_config → `scan_rag(session_id, rag_config=None)`. Mirror the SHIPPED `mcp_scan/` module (`manifest.py`, `static_analyzers.py`, `fingerprint.py`, `module.py`, `server.py scan_mcp`) as the structural template.

**Series:** R1 (backend reg) + R1b (FE) done. This is R2 (static). R3 = dynamic probes + dispatch (removes the Plan R1 409 gate). Spec: `docs/superpowers/specs/2026-06-17-rag-vector-db-scanning-design.md`. Branch: `feat/rag-vector-db`.

---

## File structure (all new unless noted)

| File                                                                                                                                  | Responsibility                                                        |
| ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `modules/rag_scan/__init__.py`                                                                                                        | exports                                                               |
| `modules/rag_scan/manifest.py`                                                                                                        | `RagIndex`, `RagSampleChunk`, `RagManifest` dataclasses               |
| `modules/rag_scan/static_analyzers.py`                                                                                                | pure analyzers → `list[Finding]`                                      |
| `modules/rag_scan/advisories.yaml`                                                                                                    | exposure/CVE signals (vector-DB vendors)                              |
| `modules/rag_scan/fingerprint.py`                                                                                                     | advisory matcher → `list[Finding]`                                    |
| `modules/rag_scan/connectors.py`                                                                                                      | `VectorDbConnector` protocol + generic-REST connector → `RagManifest` |
| `modules/rag_scan/module.py`                                                                                                          | `RagStaticScanModule(BaseTestModule)` orchestrator                    |
| `server.py`                                                                                                                           | `@mcp.tool() scan_rag` (MODIFY)                                       |
| `tests/test_rag_static_analyzers.py`, `tests/test_rag_fingerprint.py`, `tests/test_rag_connector.py`, `tests/test_rag_scan_module.py` | tests                                                                 |

Run: `cd plugins/pencheff && uv run pytest tests/test_rag_*.py -q`.

---

## Task 1: Manifest dataclasses + connector protocol

**Files:** Create `modules/rag_scan/__init__.py`, `manifest.py`, `connectors.py` (protocol only here).

- [ ] **Step 1:** `modules/rag_scan/manifest.py`:

```python
# pencheff/modules/rag_scan/manifest.py
"""Normalized, source-agnostic view of a RAG / vector-DB target. Connectors
populate these; static analyzers consume ONLY these (pure + testable)."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RagIndex:
    name: str
    dimensions: int | None = None
    metric: str | None = None
    namespaces: list[str] = field(default_factory=list)   # tenants/namespaces if discoverable
    record_count: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RagSampleChunk:
    index: str
    chunk_id: str
    text: str = ""          # retrieved/sampled chunk text (for secrets/PII at rest)
    has_raw_embedding: bool = False  # raw vector exportable via the API/query


@dataclass
class RagManifest:
    source_type: str        # managed_vdb | self_hosted_vdb | embedding_artifact
    provider: str | None = None
    endpoint: str = ""
    auth_required: bool | None = None   # did the connector reach data WITHOUT credentials?
    encoder_hint: str | None = None     # embedding model if discoverable (invertibility risk)
    tenancy_isolation: bool | None = None  # namespace/metadata isolation enforced?
    raw_embedding_export: bool | None = None  # API returns raw vectors
    indexes: list[RagIndex] = field(default_factory=list)
    samples: list[RagSampleChunk] = field(default_factory=list)
```

- [ ] **Step 2:** `modules/rag_scan/connectors.py` (protocol + stub; the generic-REST connector lands in Task 4):

```python
# pencheff/modules/rag_scan/connectors.py
"""Vector-DB connector abstraction. A connector turns a RagConfig dict into a
normalized RagManifest. v1 ships a generic-REST connector (Task 4); more
vendor-specific connectors are additive."""
from __future__ import annotations
from typing import Any, Protocol

from .manifest import RagManifest


class VectorDbConnector(Protocol):
    async def build_manifest(self, cfg: dict[str, Any]) -> RagManifest: ...
```

- [ ] **Step 3:** `modules/rag_scan/__init__.py`:

```python
from .manifest import RagManifest, RagIndex, RagSampleChunk
__all__ = ["RagManifest", "RagIndex", "RagSampleChunk"]
```

- [ ] **Step 4:** Verify import: `cd plugins/pencheff && uv run python -c "from pencheff.modules.rag_scan import RagManifest, RagIndex, RagSampleChunk; print('ok')"`.

- [ ] **Step 5:** Commit: `git add plugins/pencheff/pencheff/modules/rag_scan/__init__.py plugins/pencheff/pencheff/modules/rag_scan/manifest.py plugins/pencheff/pencheff/modules/rag_scan/connectors.py && git commit -m "feat(rag-scan): manifest dataclasses + connector protocol"`

---

## Task 2: Static analyzers (pure, TDD)

**Files:** Create `modules/rag_scan/static_analyzers.py`; test `tests/test_rag_static_analyzers.py`.

- [ ] **Step 1: Write failing tests** — `tests/test_rag_static_analyzers.py`:

```python
from pencheff.modules.rag_scan.manifest import RagManifest, RagIndex, RagSampleChunk
from pencheff.modules.rag_scan import static_analyzers as sa


def _mf(**kw):
    base = dict(source_type="managed_vdb", provider="qdrant", endpoint="https://q:6333")
    base.update(kw); return RagManifest(**base)


def test_exposure_flags_no_auth():
    mf = _mf(auth_required=False)
    f = sa.analyze_exposure(mf)
    assert len(f) >= 1 and f[0].cwe_id == "CWE-306"


def test_exposure_clean_when_auth_required():
    assert sa.analyze_exposure(_mf(auth_required=True)) == []


def test_tenancy_flags_missing_isolation():
    f = sa.analyze_tenancy(_mf(tenancy_isolation=False))
    assert len(f) >= 1 and f[0].owasp_category == "LLM08"


def test_tenancy_clean_when_isolated():
    assert sa.analyze_tenancy(_mf(tenancy_isolation=True)) == []


def test_secrets_at_rest_flags_secret_in_chunk():
    mf = _mf(samples=[RagSampleChunk(index="docs", chunk_id="c1",
             text="here is the AWS key AKIAIOSFODNN7EXAMPLE")])
    f = sa.analyze_secrets_at_rest(mf)
    assert len(f) >= 1 and f[0].owasp_category == "LLM02"


def test_secrets_at_rest_clean():
    mf = _mf(samples=[RagSampleChunk(index="docs", chunk_id="c1", text="the cat sat on the mat")])
    assert sa.analyze_secrets_at_rest(mf) == []


def test_invertibility_risk_flags_raw_export_known_encoder_no_auth():
    mf = _mf(raw_embedding_export=True, encoder_hint="text-embedding-ada-002", auth_required=False)
    f = sa.analyze_invertibility_risk(mf)
    assert len(f) >= 1 and f[0].owasp_category in ("LLM08", "LLM02")


def test_invertibility_risk_low_when_no_raw_export():
    assert sa.analyze_invertibility_risk(_mf(raw_embedding_export=False)) == []


def test_run_all_aggregates():
    mf = _mf(auth_required=False, tenancy_isolation=False)
    cats = {f.owasp_category for f in sa.run_all_static(mf)}
    assert "LLM08" in cats
```

- [ ] **Step 2: FAIL**, then implement `static_analyzers.py`. Each is a pure function → `list[Finding]`:
  - `analyze_exposure(mf)` — when `mf.auth_required is False` (connector reached data with no creds): Finding sev=critical, owasp "LLM08", cwe "CWE-306", technique `rag:exposed-db`.
  - `analyze_tenancy(mf)` — when `mf.tenancy_isolation is False`: Finding sev=high, owasp "LLM08", cwe "CWE-200", technique `rag:cross-tenant-leak` (config-level signal).
  - `analyze_secrets_at_rest(mf)` — over `mf.samples`: reuse the memory scanner's secret/PII detectors (`from pencheff_sentry.memory import scan_memory` if available; else a local regex set for AWS keys/tokens/emails) on each chunk text; Finding per hit, sev=high, owasp "LLM02", cwe "CWE-200", technique `rag:secret-at-rest`. Guard the optional import (degrade to the local regex set).
  - `analyze_invertibility_risk(mf)` — when `mf.raw_embedding_export is True` (esp. + known `encoder_hint` + `auth_required is False`): Finding sev=medium (high if also no-auth), owasp "LLM08", cwe "CWE-200", technique `rag:embedding-inversion-risk`, references vec2text.
  - `baseline_hash(mf)` — stable JSON hash of index names+dims (for drift).
  - `run_all_static(mf)` — aggregate.
    Use real `Finding`/`Severity` (verify member casing against `pencheff/config.py` + field names against `core/findings.py`).

- [ ] **Step 3: PASS** — `cd plugins/pencheff && uv run pytest tests/test_rag_static_analyzers.py -q`.

- [ ] **Step 4: Export** + Commit:

```bash
git add plugins/pencheff/pencheff/modules/rag_scan/static_analyzers.py plugins/pencheff/pencheff/modules/rag_scan/__init__.py plugins/pencheff/tests/test_rag_static_analyzers.py
git commit -m "feat(rag-scan): static analyzers (exposure, tenancy, secrets-at-rest, invertibility-risk)"
```

---

## Task 3: Exposure / CVE fingerprinting

**Files:** Create `modules/rag_scan/advisories.yaml`, `fingerprint.py`; test `tests/test_rag_fingerprint.py`. Mirror the SHIPPED `mcp_scan/fingerprint.py` + `advisories.yaml` structure exactly.

- [ ] **Step 1: Failing tests** — `tests/test_rag_fingerprint.py`: a manifest with `provider="weaviate"`, an old `metadata["version"]` below a seeded `vulnerable_below` flags; a patched version doesn't; a benign provider with no advisory → []. (Mirror `test_mcp_fingerprint.py`.)
- [ ] **Step 2: FAIL**, then `advisories.yaml` — seed with documented vector-DB exposure/CVE signals (research flagged this needs seeding; start conservative + refreshable): e.g. default-no-auth exposure note for self-hosted Chroma/Qdrant/Weaviate/Milvus when `auth_required` is false (cross-link to `analyze_exposure`), plus any version-pinned CVEs you can cite. Each entry: `id, provider_match (regex), vulnerable_below?, cve?, cvss, severity, cwe, title, description, remediation, reference`. If no firm CVE is known for a provider, include an exposure-posture advisory keyed on provider + a comment that the list is refreshable.
- [ ] **Step 3:** `fingerprint.py` — `fingerprint(mf: RagManifest) -> list[Finding]` loads `advisories.yaml`, matches `provider_match` against `mf.provider`, version-gates on `vulnerable_below` vs `mf.metadata`/`indexes` version if present (only flag when detected AND below), emits Findings (owasp "LLM08", technique `rag:known-vuln`). Mirror mcp's loader (importlib.resources) + Severity map. Verify `advisories.yaml` packages (hatchling includes package files, as mcp confirmed).
- [ ] **Step 4: PASS** + export + Commit:

```bash
git add plugins/pencheff/pencheff/modules/rag_scan/advisories.yaml plugins/pencheff/pencheff/modules/rag_scan/fingerprint.py plugins/pencheff/pencheff/modules/rag_scan/__init__.py plugins/pencheff/tests/test_rag_fingerprint.py
git commit -m "feat(rag-scan): exposure/CVE fingerprinting against vector-DB advisory list"
```

---

## Task 4: Generic-REST connector

**Files:** Extend `modules/rag_scan/connectors.py`; test `tests/test_rag_connector.py`.

v1 ships ONE connector — a generic HTTP/REST connector that handles the common vector-DB REST shape (list collections, describe, sample, detect auth) configurable per provider. pgvector + other vendor connectors are additive (note it). The normalization layer (`_normalize_*`) is pure + unit-tested; the live HTTP uses `httpx.MockTransport` in tests.

- [ ] **Step 1: Failing tests** — `tests/test_rag_connector.py`: with an `httpx.MockTransport` returning a canned collections-list + describe, `GenericRestConnector().build_manifest(cfg)` returns a `RagManifest` with the right indexes, `provider`, `endpoint`, and `auth_required` (False when an unauthenticated request succeeded; True when the mock returns 401 without creds then 200 with). Test the pure normalizers directly too.
- [ ] **Step 2: FAIL**, then implement `GenericRestConnector` in `connectors.py`: an async `build_manifest(cfg)` that uses an injectable httpx transport (for tests), probes the endpoint (with + without the configured auth header to set `auth_required`), lists collections/indexes, samples a few chunks if a sample endpoint exists, and normalizes to `RagManifest`. Keep all network non-fatal (errors → partial manifest, never crash). Provider-specific request shaping behind small per-provider helpers; default to a best-effort generic shape. Pure `_normalize_indexes`/`_normalize_samples` tested directly.
- [ ] **Step 3: PASS** + Commit:

```bash
git add plugins/pencheff/pencheff/modules/rag_scan/connectors.py plugins/pencheff/tests/test_rag_connector.py
git commit -m "feat(rag-scan): generic-REST vector-DB connector + manifest normalization"
```

---

## Task 5: `RagStaticScanModule` + `scan_rag` tool

**Files:** Create `modules/rag_scan/module.py`; modify `__init__.py`, `server.py`; test `tests/test_rag_scan_module.py`. Mirror the SHIPPED `mcp_scan/module.py` + `server.py scan_mcp`.

- [ ] **Step 1: Failing test** — `tests/test_rag_scan_module.py`: monkeypatch the connector's `build_manifest` to return a fixture `RagManifest` (auth_required=False, tenancy_isolation=False, a secret-bearing sample); `RagStaticScanModule().run(session, config={"rag_config": {...}})` returns findings incl. LLM08 + LLM02; `get_techniques()` non-empty. (embedding_artifact source: run secrets/invertibility over `cfg.items` directly without a connector.)
- [ ] **Step 2: FAIL**, then `module.py`: `RagStaticScanModule(BaseTestModule)` whose `run` reads `config["rag_config"]`; for `embedding_artifact` build a manifest from `cfg.items` (samples) directly; for managed/self_hosted use the connector (`GenericRestConnector().build_manifest(cfg)`); for `rag_endpoint` return `[]` (handled by the LlmProbe path in R3); then `run_all_static(manifest)` + `fingerprint(manifest)`; stamp `baseline_hash` into metadata; `get_techniques()` returns the rag technique tags. Non-fatal.
- [ ] **Step 3: Export** + **PASS**.
- [ ] **Step 4: `scan_rag` MCP tool** in `server.py` (mirror `scan_mcp`): `@mcp.tool() async def scan_rag(session_id, rag_config=None)` → `_require_session`, run `RagStaticScanModule`, `add_many`, standard return. Verify `import pencheff.server` clean.
- [ ] **Step 5: Commit**:

```bash
git add plugins/pencheff/pencheff/modules/rag_scan/module.py plugins/pencheff/pencheff/modules/rag_scan/__init__.py plugins/pencheff/pencheff/server.py plugins/pencheff/tests/test_rag_scan_module.py
git commit -m "feat(rag-scan): RagStaticScanModule + scan_rag MCP tool (static orchestration)"
```

---

## Task 6: Full regression

- [ ] `cd plugins/pencheff && uv run pytest tests/test_rag_*.py -q` → green; `uv run python -c "import pencheff.server"` → ok; `uv run pytest tests/ -q -k "rag or mcp or smoke"` → no regressions. Commit any fixups.

---

## Self-review

**Spec coverage (spec §6 connectors, §7a static analyzers, §7e embedding-artifact, §8 catalog):** manifest+connector (T1,T4) ✓; static analyzers exposure/tenancy/secrets-at-rest/invertibility (T2) ✓; exposure/CVE fingerprinting (T3) ✓; static orchestration + embedding_artifact path (T5) ✓. Dynamic query probes, poison injection, rag_endpoint probing, dispatch + gate removal → **Plan R3**.
**Placeholder scan:** analyzers/manifest complete; connector + advisories concrete with the explicit "v1 = generic REST + seeded list, more additive" scope note + research caveat on the exposure list.
**Type consistency:** `RagManifest`/`RagIndex`/`RagSampleChunk` consistent across files+tests; `Finding` args match core/findings.py (verify Severity casing); `rag_config` keys match Plan R1 `RagConfig`; technique tags consistent with `get_techniques()`.
**Risk note:** v1 ships ONE connector (generic REST) — vendor-specific connectors (pgvector SQL, Pinecone/Weaviate idiosyncrasies) are additive; the static analyzers + fingerprint + embedding_artifact path are the fully-tested core. Exposure advisory list is seeded + refreshable (research gap).
