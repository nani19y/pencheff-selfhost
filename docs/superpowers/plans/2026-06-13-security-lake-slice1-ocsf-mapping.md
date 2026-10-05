# Security Lake — Slice 1: OCSF Mapping & Validation Layer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pure, I/O-free Python library that converts every Pencheff finding source (SAST, SCA, secrets, IaC, DAST, runtime) into OCSF 1.3.0 events and validates each event against the official OCSF JSON Schema.

**Architecture:** A new package `pencheff_api/services/security_lake/` containing: a vendored OCSF 1.3.0 JSON-Schema bundle + a `validate_ocsf()` function; shared mapping primitives (severity/status/type ids, metadata/enrichments/unmapped builders, finding fingerprint); one pure mapper module per source; and a `map_finding()` dispatcher. No database, network, or object-store access — all of that is Slice 2. Every mapper is tested by (a) asserting the fields Pencheff controls and (b) asserting the produced event passes `validate_ocsf()`.

**Tech Stack:** Python 3.13, `jsonschema` 4.26.0 (already installed), `pytest` + `pytest-asyncio` (already installed). No new runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-06-13-pencheff-security-lake-design.md` (§2, §4).

---

## Status: COMPLETE ✅ (2026-06-13)

Implemented on branch `feature-security-lake`, 32 tests green. Final holistic review: SHIP.
Public interface: `from pencheff_api.services.security_lake import map_finding, validate_ocsf, LakeContext`.

### Carry-forward into the Slice 2 (ingestion) spec — MUST address

- **Runtime span shaping (I-1):** `map_runtime` expects a dict
  `{detection_type, severity, title, description, span_id, trace_id}`, but the
  `runtime_spans` table (migration 0053) stores `{name, kind, status, source,
trace_id, attributes(JSONB), ...}` — there is no `detection_type`/`severity`/
  `title`/`span_id` column. Slice 2's runtime ingestion path needs an explicit
  shaping step that extracts these from `attributes`/`name`/`kind`. Define that
  mapping (or stub the runtime path) before implementing runtime ingestion.
- **Runtime fingerprint is per-span by design (I-2):** runtime findings use
  `span_id` in the fingerprint, so each span is its own `finding_info.uid` — the
  "latest-event-per-uid" current-state view will NOT aggregate recurring runtime
  detections across spans the way it dedups SAST/SCA across scans. The DuckDB
  query layer must treat runtime detections as point-in-time events, not
  persistent defects. Document this in the query-layer design.

### Minor follow-ups (cosmetic, optional)

- `build_enrichments` serializes `kev=False` → `"False"` (capitalized). Consider
  `str(...).lower()` for cleaner SIEM interop. Schema-valid either way.
- SAST `file.name`/`file.path` are `""` when a finding has no file path; Slice 2's
  ingestion can filter or flag such rows.

---

## Why validator-first

We cannot assert OCSF required-field lists from memory and be sure. So Task 1 vendors the **real** OCSF 1.3.0 JSON Schema and builds the validator first. Every later mapper test ends with `validate_ocsf(event)` not raising — the schema bundle, not this document, is the source of truth for what a valid event needs. If a mapper omits a required field, its test fails loudly during execution.

## File structure

| File                                                     | Responsibility                                                                                                                                    |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pencheff_api/services/security_lake/__init__.py`        | Package marker; re-export `map_finding`, `validate_ocsf`, `LakeContext`.                                                                          |
| `pencheff_api/services/security_lake/schema/`            | Vendored OCSF 1.3.0 JSON-Schema files (one per class + base). Pinned, never edited by hand.                                                       |
| `pencheff_api/services/security_lake/validation.py`      | `validate_ocsf(event) -> None` (raises `OCSFValidationError`); schema loader (cached).                                                            |
| `pencheff_api/services/security_lake/primitives.py`      | `LakeContext`, `severity_id`, `status_id`, `epoch_ms`, `build_metadata`, `build_enrichments`, `build_unmapped`, `fingerprint`, OCSF id constants. |
| `pencheff_api/services/security_lake/mappers/sast.py`    | RepoFinding (sast) → Vulnerability Finding (2002).                                                                                                |
| `pencheff_api/services/security_lake/mappers/sca.py`     | RepoFinding (sca) → Vulnerability Finding (2002).                                                                                                 |
| `pencheff_api/services/security_lake/mappers/secrets.py` | RepoFinding (secret) → Detection Finding (2004).                                                                                                  |
| `pencheff_api/services/security_lake/mappers/iac.py`     | RepoFinding (iac) → Compliance Finding (2003).                                                                                                    |
| `pencheff_api/services/security_lake/mappers/dast.py`    | Finding (DAST) → Vulnerability Finding (2002).                                                                                                    |
| `pencheff_api/services/security_lake/mappers/runtime.py` | Runtime span → Detection Finding (2004).                                                                                                          |
| `pencheff_api/services/security_lake/dispatch.py`        | `map_finding(source, finding, ctx) -> dict`.                                                                                                      |
| `tests/test_security_lake_validation.py`                 | Validator + golden minimal events.                                                                                                                |
| `tests/test_security_lake_primitives.py`                 | Primitives + fingerprint.                                                                                                                         |
| `tests/test_security_lake_mappers.py`                    | All six mappers + dispatcher cross-source property test.                                                                                          |

All mappers accept a `Mapping`/object with attribute or key access and a `LakeContext`; none touch the DB. Tests build inputs with `SimpleNamespace`/dicts, matching `tests/test_scan_delta.py`.

---

## Task 1: OCSF 1.3.0 validator (via the `ocsf-json-schema` library)

**Approach change (2026-06-13):** Instead of scraping per-class JSON Schema from
`schema.ocsf.io` (which rate-limits hard), we use the pinned **`ocsf-json-schema`**
PyPI package. It ships the packaged OCSF 1.3.0 schema and generates **self-contained**
(no remote `$ref`) Draft-2020-12 JSON Schema per class, entirely offline. The
dependency is already declared in `apps/api/pyproject.toml`. Same goal — strict
OCSF 1.3.0 validation — but reproducible and network-free.

**Schema facts verified against the library (use these; they drive the mappers):**

- Top-level `additionalProperties: false` on every finding class. Allowed top-level
  keys include all OCSF base-event fields we use: `activity_id, category_uid,
class_uid, type_uid, time, severity_id, status_id, metadata, finding_info,
enrichments, unmapped` plus class-specific `vulnerabilities` / `compliance`.
- `vulnerability_finding` (2002) **requires** `vulnerabilities` (array).
- `compliance_finding` (2003) **requires** `compliance` (object), which itself
  **requires** `standards` (array of strings).
- `detection_finding` (2004) requires only base fields + `finding_info`.
- `finding_info`: closed object, **requires** `title`+`uid`, allows `desc`.
- `vulnerabilities[]` item: closed; allows `cve, cwe, affected_code, affected_packages,
title, severity, desc, references, remediation` — **no `cvss`** (put CVSS in `unmapped`).
- `affected_code[]`: closed, **requires** `file`; `file` is closed and **requires**
  `name`+`type_id` (use `type_id: 1` = Regular File; `path` is an allowed key).
- `affected_packages[]`: closed, **requires** `name`+`version`; allows `fixed_in_version`.
- `cve`: closed, **requires** `uid`.
- `enrichments[]`: closed, **requires** `data`+`name`+`value`; allows `type`.
- `unmapped`: open object (`additionalProperties: true`) — safe for arbitrary keys.

**Files:**

- Create: `pencheff_api/services/security_lake/__init__.py` (if not already present from Task 2 — it currently holds only a docstring; leave re-exports to Task 10)
- Create: `pencheff_api/services/security_lake/validation.py`
- Test: `tests/test_security_lake_validation.py`

- [ ] **Step 1: Ensure the dependency is installed**

Run from `apps/api`: `uv pip install ocsf-json-schema jsonschema` (both are declared in
`pyproject.toml`). Verify: `./.venv/bin/python -c "import ocsf_json_schema, jsonschema; print('ok')"` → `ok`.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_security_lake_validation.py
from __future__ import annotations

import pytest

from pencheff_api.services.security_lake.validation import (
    validate_ocsf,
    OCSFValidationError,
)


def _vuln_finding() -> dict:
    return {
        "activity_id": 1,
        "category_uid": 2,
        "class_uid": 2002,
        "type_uid": 200201,
        "time": 1_700_000_000_000,
        "severity_id": 4,
        "status_id": 1,
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Pencheff", "vendor_name": "Pencheff"},
        },
        "finding_info": {"title": "Test finding", "uid": "abc123"},
        "vulnerabilities": [{"title": "Test finding", "severity": "high"}],
    }


def _compliance_finding() -> dict:
    ev = _vuln_finding()
    ev["class_uid"] = 2003
    ev["type_uid"] = 200301
    del ev["vulnerabilities"]
    ev["compliance"] = {"standards": ["checkov"], "control": "CKV_AWS_20"}
    return ev


def _detection_finding() -> dict:
    ev = _vuln_finding()
    ev["class_uid"] = 2004
    ev["type_uid"] = 200401
    del ev["vulnerabilities"]
    return ev


def test_vulnerability_finding_validates():
    validate_ocsf(_vuln_finding())  # must not raise


def test_compliance_finding_validates():
    validate_ocsf(_compliance_finding())


def test_detection_finding_validates():
    validate_ocsf(_detection_finding())


def test_missing_required_field_raises():
    bad = _vuln_finding()
    del bad["finding_info"]
    with pytest.raises(OCSFValidationError):
        validate_ocsf(bad)


def test_vuln_finding_without_vulnerabilities_raises():
    bad = _vuln_finding()
    del bad["vulnerabilities"]
    with pytest.raises(OCSFValidationError):
        validate_ocsf(bad)


def test_unknown_class_uid_raises():
    bad = _vuln_finding()
    bad["class_uid"] = 9999
    bad["type_uid"] = 999901
    with pytest.raises(OCSFValidationError):
        validate_ocsf(bad)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_validation.py -v` (from `apps/api`)
Expected: FAIL — `ModuleNotFoundError: ...security_lake.validation`.

- [ ] **Step 4: Implement the validator**

```python
# pencheff_api/services/security_lake/validation.py
from __future__ import annotations

from functools import lru_cache

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from ocsf_json_schema import get_ocsf_schema, OcsfJsonSchemaEmbedded

OCSF_VERSION = "1.3.0"

# OCSF class_uid -> class_name (the three Finding classes the lake emits).
_CLASS_NAME = {
    2002: "vulnerability_finding",
    2003: "compliance_finding",
    2004: "detection_finding",
}


class OCSFValidationError(ValueError):
    """An event failed OCSF 1.3.0 schema validation."""


@lru_cache(maxsize=1)
def _schema_source() -> OcsfJsonSchemaEmbedded:
    # Loads the packaged OCSF 1.3.0 schema; generates self-contained per-class
    # JSON Schema with referenced objects embedded (no remote $ref, offline).
    return OcsfJsonSchemaEmbedded(get_ocsf_schema(version=OCSF_VERSION))


@lru_cache(maxsize=None)
def _validator_for(class_uid: int) -> Draft202012Validator:
    name = _CLASS_NAME.get(class_uid)
    if name is None:
        raise OCSFValidationError(f"No OCSF schema for class_uid={class_uid!r}")
    schema = _schema_source().get_class_schema(class_name=name)
    return Draft202012Validator(schema)


def validate_ocsf(event: dict) -> None:
    """Validate an OCSF event against its class schema. Raises OCSFValidationError."""
    class_uid = event.get("class_uid")
    if not isinstance(class_uid, int):
        raise OCSFValidationError(f"event missing integer class_uid: {class_uid!r}")
    try:
        _validator_for(class_uid).validate(event)
    except ValidationError as exc:
        raise OCSFValidationError(
            f"OCSF validation failed at {list(exc.absolute_path)}: {exc.message}"
        ) from exc
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_security_lake_validation.py -v` (from `apps/api`)
Expected: PASS (6 passed).

- [ ] **Step 6: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/validation.py apps/api/tests/test_security_lake_validation.py apps/api/pyproject.toml
git commit -m "feat(security-lake): OCSF 1.3.0 validator via ocsf-json-schema library"
```

---

## Task 2: Mapping primitives + fingerprint

**Files:**

- Create: `pencheff_api/services/security_lake/primitives.py`
- Test: `tests/test_security_lake_primitives.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_primitives.py
from __future__ import annotations

from pencheff_api.services.security_lake.primitives import (
    LakeContext,
    severity_id,
    status_id,
    build_metadata,
    build_enrichments,
    build_unmapped,
    fingerprint,
    CATEGORY_FINDINGS,
)


def test_severity_id_maps_pencheff_scale():
    assert severity_id("info") == 1
    assert severity_id("low") == 2
    assert severity_id("medium") == 3
    assert severity_id("high") == 4
    assert severity_id("critical") == 5
    assert severity_id("CRITICAL") == 5     # case-insensitive
    assert severity_id("bogus") == 0        # unknown


def test_status_id_from_state():
    assert status_id(verification_status="unverified", suppressed=False) == 1   # New
    assert status_id(verification_status="true_positive", suppressed=False) == 2  # In Progress
    assert status_id(verification_status="unverified", suppressed=True) == 3      # Suppressed
    assert status_id(verification_status="fixed", suppressed=False) == 4          # Resolved


def test_build_metadata_pins_version_and_product():
    md = build_metadata()
    assert md["version"] == "1.3.0"
    assert md["product"]["name"] == "Pencheff"


def test_build_enrichments_emits_epss_and_kev():
    enr = build_enrichments(epss=0.42, kev=True)
    names = {e["name"]: e["value"] for e in enr}
    assert names["epss"] == 0.42
    assert names["kev"] is True
    assert build_enrichments(epss=None, kev=None) == []   # nothing to enrich


def test_build_unmapped_drops_none_values():
    um = build_unmapped(reachability="reachable", risk_score=88.0,
                         ssvc_decision=None, ai_triage=None)
    assert um == {"reachability": "reachable", "risk_score": 88.0}


def test_fingerprint_is_stable_and_distinguishing():
    a = fingerprint(org_id="o1", asset_id="r1", source="sast",
                    rule_or_cve="py.sqli", location="app.py:10-12")
    b = fingerprint(org_id="o1", asset_id="r1", source="sast",
                    rule_or_cve="py.sqli", location="app.py:10-12")
    c = fingerprint(org_id="o1", asset_id="r1", source="sast",
                    rule_or_cve="py.sqli", location="app.py:99-99")
    assert a == b           # deterministic
    assert a != c           # location-sensitive
    assert len(a) == 64     # sha256 hex


def test_lake_context_holds_scope_and_time():
    ctx = LakeContext(org_id="o1", asset_id="r1", source="sast",
                      time_ms=1_700_000_000_000, is_new=True)
    assert ctx.org_id == "o1"
    assert CATEGORY_FINDINGS == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && python -m pytest tests/test_security_lake_primitives.py -v`
Expected: FAIL — `ModuleNotFoundError: ...primitives`.

- [ ] **Step 3: Implement primitives**

```python
# pencheff_api/services/security_lake/primitives.py
from __future__ import annotations

import hashlib
from dataclasses import dataclass

CATEGORY_FINDINGS = 2  # OCSF category_uid for Findings

# OCSF class_uid constants
CLASS_VULNERABILITY_FINDING = 2002
CLASS_COMPLIANCE_FINDING = 2003
CLASS_DETECTION_FINDING = 2004

# OCSF Finding activity_id
ACTIVITY_CREATE = 1
ACTIVITY_UPDATE = 2

_OCSF_VERSION = "1.3.0"

_SEVERITY_ID = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


@dataclass(frozen=True)
class LakeContext:
    """Scope + timing for one mapped finding. No DB handles — pure data."""
    org_id: str
    asset_id: str          # repository_id or target_id
    source: str            # sast | sca | secret | iac | dast | runtime
    time_ms: int
    is_new: bool = True
    first_seen_ms: int | None = None


def severity_id(severity: str | None) -> int:
    return _SEVERITY_ID.get((severity or "").lower().strip(), 0)


def status_id(*, verification_status: str | None, suppressed: bool) -> int:
    if suppressed:
        return 3  # Suppressed
    v = (verification_status or "").lower().strip()
    if v == "fixed":
        return 4  # Resolved
    if v in {"true_positive", "in_progress"}:
        return 2  # In Progress
    return 1      # New


def build_metadata() -> dict:
    return {
        "version": _OCSF_VERSION,
        "product": {"name": "Pencheff", "vendor_name": "Pencheff"},
    }


def build_enrichments(*, epss: float | None, kev: bool | None) -> list[dict]:
    out: list[dict] = []
    if epss is not None:
        out.append({"name": "epss", "value": epss, "type": "score"})
    if kev is not None:
        out.append({"name": "kev", "value": kev, "type": "flag"})
    return out


def build_unmapped(**fields) -> dict:
    """Pencheff-specific fields with no OCSF home. None values are dropped."""
    return {k: v for k, v in fields.items() if v is not None}


def fingerprint(*, org_id: str, asset_id: str, source: str,
                rule_or_cve: str | None, location: str,
                package: str | None = None) -> str:
    parts = [org_id, asset_id, source, rule_or_cve or "", location, package or ""]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && python -m pytest tests/test_security_lake_primitives.py -v`
Expected: PASS (7 passed).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/primitives.py apps/api/tests/test_security_lake_primitives.py
git commit -m "feat(security-lake): OCSF mapping primitives + finding fingerprint"
```

---

## Task 3: Base event builder

**Files:**

- Modify: `pencheff_api/services/security_lake/primitives.py` (add `base_event`)
- Test: `tests/test_security_lake_primitives.py` (append)

- [ ] **Step 1: Write the failing test (append to existing file)**

```python
# tests/test_security_lake_primitives.py  (append)
from pencheff_api.services.security_lake.primitives import base_event
from pencheff_api.services.security_lake.validation import validate_ocsf


def test_base_event_sets_required_skeleton_and_validates():
    ev = base_event(
        class_uid=2002,
        activity_id=1,
        ctx=LakeContext(org_id="o1", asset_id="r1", source="sast",
                        time_ms=1_700_000_000_000, is_new=True),
        finding_info={"title": "X", "uid": "fp1"},
        sev_id=4,
        stat_id=1,
    )
    assert ev["category_uid"] == 2
    assert ev["class_uid"] == 2002
    assert ev["type_uid"] == 2002 * 100 + 1
    assert ev["metadata"]["version"] == "1.3.0"
    validate_ocsf(ev)  # must not raise
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && python -m pytest tests/test_security_lake_primitives.py::test_base_event_sets_required_skeleton_and_validates -v`
Expected: FAIL — `ImportError: cannot import name 'base_event'`.

- [ ] **Step 3: Implement `base_event`**

```python
# pencheff_api/services/security_lake/primitives.py  (append)
def base_event(*, class_uid: int, activity_id: int, ctx: "LakeContext",
               finding_info: dict, sev_id: int, stat_id: int) -> dict:
    """Assemble the OCSF base-event skeleton shared by all finding classes."""
    return {
        "activity_id": activity_id,
        "category_uid": CATEGORY_FINDINGS,
        "class_uid": class_uid,
        "type_uid": class_uid * 100 + activity_id,
        "time": ctx.time_ms,
        "severity_id": sev_id,
        "status_id": stat_id,
        "metadata": build_metadata(),
        "finding_info": finding_info,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && python -m pytest tests/test_security_lake_primitives.py -v`
Expected: PASS (8 passed). If validation fails on a missing required field, add it here (read the vendored schema's `required`) — this builder is the single place the base skeleton is defined.

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/primitives.py apps/api/tests/test_security_lake_primitives.py
git commit -m "feat(security-lake): OCSF base event builder"
```

---

## Task 4: SAST mapper → Vulnerability Finding

**Files:**

- Create: `pencheff_api/services/security_lake/mappers/__init__.py` (empty)
- Create: `pencheff_api/services/security_lake/mappers/sast.py`
- Test: `tests/test_security_lake_mappers.py`

Input is a `RepoFinding`-shaped dict (see `services/repo_findings.py`): keys `scanner, rule_id, severity, title, description, file_path, line_start, line_end, code_snippet, cve, package, installed_version, fixed_version, raw`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security_lake_mappers.py
from __future__ import annotations

from pencheff_api.services.security_lake.primitives import LakeContext
from pencheff_api.services.security_lake.validation import validate_ocsf
from pencheff_api.services.security_lake.mappers.sast import map_sast


def _ctx(source="sast"):
    return LakeContext(org_id="o1", asset_id="r1", source=source,
                       time_ms=1_700_000_000_000, is_new=True)


SAST_ROW = {
    "scanner": "semgrep",
    "rule_id": "python.lang.security.sqli",
    "severity": "high",
    "title": "SQL injection",
    "description": "Tainted input flows to a SQL sink.",
    "file_path": "app/db.py",
    "line_start": 10,
    "line_end": 12,
    "code_snippet": "cursor.execute(f'... {user}')",
    "cve": None, "package": None,
    "installed_version": None, "fixed_version": None,
    "raw": {"cwe": "CWE-89"},
}


def test_map_sast_produces_valid_vuln_finding():
    ev = map_sast(SAST_ROW, _ctx())
    assert ev["class_uid"] == 2002
    assert ev["severity_id"] == 4
    assert ev["finding_info"]["title"] == "SQL injection"
    # code location lives under vulnerabilities[].affected_code[]
    code = ev["vulnerabilities"][0]["affected_code"][0]
    assert code["file"]["path"] == "app/db.py"
    assert code["start_line"] == 10 and code["end_line"] == 12
    validate_ocsf(ev)


def test_map_sast_fingerprint_in_uid():
    ev = map_sast(SAST_ROW, _ctx())
    assert len(ev["finding_info"]["uid"]) == 64  # sha256 hex
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -v`
Expected: FAIL — `ModuleNotFoundError: ...mappers.sast`.

- [ ] **Step 3: Implement the SAST mapper**

```python
# pencheff_api/services/security_lake/mappers/__init__.py
```

```python
# pencheff_api/services/security_lake/mappers/sast.py
from __future__ import annotations

from typing import Mapping

from ..primitives import (
    ACTIVITY_CREATE, ACTIVITY_UPDATE, CLASS_VULNERABILITY_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id, build_unmapped,
)


def map_sast(row: Mapping, ctx: LakeContext) -> dict:
    location = f"{row.get('file_path')}:{row.get('line_start')}-{row.get('line_end')}"
    uid = fingerprint(
        org_id=ctx.org_id, asset_id=ctx.asset_id, source="sast",
        rule_or_cve=row.get("rule_id"), location=location,
    )
    finding_info = {
        "title": (row.get("title") or "SAST finding")[:500],
        "uid": uid,
        "desc": row.get("description") or "",
    }
    ev = base_event(
        class_uid=CLASS_VULNERABILITY_FINDING,
        activity_id=ACTIVITY_CREATE if ctx.is_new else ACTIVITY_UPDATE,
        ctx=ctx, finding_info=finding_info,
        sev_id=severity_id(row.get("severity")),
        stat_id=status_id(verification_status=None,
                          suppressed=bool(row.get("suppressed"))),
    )
    ev["vulnerabilities"] = [{
        "title": finding_info["title"],
        "severity": (row.get("severity") or "medium"),
        "affected_code": [{
            "file": {"path": row.get("file_path") or "", "name":
                     (row.get("file_path") or "").rsplit("/", 1)[-1]},
            "start_line": row.get("line_start"),
            "end_line": row.get("line_end"),
        }],
    }]
    ev["unmapped"] = build_unmapped(
        scanner=row.get("scanner"), rule_id=row.get("rule_id"),
        code_snippet=row.get("code_snippet"),
        cwe=(row.get("raw") or {}).get("cwe"),
    )
    return ev
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -v`
Expected: PASS (2 passed). If validation fails, read `schema/vulnerability_finding.json` and adjust the `vulnerabilities`/`affected_code` shape to match required sub-fields.

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/mappers/ apps/api/tests/test_security_lake_mappers.py
git commit -m "feat(security-lake): SAST -> OCSF Vulnerability Finding mapper"
```

---

## Task 5: SCA mapper → Vulnerability Finding (CVE + affected package)

**Files:**

- Create: `pencheff_api/services/security_lake/mappers/sca.py`
- Test: `tests/test_security_lake_mappers.py` (append)

- [ ] **Step 1: Write the failing test (append)**

```python
# tests/test_security_lake_mappers.py  (append)
from pencheff_api.services.security_lake.mappers.sca import map_sca

SCA_ROW = {
    "scanner": "osv", "rule_id": None, "severity": "critical",
    "title": "lodash prototype pollution", "description": "CVE-2020-8203",
    "file_path": "package-lock.json", "line_start": None, "line_end": None,
    "code_snippet": None, "cve": "CVE-2020-8203", "package": "lodash",
    "installed_version": "4.17.15", "fixed_version": "4.17.19", "raw": {},
}


def test_map_sca_produces_valid_vuln_finding_with_cve_and_package():
    ev = map_sca(SCA_ROW, _ctx(source="sca"))
    assert ev["class_uid"] == 2002
    vuln = ev["vulnerabilities"][0]
    assert vuln["cve"]["uid"] == "CVE-2020-8203"
    pkg = vuln["affected_packages"][0]
    assert pkg["name"] == "lodash"
    assert pkg["version"] == "4.17.15"
    assert pkg["fixed_in_version"] == "4.17.19"
    validate_ocsf(ev)


def test_map_sca_fingerprint_uses_cve_and_package():
    ev = map_sca(SCA_ROW, _ctx(source="sca"))
    assert len(ev["finding_info"]["uid"]) == 64
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -k sca -v`
Expected: FAIL — `ModuleNotFoundError: ...mappers.sca`.

- [ ] **Step 3: Implement the SCA mapper**

```python
# pencheff_api/services/security_lake/mappers/sca.py
from __future__ import annotations

from typing import Mapping

from ..primitives import (
    ACTIVITY_CREATE, ACTIVITY_UPDATE, CLASS_VULNERABILITY_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id, build_unmapped,
)


def map_sca(row: Mapping, ctx: LakeContext) -> dict:
    uid = fingerprint(
        org_id=ctx.org_id, asset_id=ctx.asset_id, source="sca",
        rule_or_cve=row.get("cve"), location=row.get("file_path") or "",
        package=row.get("package"),
    )
    finding_info = {
        "title": (row.get("title") or "Dependency vulnerability")[:500],
        "uid": uid,
        "desc": row.get("description") or "",
    }
    ev = base_event(
        class_uid=CLASS_VULNERABILITY_FINDING,
        activity_id=ACTIVITY_CREATE if ctx.is_new else ACTIVITY_UPDATE,
        ctx=ctx, finding_info=finding_info,
        sev_id=severity_id(row.get("severity")),
        stat_id=status_id(verification_status=None,
                          suppressed=bool(row.get("suppressed"))),
    )
    vuln: dict = {
        "title": finding_info["title"],
        "severity": (row.get("severity") or "medium"),
        "affected_packages": [{
            "name": row.get("package") or "",
            "version": row.get("installed_version") or "",
            "fixed_in_version": row.get("fixed_version"),
        }],
    }
    if row.get("cve"):
        vuln["cve"] = {"uid": row["cve"]}
    ev["vulnerabilities"] = [vuln]
    ev["unmapped"] = build_unmapped(scanner=row.get("scanner"))
    return ev
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -k sca -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/mappers/sca.py apps/api/tests/test_security_lake_mappers.py
git commit -m "feat(security-lake): SCA -> OCSF Vulnerability Finding mapper"
```

---

## Task 6: Secrets mapper → Detection Finding

**Files:**

- Create: `pencheff_api/services/security_lake/mappers/secrets.py`
- Test: `tests/test_security_lake_mappers.py` (append)

- [ ] **Step 1: Write the failing test (append)**

```python
# tests/test_security_lake_mappers.py  (append)
from pencheff_api.services.security_lake.mappers.secrets import map_secret

SECRET_ROW = {
    "scanner": "gitleaks", "rule_id": "aws-access-key", "severity": "high",
    "title": "AWS access key committed", "description": "Hardcoded AWS key",
    "file_path": "config/prod.env", "line_start": 4, "line_end": 4,
    "code_snippet": "AWS_KEY=AKIA...", "cve": None, "package": None,
    "installed_version": None, "fixed_version": None, "raw": {},
}


def test_map_secret_produces_valid_detection_finding():
    ev = map_secret(SECRET_ROW, _ctx(source="secret"))
    assert ev["class_uid"] == 2004
    assert ev["finding_info"]["title"] == "AWS access key committed"
    assert ev["unmapped"]["file_path"] == "config/prod.env"
    validate_ocsf(ev)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -k secret -v`
Expected: FAIL — `ModuleNotFoundError: ...mappers.secrets`.

- [ ] **Step 3: Implement the secrets mapper**

```python
# pencheff_api/services/security_lake/mappers/secrets.py
from __future__ import annotations

from typing import Mapping

from ..primitives import (
    ACTIVITY_CREATE, ACTIVITY_UPDATE, CLASS_DETECTION_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id, build_unmapped,
)


def map_secret(row: Mapping, ctx: LakeContext) -> dict:
    location = f"{row.get('file_path')}:{row.get('line_start')}"
    uid = fingerprint(
        org_id=ctx.org_id, asset_id=ctx.asset_id, source="secret",
        rule_or_cve=row.get("rule_id"), location=location,
    )
    finding_info = {
        "title": (row.get("title") or "Exposed secret")[:500],
        "uid": uid,
        "desc": row.get("description") or "",
    }
    ev = base_event(
        class_uid=CLASS_DETECTION_FINDING,
        activity_id=ACTIVITY_CREATE if ctx.is_new else ACTIVITY_UPDATE,
        ctx=ctx, finding_info=finding_info,
        sev_id=severity_id(row.get("severity")),
        stat_id=status_id(verification_status=None,
                          suppressed=bool(row.get("suppressed"))),
    )
    ev["unmapped"] = build_unmapped(
        scanner=row.get("scanner"), rule_id=row.get("rule_id"),
        file_path=row.get("file_path"), line=row.get("line_start"),
    )
    return ev
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -k secret -v`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/mappers/secrets.py apps/api/tests/test_security_lake_mappers.py
git commit -m "feat(security-lake): secrets -> OCSF Detection Finding mapper"
```

---

## Task 7: IaC mapper → Compliance Finding

**Files:**

- Create: `pencheff_api/services/security_lake/mappers/iac.py`
- Test: `tests/test_security_lake_mappers.py` (append)

- [ ] **Step 1: Write the failing test (append)**

```python
# tests/test_security_lake_mappers.py  (append)
from pencheff_api.services.security_lake.mappers.iac import map_iac

IAC_ROW = {
    "scanner": "checkov", "rule_id": "CKV_AWS_20", "severity": "medium",
    "title": "S3 bucket allows public read", "description": "Public ACL set",
    "file_path": "infra/s3.tf", "line_start": 1, "line_end": 8,
    "code_snippet": None, "cve": None, "package": None,
    "installed_version": None, "fixed_version": None, "raw": {},
}


def test_map_iac_produces_valid_compliance_finding():
    ev = map_iac(IAC_ROW, _ctx(source="iac"))
    assert ev["class_uid"] == 2003
    assert ev["compliance"]["control"] == "CKV_AWS_20"
    assert ev["compliance"]["status"] == "Failed"
    validate_ocsf(ev)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -k iac -v`
Expected: FAIL — `ModuleNotFoundError: ...mappers.iac`.

- [ ] **Step 3: Implement the IaC mapper**

```python
# pencheff_api/services/security_lake/mappers/iac.py
from __future__ import annotations

from typing import Mapping

from ..primitives import (
    ACTIVITY_CREATE, ACTIVITY_UPDATE, CLASS_COMPLIANCE_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id, build_unmapped,
)


def map_iac(row: Mapping, ctx: LakeContext) -> dict:
    uid = fingerprint(
        org_id=ctx.org_id, asset_id=ctx.asset_id, source="iac",
        rule_or_cve=row.get("rule_id"), location=row.get("file_path") or "",
    )
    finding_info = {
        "title": (row.get("title") or "IaC misconfiguration")[:500],
        "uid": uid,
        "desc": row.get("description") or "",
    }
    ev = base_event(
        class_uid=CLASS_COMPLIANCE_FINDING,
        activity_id=ACTIVITY_CREATE if ctx.is_new else ACTIVITY_UPDATE,
        ctx=ctx, finding_info=finding_info,
        sev_id=severity_id(row.get("severity")),
        stat_id=status_id(verification_status=None,
                          suppressed=bool(row.get("suppressed"))),
    )
    ev["compliance"] = {
        "control": row.get("rule_id") or "",
        "standards": [row.get("scanner") or "iac"],
        "status": "Failed",
        "status_id": 3,  # OCSF compliance status: Failed
    }
    ev["unmapped"] = build_unmapped(
        scanner=row.get("scanner"), file_path=row.get("file_path"),
    )
    return ev
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -k iac -v`
Expected: PASS (1 passed). If `compliance.status_id` enum differs in the vendored schema, set it to the schema's "Failed" value.

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/mappers/iac.py apps/api/tests/test_security_lake_mappers.py
git commit -m "feat(security-lake): IaC -> OCSF Compliance Finding mapper"
```

---

## Task 8: DAST mapper → Vulnerability Finding

**Files:**

- Create: `pencheff_api/services/security_lake/mappers/dast.py`
- Test: `tests/test_security_lake_mappers.py` (append)

Input is a `Finding` row (web/API). Tests use `SimpleNamespace` to mirror ORM attribute access; the mapper reads via `getattr`. Fields used: `severity, cvss_score, cvss_vector, title, category, cwe_id, owasp_category, endpoint, parameter, description, verification_status, suppressed, risk_score, epss, kev, ssvc_decision, reachability`.

- [ ] **Step 1: Write the failing test (append)**

```python
# tests/test_security_lake_mappers.py  (append)
from types import SimpleNamespace
from pencheff_api.services.security_lake.mappers.dast import map_dast


def _dast_row():
    return SimpleNamespace(
        severity="high", cvss_score=7.5, cvss_vector="AV:N/...",
        title="Reflected XSS", category="xss", cwe_id="CWE-79",
        owasp_category="A03", endpoint="/search", parameter="q",
        description="Reflected user input", verification_status="true_positive",
        suppressed=False, risk_score=72.0, epss=0.1, kev=False,
        ssvc_decision="attend", reachability="exploited",
    )


def test_map_dast_produces_valid_vuln_finding():
    ev = map_dast(_dast_row(), _ctx(source="dast"))
    assert ev["class_uid"] == 2002
    assert ev["severity_id"] == 4
    assert ev["status_id"] == 2  # true_positive -> In Progress
    assert ev["unmapped"]["reachability"] == "exploited"
    enr = {e["name"]: e["value"] for e in ev["enrichments"]}
    assert enr["epss"] == 0.1 and enr["kev"] is False
    validate_ocsf(ev)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -k dast -v`
Expected: FAIL — `ModuleNotFoundError: ...mappers.dast`.

- [ ] **Step 3: Implement the DAST mapper**

```python
# pencheff_api/services/security_lake/mappers/dast.py
from __future__ import annotations

from typing import Any

from ..primitives import (
    ACTIVITY_CREATE, ACTIVITY_UPDATE, CLASS_VULNERABILITY_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id,
    build_unmapped, build_enrichments,
)


def _g(row: Any, name: str):
    return getattr(row, name, None) if not isinstance(row, dict) else row.get(name)


def map_dast(row: Any, ctx: LakeContext) -> dict:
    endpoint, parameter = _g(row, "endpoint"), _g(row, "parameter")
    location = f"{endpoint}|{parameter}"
    uid = fingerprint(
        org_id=ctx.org_id, asset_id=ctx.asset_id, source="dast",
        rule_or_cve=_g(row, "category"), location=location,
    )
    finding_info = {
        "title": (_g(row, "title") or "Web finding")[:500],
        "uid": uid,
        "desc": _g(row, "description") or "",
    }
    ev = base_event(
        class_uid=CLASS_VULNERABILITY_FINDING,
        activity_id=ACTIVITY_CREATE if ctx.is_new else ACTIVITY_UPDATE,
        ctx=ctx, finding_info=finding_info,
        sev_id=severity_id(_g(row, "severity")),
        stat_id=status_id(verification_status=_g(row, "verification_status"),
                          suppressed=bool(_g(row, "suppressed"))),
    )
    vuln: dict = {"title": finding_info["title"],
                  "severity": (_g(row, "severity") or "medium")}
    if _g(row, "cvss_score") is not None:
        vuln["cvss"] = [{"base_score": _g(row, "cvss_score"),
                         "vector_string": _g(row, "cvss_vector")}]
    ev["vulnerabilities"] = [vuln]
    ev["enrichments"] = build_enrichments(epss=_g(row, "epss"), kev=_g(row, "kev"))
    ev["unmapped"] = build_unmapped(
        endpoint=endpoint, parameter=parameter, cwe=_g(row, "cwe_id"),
        owasp_category=_g(row, "owasp_category"),
        reachability=_g(row, "reachability"),
        risk_score=_g(row, "risk_score"),
        ssvc_decision=_g(row, "ssvc_decision"),
    )
    return ev
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -k dast -v`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/mappers/dast.py apps/api/tests/test_security_lake_mappers.py
git commit -m "feat(security-lake): DAST -> OCSF Vulnerability Finding mapper"
```

---

## Task 9: Runtime mapper → Detection Finding

**Files:**

- Create: `pencheff_api/services/security_lake/mappers/runtime.py`
- Test: `tests/test_security_lake_mappers.py` (append)

Input is a runtime-protection span (Sentry). Tests use a dict with keys `detection_type` (prompt_injection | pii_disclosure | tool_authz), `severity`, `title`, `description`, `span_id`, `trace_id`.

- [ ] **Step 1: Write the failing test (append)**

```python
# tests/test_security_lake_mappers.py  (append)
from pencheff_api.services.security_lake.mappers.runtime import map_runtime

RUNTIME_SPAN = {
    "detection_type": "prompt_injection", "severity": "critical",
    "title": "Indirect prompt injection blocked",
    "description": "Tool output contained an injected instruction.",
    "span_id": "s1", "trace_id": "t1",
}


def test_map_runtime_produces_valid_detection_finding():
    ev = map_runtime(RUNTIME_SPAN, _ctx(source="runtime"))
    assert ev["class_uid"] == 2004
    assert ev["severity_id"] == 5
    assert ev["unmapped"]["detection_type"] == "prompt_injection"
    assert ev["unmapped"]["trace_id"] == "t1"
    validate_ocsf(ev)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -k runtime -v`
Expected: FAIL — `ModuleNotFoundError: ...mappers.runtime`.

- [ ] **Step 3: Implement the runtime mapper**

```python
# pencheff_api/services/security_lake/mappers/runtime.py
from __future__ import annotations

from typing import Mapping

from ..primitives import (
    ACTIVITY_CREATE, CLASS_DETECTION_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id, build_unmapped,
)


def map_runtime(span: Mapping, ctx: LakeContext) -> dict:
    uid = fingerprint(
        org_id=ctx.org_id, asset_id=ctx.asset_id, source="runtime",
        rule_or_cve=span.get("detection_type"),
        location=span.get("span_id") or "",
    )
    finding_info = {
        "title": (span.get("title") or "Runtime detection")[:500],
        "uid": uid,
        "desc": span.get("description") or "",
    }
    ev = base_event(
        class_uid=CLASS_DETECTION_FINDING,
        activity_id=ACTIVITY_CREATE,
        ctx=ctx, finding_info=finding_info,
        sev_id=severity_id(span.get("severity")),
        stat_id=status_id(verification_status=None, suppressed=False),
    )
    ev["unmapped"] = build_unmapped(
        detection_type=span.get("detection_type"),
        span_id=span.get("span_id"), trace_id=span.get("trace_id"),
    )
    return ev
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -k runtime -v`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/mappers/runtime.py apps/api/tests/test_security_lake_mappers.py
git commit -m "feat(security-lake): runtime -> OCSF Detection Finding mapper"
```

---

## Task 10: Dispatcher + cross-source validation property test

**Files:**

- Create: `pencheff_api/services/security_lake/dispatch.py`
- Modify: `pencheff_api/services/security_lake/__init__.py` (re-export `map_finding`, `LakeContext`)
- Test: `tests/test_security_lake_mappers.py` (append)

- [ ] **Step 1: Write the failing test (append)**

```python
# tests/test_security_lake_mappers.py  (append)
import pytest
from pencheff_api.services.security_lake import map_finding


@pytest.mark.parametrize("source,row", [
    ("sast", SAST_ROW),
    ("sca", SCA_ROW),
    ("secret", SECRET_ROW),
    ("iac", IAC_ROW),
    ("dast", _dast_row()),
    ("runtime", RUNTIME_SPAN),
])
def test_every_source_dispatches_to_a_valid_ocsf_event(source, row):
    ev = map_finding(source, row, _ctx(source=source))
    validate_ocsf(ev)


def test_unknown_source_raises():
    with pytest.raises(ValueError):
        map_finding("nope", {}, _ctx())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && python -m pytest tests/test_security_lake_mappers.py -k dispatch -v`
Expected: FAIL — `ImportError: cannot import name 'map_finding'`.

- [ ] **Step 3: Implement the dispatcher**

```python
# pencheff_api/services/security_lake/dispatch.py
from __future__ import annotations

from typing import Any

from .primitives import LakeContext
from .mappers.sast import map_sast
from .mappers.sca import map_sca
from .mappers.secrets import map_secret
from .mappers.iac import map_iac
from .mappers.dast import map_dast
from .mappers.runtime import map_runtime

_DISPATCH = {
    "sast": map_sast,
    "sca": map_sca,
    "secret": map_secret,
    "iac": map_iac,
    "dast": map_dast,
    "runtime": map_runtime,
}


def map_finding(source: str, finding: Any, ctx: LakeContext) -> dict:
    """Route a finding to its source-specific OCSF mapper."""
    mapper = _DISPATCH.get((source or "").lower())
    if mapper is None:
        raise ValueError(f"unknown finding source: {source!r}")
    return mapper(finding, ctx)
```

```python
# pencheff_api/services/security_lake/__init__.py  (replace contents)
"""Pencheff Security Lake — OCSF 1.3.0 mapping & validation (pure, I/O-free)."""
from .validation import validate_ocsf, OCSFValidationError  # noqa: F401
from .primitives import LakeContext  # noqa: F401
from .dispatch import map_finding  # noqa: F401
```

- [ ] **Step 4: Run the full Slice 1 suite**

Run: `cd apps/api && python -m pytest tests/test_security_lake_validation.py tests/test_security_lake_primitives.py tests/test_security_lake_mappers.py -v`
Expected: PASS (all green, ~20 tests). This proves every Pencheff source maps to a schema-valid OCSF 1.3.0 event.

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/api/pencheff_api/services/security_lake/ apps/api/tests/test_security_lake_mappers.py
git commit -m "feat(security-lake): map_finding dispatcher + cross-source OCSF validation"
```

---

## Self-review (completed by plan author)

**Spec coverage (§2, §4):** All six sources mapped (SAST, SCA, secrets, IaC, DAST, runtime) → correct OCSF classes (2002/2003/2004) ✓. Strict validation against vendored OCSF 1.3.0 ✓. Fingerprint identity (§4) ✓. `unmapped` for Pencheff differentiators + `enrichments` for epss/kev ✓. Pinned OCSF version in `metadata` ✓. Slices 2–5 (Iceberg writer, ingestion, query API, tenancy, external access) are explicitly out of scope for this plan and get their own plans.

**Placeholder scan:** No TBD/TODO; every code step shows full code; every test step shows real assertions and the exact run command + expected result. The one external unknown (OCSF export URL) is bounded by an explicit success criterion, not left vague.

**Type consistency:** `LakeContext`, `base_event`, `severity_id`, `status_id`, `fingerprint`, `build_unmapped`, `build_enrichments`, `map_finding`, `validate_ocsf`/`OCSFValidationError` are defined once and used with identical signatures across all tasks. Class-uid constants (2002/2003/2004) consistent. Each mapper named `map_<source>` and registered in `_DISPATCH` under the same source key used in `LakeContext.source` and the parametrized test.

**Risk note for the executor:** Tasks 1, 3, and 4 carry a "if validation fails on a required field, read the vendored schema and adjust" instruction. This is intentional — the vendored OCSF schema, not this document, is the authority on required fields. Expect possible small shape adjustments in `vulnerabilities`/`affected_code`/`compliance` to satisfy the real 1.3.0 schema; the test makes any mismatch obvious and local.
