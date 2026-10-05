# ML Model — Plan 2: `ml_scan` Scanner Module (static, never-load)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Build the `plugins/pencheff` `ml_scan` module that **statically** inspects a model artifact for unsafe-deserialization RCE (pickle opcodes), unsafe-format risk, Keras Lambda code-exec, and known-vuln fingerprints — then exposes a `scan_ml_model` MCP tool. Dispatch wiring + FE = Plan 3.

**Architecture:** Mirror the SHIPPED `rag_scan` module shape: normalized `MlManifest`/`MlArtifact` dataclasses → **pure** analyzers returning `list[Finding]` → `fingerprint` via `advisories.yaml` → `MlStaticScanModule(BaseTestModule)` orchestrator → `scan_ml_model` `@mcp.tool()` in `server.py`. The fetcher (bounded download / HF resolve / local read) is best-effort/non-fatal like the rag connector.

**SAFETY (non-negotiable, repeated in every relevant task):** NEVER `pickle.load`/`unpickle`/`torch.load`/`load_model`/`import` the artifact. All inspection is byte/opcode/zip-structure only via `pickletools.genops`, `zipfile`, `json`, magic-byte sniffing. Loading a malicious model would RCE our own scanner — the exact attack we detect.

**Tech Stack:** Python 3.12, FastMCP, pytest (`cd plugins/pencheff && uv run pytest`). Pure stdlib for analysis: `pickletools`, `zipfile`, `json`, `struct`, `hashlib`, `io`. `httpx` (already a dep) for fetch. **No torch/onnx/h5py/tensorflow/keras deps.** **Branch:** `feat/ml-voice-scanning` (already checked out — NO worktree, NO branch switching).

**Reference (mirror these):** `plugins/pencheff/pencheff/modules/rag_scan/{module,manifest,fingerprint,static_analyzers,__init__}.py`; `advisories.yaml`; `scan_rag` tool in `pencheff/server.py:4215`; tests in `plugins/pencheff/tests/test_rag_*.py`. Finding/Severity: `from pencheff.core.findings import Finding`, `from pencheff.config import Severity`. Module base: `from pencheff.modules.base import BaseTestModule`. Spec: `docs/superpowers/specs/2026-06-17-ml-model-scanning-design.md`.

**Finding constructor fields used:** `title, severity, category, owasp_category, description, remediation, endpoint, cwe_id, references=[], metadata={"technique": "ml:...", ...}`.

---

## Task 1: `manifest.py` (dataclasses) + `format_detect.py` (magic-byte classifier)

**Files:** Create `plugins/pencheff/pencheff/modules/ml_scan/__init__.py` (start minimal, completed in Task 6), `manifest.py`, `format_detect.py`; Test `plugins/pencheff/tests/test_ml_format_detect.py`.

- [ ] **Step 1: Write failing test** `tests/test_ml_format_detect.py`:

```python
import struct
import zipfile
import io
from pencheff.modules.ml_scan.format_detect import detect_format


def test_detects_safetensors():
    # safetensors: 8-byte little-endian header length, then a JSON object
    header = b'{"__metadata__":{}}'
    blob = struct.pack("<Q", len(header)) + header
    assert detect_format(blob, "model.safetensors") == "safetensors"


def test_detects_pickle_proto2():
    import pickle
    blob = pickle.dumps({"a": 1})  # starts with \x80\x04 (proto) — sniffed as pickle
    assert detect_format(blob, "x.bin") == "pickle"


def test_detects_zip_pytorch():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", b"\x80\x04.")
    assert detect_format(buf.getvalue(), "model.pt") == "pytorch_zip"


def test_detects_hdf5():
    blob = b"\x89HDF\r\n\x1a\n" + b"\x00" * 16
    assert detect_format(blob, "model.h5") == "hdf5"


def test_detects_gguf():
    assert detect_format(b"GGUF\x00\x00\x00\x03rest", "m.gguf") == "gguf"


def test_unknown_falls_back_to_extension_hint_then_unknown():
    assert detect_format(b"random bytes here", "mystery.dat") == "unknown"
```

- [ ] **Step 2: Run, confirm FAIL** (`uv run pytest tests/test_ml_format_detect.py -q`).

- [ ] **Step 3: Implement.** `manifest.py`:

```python
# pencheff/modules/ml_scan/manifest.py
"""Normalized, source-agnostic view of an ML model target. The fetcher populates
these; pure analyzers consume ONLY these (no network, no model loading)."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MlArtifact:
    """One file belonging to a model. `data` holds raw bytes (already size-bounded).
    NEVER deserialized — only byte/opcode/zip inspection."""
    name: str                       # logical filename, e.g. "pytorch_model.bin"
    data: bytes                     # raw bytes (bounded by max_bytes upstream)
    fmt: str = "unknown"            # set by format_detect
    size: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MlManifest:
    source_type: str                # file_url | huggingface | local_path
    origin: str = ""                # url / hf_repo / path (for endpoint field)
    provider: str | None = None     # "huggingface" | None
    hf_repo: str | None = None
    artifacts: list[MlArtifact] = field(default_factory=list)
    fetch_errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
```

`format_detect.py`:

```python
# pencheff/modules/ml_scan/format_detect.py
"""Identify model file format by MAGIC BYTES (content), not extension.
Per JFrog CVE-2025-10155: extension-based routing is bypassable, so content wins.
Pure function — no I/O, no deserialization."""
from __future__ import annotations

import struct

_PICKLE_PROTO_OPCODES = {0x80}            # PROTO opcode (proto >= 2)
_PICKLE_PROTO0_FIRST = set(b"c(}]Kt.S\x8a")  # common proto-0/1 first opcodes


def _looks_like_safetensors(data: bytes) -> bool:
    if len(data) < 8:
        return False
    n = struct.unpack("<Q", data[:8])[0]
    # header length must be sane and point at a JSON object
    if not (0 < n <= len(data) - 8) or n > 100_000_000:
        return False
    head = data[8:8 + min(n, 64)].lstrip()
    return head[:1] == b"{"


def detect_format(data: bytes, name: str = "") -> str:
    """Return one of: safetensors, pytorch_zip, keras_zip, zip, pickle, hdf5,
    gguf, onnx, joblib, numpy, unknown. Content-first; extension only as a
    last-resort disambiguator."""
    if not data:
        return "unknown"
    # Zip-based containers (PyTorch .pt/.pth, .keras, generic zip)
    if data[:4] == b"PK\x03\x04":
        lname = name.lower()
        if lname.endswith(".keras"):
            return "keras_zip"
        # .pt/.pth and unknown zips → treat as pytorch_zip (we scan embedded pickles)
        return "pytorch_zip"
    if _looks_like_safetensors(data):
        return "safetensors"
    if data[:8] == b"\x89HDF\r\n\x1a\n":
        return "hdf5"
    if data[:4] == b"GGUF":
        return "gguf"
    if data[:6] == b"\x93NUMPY":
        return "numpy"
    # ONNX = protobuf; weak signal — only trust the extension here
    if name.lower().endswith(".onnx"):
        return "onnx"
    # Pickle: PROTO opcode (\x80) or a plausible proto-0 first opcode
    if data[0] in _PICKLE_PROTO_OPCODES:
        return "pickle"
    if data[0] in _PICKLE_PROTO0_FIRST:
        return "pickle"
    if name.lower().endswith((".joblib", ".pkl", ".pickle", ".bin")):
        # joblib files are zlib/pickle; default to pickle so opcode scan runs
        return "pickle"
    return "unknown"
```

Minimal `__init__.py` (extended in Task 6):

```python
from .manifest import MlArtifact, MlManifest
from .format_detect import detect_format
__all__ = ["MlArtifact", "MlManifest", "detect_format"]
```

- [ ] **Step 4: Run, confirm PASS** (6 tests).
- [ ] **Step 5: Commit** `feat(plugin): ml_scan manifest + magic-byte format detection`.

---

## Task 2: `pickle_scan.py` — pickletools opcode danger scan (THE HEADLINE)

**Files:** Create `pencheff/modules/ml_scan/pickle_scan.py`; Test `plugins/pencheff/tests/test_ml_pickle_scan.py`.

**SAFETY:** uses ONLY `pickletools.genops` (disassembler) — it NEVER unpickles. Do not call `pickle.loads`/`Unpickler` anywhere in this module.

- [ ] **Step 1: Write failing test** `tests/test_ml_pickle_scan.py`. (Tests build malicious pickles via `pickle.dumps` of a `__reduce__` object — **serialization does not execute**; only loading would. Safe.)

```python
import io
import os
import pickle
import zipfile

from pencheff.modules.ml_scan.pickle_scan import scan_pickle_bytes, scan_pickles_in_zip


class _Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


def test_flags_os_system_reduce_proto2():
    blob = pickle.dumps(_Evil(), protocol=2)   # GLOBAL form
    hits = scan_pickle_bytes(blob)
    assert any(h["module"] == "posix" or h["module"] == "os" or "system" in h["name"] for h in hits)
    assert any(h["reduce"] for h in hits)


def test_flags_stack_global_proto4():
    blob = pickle.dumps(_Evil(), protocol=4)   # STACK_GLOBAL form
    hits = scan_pickle_bytes(blob)
    assert hits, "STACK_GLOBAL dangerous import must be detected"


def test_benign_pickle_has_no_hits():
    blob = pickle.dumps({"weights": [1, 2, 3], "name": "ok"})
    assert scan_pickle_bytes(blob) == []


def test_submodule_of_dangerous_is_flagged():
    # CVE-2025-10157: subpackage import of a dangerous module must still flag
    # craft a GLOBAL referencing "os.path" "exists" — built manually
    # \x80\x02 c os.path \n exists \n \x85 R .   (proto-2 GLOBAL + REDUCE)
    blob = b"\x80\x02cos.path\nexists\n\x85R."
    hits = scan_pickle_bytes(blob)
    assert any(h["module"].startswith("os") for h in hits)


def test_scans_all_embedded_pickles_in_zip_even_bad_crc():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", pickle.dumps(_Evil(), protocol=2))
        z.writestr("archive/version", b"3")
    hits = scan_pickles_in_zip(buf.getvalue())
    assert any(h["entry"].endswith("data.pkl") for h in hits)


def test_scans_past_first_stop():
    # two concatenated pickles; danger is in the SECOND (after first STOP)
    benign = pickle.dumps({"a": 1})
    evil = pickle.dumps(_Evil(), protocol=2)
    hits = scan_pickle_bytes(benign + evil)
    assert hits, "must continue scanning past the first STOP opcode"
```

- [ ] **Step 2: Run, confirm FAIL.**

- [ ] **Step 3: Implement** `pickle_scan.py`:

```python
# pencheff/modules/ml_scan/pickle_scan.py
"""Static pickle-opcode danger scanner. Uses pickletools.genops ONLY (a
disassembler) — NEVER unpickles. Mirrors picklescan/ModelScan/fickling logic,
hardened against the JFrog picklescan bypass CVEs (2025-10155/56/57):
  * route by content not extension (handled in format_detect)
  * scan EVERY embedded pickle in a zip even if the CRC is bad (don't fail-stop)
  * treat sub-module / sub-package imports of a dangerous module as dangerous
  * keep scanning past the first STOP opcode (concatenated pickles)
"""
from __future__ import annotations

import io
import pickletools
import zipfile

# module -> dangerous names ("*" = the whole module is dangerous)
_DANGEROUS: dict[str, set[str]] = {
    "os": {"*"}, "posix": {"*"}, "nt": {"*"},
    "subprocess": {"*"}, "sys": {"*"}, "socket": {"*"},
    "shutil": {"*"}, "pty": {"*"}, "runpy": {"*"}, "webbrowser": {"*"},
    "ctypes": {"*"}, "multiprocessing": {"*"}, "asyncio": {"*"},
    "importlib": {"*"}, "imp": {"*"}, "code": {"*"}, "codeop": {"*"},
    "pickle": {"*"}, "_pickle": {"*"},
    "builtins": {"eval", "exec", "compile", "open", "__import__", "getattr",
                 "setattr", "breakpoint", "input", "globals", "vars"},
    "__builtin__": {"eval", "exec", "compile", "open", "__import__", "getattr",
                    "setattr", "breakpoint", "input", "globals", "vars"},
    "operator": {"attrgetter", "methodcaller", "itemgetter"},
    "functools": {"partial"},
}

_STRING_OPCODES = {  # opcodes that push a string (feed STACK_GLOBAL)
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
}
_REDUCE_OPCODES = {"REDUCE", "OBJ", "INST", "NEWOBJ", "NEWOBJ_EX", "BUILD"}


def _is_dangerous(module: str, name: str) -> bool:
    """True if `module` (or any dangerous parent package of it) marks `name`
    (or '*') dangerous. Prefix match implements CVE-2025-10157 hardening."""
    candidates = set()
    parts = module.split(".")
    for i in range(1, len(parts) + 1):
        candidates.add(".".join(parts[:i]))
    for cand in candidates:
        names = _DANGEROUS.get(cand)
        if names and ("*" in names or name in names):
            return True
    return False


def scan_pickle_bytes(data: bytes) -> list[dict]:
    """Disassemble `data` and return a hit dict per dangerous global reference.
    Robust: never raises on malformed input (returns what it found so far)."""
    hits: list[dict] = []
    recent_strings: list[str] = []   # for STACK_GLOBAL (module, name)
    saw_reduce = False
    try:
        for opcode, arg, _pos in pickletools.genops(data):
            nm = opcode.name
            if nm in _REDUCE_OPCODES:
                saw_reduce = True
            if nm in _STRING_OPCODES and isinstance(arg, str):
                recent_strings.append(arg)
                if len(recent_strings) > 2:
                    recent_strings.pop(0)
                continue
            module = name = None
            if nm in ("GLOBAL", "INST"):
                # genops gives "module name" (space-joined) for GLOBAL/INST
                if isinstance(arg, str) and " " in arg:
                    module, name = arg.split(" ", 1)
                elif isinstance(arg, str):
                    module, name = arg, ""
            elif nm == "STACK_GLOBAL":
                if len(recent_strings) >= 2:
                    module, name = recent_strings[-2], recent_strings[-1]
            if module is not None and _is_dangerous(module, name or ""):
                hits.append({"module": module, "name": name or "",
                             "opcode": nm, "reduce": False})
    except Exception:
        # malformed/truncated pickle — keep what we have (don't fail-stop)
        pass
    # annotate whether a REDUCE-family invocation appeared anywhere
    if saw_reduce:
        for h in hits:
            h["reduce"] = True
    return hits


def scan_pickles_in_zip(data: bytes) -> list[dict]:
    """Scan EVERY entry of a zip (PyTorch .pt/.pth, joblib) for embedded pickles,
    even if individual entries have a bad CRC (CVE-2025-10156: don't fail-stop)."""
    out: list[dict] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return out
    for info in zf.infolist():
        if info.is_dir():
            continue
        raw = b""
        try:
            raw = zf.read(info.filename)        # validates CRC
        except Exception:
            # bad CRC / corrupt entry — read raw bytes anyway and scan them
            try:
                with zf.open(info, "r") as fh:
                    raw = fh.read()
            except Exception:
                try:
                    raw = _read_raw_local(data, info)
                except Exception:
                    continue
        for h in scan_pickle_bytes(raw):
            h["entry"] = info.filename
            out.append(h)
    return out


def _read_raw_local(data: bytes, info: zipfile.ZipInfo) -> bytes:
    """Best-effort raw read of a stored (uncompressed) zip entry by offset,
    used only when the normal path raised. Returns b'' if it can't."""
    if info.compress_type != zipfile.ZIP_STORED:
        return b""
    start = info.header_offset
    if data[start:start + 4] != b"PK\x03\x04":
        return b""
    n_len = int.from_bytes(data[start + 26:start + 28], "little")
    e_len = int.from_bytes(data[start + 28:start + 30], "little")
    body = start + 30 + n_len + e_len
    return data[body:body + info.file_size]
```

- [ ] **Step 4: Run, confirm PASS** (6 tests). If `test_scans_past_first_stop` fails because `genops` stops at the first STOP, wrap the scan to re-enter genops on the remaining bytes: track the position after STOP and re-call `genops(data[pos:])` in a loop. Implement that fallback only if needed — `pickletools.genops` typically does continue, but verify; if it stops, add:

```python
    # (inside scan_pickle_bytes, replace the single genops loop with a resumable one)
    offset = 0
    while offset < len(data):
        last = offset
        try:
            for opcode, arg, pos in pickletools.genops(data[offset:]):
                last = offset + pos
                ...  # same body as above
                if opcode.name == "STOP":
                    break
        except Exception:
            break
        new = last + 1
        if new <= offset:
            break
        offset = new
```

- [ ] **Step 5: Commit** `feat(plugin): static pickle-opcode RCE scanner (genops, bypass-hardened)`.

---

## Task 3: `analyzers.py` — format-safety + Keras-Lambda + provenance (pure)

**Files:** Create `pencheff/modules/ml_scan/analyzers.py`; Test `plugins/pencheff/tests/test_ml_analyzers.py`.

- [ ] **Step 1: Write failing test** `tests/test_ml_analyzers.py`:

```python
import io
import json
import struct
import zipfile

from pencheff.modules.ml_scan.manifest import MlArtifact, MlManifest
from pencheff.modules.ml_scan.analyzers import (
    analyze_pickle_rce, analyze_format_safety, analyze_keras_lambda,
    analyze_provenance, run_all_static,
)


def _mf(*arts, source_type="file_url", origin="https://h/m", **kw):
    return MlManifest(source_type=source_type, origin=origin, artifacts=list(arts), **kw)


def test_pickle_format_is_flagged_even_without_dangerous_opcode():
    import pickle
    art = MlArtifact(name="m.pkl", data=pickle.dumps({"w": [1]}), fmt="pickle", size=10)
    fs = analyze_format_safety(_mf(art))
    assert any(f.metadata["technique"] == "ml:unsafe-format" for f in fs)


def test_safetensors_is_safe_no_finding():
    header = b'{"__metadata__":{}}'
    blob = struct.pack("<Q", len(header)) + header
    art = MlArtifact(name="m.safetensors", data=blob, fmt="safetensors", size=len(blob))
    assert analyze_format_safety(_mf(art)) == []


def test_pickle_rce_finding_from_dangerous_opcode():
    import os, pickle
    class E:
        def __reduce__(self): return (os.system, ("x",))
    art = MlArtifact(name="m.pkl", data=pickle.dumps(E()), fmt="pickle", size=10)
    fs = analyze_pickle_rce(_mf(art))
    assert fs and fs[0].metadata["technique"] == "ml:pickle-rce"
    assert fs[0].cwe_id == "CWE-502"


def test_keras_lambda_detected_in_keras_zip():
    cfg = {"config": {"layers": [{"class_name": "Lambda", "config": {}}]}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("config.json", json.dumps(cfg))
    art = MlArtifact(name="m.keras", data=buf.getvalue(), fmt="keras_zip", size=10)
    fs = analyze_keras_lambda(_mf(art))
    assert fs and fs[0].metadata["technique"] == "ml:keras-lambda"


def test_h5_is_flagged_as_keras_risk():
    art = MlArtifact(name="m.h5", data=b"\x89HDF\r\n\x1a\n" + b"\x00" * 8, fmt="hdf5", size=16)
    fs = analyze_keras_lambda(_mf(art))
    assert fs and fs[0].metadata["technique"] == "ml:keras-lambda"


def test_provenance_flags_hf_without_safetensors():
    import pickle
    art = MlArtifact(name="pytorch_model.bin", data=pickle.dumps({"w": 1}), fmt="pickle", size=10)
    mf = _mf(art, source_type="huggingface", origin="owner/model", provider="huggingface", hf_repo="owner/model")
    fs = analyze_provenance(mf)
    assert any(f.metadata["technique"] == "ml:supply-chain" for f in fs)


def test_run_all_static_aggregates():
    import os, pickle
    class E:
        def __reduce__(self): return (os.system, ("x",))
    art = MlArtifact(name="m.pkl", data=pickle.dumps(E()), fmt="pickle", size=10)
    fs = run_all_static(_mf(art))
    techniques = {f.metadata["technique"] for f in fs}
    assert "ml:pickle-rce" in techniques
    assert "ml:unsafe-format" in techniques
```

- [ ] **Step 2: Run, confirm FAIL.**

- [ ] **Step 3: Implement** `analyzers.py`:

```python
# pencheff/modules/ml_scan/analyzers.py
"""Pure static analyzers over an MlManifest. No network, no model loading;
fully unit-testable. Each analyze_* returns list[Finding]; run_all_static
aggregates them."""
from __future__ import annotations

import io
import json
import zipfile

from pencheff.config import Severity
from pencheff.core.findings import Finding

from .manifest import MlArtifact, MlManifest
from .pickle_scan import scan_pickle_bytes, scan_pickles_in_zip

# Format -> (severity, human label). safetensors/onnx/gguf/numpy = safe-ish.
_UNSAFE_FORMATS = {
    "pickle": (Severity.HIGH, "raw pickle"),
    "pytorch_zip": (Severity.HIGH, "PyTorch (zip-wrapped pickle)"),
    "joblib": (Severity.HIGH, "joblib (pickle-backed)"),
    "hdf5": (Severity.MEDIUM, "HDF5 / legacy Keras"),
    "keras_zip": (Severity.MEDIUM, "Keras v3 archive"),
}
_SAFE_FORMATS = {"safetensors", "gguf", "numpy", "onnx"}


def _pickle_streams(art: MlArtifact) -> list[dict]:
    if art.fmt in ("pytorch_zip", "keras_zip"):
        return scan_pickles_in_zip(art.data)
    if art.fmt in ("pickle", "joblib", "unknown"):
        return scan_pickle_bytes(art.data)
    return []


def analyze_pickle_rce(mf: MlManifest) -> list[Finding]:
    out: list[Finding] = []
    for art in mf.artifacts:
        hits = _pickle_streams(art)
        if not hits:
            continue
        refs = sorted({f"{h['module']}.{h['name']}".rstrip(".") for h in hits})
        entries = sorted({h.get("entry", art.name) for h in hits})
        out.append(Finding(
            title=f"Unsafe-deserialization RCE in model artifact {art.name!r}",
            severity=Severity.CRITICAL,
            category="ml_pickle_rce",
            owasp_category="LLM04",
            cwe_id="CWE-502",
            description=(
                f"The artifact {art.name!r} contains pickle opcodes that import "
                f"dangerous callables ({', '.join(refs)}). Loading this model with "
                "torch.load / pickle / joblib would execute attacker-controlled code "
                "(arbitrary command/code execution). Detected statically via opcode "
                "disassembly; the model was NEVER loaded."
            ),
            remediation=(
                "Do NOT load this artifact. Obtain the model in safetensors format, "
                "or rebuild it from a trusted source. If you must accept pickle-based "
                "weights, scan every artifact with a no-load opcode scanner and load "
                "only in a sandbox."
            ),
            endpoint=mf.origin or art.name,
            references=[
                "https://protectai.com/blog/announcing-modelscan",
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ],
            metadata={
                "technique": "ml:pickle-rce",
                "artifact": art.name,
                "entries": entries,
                "dangerous_refs": refs,
                "reduce_present": any(h.get("reduce") for h in hits),
            },
        ))
    return out


def analyze_format_safety(mf: MlManifest) -> list[Finding]:
    out: list[Finding] = []
    for art in mf.artifacts:
        if art.fmt in _SAFE_FORMATS:
            continue
        spec = _UNSAFE_FORMATS.get(art.fmt)
        if not spec:
            continue
        sev, label = spec
        out.append(Finding(
            title=f"Unsafe model format ({label}) in {art.name!r}",
            severity=sev,
            category="ml_unsafe_format",
            owasp_category="LLM03",
            cwe_id="CWE-502",
            description=(
                f"The artifact {art.name!r} uses the {label} format, which executes "
                "embedded code on load by design. Even absent a currently-detectable "
                "dangerous opcode, this format is inherently unsafe to load from an "
                "untrusted source."
            ),
            remediation=(
                "Prefer safetensors (no code execution on load). Convert or "
                "re-export the model; treat pickle/joblib/HDF5 artifacts from "
                "untrusted sources as hostile."
            ),
            endpoint=mf.origin or art.name,
            metadata={"technique": "ml:unsafe-format", "artifact": art.name, "format": art.fmt},
        ))
    return out


def analyze_keras_lambda(mf: MlManifest) -> list[Finding]:
    out: list[Finding] = []
    for art in mf.artifacts:
        flagged = False
        detail = ""
        if art.fmt == "keras_zip":
            try:
                zf = zipfile.ZipFile(io.BytesIO(art.data))
                names = [n for n in zf.namelist() if n.endswith("config.json") or n == "config.json"]
                for n in names:
                    try:
                        text = zf.read(n).decode("utf-8", "replace")
                    except Exception:
                        continue
                    if '"Lambda"' in text or '"class_name": "Lambda"' in text or '"function"' in text and "Lambda" in text:
                        flagged = True
                        detail = f"Lambda layer found in {n}"
                        break
            except Exception:
                pass
        elif art.fmt == "hdf5":
            flagged = True
            detail = "Legacy HDF5 Keras model — safe_mode is not honored on H5 load"
        if not flagged:
            continue
        out.append(Finding(
            title=f"Keras code-execution risk in {art.name!r}",
            severity=Severity.CRITICAL if art.fmt == "keras_zip" else Severity.HIGH,
            category="ml_keras_lambda",
            owasp_category="LLM04",
            cwe_id="CWE-502",
            description=(
                f"{detail}. Keras Lambda layers (and legacy H5 models) can carry "
                "marshalled Python that executes when the model is loaded "
                "(CVE-2024-3660 / VU#253266; safe_mode bypasses CVE-2025-1550 et al.)."
            ),
            remediation=(
                "Rebuild the model without Lambda layers, or load with safe_mode=True "
                "on a patched Keras and never from an untrusted source. Avoid legacy "
                "H5 for untrusted models."
            ),
            endpoint=mf.origin or art.name,
            references=["https://kb.cert.org/vuls/id/253266"],
            metadata={"technique": "ml:keras-lambda", "artifact": art.name, "format": art.fmt},
        ))
    return out


def analyze_provenance(mf: MlManifest) -> list[Finding]:
    """Light HF supply-chain signals: pickle-based weights with no safetensors variant."""
    if mf.source_type != "huggingface":
        return []
    fmts = {a.fmt for a in mf.artifacts}
    has_safetensors = "safetensors" in fmts
    has_unsafe = bool(fmts & set(_UNSAFE_FORMATS))
    if has_safetensors or not has_unsafe:
        return []
    return [Finding(
        title=f"HuggingFace model {mf.hf_repo!r} ships only unsafe-format weights",
        severity=Severity.MEDIUM,
        category="ml_supply_chain",
        owasp_category="LLM03",
        cwe_id="CWE-494",
        description=(
            f"The repo {mf.hf_repo!r} provides pickle/PyTorch weights but no "
            "safetensors variant, forcing consumers into an unsafe load path."
        ),
        remediation=(
            "Request or generate a safetensors variant; verify the publisher and "
            "model card before use."
        ),
        endpoint=mf.origin or (mf.hf_repo or ""),
        metadata={"technique": "ml:supply-chain", "formats": sorted(fmts)},
    )]


def run_all_static(mf: MlManifest) -> list[Finding]:
    out: list[Finding] = []
    out.extend(analyze_pickle_rce(mf))
    out.extend(analyze_format_safety(mf))
    out.extend(analyze_keras_lambda(mf))
    out.extend(analyze_provenance(mf))
    return out
```

- [ ] **Step 4: Run, confirm PASS** (7 tests).
- [ ] **Step 5: Commit** `feat(plugin): ml_scan static analyzers (format-safety, keras-lambda, provenance)`.

---

## Task 4: `fingerprint.py` + `advisories.yaml` (known-vuln, refreshable)

**Files:** Create `pencheff/modules/ml_scan/fingerprint.py`, `advisories.yaml`; Test `plugins/pencheff/tests/test_ml_fingerprint.py`.

- [ ] **Step 1: Write failing test** `tests/test_ml_fingerprint.py`:

```python
from pencheff.modules.ml_scan.manifest import MlArtifact, MlManifest
from pencheff.modules.ml_scan.fingerprint import fingerprint


def test_keras_h5_matches_safe_mode_advisory():
    art = MlArtifact(name="m.h5", data=b"\x89HDF\r\n\x1a\n", fmt="hdf5", size=8)
    mf = MlManifest(source_type="file_url", origin="https://h/m.h5", artifacts=[art])
    out = fingerprint(mf)
    assert any(f.metadata.get("technique") == "ml:known-vuln" for f in out)


def test_safetensors_matches_nothing():
    import struct
    blob = struct.pack("<Q", 2) + b"{}"
    art = MlArtifact(name="m.safetensors", data=blob, fmt="safetensors", size=len(blob))
    mf = MlManifest(source_type="file_url", origin="x", artifacts=[art])
    assert fingerprint(mf) == []
```

- [ ] **Step 2: Run, confirm FAIL.**

- [ ] **Step 3: Implement** `advisories.yaml` (format-gated, refreshable):

```yaml
# ml_scan known-vuln advisories. Matched by `format_match` (regex over artifact
# fmt). Refreshable; sources are dated/primary (spec 2026-06-17 §10).
- id: keras-safe-mode-bypass
  title: "Keras safe_mode bypass family (Lambda / H5 / torch fallback code exec)"
  format_match: "^(hdf5|keras_zip)$"
  severity: high
  cwe: CWE-502
  cve: "CVE-2025-1550"
  description: >
    Keras model loading has multiple safe_mode bypasses allowing arbitrary code
    execution via Lambda layers, legacy H5 deserialization, or torch-backend
    fallback (CVE-2025-1550 / 8747 / 9905 / 9906 / 49655). H5 does not honor
    safe_mode at all.
  remediation: >
    Upgrade Keras to a patched release, never load untrusted models, prefer
    safetensors, and avoid legacy H5.
  reference: "https://nvd.nist.gov/vuln/detail/CVE-2025-1550"
  cvss: 7.8
```

`fingerprint.py`:

```python
# pencheff/modules/ml_scan/fingerprint.py
"""Match an MlManifest's artifact formats against pinned ML known-vuln advisories
(refreshable advisories.yaml). Pure; no I/O beyond reading the bundled yaml."""
from __future__ import annotations

import re
from importlib.resources import files

import yaml

from pencheff.config import Severity
from pencheff.core.findings import Finding

from .manifest import MlManifest

_SEV = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}
_cache: list[dict] | None = None


def _load() -> list[dict]:
    global _cache
    if _cache is None:
        text = files("pencheff.modules.ml_scan").joinpath("advisories.yaml").read_text("utf-8")
        _cache = yaml.safe_load(text) or []
    return _cache


def fingerprint(mf: MlManifest) -> list[Finding]:
    fmts = {a.fmt for a in mf.artifacts}
    out: list[Finding] = []
    for adv in _load():
        pat = adv.get("format_match")
        if not pat or not any(re.search(pat, f) for f in fmts):
            continue
        out.append(Finding(
            title=adv["title"],
            severity=_SEV.get(adv.get("severity", "medium"), Severity.MEDIUM),
            category="ml_known_vuln",
            owasp_category="LLM03",
            cwe_id=adv.get("cwe"),
            description=adv["description"],
            remediation=adv["remediation"],
            endpoint=mf.origin or "",
            references=[adv["reference"]] if adv.get("reference") else [],
            metadata={"technique": "ml:known-vuln", "cve": adv.get("cve"), "cvss": adv.get("cvss")},
        ))
    return out
```

- [ ] **Step 4: Run, confirm PASS** (2 tests).
- [ ] **Step 5: Commit** `feat(plugin): ml_scan known-vuln fingerprinting + advisories`.

---

## Task 5: `fetcher.py` — bounded, best-effort artifact retrieval (no execution)

**Files:** Create `pencheff/modules/ml_scan/fetcher.py`; Test `plugins/pencheff/tests/test_ml_fetcher.py`.

**SAFETY:** the fetcher only downloads/reads BYTES into `MlArtifact.data` (bounded by `max_bytes`) and calls `detect_format`. It NEVER loads/deserializes. All network is best-effort/non-fatal (errors → `mf.fetch_errors`).

- [ ] **Step 1: Write failing test** `tests/test_ml_fetcher.py`:

```python
import asyncio
import os
import pickle
import struct

from pencheff.modules.ml_scan.fetcher import build_manifest


def test_local_path_reads_and_detects(tmp_path):
    p = tmp_path / "m.pkl"
    p.write_bytes(pickle.dumps({"w": [1, 2]}))
    cfg = {"kind": "ml_model", "source_type": "local_path", "local_path": str(p)}
    mf = asyncio.run(build_manifest(cfg))
    assert mf.source_type == "local_path"
    assert len(mf.artifacts) == 1
    assert mf.artifacts[0].fmt == "pickle"
    assert mf.artifacts[0].size > 0


def test_local_path_enforces_max_bytes(tmp_path):
    p = tmp_path / "big.bin"
    p.write_bytes(b"\x80\x04" + b"\x00" * 5000)
    cfg = {"kind": "ml_model", "source_type": "local_path", "local_path": str(p), "max_bytes": 1000}
    mf = asyncio.run(build_manifest(cfg))
    # bounded read: artifact data must not exceed max_bytes
    assert mf.artifacts[0].size <= 1000


def test_missing_local_path_records_error_non_fatal(tmp_path):
    cfg = {"kind": "ml_model", "source_type": "local_path", "local_path": str(tmp_path / "nope.pkl")}
    mf = asyncio.run(build_manifest(cfg))
    assert mf.artifacts == []
    assert mf.fetch_errors


def test_safetensors_detected_from_local(tmp_path):
    header = b'{"__metadata__":{}}'
    blob = struct.pack("<Q", len(header)) + header
    p = tmp_path / "m.safetensors"
    p.write_bytes(blob)
    cfg = {"kind": "ml_model", "source_type": "local_path", "local_path": str(p)}
    mf = asyncio.run(build_manifest(cfg))
    assert mf.artifacts[0].fmt == "safetensors"
```

- [ ] **Step 2: Run, confirm FAIL.**

- [ ] **Step 3: Implement** `fetcher.py`:

```python
# pencheff/modules/ml_scan/fetcher.py
"""Bounded, best-effort retrieval of model artifacts into an MlManifest.
NEVER deserializes — only reads bytes and classifies by magic. Network/file
errors are non-fatal (recorded in mf.fetch_errors)."""
from __future__ import annotations

import logging
import os

import httpx

from .format_detect import detect_format
from .manifest import MlArtifact, MlManifest

log = logging.getLogger("pencheff.modules.ml_scan.fetcher")

_DEFAULT_MAX = 524_288_000          # 500 MB
_HF_API = "https://huggingface.co/api/models/{repo}"
_HF_FILE = "https://huggingface.co/{repo}/resolve/{rev}/{path}"
# HF filenames worth fetching for static inspection (skip giant safe shards if huge)
_INTERESTING = (".pkl", ".pickle", ".bin", ".pt", ".pth", ".ckpt", ".h5",
                ".keras", ".joblib", ".safetensors", ".gguf", ".onnx", ".npy")


def _bounded(data: bytes, max_bytes: int) -> bytes:
    return data[:max_bytes] if max_bytes and len(data) > max_bytes else data


async def build_manifest(cfg: dict) -> MlManifest:
    st = cfg.get("source_type")
    max_bytes = int(cfg.get("max_bytes") or _DEFAULT_MAX)
    if st == "local_path":
        return _from_local(cfg, max_bytes)
    if st == "file_url":
        return await _from_url(cfg, max_bytes)
    if st == "huggingface":
        return await _from_hf(cfg, max_bytes)
    mf = MlManifest(source_type=str(st), origin="")
    mf.fetch_errors.append(f"unsupported source_type {st!r}")
    return mf


def _from_local(cfg: dict, max_bytes: int) -> MlManifest:
    path = cfg.get("local_path") or ""
    mf = MlManifest(source_type="local_path", origin=path)
    try:
        with open(path, "rb") as fh:
            data = _bounded(fh.read(max_bytes + 1), max_bytes)
        name = os.path.basename(path) or "artifact"
        mf.artifacts.append(MlArtifact(name=name, data=data,
                                       fmt=detect_format(data, name), size=len(data)))
    except Exception as e:
        mf.fetch_errors.append(f"local read failed: {e}")
    return mf


async def _from_url(cfg: dict, max_bytes: int) -> MlManifest:
    url = cfg.get("url") or ""
    mf = MlManifest(source_type="file_url", origin=url)
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            data = await _get_bounded(client, url, max_bytes, cfg)
        name = url.rsplit("/", 1)[-1].split("?")[0] or "artifact"
        mf.artifacts.append(MlArtifact(name=name, data=data,
                                       fmt=detect_format(data, name), size=len(data)))
    except Exception as e:
        mf.fetch_errors.append(f"url fetch failed: {e}")
    return mf


async def _from_hf(cfg: dict, max_bytes: int) -> MlManifest:
    repo = cfg.get("hf_repo") or ""
    rev = cfg.get("hf_revision") or "main"
    mf = MlManifest(source_type="huggingface", origin=repo, provider="huggingface", hf_repo=repo)
    headers = {}
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            meta = await client.get(_HF_API.format(repo=repo), headers=headers)
            meta.raise_for_status()
            siblings = [s.get("rfilename", "") for s in (meta.json().get("siblings") or [])]
            wanted = [f for f in siblings if f.lower().endswith(_INTERESTING)]
            mf.metadata["card_present"] = any(s.lower() == "readme.md" for s in siblings)
            for path in wanted[:20]:   # bound artifact count
                url = _HF_FILE.format(repo=repo, rev=rev, path=path)
                try:
                    data = await _get_bounded(client, url, max_bytes, cfg)
                    mf.artifacts.append(MlArtifact(name=path, data=data,
                                                   fmt=detect_format(data, path), size=len(data)))
                except Exception as e:
                    mf.fetch_errors.append(f"hf file {path} failed: {e}")
    except Exception as e:
        mf.fetch_errors.append(f"hf resolve failed: {e}")
    return mf


async def _get_bounded(client: httpx.AsyncClient, url: str, max_bytes: int, cfg: dict) -> bytes:
    """Stream up to max_bytes+1 then truncate, so we never buffer an unbounded body."""
    chunks: list[bytes] = []
    total = 0
    async with client.stream("GET", url) as resp:
        resp.raise_for_status()
        async for chunk in resp.aiter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                break
    return _bounded(b"".join(chunks), max_bytes)
```

- [ ] **Step 4: Run, confirm PASS** (4 tests). (These tests only exercise the local path — no network needed.)
- [ ] **Step 5: Commit** `feat(plugin): ml_scan bounded best-effort fetcher (no model loading)`.

---

## Task 6: `module.py` orchestrator + finalize `__init__.py`

**Files:** Create `pencheff/modules/ml_scan/module.py`; overwrite `__init__.py`; Test `plugins/pencheff/tests/test_ml_scan_module.py`.

- [ ] **Step 1: Write failing test** `tests/test_ml_scan_module.py`:

```python
import asyncio
import os
import pickle

from pencheff.core.session import create_session
from pencheff.modules.ml_scan.manifest import MlArtifact, MlManifest
from pencheff.modules.ml_scan.module import MlStaticScanModule


def test_module_runs_static_on_injected_manifest(monkeypatch):
    class _E:
        def __reduce__(self): return (os.system, ("x",))
    art = MlArtifact(name="m.pkl", data=pickle.dumps(_E()), fmt="pickle", size=10)
    mf = MlManifest(source_type="file_url", origin="https://h/m.pkl", artifacts=[art])

    async def _fake_build(cfg): return mf
    monkeypatch.setattr("pencheff.modules.ml_scan.module.build_manifest", _fake_build)

    sess = create_session(target_url="https://h/m.pkl", depth="quick")
    findings = asyncio.run(MlStaticScanModule().run(sess, http=None, config={
        "ml_config": {"kind": "ml_model", "source_type": "file_url", "url": "https://h/m.pkl"},
    }))
    techniques = {f.metadata["technique"] for f in findings}
    assert "ml:pickle-rce" in techniques
    assert MlStaticScanModule().get_techniques()


def test_module_non_fatal_on_fetch_error(monkeypatch):
    mf = MlManifest(source_type="file_url", origin="x")
    mf.fetch_errors.append("boom")

    async def _fake_build(cfg): return mf
    monkeypatch.setattr("pencheff.modules.ml_scan.module.build_manifest", _fake_build)
    sess = create_session(target_url="x", depth="quick")
    findings = asyncio.run(MlStaticScanModule().run(sess, http=None, config={
        "ml_config": {"kind": "ml_model", "source_type": "file_url", "url": "x"},
    }))
    assert isinstance(findings, list)   # no artifacts → no crash
```

- [ ] **Step 2: Run, confirm FAIL.**

- [ ] **Step 3: Implement** `module.py`:

```python
# pencheff/modules/ml_scan/module.py
"""Static ML-model scan module: fetch (bounded, never load) → classify →
pure static analyzers + known-vuln fingerprint. Mirrors RagStaticScanModule."""
from __future__ import annotations

from pencheff.core.findings import Finding
from pencheff.modules.base import BaseTestModule

from .analyzers import run_all_static
from .fetcher import build_manifest
from .fingerprint import fingerprint


class MlStaticScanModule(BaseTestModule):
    name = "ml_static_scan"
    category = "ML Model Security"
    owasp_categories = ["LLM03", "LLM04"]
    description = (
        "Statically inspect a model artifact (pickle opcodes, format safety, "
        "Keras Lambda, known vulns) WITHOUT ever loading or deserializing it."
    )

    async def run(self, session, http=None, targets=None, config=None) -> list[Finding]:
        cfg = (config or {}).get("ml_config") or {}
        try:
            manifest = await build_manifest(cfg)
        except Exception:
            return []
        findings = run_all_static(manifest)
        findings.extend(fingerprint(manifest))
        if manifest.fetch_errors:
            for f in findings:
                f.metadata = {**(f.metadata or {}), "fetch_errors": manifest.fetch_errors}
        return findings

    def get_techniques(self) -> list[str]:
        return [
            "ml:pickle-rce",
            "ml:unsafe-format",
            "ml:keras-lambda",
            "ml:known-vuln",
            "ml:supply-chain",
        ]
```

Overwrite `__init__.py`:

```python
from .manifest import MlArtifact, MlManifest
from .format_detect import detect_format
from .module import MlStaticScanModule
from . import pickle_scan
from . import analyzers
from . import fingerprint
from . import fetcher
__all__ = ["MlArtifact", "MlManifest", "detect_format", "MlStaticScanModule",
           "pickle_scan", "analyzers", "fingerprint", "fetcher"]
```

- [ ] **Step 4: Run, confirm PASS** (2 tests).
- [ ] **Step 5: Commit** `feat(plugin): ml_scan orchestrator module + package exports`.

---

## Task 7: `scan_ml_model` MCP tool + broad regression

**Files:** Modify `plugins/pencheff/pencheff/server.py` (add tool after `scan_rag`, ~line 4243); Test `plugins/pencheff/tests/test_ml_plugin.py`.

- [ ] **Step 1: Write failing test** `tests/test_ml_plugin.py` (mirror `test_rag_plugin.py`):

```python
import asyncio
import os
import pickle

import pencheff.server as server


def test_scan_ml_model_tool_registers_findings(monkeypatch):
    class _E:
        def __reduce__(self): return (os.system, ("x",))
    from pencheff.modules.ml_scan.manifest import MlArtifact, MlManifest
    art = MlArtifact(name="m.pkl", data=pickle.dumps(_E()), fmt="pickle", size=10)
    mf = MlManifest(source_type="file_url", origin="https://h/m.pkl", artifacts=[art])

    async def _fake_build(cfg): return mf
    monkeypatch.setattr("pencheff.modules.ml_scan.module.build_manifest", _fake_build)

    sid = "ml-test-session"
    server.SESSIONS[sid] = server.create_session(target_url="https://h/m.pkl", depth="quick")
    fn = server.scan_ml_model.fn if hasattr(server.scan_ml_model, "fn") else server.scan_ml_model
    res = asyncio.run(fn(sid, {"kind": "ml_model", "source_type": "file_url", "url": "https://h/m.pkl"}))
    assert res["new_findings"] >= 1
    assert res["total_findings"] >= 1
```

(If `server.SESSIONS`/`server.create_session` names differ, read how `test_rag_plugin.py` constructs the session and copy that exactly.)

- [ ] **Step 2: Run, confirm FAIL.**

- [ ] **Step 3: Implement** — add after `scan_rag` in `server.py`:

```python
@mcp.tool()
async def scan_ml_model(session_id: str, ml_config: dict | None = None) -> dict[str, Any]:
    """Statically scan an ML model artifact for unsafe-deserialization RCE
    (pickle opcodes), unsafe-format risk, Keras Lambda code-exec, and known vulns.
    The model is NEVER loaded or deserialized — analysis is byte/opcode/zip only.

    ml_config is the target's MlModelConfig dict (kind="ml_model", source_type,
    url/hf_repo/local_path, ...). Returns the standard scan_* shape.
    """
    session = _require_session(session_id)
    cfg = ml_config or (session.llm_config if isinstance(session.llm_config, dict)
                        and session.llm_config.get("kind") == "ml_model" else None)
    if not cfg:
        raise ValueError("scan_ml_model requires ml_config (the target's MlModelConfig).")
    from pencheff.modules.ml_scan.module import MlStaticScanModule
    session.discovered.running_module = "scan_ml_model"
    try:
        findings = await MlStaticScanModule().run(session, http=None, config={"ml_config": cfg})
    finally:
        session.discovered.running_module = None
    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_ml_model")
    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": ["Review ML findings; the model was never loaded. Prefer safetensors for flagged artifacts."],
    }
```

- [ ] **Step 4: Run, confirm PASS.**
- [ ] **Step 5: Broad regression** — `cd plugins/pencheff && uv run pytest tests/ -q -k "ml or rag or mcp or smoke or sentry"` → all green; and `uv run python -c "import pencheff.server; print('server ok')"`.
- [ ] **Step 6: Commit** `feat(plugin): scan_ml_model MCP tool (static, never-load)`.

---

## Self-review

**Spec coverage (§6 analyzers):** 6a pickle-opcode (T2, bypass-hardened) ✓; 6b format-safety (T3) ✓; 6c Keras Lambda/H5 (T3) ✓; 6d known-vuln fingerprint (T4) ✓; 6e provenance (T3) ✓. Fetch (§4) = T5 bounded, never-load ✓. Tool + orchestration (§9) = T6/T7 ✓.
**SAFETY invariant:** no `pickle.load`/`Unpickler`/`torch.load`/`load_model`/`__import__` of artifact bytes anywhere — only `pickletools.genops`, `zipfile`, `json`, magic bytes. ✓
**Type consistency:** `MlManifest`/`MlArtifact` fields (name/data/fmt/size, source_type/origin/provider/hf_repo/artifacts/fetch_errors/metadata) used identically across fetcher/analyzers/fingerprint/module. Technique ids `ml:pickle-rce|unsafe-format|keras-lambda|known-vuln|supply-chain` consistent across analyzers + `get_techniques`. Tool name `scan_ml_model`, config key `ml_config`. CWE-502 on RCE/format/keras; CWE-494 on supply-chain.
**Dispatch + FE deferred to Plan 3** (scan_runner ml_model branch, 409-gate removal, migration marker, MlModelFormSection).
