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
                    if '"Lambda"' in text:
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
