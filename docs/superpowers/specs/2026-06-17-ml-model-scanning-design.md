# ML Model / Pipeline — Source-Aware Registration & Static Artifact Scanning

- **Date:** 2026-06-17
- **Status:** Draft design → awaiting approval
- **Series:** 4th AI target type (after MCP, RAG, Agent Memory). New wire kind `ml_model`. Mirrors the shipped per-type pattern (kind + Config + scanner module + consent + dispatch).

---

## 1. Goal

Turn the "ML Model / Pipeline" card (currently `kind="llm"`) into a first-class target that **statically** inspects a model artifact for the research-validated, high-impact attack class: **unsafe-deserialization arbitrary-code-execution on model load**, plus format-safety and known-vuln signals.

## 2. Safety principle (non-negotiable)

The scanner **MUST NEVER deserialize/load/execute** an untrusted model. All analysis is static byte/opcode/structure inspection (the ModelScan/picklescan approach). Loading a malicious pickle would RCE _our own scanner_ — the exact attack we detect.

## 3. Scope decisions

| Decision     | Choice                                                                                                                                                                                                |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Modeling     | New wire kind `ml_model` + `MlModelConfig` (no DB enum migration; `String(16)`).                                                                                                                      |
| Sources (v1) | `file_url` (fetch a model file by URL, bounded size), `huggingface` (owner/repo[+revision]), `local_path` (a path on the scanner host). (`inline_upload` deferred.)                                   |
| Analysis     | Static only — never load the model. Fetch (bounded) → inspect bytes/opcodes/structure.                                                                                                                |
| Coverage     | Pickle-opcode danger scan, format-safety classification, Keras-Lambda detection, known-vuln fingerprinting. Backdoors/poisoning/extraction = out of scope v1 (dynamic/undecidable statically — note). |

## 4. Architecture & data flow

```
Register (kind="ml_model", MlModelConfig.source_type)
  → Commission scan (consent: ml_fetch — download + static-inspect)
  → scan_runner dispatches kind="ml_model" → scan_ml_model (mirrors scan_mcp)
  → pencheff ml_scan orchestrator:
       fetch artifact (bounded, to a temp file; HF → resolve file list)
       → classify format (magic bytes, NOT extension)
       → per artifact:
          ├─ pickle-opcode scan (pickletools.genops; flag dangerous GLOBAL/STACK_GLOBAL/INST/REDUCE)
          ├─ format-safety classification (safetensors=safe; pickle/joblib/dill/cloudpickle=critical-risk)
          ├─ Keras Lambda-layer / embedded-code detection (.keras zip+config.json; .h5 HDF5 markers)
          └─ known-vuln fingerprint (Keras safe_mode CVEs, picklescan<0.0.31, framework versions)
  → Findings (OWASP LLM03/LLM04 + ml:* technique, CVSS, CWE-502) → DB → report
```

New engineering: the `ml_scan` module. **Pickle-opcode scanning is pure stdlib (`pickletools`, `zipfile`) — no torch/onnx/h5py deps, no model loading.**

## 5. Registration & config — `MlModelConfig`

```
kind: "ml_model"
source_type: "file_url" | "huggingface" | "local_path"
url: str | None            # file_url
hf_repo: str | None        # huggingface (owner/name)
hf_revision: str | None
local_path: str | None
format_hint: "auto" | "pickle" | "pytorch" | "safetensors" | "keras" | "h5" | "savedmodel" | "gguf" | "joblib" = "auto"
max_bytes: int = 524288000  # 500MB fetch cap
```

Auth (HF token / URL creds) → `kind_credentials_encrypted`. New FE `MlModelFormSection` (source_type picker). Validation: file_url→url; huggingface→hf_repo; local_path→local_path.

## 6. Scanner analyzers (all static; pure where possible)

### 6a. Pickle-opcode danger scan (the headline — pure `pickletools`)

Disassemble every pickle stream found (raw `.pkl`/`.bin`, and pickles INSIDE PyTorch zip archives / joblib) via `pickletools.genops` (NEVER unpickle). Flag `GLOBAL`/`STACK_GLOBAL`/`INST`/`OBJ`/`REDUCE` that reference dangerous callables: `os`, `subprocess`, `sys`, `builtins.eval`/`exec`/`compile`/`__import__`, `posix`, `socket`, `pty`, `runpy`, `nt`, `webbrowser`, `importlib`, etc. **Bypass-hardened (per JFrog CVEs):** route by CONTENT/magic-bytes not extension (CVE-2025-10155); scan ALL embedded pickles even if zip CRC is bad (CVE-2025-10156 — don't fail-stop); treat dangerous-module _submodule/subclass_ imports as dangerous, not merely suspicious (CVE-2025-10157); scan past the first `STOP`. → `ml:pickle-rce`, critical, LLM04, CWE-502.

### 6b. Format-safety classification

Identify format by magic bytes; classify: safetensors → safe (recommend); pickle/joblib/dill/cloudpickle/raw-torch → very-high-risk (flag even absent a dangerous opcode — the format itself is dangerous); ONNX/protobuf → lower. → `ml:unsafe-format`, sev by class, LLM03.

### 6c. Keras Lambda / embedded-code detection

`.keras` (zip) → parse `config.json` for `"class_name": "Lambda"` / embedded marshalled code; legacy `.h5`/HDF5 → flag (safe_mode not honored on H5); SavedModel → flag custom ops. Never execute. → `ml:keras-lambda`, critical, LLM04, CWE-502.

### 6d. Known-vuln fingerprinting (advisory list, refreshable)

Match detected framework/format versions against a pinned advisory list: Keras safe_mode bypasses (CVE-2025-1550/8747/9905/9906/49655), and (meta) warn if the target's own loading stack uses picklescan <0.0.31 (JFrog CVE-2025-10155/56/57). → `ml:known-vuln`, LLM03.

### 6e. Provenance / supply-chain signals (light)

HF source: flag missing model card / no safetensors variant / obvious typosquat of a popular repo name. → `ml:supply-chain`, medium, LLM03.

## 7. Attack catalog (research-validated, cited — §10)

| Attack                                            | Detection                      | Mapping / Source                                                                       |
| ------------------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------- |
| Pickle `__reduce__` RCE on load                   | 6a opcode scan                 | LLM04, CWE-502 · ModelScan/picklescan docs, JFrog HF-malware (baller423 reverse shell) |
| In-the-wild malicious HF models (nullifAI)        | 6a + 6b (scan despite evasion) | LLM03/LLM04 · ReversingLabs Feb-2025                                                   |
| Keras Lambda-layer code exec                      | 6c                             | LLM04, CWE-502 · CERT/CC VU#253266, CVE-2024-3660                                      |
| Keras safe_mode bypass (config/H5/torch fallback) | 6c + 6d                        | LLM04 · CVE-2025-1550/8747/9905/9906/49655, IEEE S&P 2026                              |
| Unsafe-format risk (pickle/joblib/dill)           | 6b                             | LLM03 · ModelScan format hierarchy                                                     |
| Scanner-bypass evasions (ext/CRC/subclass)        | 6a hardening                   | — · JFrog picklescan CVEs (design lessons)                                             |

Reference tools (mechanisms to mirror, not vendor): Protect AI **ModelScan** (byte-level, no-load), **picklescan** (`pickletools.genops` allow/deny), Trail of Bits **fickling**.

## 8. Consent & safety

Add `ml_model` to `KIND_REQUIRED_DISCLOSED_ACTIONS`: `ml_fetch` (download the artifact + static-inspect — always; no execution, so a single low-risk disclosure). No destructive tier (we never load). Default + only behavior is static. `start_scan` gate until the scanner ships.

## 9. Findings / profiles / FE / dispatch

Findings reuse the model + judge + reporting (OWASP-LLM + `ml:*` technique + CWE-502 + CVSS). Profiles: Quick = opcode + format only; Standard = + Keras/fingerprint; Deep = + provenance. FE: `MlModelFormSection`, consent vocab, list/detail/edit, badge. BE: TargetKind/`_KINDS_REQUIRING_CONFIG`/`MlModelConfig`/KindConfig union; consent; `scan_runner` `ml_model` dispatch (mirror mcp) + `_run_ml_scan`; pencheff `scan_ml_model` tool + `ml_scan` module; migration marker.

## 10. Sources (primary, verified 2026-06-17)

- Protect AI **ModelScan** model-serialization-attacks docs; **picklescan** (`scanner.py` opcode logic).
- **JFrog** — malicious HF models (silent backdoor / reverse shell); **picklescan CVE-2025-10155/56/57** (bypass lessons); Keras safe_mode bypass.
- **CERT/CC VU#253266 / CVE-2024-3660** — Keras Lambda layers.
- **CVE-2025-1550/8747/9905/9906/49655** — Keras safe_mode bypasses; **IEEE S&P 2026 / arXiv 2509.06703** (first safe_mode CVEs).
- **ReversingLabs** — nullifAI (Feb 2025).

## 11. Out of scope v1

Weight/architectural backdoors, training-data poisoning, model extraction, membership inference (dynamic / statically-undecidable — research thin); inline file upload UI; actually loading models (never).
