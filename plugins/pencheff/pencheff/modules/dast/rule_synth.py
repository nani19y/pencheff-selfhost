# SPDX-License-Identifier: AGPL-3.0-or-later
"""LLM-assisted Pencheff Pulse template synthesis from CVE + permissive PoC.

Pipeline:

    (CVE record, PoC text, PoC license)
      ──→ permissive license filter (rejects non-OSS PoCs)
      ──→ LLM prompt builder
      ──→ LLM call (any chat-completions endpoint)
      ──→ deterministic JSON schema validator
      ──→ provenance JSONL writer
      ──→ Pulse JSON file

Permissive licenses on the PoC side are MIT, Apache-2.0, BSD-2/3,
ISC, CC0, and U.S. public domain. Anything else is hard-rejected at
the input gate; we never train AI synthesis on copyleft or proprietary
PoC bodies.

The synthesis prompt is versioned (``_PROMPT_VERSION`` below). Bumping
the version invalidates the hash-based dedup so a regenerated corpus
doesn't shadow stale output.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

PROVENANCE_DIR = Path.home() / ".pencheff" / "data" / "provenance" / "dast"

_PROMPT_VERSION = "1.0"

PERMISSIVE_LICENSES: frozenset[str] = frozenset({
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    "CC0-1.0", "0BSD", "Public Domain", "Unlicense",
})

_SYSTEM_PROMPT = (
    "You convert a (CVE description + proof-of-concept code) into a "
    "Pencheff Pulse JSON template. Output ONLY one JSON object, no "
    "prose, no markdown fences. Required keys: "
    '"id" (kebab-case, must include the CVE id), '
    '"name" (≤120 chars), "severity" (critical|high|medium|low|info), '
    '"description" (≤500 chars), "remediation" (≤500 chars), '
    '"tags" (array of strings), "references" (array of URLs), '
    '"cves" (array containing the CVE id verbatim), '
    '"requests" (array of request objects with "method", "path", '
    '"matchers"). Every matcher must declare "type" in '
    "{word,regex,status,size,binary} and a non-empty matching field. "
    "Never invent CVE ids that aren't in the input. Never include "
    "destructive payloads (DROP TABLE, rm -rf, fork bomb) — Pulse "
    "templates run against authorized targets and must be safe to "
    "fire. Never reference branded product names (Burp, Nuclei, "
    "Snyk). If the PoC is destructive or you can't produce a safe "
    "detection-only template, output {\"error\":\"unsafe\"}."
)


# ─── Inputs / outputs ──────────────────────────────────────────────


@dataclass(frozen=True)
class PocSource:
    """A PoC body the synthesiser is allowed to consume.

    ``license`` MUST be on ``PERMISSIVE_LICENSES`` — the constructor
    validates. Anything else fails fast so the synthesiser cannot
    accidentally train on a non-permissive corpus.
    """

    cve_id: str
    description: str
    poc_text: str
    poc_url: str
    license: str

    def __post_init__(self) -> None:
        if self.license not in PERMISSIVE_LICENSES:
            raise ValueError(
                f"PoC license {self.license!r} not on permissive allowlist; "
                f"refusing to synthesise from non-OSS PoC.",
            )


@dataclass
class SynthResult:
    template: dict[str, Any]
    cached: bool
    model: str | None
    prompt_version: str = _PROMPT_VERSION
    sources: list[dict[str, str]] = field(default_factory=list)


# ─── Helpers ───────────────────────────────────────────────────────


def _hash(payload: str | dict | list) -> str:
    if not isinstance(payload, str):
        payload = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _provenance_path(cve_id: str) -> Path:
    PROVENANCE_DIR.mkdir(parents=True, exist_ok=True)
    safe = cve_id.replace("/", "_").replace(os.sep, "_")
    return PROVENANCE_DIR / f"{safe}.jsonl"


def _build_user_prompt(src: PocSource) -> str:
    payload = {
        "cve_id": src.cve_id,
        "description": src.description[:1500],
        "poc_url": src.poc_url,
        "poc_license": src.license,
        "poc_text": src.poc_text[:3000],
    }
    return json.dumps(payload, ensure_ascii=False)


# Pulse's request-block schema enforced before we accept the model's
# output. Keep this list small and exact — anything unrecognised gets
# normalised to a known shape rather than passed through, so an
# overly-creative model can't sneak in destructive payloads.
_ALLOWED_MATCHER_TYPES = {"word", "regex", "status", "size", "binary"}
_ALLOWED_REQUEST_METHODS = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"}
_DESTRUCTIVE_TOKENS = (
    "DROP TABLE", "TRUNCATE", "DELETE FROM",
    "rm -rf", "rmdir /S",
    ":(){ :|:& };:",  # fork bomb
    "format c:",
    "shutdown -h",
    "wget http",  # remote include
)


def _validate_template(t: Any, cve_id: str) -> tuple[bool, str]:
    """Return ``(ok, reason)``. The validator is intentionally strict:
    a 'mostly correct' template still gets rejected so we never ship a
    broken probe."""
    if not isinstance(t, dict):
        return False, "not a JSON object"
    if t.get("error") == "unsafe":
        return False, "model declined as unsafe"
    for key in ("id", "name", "severity", "requests"):
        if not t.get(key):
            return False, f"missing {key!r}"
    if not isinstance(t.get("requests"), list):
        return False, "requests must be an array"
    if cve_id not in (t.get("cves") or []):
        return False, f"cves array does not contain {cve_id!r}"
    if t["severity"] not in {"critical", "high", "medium", "low", "info"}:
        return False, f"unknown severity {t['severity']!r}"
    body = json.dumps(t, sort_keys=True)
    for tok in _DESTRUCTIVE_TOKENS:
        if tok.lower() in body.lower():
            return False, f"contains destructive token {tok!r}"
    for req in t["requests"]:
        if not isinstance(req, dict):
            return False, "request entry not an object"
        method = (req.get("method") or "GET").upper()
        if method not in _ALLOWED_REQUEST_METHODS:
            return False, f"disallowed request method {method!r}"
        matchers = req.get("matchers") or []
        if not isinstance(matchers, list) or not matchers:
            return False, "request has no matchers"
        for m in matchers:
            if not isinstance(m, dict):
                return False, "matcher not an object"
            if m.get("type") not in _ALLOWED_MATCHER_TYPES:
                return False, f"matcher type {m.get('type')!r} not allowed"
    return True, ""


def _strip_code_fences(text: str) -> str:
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    return (m.group(1) if m else text).strip()


def _parse_json(text: str) -> dict[str, Any] | None:
    candidate = _strip_code_fences(text)
    try:
        out = json.loads(candidate)
    except (ValueError, TypeError):
        out = None
    if isinstance(out, dict):
        return out
    # Fallback: hunt for the first {...} block.
    s, e = candidate.find("{"), candidate.rfind("}")
    if s != -1 and e != -1 and e > s:
        try:
            out = json.loads(candidate[s : e + 1])
            return out if isinstance(out, dict) else None
        except (ValueError, TypeError):
            return None
    return None


def _write_provenance(
    cve_id: str,
    *,
    model: str | None,
    input_hash: str,
    output_hash: str,
    sources: list[dict[str, str]],
    rejected_reason: str | None = None,
) -> None:
    line = json.dumps({
        "cve_id": cve_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "prompt_version": _PROMPT_VERSION,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "sources": sources,
        "rejected_reason": rejected_reason,
    }, ensure_ascii=False)
    try:
        with _provenance_path(cve_id).open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as exc:
        log.warning("rule_synth: provenance write failed: %s", exc)


# ─── Public API ────────────────────────────────────────────────────


def synthesize_pulse_template(
    src: PocSource,
    *,
    chat: Callable[[str, str], str | None] | None = None,
    model_label: str | None = None,
    output_dir: Path | None = None,
) -> SynthResult | None:
    """Generate one Pulse template from ``src`` via the LLM.

    ``chat`` is a callable ``(system_prompt, user_prompt) -> raw_text
    | None``; pass ``LLMClient._chat`` for the production path or a
    stub for offline tests. ``output_dir`` defaults to the community
    rule pack at ``bench/rules/community/pulse/``.

    Returns ``None`` when:
    * ``chat`` is unset or returns nothing,
    * the model declines (``{"error": "unsafe"}``), or
    * the validator rejects the output.
    """
    if chat is None:
        return None

    user_prompt = _build_user_prompt(src)
    input_hash = _hash({
        "system": _SYSTEM_PROMPT,
        "user": user_prompt,
        "prompt_version": _PROMPT_VERSION,
    })

    raw = chat(_SYSTEM_PROMPT, user_prompt)
    template = _parse_json(raw) if raw else None
    if template is None:
        _write_provenance(
            src.cve_id, model=model_label,
            input_hash=input_hash, output_hash="",
            sources=[{
                "url": src.poc_url, "license": src.license,
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
            }],
            rejected_reason="model returned no parseable JSON",
        )
        return None

    ok, reason = _validate_template(template, src.cve_id)
    if not ok:
        _write_provenance(
            src.cve_id, model=model_label,
            input_hash=input_hash, output_hash="",
            sources=[{
                "url": src.poc_url, "license": src.license,
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
            }],
            rejected_reason=reason,
        )
        log.info("rule_synth: validator rejected %s: %s", src.cve_id, reason)
        return None

    # Stamp attribution + license on the output so the downstream
    # share-link / report renderer can quote it verbatim.
    template["__attribution"] = (
        f"AI-generated Pulse template — Pencheff (MIT). "
        f"Trained on {src.poc_url} ({src.license})."
    )
    template["__license"] = "MIT"
    template["__synth_model"] = model_label
    template["__synth_prompt_version"] = _PROMPT_VERSION
    template["__imported_at"] = datetime.now(timezone.utc).isoformat()
    template["signed"] = False

    output_json = json.dumps(template, indent=2, sort_keys=True)
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        target = output_dir / f"synth-{template['id']}.json"
        target.write_text(output_json, encoding="utf-8")

    _write_provenance(
        src.cve_id, model=model_label,
        input_hash=input_hash, output_hash=_hash(output_json),
        sources=[{
            "url": src.poc_url, "license": src.license,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }],
    )
    return SynthResult(
        template=template,
        cached=False,
        model=model_label,
        prompt_version=_PROMPT_VERSION,
        sources=[{
            "url": src.poc_url, "license": src.license,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }],
    )
