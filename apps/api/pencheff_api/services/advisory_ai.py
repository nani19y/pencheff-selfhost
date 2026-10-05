# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-advisory AI enrichment with provenance.

Wraps the existing ``LLMClient`` to produce an exploit walkthrough and
fix recipe for a given advisory. Two guarantees:

1. **Provenance-logged.** Every AI-generated row writes a JSONL entry
   to ``~/.pencheff/data/provenance/<advisory_id>.jsonl`` recording
   the input source URLs (with their licenses), retrieval timestamp,
   model id, prompt hash, and output hash. This is the audit trail
   that lets us answer "where did this walkthrough come from?" if a
   downstream user questions a generated fix.

2. **Cached by content hash.** A SQLite cache (
   ``ai_advisory_cache`` in the existing CVE feed db) keys on
   ``advisory_id`` + ``input_hash`` so the same advisory body never
   re-bills the LLM. Bumping the prompt template invalidates by
   changing the hash automatically.

Inputs are pulled from the bulk-advisory cache populated by Phase 1.1b
``OsvBulkSource``, the per-CVE ``CveFeed.enrich``, and the on-demand
``CveFeed.nvd_enrich``. Only permissively-licensed feeds are read —
the licensing engineer's audit (see ``CONTRIBUTING.md``) is enforced
upstream.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .llm import LLMClient, _parse_json_object, get_client

log = logging.getLogger(__name__)

PROVENANCE_DIR = Path.home() / ".pencheff" / "data" / "provenance"

_PROMPT_VERSION = "1.0"
_SYSTEM_PROMPT = (
    "You are a senior application-security engineer producing concise, "
    "factual advisory enrichment for a vulnerability dashboard. Output "
    "ONLY a single JSON object with keys: "
    '"exploit_walkthrough" (≤300 words, plain prose, technical), '
    '"fix_recipe" (≤200 words, ordered steps), '
    '"reachability_signals" (array of short strings, ≤6 entries — '
    'function names / config tokens / call patterns to grep for), '
    '"references" (array of URLs from the input, never invented). '
    "Never mention companies' branding (Snyk / Burp / Checkmarx / "
    "Veracode / Promptfoo). Never echo the prompt. Never hallucinate "
    "a CVE id that's not in the input."
)


@dataclass
class AdvisoryEnrichment:
    advisory_id: str
    exploit_walkthrough: str
    fix_recipe: str
    reachability_signals: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    model: str | None = None
    prompt_version: str = _PROMPT_VERSION
    cached: bool = False


@dataclass
class _ProvenanceRecord:
    """Per-output provenance row, persisted as a JSONL entry."""

    advisory_id: str
    generated_at: str
    model: str | None
    prompt_version: str
    input_hash: str
    output_hash: str
    sources: list[dict[str, str]]  # [{url, license, retrieved_at}]


def _provenance_path(advisory_id: str) -> Path:
    PROVENANCE_DIR.mkdir(parents=True, exist_ok=True)
    safe = advisory_id.replace("/", "_").replace(os.sep, "_")
    return PROVENANCE_DIR / f"{safe}.jsonl"


def _hash(payload: str | dict | list) -> str:
    if not isinstance(payload, str):
        payload = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _ensure_cache_table(conn) -> None:
    """The ``ai_advisory_cache`` lives in the CVE-feed SQLite db so it
    inherits the same TTL / cleanup story as the rest of the cache."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ai_advisory_cache ("
        "advisory_id TEXT NOT NULL, "
        "input_hash TEXT NOT NULL, "
        "output_json TEXT, "
        "model TEXT, "
        "prompt_version TEXT, "
        "generated_at TEXT, "
        "PRIMARY KEY (advisory_id, input_hash))"
    )
    conn.commit()


def _build_user_prompt(
    advisory_id: str, advisory: dict[str, Any], extras: dict[str, Any] | None,
) -> str:
    """Render the input advisory into a compact prompt the LLM can chew on."""
    payload = {
        "advisory_id": advisory_id,
        "summary": advisory.get("summary", "")[:500],
        "details": (advisory.get("details") or "")[:2500],
        "affected": advisory.get("affected", [])[:5],
        "severity": advisory.get("severity", []),
        "references": [
            r.get("url") for r in (advisory.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ][:6],
    }
    if extras:
        # ``extras`` carries per-CVE NVD enrichment (CWE list, CPE
        # URIs, NVD CVSS) when available; pass through verbatim.
        payload["nvd"] = {
            k: extras.get(k) for k in (
                "cwe_ids", "cpe_uris", "nvd_cvss_score",
                "nvd_cvss_severity", "primary_url", "description",
            )
        }
    return json.dumps(payload, ensure_ascii=False)


def _parse_output(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    obj = _parse_json_object(raw)
    if not isinstance(obj, dict):
        return None
    # Normalize the keys + types so a flaky model doesn't break callers.
    out: dict[str, Any] = {
        "exploit_walkthrough": str(obj.get("exploit_walkthrough") or "")[:3000],
        "fix_recipe": str(obj.get("fix_recipe") or "")[:2000],
        "reachability_signals": [
            str(s)[:120] for s in (obj.get("reachability_signals") or [])
            if s
        ][:6],
        "references": [
            str(u)[:500] for u in (obj.get("references") or [])
            if isinstance(u, str)
        ][:8],
    }
    return out


def _write_provenance(
    record: _ProvenanceRecord,
) -> None:
    path = _provenance_path(record.advisory_id)
    line = json.dumps({
        "advisory_id": record.advisory_id,
        "generated_at": record.generated_at,
        "model": record.model,
        "prompt_version": record.prompt_version,
        "input_hash": record.input_hash,
        "output_hash": record.output_hash,
        "sources": record.sources,
    }, ensure_ascii=False)
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def explain_advisory(
    *,
    advisory_id: str,
    advisory: dict[str, Any],
    sources: list[dict[str, str]],
    nvd_extras: dict[str, Any] | None = None,
    cve_feed=None,
    client: LLMClient | None = None,
) -> AdvisoryEnrichment | None:
    """Return AI enrichment for ``advisory_id``, cached when possible.

    ``sources`` is the provenance trail for ``advisory`` — a list of
    ``{url, license, retrieved_at}`` dicts naming where the input
    came from (e.g. OSV, NVD, RustSec, GoVulnDB). Recorded verbatim
    in the per-output JSONL.

    Returns ``None`` when the LLM is disabled / rate-limited and no
    cached row exists.
    """
    # Deliberately stays on Pencheff's default LLM (get_client()), NOT an org's
    # BYO custom provider. Advisory enrichment is a globally shared resource:
    # the result is cached by (advisory_id, input_hash) in a single shared CVE
    # cache and reused across every org. Routing it through one org's BYO key
    # would bill that org for output served to all the others — so custom LLM
    # providers intentionally do not apply here. See the custom-llm-providers
    # spec (2026-06-14): advisory enrichment is out of scope for BYO routing.
    client = client or get_client()
    if not client.enabled and cve_feed is None:
        return None

    user_prompt = _build_user_prompt(advisory_id, advisory, nvd_extras)
    input_hash = _hash({
        "prompt_version": _PROMPT_VERSION,
        "system": _SYSTEM_PROMPT,
        "user": user_prompt,
    })

    # ── Cache hit ─────────────────────────────────────────────────
    if cve_feed is not None:
        _ensure_cache_table(cve_feed.conn)
        row = cve_feed.conn.execute(
            "SELECT output_json, model, prompt_version "
            "FROM ai_advisory_cache "
            "WHERE advisory_id = ? AND input_hash = ?",
            (advisory_id, input_hash),
        ).fetchone()
        if row and row[0]:
            try:
                payload = json.loads(row[0])
            except json.JSONDecodeError:
                payload = None
            if payload:
                return AdvisoryEnrichment(
                    advisory_id=advisory_id,
                    exploit_walkthrough=payload.get("exploit_walkthrough", ""),
                    fix_recipe=payload.get("fix_recipe", ""),
                    reachability_signals=payload.get("reachability_signals", []),
                    references=payload.get("references", []),
                    model=row[1],
                    prompt_version=row[2] or _PROMPT_VERSION,
                    cached=True,
                )

    # ── Live call ─────────────────────────────────────────────────
    if not client.enabled:
        return None

    raw = client._chat(_SYSTEM_PROMPT, user_prompt)
    payload = _parse_output(raw)
    if payload is None:
        log.info("advisory_ai: LLM returned no parseable output for %s", advisory_id)
        return None

    output_json = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    record = _ProvenanceRecord(
        advisory_id=advisory_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        model=client.label,
        prompt_version=_PROMPT_VERSION,
        input_hash=input_hash,
        output_hash=_hash(output_json),
        sources=list(sources),
    )
    try:
        _write_provenance(record)
    except OSError as exc:
        log.warning("advisory_ai: provenance write failed: %s", exc)

    if cve_feed is not None:
        try:
            cve_feed.conn.execute(
                "INSERT OR REPLACE INTO ai_advisory_cache "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    advisory_id, input_hash, output_json,
                    client.label, _PROMPT_VERSION, record.generated_at,
                ),
            )
            cve_feed.conn.commit()
        except Exception as exc:  # noqa: BLE001
            log.warning("advisory_ai: cache write failed: %s", exc)

    return AdvisoryEnrichment(
        advisory_id=advisory_id,
        exploit_walkthrough=payload["exploit_walkthrough"],
        fix_recipe=payload["fix_recipe"],
        reachability_signals=payload["reachability_signals"],
        references=payload["references"],
        model=client.label,
        prompt_version=_PROMPT_VERSION,
        cached=False,
    )


def read_provenance(advisory_id: str) -> list[dict[str, Any]]:
    """Return every provenance row recorded for ``advisory_id``.

    The on-disk JSONL grows append-only — this helper reads it back
    for the ``GET /advisories/{id}`` endpoint to surface the audit
    trail to operators.
    """
    path = _provenance_path(advisory_id)
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        log.warning("advisory_ai: provenance read failed: %s", exc)
        return []
    return out
