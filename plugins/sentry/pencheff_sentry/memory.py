# SPDX-License-Identifier: AGPL-3.0-or-later
"""Memory scanner — scan agent memory / vector-store / context items.

Where ``core`` gates a single live prompt/response and ``firewall`` gates a
tool call, the memory scanner audits the DATA an agent has accumulated and
trusts: long-term memory rows, RAG / vector-store chunks, retrieved
documents, conversation-context entries. Two failure classes matter:

  * **Secrets / PII at rest** (LLM02) — a credential or PII shape sitting in
    memory that the agent could later surface or exfiltrate.
  * **Memory poisoning** (LLM04) — injected instructions hidden inside a
    *stored* item. This is worse than a live prompt injection: the content
    is in trusted context, so it fires on every future retrieval until
    removed. We reuse the same injection detectors (with normalization, so
    fullwidth / zero-width obfuscation is caught) but score it higher
    because its provenance is "trusted memory", not "user input".

Pure functions, no I/O — the hosted endpoint and the SDK both call
:func:`scan_memory`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .core import (
    _EXFIL_INSTRUCTION_PATTERNS,
    _INJECTION_BASE_RISK,
    _INJECTION_PATTERNS,
    _MCP_INPUT_PATTERNS,
    _MANIPULATION_DIRECTIVE_PATTERNS,
    _PERSISTENCE_MARKER_PATTERNS,
    _PII_PATTERNS,
    _RAG_OUTPUT_EXFIL_PATTERNS,
    _all_matches,
    _normalize_for_detection,
    find_hidden_content,
)

# Input caps — the scanner runs CPU-bound regex synchronously, and its
# expected input is adversarial (poisoned content), so an unbounded batch
# could pin a worker. Mirror the trace-ingest cap.
_MAX_ITEMS = 500
_MAX_ITEM_CHARS = 100_000

# Detector → severity for the LLM02 (secret / PII) findings.
_CRITICAL_SECRET_DETECTORS = {
    "aws-access-key", "aws-secret-key", "openai-key", "stripe-key",
    "db-connection-string", "github-pat-classic", "github-pat-fg",
    "jwt", "private-key",
}
_HIGH_PII_DETECTORS = {"ssn", "credit-card"}
# email / phone / iban and anything else → medium.
# iban is medium because the [A-Z]{2}\d{2}[A-Z0-9]{11,30} shape has moderate
# FP risk (API keys, ID strings); keep at medium until tightened.


@dataclass
class MemoryItem:
    id: str
    text: str
    namespace: str | None = None
    source: str | None = None


def _mask(text: str) -> str:
    text = text.strip().replace("\n", " ")
    if len(text) <= 8:
        return "***"
    return f"{text[:4]}***{text[-4:]}"


@dataclass
class MemoryFinding:
    item_id: str
    category: str       # LLM02 (secret/PII) | LLM04 (poisoning)
    detector: str
    severity: str       # critical | high | medium
    reason: str
    matched_text: str   # masked snippet — never the raw secret / payload
    risk_score: float = 0.0


@dataclass
class MemoryScanResult:
    items_scanned: int
    findings: list[MemoryFinding] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.findings

    @property
    def severity_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


def _pii_severity(detector: str) -> str:
    if detector in _CRITICAL_SECRET_DETECTORS:
        return "critical"
    if detector in _HIGH_PII_DETECTORS:
        return "high"
    return "medium"


def scan_memory_item(item_id: str, text: str) -> list[MemoryFinding]:
    """Scan one memory item's text for secrets/PII and poisoning."""
    findings: list[MemoryFinding] = []
    text = text or ""

    # ── Secrets / PII at rest (LLM02) ──
    for m in _all_matches(text, _PII_PATTERNS, "LLM02"):
        findings.append(MemoryFinding(
            item_id=item_id, category="LLM02", detector=m.detector,
            severity=_pii_severity(m.detector),
            reason=f"{m.detector.replace('-', ' ')} stored in memory",
            matched_text=_mask(m.matched_text),
            risk_score=0.9 if _pii_severity(m.detector) == "critical" else 0.6,
        ))

    # ── Memory poisoning: injected instructions in stored content (LLM04) ──
    # Raw first, then a normalized view to catch obfuscated payloads.
    matches = _all_matches(text, _INJECTION_PATTERNS, "LLM04")
    obfuscated = False
    if not matches:
        norm = _normalize_for_detection(text)
        if norm != text:
            norm_matches = _all_matches(norm, _INJECTION_PATTERNS, "LLM04")
            if norm_matches:
                matches, obfuscated = norm_matches, True
    if matches:
        techniques = sorted({m.detector for m in matches})
        primary = max(
            matches, key=lambda mm: _INJECTION_BASE_RISK.get(mm.detector, 0.7)
        )
        # Stored injection is poisoning — start above a live-prompt hit.
        risk = min(1.0, _INJECTION_BASE_RISK.get(primary.detector, 0.7) + 0.1)
        # critical when it's obfuscated or stacks multiple techniques.
        severity = "critical" if (obfuscated or len(techniques) > 1) else "high"
        reason = "injected instructions stored in memory (" + ", ".join(techniques) + ")"
        if obfuscated:
            reason += " [obfuscated]"
        findings.append(MemoryFinding(
            item_id=item_id, category="LLM04",
            detector="memory-poisoning:" + primary.detector
            + ("+obfuscated" if obfuscated else ""),
            severity=severity, reason=reason,
            matched_text=_mask(primary.matched_text),
            risk_score=risk,
        ))

    # ── SpAIware: standing exfiltration instructions (LLM02) ──
    for m in _all_matches(text, _EXFIL_INSTRUCTION_PATTERNS, "LLM02"):
        findings.append(MemoryFinding(
            item_id=item_id, category="LLM02", detector=f"memory:{m.detector}",
            severity="critical",
            reason="standing instruction to exfiltrate data to an external destination (SpAIware-style persistent exfiltration)",
            matched_text=_mask(m.matched_text), risk_score=0.95))

    # ── MINJA: persistence / memory-injection markers (LLM04) ──
    # Two-signal check: requires BOTH a standing-persistence marker AND a
    # manipulative directive. A bare preference ("from now on use metric units")
    # has no directive and must not fire.
    _persist_markers = list(_all_matches(text, _PERSISTENCE_MARKER_PATTERNS, "LLM04"))
    _persist_directives = list(_all_matches(text, _MANIPULATION_DIRECTIVE_PATTERNS, "LLM04"))
    if _persist_markers and _persist_directives:
        findings.append(MemoryFinding(
            item_id=item_id, category="LLM04",
            detector=f"memory:persistence:{_persist_directives[0].detector}",
            severity="medium",
            reason="persistent memory-injection: a standing-rule marker co-occurs with a manipulative directive (re-activates across future sessions)",
            matched_text=_mask(_persist_directives[0].matched_text), risk_score=0.6))

    # ── Hidden / invisible content (LLM01) ──
    _hidden = find_hidden_content(text)
    if _hidden:
        findings.append(MemoryFinding(
            item_id=item_id, category="LLM01", detector="memory:hidden-content",
            severity="high",
            reason=f"hidden/invisible characters in stored memory ({_hidden}) — smuggled instruction vector",
            matched_text=_mask(_hidden), risk_score=0.85))

    # ── Tool/MCP-style injected instructions in stored content (LLM06) ──
    # Patterns target instruction-injection shapes from MCP tool descriptions
    # or prompt templates. Stored, they re-inject on every future retrieval.
    for m in _all_matches(text, _MCP_INPUT_PATTERNS, "LLM06"):
        findings.append(MemoryFinding(
            item_id=item_id, category="LLM06",
            detector=f"memory:tool-output:{m.detector}",
            severity="high",
            reason="tool/MCP-style injected instruction stored in memory (re-injects when recalled)",
            matched_text=_mask(m.matched_text), risk_score=0.8))

    # ── RAG-output exfiltration markers in stored content (LLM02) ──
    # Detects canary doc-ID leaks and confidential-marker shapes that
    # indicate a retrieved chunk was poisoned before storage.
    for m in _all_matches(text, _RAG_OUTPUT_EXFIL_PATTERNS, "LLM02"):
        findings.append(MemoryFinding(
            item_id=item_id, category="LLM02",
            detector=f"memory:tool-output:{m.detector}",
            severity="high",
            reason="RAG-output exfiltration marker stored in memory",
            matched_text=_mask(m.matched_text), risk_score=0.8))

    return findings


def _coerce_items(items: object) -> list[MemoryItem]:
    """Accept ``[{"id","text","namespace","source"}, ...]`` or ``["text", ...]``;
    index-name the bare-string form. Raises ValueError on a malformed shape."""
    if not isinstance(items, list) or not items:
        raise ValueError("'items' must be a non-empty list")
    if len(items) > _MAX_ITEMS:
        raise ValueError(f"too many items (max {_MAX_ITEMS})")
    out: list[MemoryItem] = []
    for i, it in enumerate(items):
        if isinstance(it, str):
            out.append(MemoryItem(id=str(i), text=it[:_MAX_ITEM_CHARS]))
        elif isinstance(it, dict):
            out.append(MemoryItem(
                id=str(it.get("id") or i),
                text=str(it.get("text") or "")[:_MAX_ITEM_CHARS],
                namespace=it.get("namespace"),
                source=it.get("source"),
            ))
        else:
            raise ValueError(f"item #{i + 1} must be a string or object")
    return out


_REF_SUFFIX_RE = re.compile(r"\s*\((?:ref\s*)?\d+\)\s*$", re.IGNORECASE)


def _normalize_text(text: str) -> str:
    """Lowercase, collapse whitespace, strip trailing '(ref N)' / '(N)' suffix."""
    text = text.lower().strip()
    text = _REF_SUFFIX_RE.sub("", text)
    text = re.sub(r"\s+", " ", text)
    return text


def _shingles(text: str, n: int = 3) -> set[str]:
    """Word n-gram shingle set for Jaccard similarity."""
    words = text.split()
    if len(words) < n:
        return {text}
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    u = a | b
    return len(a & b) / len(u)


def detect_near_dup_flooding(
    items: list[MemoryItem],
    *,
    min_cluster: int = 10,
    sim_threshold: float = 0.85,
) -> list[MemoryFinding]:
    """Detect near-duplicate flooding (RAGPoison halo injection)."""
    if len(items) < min_cluster:
        return []

    norms = [_normalize_text(it.text) for it in items]
    shingle_sets = [_shingles(n) for n in norms]

    assigned = [False] * len(items)
    largest_cluster: list[int] = []
    example_text = ""

    for i in range(len(items)):
        if assigned[i]:
            continue
        cluster = [i]
        for j in range(i + 1, len(items)):
            if not assigned[j] and _jaccard(shingle_sets[i], shingle_sets[j]) >= sim_threshold:
                cluster.append(j)
        if len(cluster) > len(largest_cluster):
            largest_cluster = cluster
            example_text = items[i].text
        if len(cluster) >= min_cluster:
            for idx in cluster:
                assigned[idx] = True

    if len(largest_cluster) >= min_cluster:
        size = len(largest_cluster)
        return [MemoryFinding(
            item_id="batch",
            category="LLM08",
            detector="memory:poison-flooding",
            severity="high",
            reason=(
                f"{size} near-identical memory items (Jaccard≥{sim_threshold})"
                " — possible poison flooding / halo injection"
            ),
            matched_text=_mask(example_text),
            risk_score=0.7,
        )]
    return []


_COLLECT_RE = re.compile(
    r"(?i)\b(look up|collect|gather|read|retrieve|access|fetch)\b"
    r"[^.\n]{0,60}"
    r"\b(address|messages?|email|profile|secrets?|credentials?|personal|history|contacts?|data)\b"
)
_EXFIL_SEND_RE = re.compile(
    r"(?i)\b(send|post|transmit|upload|exfiltrate|forward)\b[^.\n]{0,60}(https?://|@)"
)


def detect_exfil_chain(items: list[MemoryItem]) -> list[MemoryFinding]:
    """Detect a collect→exfiltrate plan spread across multiple memory items."""
    has_collect = False
    exfil_text = ""

    for it in items:
        if _COLLECT_RE.search(it.text):
            has_collect = True
        # Also check _EXFIL_INSTRUCTION_PATTERNS via the imported tuple
        exfil_match = _EXFIL_SEND_RE.search(it.text)
        if not exfil_match:
            # Try the standing-channel pattern from core
            for pat, _ in _EXFIL_INSTRUCTION_PATTERNS:
                m = re.search(pat, it.text)
                if m:
                    exfil_match = m
                    break
        if exfil_match and not exfil_text:
            exfil_text = it.text

    if has_collect and exfil_text:
        return [MemoryFinding(
            item_id="batch",
            category="LLM01",
            detector="memory:exfil-chain",
            severity="high",
            reason="memory items form a collect→exfiltrate chain (plan-injection / lethal-trifecta)",
            matched_text=_mask(exfil_text),
            risk_score=0.85,
        )]
    return []


def detect_cross_tenant(items: list[MemoryItem]) -> list[MemoryFinding]:
    """Detect cross-tenant co-mingling when items carry different namespaces."""
    namespaces = {it.namespace for it in items if it.namespace is not None}
    if len(namespaces) < 2:
        return []
    n = len(namespaces)
    return [MemoryFinding(
        item_id="batch",
        category="LLM08",
        detector="memory:cross-tenant",
        severity="medium",
        reason=(
            f"memory batch co-mingles {n} tenants/namespaces"
            f" ({', '.join(sorted(namespaces))}) — isolation smell"
        ),
        matched_text="",
        risk_score=0.5,
    )]


def scan_memory(items: object) -> MemoryScanResult:
    """Scan a batch of memory items. ``items`` is a list of ``{"id","text"}``
    objects or bare strings."""
    coerced = _coerce_items(items)
    result = MemoryScanResult(items_scanned=len(coerced))
    for it in coerced:
        result.findings.extend(scan_memory_item(it.id, it.text))
    for fn in (detect_near_dup_flooding, detect_exfil_chain, detect_cross_tenant):
        try:
            result.findings.extend(fn(coerced))
        except Exception:
            pass
    return result
