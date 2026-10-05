# pencheff/modules/rag_scan/static_analyzers.py
"""Pure static analyzers over a RagManifest. No network; fully unit-testable.

Each analyze_* returns a list[Finding]. run_all_static() aggregates them.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re

from pencheff.config import Severity
from pencheff.core.findings import Finding

from .manifest import RagManifest

_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                          # AWS access key ID
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[=:]\s*\S+"),  # key=val
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                   # OpenAI-style secret key
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),  # private key
    re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),  # JWT
    # Credential embedded in a connection-string URI: scheme://user:pass@host
    # (mysql/postgres/mongodb/redis/amqp/…). The user:pass@ segment is the secret.
    re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+"),
]


def _has_secret(text: str) -> bool:
    """Return True if text contains a detectable secret. Self-contained
    (regex-only) to stay deterministic regardless of ambient imports."""
    if not text:
        return False
    return any(p.search(text) for p in _SECRET_PATTERNS)


# Imperative / override phrasing injected into indexed documents (indirect
# prompt injection at rest — Greshake et al.).
_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore (all |the |any )?(previous|prior|above) (instructions?|context)"),
    re.compile(r"(?i)\bsystem override\b"),
    re.compile(r"(?i)disregard (the )?(above|prior|previous)"),
    re.compile(r"(?i)\byou must\b[^.]{0,60}\b(output|respond|reply|print|say)\b"),
    re.compile(r"(?i)new (official )?(policy|instruction) is\b"),
]

# Hidden / invisible characters: Unicode Tags block + zero-width / bidi / BOM.
# ponytail: local copy of the same regex MCP static uses — kept here to avoid
# coupling rag_scan to mcp_scan internals; both evolve independently.
_HIDDEN_RE = re.compile(
    "["
    "\U000E0000-\U000E007F"      # Unicode Tags block
    "​-‏"              # zero-width space, ZWNJ, ZWJ, LRM, RLM
    "‪-‮"              # bidi overrides
    "⁦-⁩"              # bidi isolates
    "﻿"                     # BOM / zero-width no-break space
    "]"
)

# Markdown image/link whose URL carries a query string or a {…}/%s template
# placeholder — a data-exfiltration channel embedded in a retrieved document.
_EXFIL_LINK_RE = re.compile(
    r"!?\[[^\]]*\]\((https?://[^)\s]*(?:\?[^)\s]*|\{[^}]*\}|%s)[^)]*)\)"
)


def analyze_indirect_injection_at_rest(mf: RagManifest) -> list[Finding]:
    """Flag indexed chunks that carry prompt-injection carriers (already-poisoned
    docs sitting in the KB) — imperative-override phrasing or hidden characters."""
    out: list[Finding] = []
    for chunk in getattr(mf, "samples", None) or []:
        text = getattr(chunk, "text", "") or ""
        if not text:
            continue
        injection_hit = any(p.search(text) for p in _INJECTION_PATTERNS)
        hidden_hit = bool(_HIDDEN_RE.search(text))
        if not (injection_hit or hidden_hit):
            continue
        kind = "imperative-override phrasing" if injection_hit else "hidden/invisible characters"
        out.append(Finding(
            title=f"Indirect prompt injection at rest in indexed chunk '{chunk.chunk_id}'",
            severity=Severity.HIGH,
            category="rag_indirect_injection",
            owasp_category="LLM04",
            cwe_id="CWE-94",
            description=(
                f"Chunk '{chunk.chunk_id}' in index '{getattr(chunk, 'index', '')}' contains "
                f"{kind}. When this document is retrieved, its embedded directive enters the "
                "model's context and can hijack the answer (indirect prompt injection)."
            ),
            remediation=(
                "Sanitize ingested documents: strip imperative-override phrasing and "
                "zero-width/bidi/Unicode-tag characters before embedding. Treat retrieved "
                "content as untrusted data, never as instructions."
            ),
            endpoint=getattr(mf, "endpoint", "") or "",
            parameter=chunk.chunk_id,
            metadata={"technique": "rag:indirect-injection-at-rest",
                      "index": getattr(chunk, "index", "")},
        ))
    return out


def analyze_exfil_link_at_rest(mf: RagManifest) -> list[Finding]:
    """Flag indexed chunks containing a markdown image/link to an external host
    whose URL carries a data placeholder/template (data-exfiltration channel)."""
    out: list[Finding] = []
    for chunk in getattr(mf, "samples", None) or []:
        text = getattr(chunk, "text", "") or ""
        m = _EXFIL_LINK_RE.search(text) if text else None
        if not m:
            continue
        out.append(Finding(
            title=f"Data-exfiltration link in indexed chunk '{chunk.chunk_id}'",
            severity=Severity.HIGH,
            category="rag_exfil_link",
            owasp_category="LLM02",
            cwe_id="CWE-200",
            description=(
                f"Chunk '{chunk.chunk_id}' contains a markdown link/image to an external "
                f"host with a data-carrying URL ({m.group(1)[:120]!r}). If retrieved and "
                "rendered, the model can be steered to embed sensitive context in the URL, "
                "exfiltrating it to the external host."
            ),
            remediation=(
                "Strip or neutralize markdown links/images in retrieved content, or render "
                "them inert. Block auto-rendering of external image URLs from RAG output."
            ),
            endpoint=getattr(mf, "endpoint", "") or "",
            parameter=chunk.chunk_id,
            metadata={"technique": "rag:exfil-link-at-rest",
                      "index": getattr(chunk, "index", "")},
        ))
    return out


def analyze_exposure(mf: RagManifest) -> list[Finding]:
    """Flag unauthenticated vector DB endpoints (CWE-306)."""
    if mf.auth_required is False:
        return [Finding(
            title="Unauthenticated vector DB endpoint exposed",
            severity=Severity.CRITICAL,
            category="rag_exposed_db",
            owasp_category="LLM08",
            cwe_id="CWE-306",
            description=(
                f"The vector database at {mf.endpoint!r} requires no authentication. "
                "An attacker can directly query, enumerate, or exfiltrate all stored "
                "embeddings and associated chunk text without any credential."
            ),
            remediation=(
                "Enable authentication on the vector DB (API key, mTLS, or IAM). "
                "Place the endpoint behind a private network boundary and restrict "
                "public exposure."
            ),
            endpoint=mf.endpoint,
            metadata={"technique": "rag:exposed-db"},
        )]
    return []


def analyze_tenancy(mf: RagManifest) -> list[Finding]:
    """Flag missing tenant isolation (cross-tenant data leakage)."""
    if mf.tenancy_isolation is False:
        return [Finding(
            title="Vector DB lacks tenant isolation — cross-tenant leak risk",
            severity=Severity.HIGH,
            category="rag_cross_tenant",
            owasp_category="LLM08",
            cwe_id="CWE-200",
            description=(
                "The vector database has no tenant isolation configured. In a "
                "multi-tenant deployment, one tenant's queries can retrieve chunks "
                "from another tenant's knowledge base, leaking confidential data."
            ),
            remediation=(
                "Partition indexes or namespaces per tenant and enforce tenant-scoped "
                "filters on every query. Never allow cross-namespace queries without "
                "explicit authorization."
            ),
            endpoint=mf.endpoint,
            metadata={"technique": "rag:cross-tenant-leak"},
        )]
    return []


def analyze_secrets_at_rest(mf: RagManifest) -> list[Finding]:
    """Scan indexed chunk text for secrets stored in the vector DB."""
    out: list[Finding] = []
    for chunk in mf.samples:
        if _has_secret(chunk.text):
            out.append(Finding(
                title=f"Secret detected in indexed chunk '{chunk.chunk_id}'",
                severity=Severity.HIGH,
                category="rag_secret_at_rest",
                owasp_category="LLM02",
                cwe_id="CWE-200",
                description=(
                    f"Chunk '{chunk.chunk_id}' in index '{chunk.index}' contains what "
                    "appears to be a secret (API key, token, password, or credential). "
                    "Embedding a secret embeds it permanently; any user with query access "
                    "can retrieve it via semantic similarity or keyword search."
                ),
                remediation=(
                    "Scrub secrets from source documents before ingestion. Run a "
                    "pre-ingestion secret scanner (e.g. gitleaks, trufflehog) in the "
                    "RAG pipeline and reject documents that contain credentials."
                ),
                endpoint=mf.endpoint,
                parameter=chunk.chunk_id,
                metadata={"technique": "rag:secret-at-rest", "index": chunk.index},
            ))
    return out


# PII at rest: US SSN (dashed) + Luhn-valid payment-card numbers. Kept narrow
# (dashed SSN, Luhn-checked cards) so ports/dates/phone numbers don't false-fire.
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _find_pii(text: str) -> list[str]:
    """Return the PII types found in ``text`` (empty when none)."""
    hits: list[str] = []
    if _SSN_RE.search(text):
        hits.append("US Social Security Number")
    for m in _CC_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        digits = raw.replace(" ", "").replace("-", "")
        if not (13 <= len(digits) <= 19):
            continue
        # Flag when Luhn-valid OR when written in card-style groups (≥3
        # separators, e.g. 4-4-4-4). Documents often carry non-Luhn sample/test
        # card numbers that are still regulated PII; the grouping is the signal.
        # ponytail: separator heuristic — tighten if real corpora false-fire.
        sep_count = raw.count("-") + raw.count(" ")
        if _luhn_ok(digits) or sep_count >= 3:
            hits.append("payment card number")
            break
    return hits


def analyze_pii_at_rest(mf: RagManifest) -> list[Finding]:
    """Scan indexed chunk text for PII (SSN, payment-card numbers) stored in the
    vector DB — retrievable by anyone with query access."""
    out: list[Finding] = []
    for chunk in getattr(mf, "samples", None) or []:
        text = getattr(chunk, "text", "") or ""
        if not text:
            continue
        found = _find_pii(text)
        if not found:
            continue
        kinds = ", ".join(sorted(set(found)))
        out.append(Finding(
            title=f"PII detected in indexed chunk '{chunk.chunk_id}'",
            severity=Severity.HIGH,
            category="rag_pii_at_rest",
            owasp_category="LLM02",
            cwe_id="CWE-359",
            description=(
                f"Chunk '{chunk.chunk_id}' in index '{getattr(chunk, 'index', '')}' "
                f"contains personal data ({kinds}). Embedding PII stores it permanently "
                "in the vector DB; any user with query access can retrieve it via "
                "semantic similarity or keyword search."
            ),
            remediation=(
                "Redact or tokenize PII (SSN, payment-card, DOB, contact data) before "
                "ingestion. Run a PII scrubber in the RAG pipeline and reject or mask "
                "documents that carry regulated personal data (PCI-DSS / GDPR / HIPAA)."
            ),
            endpoint=getattr(mf, "endpoint", "") or "",
            parameter=chunk.chunk_id,
            metadata={"technique": "rag:pii-at-rest",
                      "pii_types": sorted(set(found)),
                      "index": getattr(chunk, "index", "")},
        ))
    return out


def analyze_invertibility_risk(mf: RagManifest) -> list[Finding]:
    """Flag raw embedding export when paired with a known encoder (vec2text risk)."""
    if mf.raw_embedding_export is not True:
        return []
    severity = Severity.HIGH if mf.auth_required is False else Severity.MEDIUM
    encoder_note = (
        f" The encoder hint '{mf.encoder_hint}' makes the embedding space known, "
        "enabling model-specific vec2text inversion attacks."
        if mf.encoder_hint
        else ""
    )
    return [Finding(
        title="Raw embedding export enables vec2text-style text inversion",
        severity=severity,
        category="rag_embedding_inversion_risk",
        owasp_category="LLM08",
        cwe_id="CWE-200",
        description=(
            "The vector DB exposes raw float embeddings via its API. An attacker who "
            "can retrieve embeddings can reconstruct the original text using "
            "vec2text-style inversion techniques (Morris et al., 2023)."
            + encoder_note
        ),
        remediation=(
            "Disable raw embedding export unless strictly required. If export is "
            "needed, apply differential privacy noise or return only approximate "
            "nearest-neighbor distances rather than raw vectors."
        ),
        endpoint=mf.endpoint,
        references=["https://arxiv.org/abs/2310.06816"],
        metadata={"technique": "rag:embedding-inversion-risk", "encoder_hint": mf.encoder_hint},
    )]


# Retrieval-dominance heuristic: a chunk whose most-frequent non-trivial token
# is repeated abnormally is likely keyword-stuffed to dominate retrieval.
# ponytail: fixed thresholds; tune if real corpora trip false positives.
_DOMINANCE_MIN_REPEATS = 8
_DOMINANCE_RATIO = 0.25
_STOPWORDS = {"the", "and", "for", "with", "from", "this", "that", "are", "was",
              "you", "your", "our", "all", "any", "can", "will", "has", "have"}


def analyze_retrieval_dominance(mf: RagManifest) -> list[Finding]:
    """Flag indexed chunks that look keyword-stuffed to dominate retrieval."""
    out: list[Finding] = []
    for chunk in getattr(mf, "samples", None) or []:
        text = getattr(chunk, "text", "") or ""
        tokens = [t for t in re.findall(r"[a-zA-Z]{3,}", text.lower()) if t not in _STOPWORDS]
        if len(tokens) < _DOMINANCE_MIN_REPEATS:
            continue
        counts: dict[str, int] = {}
        for t in tokens:
            counts[t] = counts.get(t, 0) + 1
        top_token, top_count = max(counts.items(), key=lambda kv: kv[1])
        if top_count >= _DOMINANCE_MIN_REPEATS and (top_count / len(tokens)) >= _DOMINANCE_RATIO:
            out.append(Finding(
                title=f"Retrieval-dominance keyword stuffing in chunk '{chunk.chunk_id}'",
                severity=Severity.MEDIUM,
                category="rag_retrieval_dominance",
                owasp_category="LLM04",
                cwe_id="CWE-20",
                description=(
                    f"Chunk '{chunk.chunk_id}' repeats the token '{top_token}' {top_count} times "
                    f"({top_count / len(tokens):.0%} of its content), a keyword-stuffing pattern "
                    "used to make a document dominate retrieval and crowd out legitimate "
                    "context (PoisonedRAG relevance hijack)."
                ),
                remediation=(
                    "Detect and down-rank keyword-stuffed documents during ingestion. "
                    "Apply diversity/MMR re-ranking so a single document cannot monopolize "
                    "the retrieved context."
                ),
                endpoint=getattr(mf, "endpoint", "") or "",
                parameter=chunk.chunk_id,
                metadata={"technique": "rag:retrieval-dominance",
                          "top_token": top_token, "count": top_count},
            ))
    return out


def baseline_hash(mf: RagManifest) -> str:
    """Stable sha256 of sorted index metadata, for drift detection."""
    items = sorted(
        json.dumps([i.name, i.dimensions], sort_keys=True)
        for i in mf.indexes
    )
    return hashlib.sha256(json.dumps(items).encode("utf-8")).hexdigest()


def run_all_static(mf: RagManifest) -> list[Finding]:
    """Aggregate all static analyzers. One analyzer raising must not abort the pass."""
    out: list[Finding] = []
    for fn in (
        analyze_exposure,
        analyze_tenancy,
        analyze_secrets_at_rest,
        analyze_pii_at_rest,
        analyze_invertibility_risk,
        analyze_indirect_injection_at_rest,
        analyze_exfil_link_at_rest,
        analyze_retrieval_dominance,
    ):
        try:
            out.extend(fn(mf))
        except Exception:  # noqa: BLE001 — one analyzer must never abort the static pass
            logging.getLogger(__name__).exception("rag static analyzer %s raised", fn.__name__)
    return out
