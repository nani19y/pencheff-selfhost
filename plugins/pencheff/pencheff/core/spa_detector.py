"""Single-page-app fallback detection.

Single-page applications routinely serve `index.html` with HTTP 200 for any
unknown path so that client-side routing works. Path-brute-force modules
that decide a finding is real based on "got a 200" alone fire a flood of
false positives against SPA targets — admin paths, JBoss-style
deserialization endpoints, OAuth probes, login-rate-limit checks, etc.

This module establishes a *target-derived* fallback signature once at scan
start by probing two random non-existent paths. Modules then call
:func:`is_real_endpoint` before emitting; if the response matches the
fallback, the path doesn't really exist and no finding is emitted. No
hard-coded path blacklists, no per-module heuristics.

Edge cases handled:

* If the two random probes disagree (e.g. a real 404 page rendered with a
  timestamp), we *cannot* fingerprint deterministically — leave
  ``fallback_signature`` as ``None`` and ``is_real_endpoint`` always
  returns ``True`` (preserves current behaviour).
* If the fallback returns a non-200 status (proper webserver), every 200
  in subsequent probes is real — fingerprint stores the status and the
  comparison is status-only.
* Body comparison strips embedded URLs / random IDs that some SPA shells
  include (e.g. nonces, request IDs) to avoid false negatives.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# Body bytes considered for hashing. Anything beyond this is content-heavy
# enough that two SPA-fallback responses would already match in their
# first few KB, and capping protects us from huge SSR pages.
_BODY_HASH_LIMIT = 16 * 1024

# Substrings we strip before hashing so two SPA fallbacks for distinct
# unknown paths still hash identically. Most SPA shells insert the
# requested path or a random nonce; everything else is template HTML.
_STRIP_PATTERNS = [
    re.compile(r'href="[^"]*"', re.IGNORECASE),
    re.compile(r'src="[^"]*"', re.IGNORECASE),
    re.compile(r'<meta[^>]*content="[^"]*"[^>]*>', re.IGNORECASE),
    # CSRF tokens, request IDs, build hashes, nonces.
    re.compile(r'(name="(?:csrf|request|trace)[-_]?(?:id|token)"\s+content=)"[^"]*"', re.IGNORECASE),
    re.compile(r'\b[0-9a-f]{16,64}\b'),  # hex IDs
    re.compile(r'\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b'),  # JWTs
]


@dataclass(frozen=True)
class FallbackSignature:
    """Fingerprint of what a non-existent path looks like on this target."""

    status: int
    body_hash: str | None  # None when status alone is enough (e.g. 404)
    body_length: int


def _normalise_body(body: str) -> str:
    """Strip per-request variable substrings so two fallbacks hash equally."""
    if not body:
        return ""
    body = body[:_BODY_HASH_LIMIT]
    for pat in _STRIP_PATTERNS:
        body = pat.sub("", body)
    return body


def _body_hash(body: str) -> str:
    return hashlib.sha256(_normalise_body(body).encode("utf-8", "ignore")).hexdigest()


def _random_path() -> str:
    """A path that's overwhelmingly unlikely to exist on the target.

    We generate a path that no real router would have a route for, and that
    doesn't look like a security-tool probe (so a WAF doesn't 403 it).
    """
    return f"/_pencheff_probe_{secrets.token_hex(12)}"


async def establish_spa_fingerprint(session: Any, http: Any) -> None:
    """Probe two random paths and store the fallback signature on the session.

    Idempotent — if the signature is already set, this is a no-op. Called
    once from the API scan runner at scan start, before any path-
    brute-force module runs.

    ``session`` is a :class:`pencheff.core.session.PentestSession`;
    ``http`` is a :class:`pencheff.core.http_client.PencheffHTTPClient`.
    Both are passed loosely-typed to keep this module import-light.
    """
    if getattr(session.target, "fallback_signature", None) is not None:
        return

    base_url = session.target.base_url.rstrip("/")
    probes: list[FallbackSignature] = []
    for _ in range(2):
        url = f"{base_url}{_random_path()}"
        try:
            resp = await http.get(url, module="spa_detector")
        except Exception as exc:  # noqa: BLE001
            log.debug("spa_detector probe failed for %s: %s", url, exc)
            continue
        body = getattr(resp, "text", "") or ""
        probes.append(FallbackSignature(
            status=resp.status_code,
            body_hash=_body_hash(body) if body else None,
            body_length=len(body),
        ))

    if len(probes) < 2:
        # Network errors prevented us from establishing a baseline. Stay
        # safe: leave fingerprint unset so is_real_endpoint allows
        # everything (no behavioural change).
        log.info("spa_detector: insufficient probe responses; no fingerprint set")
        return

    a, b = probes[0], probes[1]

    # Agreement check. Status must match; body hash must match (or both
    # be None, i.e. empty bodies). Length comparison tolerates ±1% jitter.
    if a.status != b.status:
        log.info(
            "spa_detector: probes returned different statuses (%d vs %d) — no SPA fallback",
            a.status, b.status,
        )
        return

    body_match = a.body_hash == b.body_hash
    length_close = (
        a.body_length == b.body_length
        or abs(a.body_length - b.body_length) <= max(1, int(0.01 * max(a.body_length, b.body_length)))
    )
    if not (body_match and length_close):
        log.info(
            "spa_detector: probes diverge (hash_match=%s len=%d/%d) — no SPA fallback",
            body_match, a.body_length, b.body_length,
        )
        return

    # Definitive: this is what a non-existent path looks like on the target.
    sig = FallbackSignature(
        status=a.status,
        body_hash=a.body_hash,
        body_length=a.body_length,
    )
    session.target.fallback_signature = sig
    log.info(
        "spa_detector: fallback fingerprint established status=%d len=%d hash=%s…",
        sig.status, sig.body_length, (sig.body_hash or "")[:12],
    )


def is_real_endpoint(response: Any, session: Any) -> bool:
    """Decide whether ``response`` represents a real endpoint or the SPA
    fallback served for unknown paths.

    Returns ``True`` (i.e. "treat as real") when:

    * No fingerprint is established (server returns proper 404s, or the
      probe failed) — preserves current scanner behaviour.
    * The response status differs from the fallback status.
    * The response body hash differs from the fallback body hash (the
      response shape is genuinely different).

    Returns ``False`` only when the response is *indistinguishable* from
    the recorded fallback. Modules use this as a guard before emitting
    findings that rely on "endpoint exists" inferences.
    """
    sig: FallbackSignature | None = getattr(session.target, "fallback_signature", None)
    if sig is None:
        return True

    status = getattr(response, "status_code", None)
    if status is None or status != sig.status:
        return True

    body = getattr(response, "text", "") or ""
    if not body and sig.body_hash is None:
        # Both empty + same status — same signature, almost certainly fallback.
        return False
    if not body or sig.body_hash is None:
        return True

    if _body_hash(body) == sig.body_hash:
        return False

    # Status agrees but body diverges — different content means real endpoint.
    return True
