"""Header / URL / argv redaction used everywhere a request becomes a
span attribute.

The pencheff scanning pipeline injects credentials into outgoing requests
(``http_client.py`` line 81) and runs hydra/sqlmap with ``-p <password>``
on the command line. Without explicit redaction those values would
travel into ``otel_spans.attributes`` and live there for ``retention_days``
days — a worse footprint than the existing stderr logs they replace.

The denylist is an allow-everything-EXCEPT model: anything not on the
list passes through, the listed names are replaced with ``"[REDACTED]"``.
Belt-and-suspenders: callers should never store raw subprocess argv at
all; ``tool_runner`` hashes the joined args instead of redacting them.
"""
from __future__ import annotations

import hashlib
from typing import Iterable, Mapping
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


# Lower-case match. HTTP header names are case-insensitive per RFC 7230.
SENSITIVE_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-amz-security-token",
    "x-csrf-token",
    "x-forwarded-authorization",
    "x-pencheff-api-key",
    "x-anthropic-api-key",
    "openai-api-key",
})

# Query-string parameter names commonly carrying credentials. Pentest
# targets often have these in URLs (a session-token-in-querystring is
# itself a finding pencheff likes to surface), so we redact the *value*
# and keep the *key* visible — operators can still see the URL shape
# in the trace and recognise the auth-by-querystring smell.
SENSITIVE_QUERY_PARAMS: frozenset[str] = frozenset({
    "token", "api_key", "apikey", "key", "password", "passwd", "pwd",
    "auth", "authorization", "access_token", "id_token", "refresh_token",
    "session", "sessionid", "session_id", "sid", "secret", "credentials",
    "signature", "sig", "x-amz-signature",
})

REDACTED = "[REDACTED]"


def redact_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Return a copy of ``headers`` with sensitive values masked."""
    if not headers:
        return {}
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            out[k] = REDACTED
        else:
            out[k] = v
    return out


def redact_url(url: str) -> str:
    """Strip sensitive query-param values from ``url``.

    The path, host, and non-sensitive query parameters survive verbatim
    so an operator can still recognise the request in a trace waterfall.
    Failures (malformed URL, etc.) return the input unchanged — the
    redaction layer should never raise into the hot path.
    """
    if not url:
        return url
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
        scrubbed: list[tuple[str, str]] = []
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            if k.lower() in SENSITIVE_QUERY_PARAMS:
                scrubbed.append((k, REDACTED))
            else:
                scrubbed.append((k, v))
        return urlunparse(parsed._replace(query=urlencode(scrubbed)))
    except Exception:
        return url


def hash_argv(argv: Iterable[str]) -> str:
    """SHA-256 of joined argv for a subprocess invocation.

    We never want raw argv in span attributes — hydra/sqlmap routinely
    receive ``-p <password>`` or ``-D <database> --tamper=...``. The
    hash gives operators a stable identity for the invocation (same
    args → same hash) without exposing the secret material.
    """
    joined = "\x00".join(str(a) for a in argv)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()
