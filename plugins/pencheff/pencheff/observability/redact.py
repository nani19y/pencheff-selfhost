"""Header / URL / argv redaction for plugin-side spans.

Mirrors ``apps/api/pencheff_api/observability/redact.py``. The two are
intentionally duplicated rather than factored out — the plugin and
the API are independently distributable packages, and a shared module
would force a runtime dependency that doesn't exist today.

This file should be kept in sync with the API copy.
"""
from __future__ import annotations

import hashlib
from typing import Iterable, Mapping
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


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

SENSITIVE_QUERY_PARAMS: frozenset[str] = frozenset({
    "token", "api_key", "apikey", "key", "password", "passwd", "pwd",
    "auth", "authorization", "access_token", "id_token", "refresh_token",
    "session", "sessionid", "session_id", "sid", "secret", "credentials",
    "signature", "sig", "x-amz-signature",
})

REDACTED = "[REDACTED]"


def redact_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
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
    joined = "\x00".join(str(a) for a in argv)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()
