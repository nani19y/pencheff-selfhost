"""Pick the most-login-shaped URL from a crawled endpoint list.

Pure function over a list of endpoint dicts (the same shape stored in
``session.discovered.endpoints``). No HTTP calls — the caller has
already crawled. Used by the ``api_authenticator`` playbook to feed a
*real* login URL into :class:`pencheff.modules.auth.api_login.ApiLoginModule`
instead of the static 14-path probe list.

Scoring rubric (additive):

| Signal                                                       | Score |
|--------------------------------------------------------------|------:|
| Path matches `/(api/)?(auth/)?(login|signin|sign[_-]?in|sessions?|tokens?)$` | +10 |
| Path contains ``oauth/token`` / ``users/sign_in`` / ``account/signin`` |  +5 |
| Path contains ``/login`` or ``/signin`` (substring, not endswith) |  +3 |
| Method is POST                                                |  +2 |
| Params include ``password`` / ``email`` / ``username``        |  +3 |
| Form ``source`` (came from ``<form>`` not a link)             |  +1 |
| Path looks like a static asset                                |  -5 |
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

_LOGIN_ENDS = re.compile(
    r"/(?:api/)?(?:auth/)?(?:login|signin|sign[_-]?in|sessions?|tokens?)/?$",
    re.IGNORECASE,
)
_LOGIN_CONTAINS_STRONG = (
    "oauth/token", "users/sign_in", "account/signin", "accounts/login",
    "auth/sessions", "api/auth/login",
)
_LOGIN_CONTAINS_WEAK = ("/login", "/signin", "/sign_in", "/auth/")
_PASSWORD_PARAM_NAMES = {"password", "passwd", "pwd", "pass", "secret"}
_USERNAME_PARAM_NAMES = {"username", "user", "email", "login", "identifier", "account"}
_STATIC_SUFFIXES = {".css", ".js", ".png", ".jpg", ".svg", ".woff",
                    ".woff2", ".map", ".ico", ".gif", ".webp"}


def score_login_candidate(endpoint: dict[str, Any]) -> int:
    url = (endpoint or {}).get("url", "") or ""
    if not url:
        return 0
    parsed = urlparse(url)
    path = (parsed.path or "/").lower()
    method = (endpoint.get("method") or "GET").upper()
    params = [p.lower() for p in (endpoint.get("params") or []) if isinstance(p, str)]
    source = (endpoint.get("source") or "").lower()

    score = 0
    if _LOGIN_ENDS.search(path):
        score += 10
    if any(s in path for s in _LOGIN_CONTAINS_STRONG):
        score += 5
    if any(s in path for s in _LOGIN_CONTAINS_WEAK):
        score += 3

    if method == "POST":
        score += 2

    if any(p in _PASSWORD_PARAM_NAMES for p in params):
        score += 3
    if any(p in _USERNAME_PARAM_NAMES for p in params):
        score += 1

    if "form" in source:
        score += 1

    # Penalise obvious static URLs.
    suffix = "." + path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
    if suffix in _STATIC_SUFFIXES:
        score -= 5

    return score


def pick_login_url(
    endpoints: list[dict[str, Any]],
    *,
    minimum_score: int = 5,
) -> str | None:
    """Return the URL of the highest-scoring login candidate, or ``None``.

    ``minimum_score`` defaults to 5 so we don't auto-pick a homepage
    just because it returned 200; we want at least one strong signal
    (path-shape match, password param, etc.).
    """
    if not endpoints:
        return None
    best_url: str | None = None
    best_score = minimum_score - 1
    for ep in endpoints:
        s = score_login_candidate(ep)
        if s > best_score:
            best_score = s
            best_url = ep.get("url")
    return best_url


def all_login_candidates(
    endpoints: list[dict[str, Any]],
    *,
    minimum_score: int = 5,
) -> list[tuple[str, int]]:
    """Return every URL whose login-shape score >= minimum, sorted desc.

    Useful when you want to try several URLs in fallback order.
    """
    out: list[tuple[str, int]] = []
    for ep in endpoints or []:
        s = score_login_candidate(ep)
        if s >= minimum_score and ep.get("url"):
            out.append((ep["url"], s))
    out.sort(key=lambda x: x[1], reverse=True)
    # Dedupe URLs while preserving order.
    seen: set[str] = set()
    deduped: list[tuple[str, int]] = []
    for url, sc in out:
        if url in seen:
            continue
        seen.add(url)
        deduped.append((url, sc))
    return deduped
