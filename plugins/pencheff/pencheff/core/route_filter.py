"""Filter crawled routes down to ones worth pentesting.

The crawl-first phase populates ``session.discovered.endpoints`` with
everything it finds — including static assets, third-party CDN URLs, and
fragment links. The vuln playbooks consume that list verbatim through
:meth:`pencheff.modules.base.BaseTestModule._get_target_endpoints`, so
junk routes turn into wasted probes (and noisy 414 / cross-origin
errors). This filter is applied at storage time so downstream modules
see only useful entries.

A route is "useful" if it could plausibly host a vulnerability we test
for: an application route, an API endpoint, a form target, or a path
that returned an interesting status code during the crawl probe.

The function returns ``(keep, score)``. Score is a weight 0–10 used
later by :mod:`login_finder` and (potentially) by report ranking;
filtering only keeps routes with ``score >= 1``.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

# Static-asset suffixes. These almost never host application logic.
# Keep the list conservative — anything with a query string is still
# worth testing (path traversal / SSRF / open redirect can hide on
# image proxies, font endpoints, etc.).
_STATIC_SUFFIXES: tuple[str, ...] = (
    ".css", ".js", ".mjs", ".cjs",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".bmp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".map",
    ".pdf", ".zip", ".tar.gz", ".tgz",
    ".mp3", ".mp4", ".ogg", ".webm", ".mov",
)

# Third-party hosts that frequently appear in crawled link sets but are
# never in scope. We only drop these when they don't share the session's
# base host (the caller passes ``base_host`` for that comparison).
_OBVIOUS_THIRD_PARTY = (
    "googletagmanager.com", "google-analytics.com", "googleadservices.com",
    "gstatic.com", "googleapis.com", "fonts.gstatic.com",
    "fontawesome.com", "use.fontawesome.com", "kit.fontawesome.com",
    "cloudfront.net", "akamaihd.net", "akamaized.net",
    "facebook.net", "twitter.com", "linkedin.com",
    "doubleclick.net", "adservice.google.com",
    "cdn.jsdelivr.net", "unpkg.com",
    "stripe.com", "stripe.network",
    "intercom.io", "intercomcdn.com",
    "hotjar.com", "segment.io", "segment.com",
)

# Non-HTTP URI schemes the crawler sometimes emits.
_NON_HTTP_SCHEMES = ("mailto:", "tel:", "javascript:", "sms:", "ftp:")

# Path segments that score the route up — strong "this is application
# logic, not a static file" signals.
_APP_SIGNALS = (
    "/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/v5/",
    "/graphql", "/rest/", "/internal/", "/admin/", "/_internal/",
    "/auth/", "/login", "/logout", "/signin", "/sign_in", "/signup",
    "/oauth", "/sso", "/saml",
    "/upload", "/download", "/export", "/import",
    "/search", "/query",
    "/dashboard", "/account", "/profile",
)


def _ext_of(path: str) -> str:
    """Last suffix of the URL path, lowercased. Empty if no dot."""
    last_seg = path.rsplit("/", 1)[-1].lower()
    if "." not in last_seg:
        return ""
    # ``.tar.gz`` style: take the last two segments if both look like exts
    parts = last_seg.split(".")
    if len(parts) >= 3 and parts[-2] == "tar":
        return f".{parts[-2]}.{parts[-1]}"
    return f".{parts[-1]}"


def is_useful_for_pentest(
    endpoint: dict[str, Any],
    *,
    base_host: str | None = None,
) -> tuple[bool, int]:
    """Decide whether to keep a crawled endpoint, with a usefulness score.

    Args:
        endpoint: dict with at least ``url``; optionally ``method``,
            ``params``, ``status``.
        base_host: hostname of the in-scope target. When given, any URL
            on a different host is dropped as third-party.

    Returns:
        ``(keep, score)`` — when ``keep`` is False, ``score`` is 0.
    """
    url = (endpoint or {}).get("url", "") or ""
    if not url or not isinstance(url, str):
        return False, 0

    # Drop non-HTTP schemes outright.
    lower = url.lower()
    for sch in _NON_HTTP_SCHEMES:
        if lower.startswith(sch):
            return False, 0
    if lower.startswith("#"):
        return False, 0

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    query = parsed.query or ""

    # Cross-origin filter — drop anything off-host. ``base_host`` of None
    # disables this check so the helper is usable in unit tests where the
    # caller doesn't carry session context.
    if base_host:
        if host and host != base_host.lower() and not host.endswith("." + base_host.lower()):
            return False, 0
    # Third-party CDN / analytics drop, regardless of base_host.
    if host:
        for tp in _OBVIOUS_THIRD_PARTY:
            if host == tp or host.endswith("." + tp):
                return False, 0

    # Static-asset filter: only drop if the path ends in a known static
    # suffix AND there's no query string (a query-bearing static URL is
    # often a sign of a thin asset proxy worth probing).
    ext = _ext_of(path)
    if ext in _STATIC_SUFFIXES and not query:
        return False, 0

    # Score it from here on.
    score = 1  # plain GET HTML page baseline

    if any(sig in path.lower() for sig in _APP_SIGNALS):
        score += 5

    if query:
        score += 2

    method = (endpoint.get("method") or "GET").upper()
    if method != "GET":
        score += 2

    params = endpoint.get("params") or []
    if params:
        # Even on GET, having extracted parameter names is useful for fuzz.
        score += 1

    status = endpoint.get("status")
    if isinstance(status, int) and status in (200, 201, 302, 401, 403):
        # The crawl probe touched this URL successfully — existence-confirmed.
        score += 1

    # Pure home page deserves to be there but doesn't deserve a high score.
    if path in ("", "/") and not query and method == "GET":
        score = max(1, score - 1)

    return True, min(10, score)


def filter_endpoints(
    endpoints: list[dict[str, Any]],
    *,
    base_host: str | None = None,
) -> list[dict[str, Any]]:
    """Convenience wrapper: drop unusable, sort high-score first."""
    kept: list[tuple[int, dict[str, Any]]] = []
    seen: set[tuple[str, str]] = set()
    for ep in endpoints or []:
        keep, score = is_useful_for_pentest(ep, base_host=base_host)
        if not keep:
            continue
        key = (ep.get("url", ""), (ep.get("method") or "GET").upper())
        if key in seen:
            continue
        seen.add(key)
        kept.append((score, {**ep, "_useful_score": score}))
    kept.sort(key=lambda x: x[0], reverse=True)
    return [ep for _, ep in kept]
