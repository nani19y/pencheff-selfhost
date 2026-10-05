"""Robust ``Set-Cookie`` header parsing.

The naive ``cookie.split("=")[1].split(";")[0]`` pattern that several
modules used to extract session-ID values misfires when a cookie attribute
(``Path=/``, ``Domain=…``) ends up being parsed as a standalone cookie —
producing nonsense findings like *"Session IDs are short (length: 1)"* or
*"Cookie Missing 'SameSite' Attribute: Path"*.

This parser uses ``http.cookies.SimpleCookie`` and additionally drops any
"cookie" whose name happens to be a reserved attribute keyword (``path``,
``domain``, ``secure``, ``httponly``, ``samesite``, ``expires``,
``max-age``). The result is the list of *real* cookies, each with a
correctly-extracted name, value, and security-flag set.
"""

from __future__ import annotations

import http.cookies
from dataclasses import dataclass

# Reserved cookie *attributes* — never the name of a real cookie.
# Lower-cased; comparison is case-insensitive.
_COOKIE_ATTRIBUTES: frozenset[str] = frozenset({
    "path",
    "domain",
    "secure",
    "httponly",
    "samesite",
    "expires",
    "max-age",
    "comment",
    "version",
    "discard",
})


@dataclass(frozen=True)
class ParsedCookie:
    name: str
    value: str
    secure: bool
    httponly: bool
    samesite: str  # "" / "Lax" / "Strict" / "None"

    @property
    def has_samesite(self) -> bool:
        return bool(self.samesite)


def parse_set_cookie(raw: str) -> list[ParsedCookie]:
    """Parse a ``Set-Cookie`` header value into a list of real cookies.

    Returns ``[]`` if ``raw`` is empty or unparseable. Skips entries whose
    name matches a reserved cookie attribute (the SPA-200 trap source).
    """
    if not raw or not raw.strip():
        return []
    try:
        c = http.cookies.SimpleCookie()
        c.load(raw)
    except Exception:
        return []
    out: list[ParsedCookie] = []
    for name, morsel in c.items():
        if not name or name.lower() in _COOKIE_ATTRIBUTES:
            continue
        secure = bool(morsel["secure"])
        httponly = bool(morsel["httponly"])
        samesite = morsel["samesite"] or ""
        out.append(ParsedCookie(
            name=name,
            value=morsel.value,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        ))
    return out
