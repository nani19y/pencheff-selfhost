"""Payload transformation pipeline for fuzzing wordlists.

Callers specify one or more encoders (``url``, ``double-url``, ``base64``,
``unicode``, ``case-flip``, ``null-byte``) and the engine expands each base
word into the full set of variations. The expansion is memoised so repeated
calls over the same wordlist are fast.
"""

from __future__ import annotations

import base64
import urllib.parse
from functools import lru_cache


@lru_cache(maxsize=2048)
def apply(word: str, encoders: tuple[str, ...]) -> tuple[str, ...]:
    variants: list[str] = [word]
    for enc in encoders:
        new: list[str] = []
        for w in variants:
            new.extend(_apply_one(w, enc))
        variants = list(dict.fromkeys(variants + new))
    return tuple(variants)


def _apply_one(word: str, enc: str) -> list[str]:
    if enc == "url":
        return [urllib.parse.quote(word, safe="")]
    if enc == "double-url":
        return [urllib.parse.quote(urllib.parse.quote(word, safe=""), safe="")]
    if enc == "base64":
        return [base64.b64encode(word.encode()).decode()]
    if enc == "unicode":
        return ["".join(f"\\u{ord(c):04x}" for c in word)]
    if enc == "case-flip":
        return [word.upper(), word.lower(), word.swapcase()]
    if enc == "null-byte":
        return [word + "%00", word + "\x00"]
    if enc == "html-entity":
        return ["".join(f"&#{ord(c)};" for c in word)]
    return [word]
