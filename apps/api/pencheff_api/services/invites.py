"""Token generation + hashing for org member invites.

We keep a SHA-256 of the token in the DB and hand the raw token to the
caller (who emails it to the invitee). On accept we hash again and look
the row up by hash — so a DB leak never exposes usable invite URLs.
"""
from __future__ import annotations

import hashlib
import secrets

_TOKEN_BYTES = 32  # 256-bit — ~43 chars after base64url


def generate_token() -> tuple[str, str]:
    """Return (raw_token, token_hash). Only the hash is persisted."""
    raw = secrets.token_urlsafe(_TOKEN_BYTES)
    return raw, hash_token(raw)


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
