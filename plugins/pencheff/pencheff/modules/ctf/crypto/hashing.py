"""Hash identification + length-extension helper.

Sources:
- Hash format references on https://hashcat.net/wiki/doku.php?id=example_hashes.
- Length-extension attack: Wikipedia "Length extension attack" + RFC 1320 §3.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class HashGuess:
    name: str
    hashcat_mode: str
    confidence: float


_PATTERNS: tuple[tuple[re.Pattern[str], HashGuess], ...] = (
    (re.compile(r"^[a-f0-9]{32}$", re.I),    HashGuess("MD5",     "0",    0.50)),
    (re.compile(r"^[a-f0-9]{40}$", re.I),    HashGuess("SHA-1",   "100",  0.70)),
    (re.compile(r"^[a-f0-9]{56}$", re.I),    HashGuess("SHA-224", "1300", 0.80)),
    (re.compile(r"^[a-f0-9]{64}$", re.I),    HashGuess("SHA-256", "1400", 0.85)),
    (re.compile(r"^[a-f0-9]{96}$", re.I),    HashGuess("SHA-384", "10800",0.85)),
    (re.compile(r"^[a-f0-9]{128}$", re.I),   HashGuess("SHA-512", "1700", 0.85)),
    (re.compile(r"^\$2[abxy]\$\d{2}\$.{53}$"), HashGuess("bcrypt", "3200", 0.99)),
    (re.compile(r"^\$argon2(id|i|d)\$"),     HashGuess("argon2",  "21100",0.99)),
    (re.compile(r"^\$1\$[^$]{1,8}\$.{22}$"), HashGuess("MD5-crypt","500",0.95)),
    (re.compile(r"^\$5\$"),                  HashGuess("SHA-256-crypt","7400",0.95)),
    (re.compile(r"^\$6\$"),                  HashGuess("SHA-512-crypt","1800",0.95)),
    (re.compile(r"^\$krb5tgs\$"),            HashGuess("Kerberos TGS-REP",   "13100",0.99)),
    (re.compile(r"^\$krb5asrep\$"),          HashGuess("Kerberos AS-REP",    "18200",0.99)),
    (re.compile(r"^\$NETNTLMv2\$|::.*::"),   HashGuess("NTLMv2",             "5600", 0.90)),
)


def identify(value: str) -> list[HashGuess]:
    out = []
    s = value.strip()
    for pat, guess in _PATTERNS:
        if pat.match(s):
            out.append(guess)
    return sorted(out, key=lambda g: -g.confidence)


# ─── Length extension (MD5 / SHA-256) — pure-Python implementation ──────
def md5_length_extend(
    *,
    original_hash: str,
    original_length: int,
    extension: bytes,
) -> tuple[str, bytes]:
    """Forge a new (hash, padded_extension) pair without knowing the secret.

    Returns the new hex digest and the bytes appended after the secret to
    produce a valid HMAC-style hash.

    Source: RFC 1320 §3.1 (padding) and the standard length-extension proof.
    """
    glue = _md5_glue_padding(original_length)
    new_data = glue + extension
    new_hash = _md5_resume(bytes.fromhex(original_hash), original_length, extension)
    return new_hash, new_data


def _md5_glue_padding(message_length: int) -> bytes:
    pad_len = (56 - (message_length + 1) % 64) % 64
    return b"\x80" + b"\x00" * pad_len + struct.pack("<Q", message_length * 8)


def _md5_resume(state_hex: bytes, message_length: int, extension: bytes) -> str:
    # Pure-Python MD5 with custom IV. Reference: RFC 1320.
    a, b, c, d = struct.unpack("<4I", state_hex)
    block_count_so_far = (message_length + 9 + 63) // 64
    total_len = block_count_so_far * 64 + len(extension)
    msg = extension + b"\x80"
    msg += b"\x00" * ((56 - (len(extension) + 1) % 64) % 64)
    msg += struct.pack("<Q", total_len * 8)

    s = (
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    )
    K = tuple(int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64))

    for off in range(0, len(msg), 64):
        m = struct.unpack("<16I", msg[off:off + 64])
        aa, bb, cc, dd = a, b, c, d
        for i in range(64):
            if i < 16:
                f = (b & c) | (~b & d)
                g = i
            elif i < 32:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * i) % 16
            f = (f + a + K[i] + m[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + _rotl32(f, s[i])) & 0xFFFFFFFF
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d).hex()


def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# Tiny hash-by-name convenience for tests + solver chain.
def by_name(name: str) -> "hashlib._Hash":  # type: ignore[name-defined]
    return hashlib.new(name)
