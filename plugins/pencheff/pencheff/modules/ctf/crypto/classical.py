"""Classical-cipher solvers — purely deterministic, no model.

Sources:
- Caesar / Vigenère: any introductory cryptography text (Stinson §1.2).
- Kasiski / IC: Kasiski 1863, Friedman 1922 — see Stinson §2.3.
- Morse / Atbash / base*: standard tables / RFC 4648.
"""

from __future__ import annotations

import base64
import re
import string
from collections import Counter
from typing import Iterable


# English letter frequency (Wikipedia "Letter frequency").
ENGLISH_FREQ = {
    "e": 0.127, "t": 0.091, "a": 0.082, "o": 0.075, "i": 0.070, "n": 0.067,
    "s": 0.063, "h": 0.061, "r": 0.060, "d": 0.043, "l": 0.040, "c": 0.028,
    "u": 0.028, "m": 0.024, "w": 0.024, "f": 0.022, "g": 0.020, "y": 0.020,
    "p": 0.019, "b": 0.015, "v": 0.010, "k": 0.008, "j": 0.0015,
    "x": 0.0015, "q": 0.001, "z": 0.0007,
}


# ─── single-byte ciphers ────────────────────────────────────────────────
def caesar_shift(text: str, shift: int) -> str:
    out: list[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def rot13(text: str) -> str:
    return caesar_shift(text, 13)


def caesar_brute(text: str) -> list[tuple[int, str, float]]:
    """All 25 shifts ranked by chi-squared distance to English frequency.

    Returns ``[(shift, plaintext, chi_squared), ...]`` best first.
    """
    out: list[tuple[int, str, float]] = []
    for shift in range(1, 26):
        candidate = caesar_shift(text, shift)
        score = _chi_squared_english(candidate)
        out.append((shift, candidate, score))
    return sorted(out, key=lambda t: t[2])


def atbash(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(ord("a") + (ord("z") - ord(ch))))
        elif "A" <= ch <= "Z":
            out.append(chr(ord("A") + (ord("Z") - ord(ch))))
        else:
            out.append(ch)
    return "".join(out)


# ─── Vigenère ───────────────────────────────────────────────────────────
def vigenere_decrypt(ciphertext: str, key: str) -> str:
    if not key:
        return ciphertext
    key_norm = "".join(c for c in key.lower() if c.isalpha())
    if not key_norm:
        return ciphertext
    out: list[str] = []
    j = 0
    for ch in ciphertext:
        if ch.isalpha():
            shift = ord(key_norm[j % len(key_norm)]) - 97
            base = ord("a") if ch.islower() else ord("A")
            out.append(chr((ord(ch) - base - shift) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_break_kasiski(ciphertext: str, *, max_key_len: int = 16) -> tuple[str, str, float]:
    """Estimate Vigenère key length via index of coincidence and recover key.

    Returns (best_key, plaintext, key_confidence). ``key_confidence`` is the
    average IC of the columns at the chosen length — closer to 0.067 means
    English-like.
    """
    only_alpha = [c for c in ciphertext if c.isalpha()]
    if len(only_alpha) < 20:
        return "", ciphertext, 0.0

    best_len = 1
    best_ic = -1.0
    for klen in range(2, max_key_len + 1):
        cols = [only_alpha[i::klen] for i in range(klen)]
        ics = [_index_of_coincidence(col) for col in cols if col]
        avg_ic = sum(ics) / len(ics)
        # Prefer higher IC closer to English (0.0667).
        if avg_ic > best_ic:
            best_ic = avg_ic
            best_len = klen

    cols = [only_alpha[i::best_len] for i in range(best_len)]
    key = ""
    for col in cols:
        # For each column, choose the shift minimizing chi-squared.
        best_shift, _ = min(
            ((s, _chi_squared_english(caesar_shift("".join(col), -s)))
             for s in range(26)),
            key=lambda pair: pair[1],
        )
        key += chr(97 + best_shift)
    return key, vigenere_decrypt(ciphertext, key), best_ic


# ─── XOR ────────────────────────────────────────────────────────────────
def xor_known_plaintext(ciphertext: bytes, known_plaintext: bytes) -> bytes:
    """Recover the keystream prefix when both ciphertext and plaintext share length."""
    n = min(len(ciphertext), len(known_plaintext))
    return bytes(c ^ p for c, p in zip(ciphertext[:n], known_plaintext[:n]))


def xor_repeating_key(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


# ─── Morse ─────────────────────────────────────────────────────────────
_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z",
    ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5",
    "-....": "6", "--...": "7", "---..": "8", "----.": "9", "-----": "0",
}


def morse_decode(text: str) -> str:
    words = re.split(r"\s{2,}|/", text.strip())
    out: list[str] = []
    for word in words:
        chars = [_MORSE.get(tok, "?") for tok in word.split()]
        out.append("".join(chars))
    return " ".join(out)


# ─── base encodings ────────────────────────────────────────────────────
def base64_decode(text: str) -> bytes | None:
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (ValueError, base64.binascii.Error):
        return None


def base32_decode(text: str) -> bytes | None:
    try:
        return base64.b32decode(text + "=" * (-len(text) % 8), casefold=True)
    except (ValueError, base64.binascii.Error):
        return None


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_decode(text: str) -> bytes | None:
    n = 0
    for ch in text:
        if ch not in _B58_ALPHABET:
            return None
        n = n * 58 + _B58_ALPHABET.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    leading_zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading_zeros + raw


# ─── auto-decode ───────────────────────────────────────────────────────
def auto_decode(text: str, *, depth: int = 4) -> list[tuple[str, str]]:
    """Try common decodings up to ``depth`` levels deep.

    Returns ``[(transformation_chain, decoded_text), ...]`` for each
    successful path. Order is deterministic — alphabetical by chain.
    """
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    _walk(text, "", depth, seen, out)
    return sorted(out, key=lambda t: t[0])


def _walk(value: str, chain: str, depth: int, seen: set[str], out: list) -> None:
    if depth == 0 or value in seen or not value.strip():
        return
    seen.add(value)
    candidates: list[tuple[str, str]] = []
    # Base64
    b64 = base64_decode(value)
    if b64 is not None and _printable(b64):
        candidates.append(("b64", b64.decode("utf-8", "replace")))
    # Base32
    b32 = base32_decode(value)
    if b32 is not None and _printable(b32):
        candidates.append(("b32", b32.decode("utf-8", "replace")))
    # Base58
    b58 = base58_decode(value)
    if b58 is not None and _printable(b58):
        candidates.append(("b58", b58.decode("utf-8", "replace")))
    # Hex
    if re.fullmatch(r"[0-9a-fA-F]+", value.strip()):
        try:
            raw = bytes.fromhex(value.strip())
            if _printable(raw):
                candidates.append(("hex", raw.decode("utf-8", "replace")))
        except ValueError:
            pass
    # ROT13
    if any(c.isalpha() for c in value):
        candidates.append(("rot13", rot13(value)))
    # Atbash
    if any(c.isalpha() for c in value):
        candidates.append(("atbash", atbash(value)))
    # Morse
    if set(value) <= set(". -/" + string.whitespace):
        candidates.append(("morse", morse_decode(value)))

    for label, decoded in candidates:
        new_chain = f"{chain}>{label}" if chain else label
        out.append((new_chain, decoded))
        _walk(decoded, new_chain, depth - 1, seen, out)


# ─── helpers ────────────────────────────────────────────────────────────
def _index_of_coincidence(text: Iterable[str]) -> float:
    text = [c.lower() for c in text if c.isalpha()]
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def _chi_squared_english(text: str) -> float:
    only = [c.lower() for c in text if c.isalpha()]
    if not only:
        return float("inf")
    n = len(only)
    counts = Counter(only)
    chi2 = 0.0
    for letter, expected_freq in ENGLISH_FREQ.items():
        observed = counts.get(letter, 0)
        expected = expected_freq * n
        chi2 += (observed - expected) ** 2 / max(expected, 1e-6)
    return chi2


def _printable(data: bytes, *, ratio: float = 0.85) -> bool:
    if not data:
        return False
    printable_set = set(string.printable.encode())
    hits = sum(1 for b in data if b in printable_set)
    return hits / len(data) >= ratio
