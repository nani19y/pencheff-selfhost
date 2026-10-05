"""RSA attack helpers — Wiener, Fermat, common-modulus, small-e.

Sources:
- Wiener 1990 "Cryptanalysis of Short RSA Secret Exponents".
- Fermat factorization (Stinson §3.4.4).
- Hastad 1985 broadcast attack (when used).
- Common-modulus attack (Boneh "Twenty Years of Attacks on the RSA
  Cryptosystem", §3).

We deliberately implement small, well-known attacks. CTF-scale only.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction


@dataclass
class RSAResult:
    method: str
    p: int = 0
    q: int = 0
    d: int = 0
    plaintext: int | None = None
    notes: str = ""


# ─── Fermat (close-prime) factorization ────────────────────────────────
def fermat_factor(n: int, *, max_iter: int = 1_000_000) -> RSAResult | None:
    """Recover (p, q) when |p - q| is small."""
    if n % 2 == 0:
        return RSAResult(method="fermat", p=2, q=n // 2)
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        if b2 < 0:
            a += 1
            continue
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a + b, a - b
            if p > 1 and q > 1 and p * q == n:
                return RSAResult(method="fermat", p=p, q=q)
        a += 1
    return None


# ─── Wiener (small private exponent) ───────────────────────────────────
def wiener(n: int, e: int) -> RSAResult | None:
    """Recover d when d < N^0.25 / 3 via continued-fraction expansion."""
    cf = _continued_fraction(e, n)
    for k, d in _convergents(cf):
        if k == 0:
            continue
        phi = (e * d - 1) // k
        # Solve x^2 - (n - phi + 1)x + n = 0
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        root = math.isqrt(disc)
        if root * root != disc:
            continue
        p = (s + root) // 2
        q = (s - root) // 2
        if p * q == n and p > 1 and q > 1:
            return RSAResult(method="wiener", p=p, q=q, d=d)
    return None


# ─── Common modulus attack (same n, different e₁/e₂) ────────────────────
def common_modulus(n: int, e1: int, e2: int, c1: int, c2: int) -> RSAResult | None:
    g, u, v = _xgcd(e1, e2)
    if g != 1:
        return None
    if u < 0:
        c1 = pow(c1, -1, n)
        u = -u
    if v < 0:
        c2 = pow(c2, -1, n)
        v = -v
    m = (pow(c1, u, n) * pow(c2, v, n)) % n
    return RSAResult(method="common_modulus", plaintext=m)


# ─── Small-e cube-root attack (Hastad-flavoured single-recipient) ──────
def small_e_cube_root(c: int) -> RSAResult | None:
    """If e=3 and m^3 < n (no padding), recover m via integer cube root."""
    m = _integer_nth_root(c, 3)
    if m * m * m == c:
        return RSAResult(method="small_e_cube_root", plaintext=m,
                         notes="works only when m^e < n (no padding).")
    return None


# ─── helpers ────────────────────────────────────────────────────────────
def _continued_fraction(num: int, den: int) -> list[int]:
    out: list[int] = []
    while den:
        q, num, den = num // den, den, num - (num // den) * den
        out.append(q)
    return out


def _convergents(cf: list[int]):
    h_prev, h = 1, 0
    k_prev, k = 0, 1
    for q in cf:
        h_prev, h = h, q * h + h_prev
        k_prev, k = k, q * k + k_prev
        yield h, k


def _xgcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _xgcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def _integer_nth_root(x: int, n: int) -> int:
    if x < 0:
        return -_integer_nth_root(-x, n)
    if x in (0, 1):
        return x
    lo, hi = 1, 1 << ((x.bit_length() + n - 1) // n + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** n <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def derive_d(p: int, q: int, e: int) -> int:
    phi = (p - 1) * (q - 1)
    return pow(e, -1, phi)
