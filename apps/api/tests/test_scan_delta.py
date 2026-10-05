"""Delta vs the target's previous scan — the core of requirement #1. The diff
is pure set math over a stable fingerprint (endpoint|parameter|category|title),
so it's tested dependency-free with fake row objects. ``_compute_previous_
comparison`` itself is DB-bound; here we lock the fingerprint + set logic that
produces the new / fixed / persisted counts users see.
"""
from __future__ import annotations

from types import SimpleNamespace

from pencheff_api.services.scan_runner import _finding_fingerprint


def _row(title, *, endpoint=None, parameter=None, category="injection", suppressed=False):
    return SimpleNamespace(
        title=title, endpoint=endpoint, parameter=parameter,
        category=category, suppressed=suppressed,
    )


def test_fingerprint_is_stable_and_case_insensitive():
    a = _row("Reflected XSS", endpoint="/Search", parameter="Q", category="XSS")
    b = _row("reflected xss", endpoint="/search", parameter="q", category="xss")
    assert _finding_fingerprint(a) == _finding_fingerprint(b)


def test_fingerprint_distinguishes_endpoint_and_param():
    base = _row("SQLi", endpoint="/login", parameter="user")
    other_ep = _row("SQLi", endpoint="/admin", parameter="user")
    other_param = _row("SQLi", endpoint="/login", parameter="pass")
    fps = {_finding_fingerprint(base), _finding_fingerprint(other_ep),
           _finding_fingerprint(other_param)}
    assert len(fps) == 3


def test_new_fixed_persisted_set_math():
    # Mirrors the diff inside _compute_previous_comparison.
    prev = [_row("SQLi", endpoint="/login"), _row("XSS", endpoint="/search")]
    curr = [_row("XSS", endpoint="/search"), _row("SSRF", endpoint="/fetch")]

    prev_fps = {_finding_fingerprint(r) for r in prev if not r.suppressed}
    cur_fps = {_finding_fingerprint(r) for r in curr if not r.suppressed}

    assert len(cur_fps - prev_fps) == 1   # new: SSRF
    assert len(prev_fps - cur_fps) == 1   # fixed: SQLi
    assert len(cur_fps & prev_fps) == 1   # persisted: XSS


def test_suppressed_rows_excluded_from_diff():
    curr = [_row("XSS", endpoint="/search"),
            _row("Noise", endpoint="/x", suppressed=True)]
    cur_fps = {_finding_fingerprint(r) for r in curr if not r.suppressed}
    assert len(cur_fps) == 1
