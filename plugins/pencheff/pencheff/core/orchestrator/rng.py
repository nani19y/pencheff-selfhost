"""Deterministic randomness for reproducible engagements.

The orchestrator never reaches for the global ``random`` module. All choices
that need randomness — payload ordering, jitter values, probe ID generation —
go through here so two runs of the same session against the same target
produce the same probe sequence.
"""

from __future__ import annotations

import hashlib
import random


def deterministic_rng(*parts: str) -> random.Random:
    """Return a ``random.Random`` seeded from a stable hash of ``parts``.

    Use ``deterministic_rng(session_id, phase_name)`` to derive a per-phase
    RNG that survives process restarts.
    """
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).digest()
    seed = int.from_bytes(digest[:8], "big", signed=False)
    return random.Random(seed)
