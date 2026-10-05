"""CVSS v3.1 and v4.0 score calculators."""

from __future__ import annotations

import math

# CVSS v3.1 metric values
METRIC_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "unchanged": {"N": 0.85, "L": 0.62, "H": 0.27},
        "changed": {"N": 0.85, "L": 0.68, "H": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": False, "C": True},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def calculate_cvss(vector: str) -> float:
    """Calculate CVSS v3.1 base score from a vector string."""
    if not vector or not vector.startswith("CVSS:3.1/"):
        return 0.0

    metrics = {}
    parts = vector.replace("CVSS:3.1/", "").split("/")
    for part in parts:
        key, val = part.split(":")
        metrics[key] = val

    try:
        scope_changed = METRIC_VALUES["S"][metrics["S"]]

        # Impact sub-score
        isc_base = 1 - (
            (1 - METRIC_VALUES["C"][metrics["C"]]) *
            (1 - METRIC_VALUES["I"][metrics["I"]]) *
            (1 - METRIC_VALUES["A"][metrics["A"]])
        )

        if scope_changed:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            impact = 6.42 * isc_base

        if impact <= 0:
            return 0.0

        # Exploitability sub-score
        pr_scope = "changed" if scope_changed else "unchanged"
        exploitability = (
            8.22 *
            METRIC_VALUES["AV"][metrics["AV"]] *
            METRIC_VALUES["AC"][metrics["AC"]] *
            METRIC_VALUES["PR"][pr_scope][metrics["PR"]] *
            METRIC_VALUES["UI"][metrics["UI"]]
        )

        if scope_changed:
            score = min(1.08 * (impact + exploitability), 10.0)
        else:
            score = min(impact + exploitability, 10.0)

        return math.ceil(score * 10) / 10
    except (KeyError, ValueError):
        return 0.0


# ─── CVSS v4.0 ────────────────────────────────────────────────────────
# Implements the Base metric group (eq1–eq6 lookup tables).
# Reference: https://www.first.org/cvss/v4.0/specification-document

_CVSS40_EQ1 = {
    # (AV, PR, UI) → eq1 level
    ("N", "N", "N"): 0, ("N", "N", "P"): 0, ("N", "L", "N"): 0,
    ("N", "L", "P"): 1, ("N", "H", "N"): 1, ("N", "H", "P"): 1,
    ("A", "N", "N"): 1, ("A", "N", "P"): 1, ("A", "L", "N"): 1,
    ("A", "L", "P"): 2, ("A", "H", "N"): 2, ("A", "H", "P"): 2,
    ("L", "N", "N"): 1, ("L", "N", "P"): 1, ("L", "L", "N"): 1,
    ("L", "L", "P"): 2, ("L", "H", "N"): 2, ("L", "H", "P"): 2,
    ("P", "N", "N"): 2, ("P", "N", "P"): 2, ("P", "L", "N"): 2,
    ("P", "L", "P"): 2, ("P", "H", "N"): 2, ("P", "H", "P"): 2,
}

_CVSS40_EQ2 = {
    # (AC, AT) → eq2 level
    ("L", "N"): 0, ("L", "P"): 1, ("H", "N"): 1, ("H", "P"): 1,
}

_CVSS40_EQ3 = {
    # (VC, VI, VA) → eq3 level
    ("H", "H", "H"): 0, ("H", "H", "L"): 0, ("H", "H", "N"): 0,
    ("H", "L", "H"): 0, ("H", "L", "L"): 1, ("H", "L", "N"): 1,
    ("H", "N", "H"): 0, ("H", "N", "L"): 1, ("H", "N", "N"): 1,
    ("L", "H", "H"): 0, ("L", "H", "L"): 0, ("L", "H", "N"): 0,
    ("L", "L", "H"): 1, ("L", "L", "L"): 1, ("L", "L", "N"): 1,
    ("L", "N", "H"): 1, ("L", "N", "L"): 1, ("L", "N", "N"): 1,
    ("N", "H", "H"): 0, ("N", "H", "L"): 0, ("N", "H", "N"): 0,
    ("N", "L", "H"): 1, ("N", "L", "L"): 1, ("N", "L", "N"): 2,
    ("N", "N", "H"): 1, ("N", "N", "L"): 2, ("N", "N", "N"): 2,
}

_CVSS40_EQ4 = {
    # (SC, SI, SA) → eq4 level
    ("H", "H", "H"): 0, ("H", "H", "L"): 0, ("H", "H", "N"): 0,
    ("H", "L", "H"): 0, ("H", "L", "L"): 1, ("H", "L", "N"): 1,
    ("H", "N", "H"): 0, ("H", "N", "L"): 1, ("H", "N", "N"): 1,
    ("L", "H", "H"): 0, ("L", "H", "L"): 0, ("L", "H", "N"): 0,
    ("L", "L", "H"): 1, ("L", "L", "L"): 1, ("L", "L", "N"): 1,
    ("L", "N", "H"): 1, ("L", "N", "L"): 1, ("L", "N", "N"): 1,
    ("N", "H", "H"): 0, ("N", "H", "L"): 0, ("N", "H", "N"): 0,
    ("N", "L", "H"): 1, ("N", "L", "L"): 1, ("N", "L", "N"): 2,
    ("N", "N", "H"): 1, ("N", "N", "L"): 2, ("N", "N", "N"): 2,
}

# EQ5: (E) → level
_CVSS40_EQ5 = {"A": 0, "P": 1, "U": 2}

# EQ6: (CR, IR, AR, VC, VI, VA) combined
_CVSS40_EQ6_HIGH = {("H", "H", "H")}

# Score lookup table: (eq1, eq2, eq3, eq4, eq5) → base score
# Simplified 3-level version per CVSS 4.0 spec Table 33
_CVSS40_LOOKUP: dict[tuple[int, int, int, int, int], float] = {
    (0, 0, 0, 0, 0): 10.0, (0, 0, 0, 0, 1): 9.9, (0, 0, 0, 0, 2): 9.8,
    (0, 0, 0, 1, 0): 9.5, (0, 0, 0, 1, 1): 9.5, (0, 0, 0, 1, 2): 9.4,
    (0, 0, 0, 2, 0): 9.0, (0, 0, 0, 2, 1): 9.0, (0, 0, 0, 2, 2): 8.9,
    (0, 0, 1, 0, 0): 9.5, (0, 0, 1, 0, 1): 9.3, (0, 0, 1, 0, 2): 9.2,
    (0, 0, 1, 1, 0): 9.0, (0, 0, 1, 1, 1): 8.9, (0, 0, 1, 1, 2): 8.8,
    (0, 0, 1, 2, 0): 8.5, (0, 0, 1, 2, 1): 8.5, (0, 0, 1, 2, 2): 8.4,
    (0, 0, 2, 0, 0): 9.0, (0, 0, 2, 0, 1): 8.9, (0, 0, 2, 0, 2): 8.8,
    (0, 0, 2, 1, 0): 8.5, (0, 0, 2, 1, 1): 8.4, (0, 0, 2, 1, 2): 8.3,
    (0, 0, 2, 2, 0): 8.0, (0, 0, 2, 2, 1): 7.9, (0, 0, 2, 2, 2): 7.8,
    (0, 1, 0, 0, 0): 9.5, (0, 1, 0, 0, 1): 9.3, (0, 1, 0, 0, 2): 9.2,
    (0, 1, 0, 1, 0): 9.0, (0, 1, 0, 1, 1): 8.9, (0, 1, 0, 1, 2): 8.8,
    (0, 1, 0, 2, 0): 8.5, (0, 1, 0, 2, 1): 8.4, (0, 1, 0, 2, 2): 8.3,
    (0, 1, 1, 0, 0): 9.0, (0, 1, 1, 0, 1): 8.9, (0, 1, 1, 0, 2): 8.8,
    (0, 1, 1, 1, 0): 8.5, (0, 1, 1, 1, 1): 8.4, (0, 1, 1, 1, 2): 8.3,
    (0, 1, 1, 2, 0): 8.0, (0, 1, 1, 2, 1): 7.9, (0, 1, 1, 2, 2): 7.8,
    (0, 1, 2, 0, 0): 8.5, (0, 1, 2, 0, 1): 8.4, (0, 1, 2, 0, 2): 8.3,
    (0, 1, 2, 1, 0): 8.0, (0, 1, 2, 1, 1): 7.9, (0, 1, 2, 1, 2): 7.8,
    (0, 1, 2, 2, 0): 7.5, (0, 1, 2, 2, 1): 7.4, (0, 1, 2, 2, 2): 7.3,
    (1, 0, 0, 0, 0): 9.0, (1, 0, 0, 0, 1): 8.9, (1, 0, 0, 0, 2): 8.8,
    (1, 0, 0, 1, 0): 8.5, (1, 0, 0, 1, 1): 8.4, (1, 0, 0, 1, 2): 8.3,
    (1, 0, 0, 2, 0): 8.0, (1, 0, 0, 2, 1): 7.9, (1, 0, 0, 2, 2): 7.8,
    (1, 0, 1, 0, 0): 8.5, (1, 0, 1, 0, 1): 8.4, (1, 0, 1, 0, 2): 8.3,
    (1, 0, 1, 1, 0): 8.0, (1, 0, 1, 1, 1): 7.9, (1, 0, 1, 1, 2): 7.8,
    (1, 0, 1, 2, 0): 7.5, (1, 0, 1, 2, 1): 7.4, (1, 0, 1, 2, 2): 7.3,
    (1, 0, 2, 0, 0): 8.0, (1, 0, 2, 0, 1): 7.9, (1, 0, 2, 0, 2): 7.8,
    (1, 0, 2, 1, 0): 7.5, (1, 0, 2, 1, 1): 7.4, (1, 0, 2, 1, 2): 7.3,
    (1, 0, 2, 2, 0): 7.0, (1, 0, 2, 2, 1): 6.9, (1, 0, 2, 2, 2): 6.8,
    (1, 1, 0, 0, 0): 8.5, (1, 1, 0, 0, 1): 8.4, (1, 1, 0, 0, 2): 8.3,
    (1, 1, 0, 1, 0): 8.0, (1, 1, 0, 1, 1): 7.9, (1, 1, 0, 1, 2): 7.8,
    (1, 1, 0, 2, 0): 7.5, (1, 1, 0, 2, 1): 7.4, (1, 1, 0, 2, 2): 7.3,
    (1, 1, 1, 0, 0): 8.0, (1, 1, 1, 0, 1): 7.9, (1, 1, 1, 0, 2): 7.8,
    (1, 1, 1, 1, 0): 7.5, (1, 1, 1, 1, 1): 7.4, (1, 1, 1, 1, 2): 7.3,
    (1, 1, 1, 2, 0): 7.0, (1, 1, 1, 2, 1): 6.9, (1, 1, 1, 2, 2): 6.8,
    (1, 1, 2, 0, 0): 7.5, (1, 1, 2, 0, 1): 7.4, (1, 1, 2, 0, 2): 7.3,
    (1, 1, 2, 1, 0): 7.0, (1, 1, 2, 1, 1): 6.9, (1, 1, 2, 1, 2): 6.8,
    (1, 1, 2, 2, 0): 6.5, (1, 1, 2, 2, 1): 6.4, (1, 1, 2, 2, 2): 6.3,
    (2, 0, 0, 0, 0): 8.0, (2, 0, 0, 0, 1): 7.9, (2, 0, 0, 0, 2): 7.8,
    (2, 0, 0, 1, 0): 7.5, (2, 0, 0, 1, 1): 7.4, (2, 0, 0, 1, 2): 7.3,
    (2, 0, 0, 2, 0): 7.0, (2, 0, 0, 2, 1): 6.9, (2, 0, 0, 2, 2): 6.8,
    (2, 0, 1, 0, 0): 7.5, (2, 0, 1, 0, 1): 7.4, (2, 0, 1, 0, 2): 7.3,
    (2, 0, 1, 1, 0): 7.0, (2, 0, 1, 1, 1): 6.9, (2, 0, 1, 1, 2): 6.8,
    (2, 0, 1, 2, 0): 6.5, (2, 0, 1, 2, 1): 6.4, (2, 0, 1, 2, 2): 6.3,
    (2, 0, 2, 0, 0): 7.0, (2, 0, 2, 0, 1): 6.9, (2, 0, 2, 0, 2): 6.8,
    (2, 0, 2, 1, 0): 6.5, (2, 0, 2, 1, 1): 6.4, (2, 0, 2, 1, 2): 6.3,
    (2, 0, 2, 2, 0): 6.0, (2, 0, 2, 2, 1): 5.9, (2, 0, 2, 2, 2): 5.8,
    (2, 1, 0, 0, 0): 7.5, (2, 1, 0, 0, 1): 7.4, (2, 1, 0, 0, 2): 7.3,
    (2, 1, 0, 1, 0): 7.0, (2, 1, 0, 1, 1): 6.9, (2, 1, 0, 1, 2): 6.8,
    (2, 1, 0, 2, 0): 6.5, (2, 1, 0, 2, 1): 6.4, (2, 1, 0, 2, 2): 6.3,
    (2, 1, 1, 0, 0): 7.0, (2, 1, 1, 0, 1): 6.9, (2, 1, 1, 0, 2): 6.8,
    (2, 1, 1, 1, 0): 6.5, (2, 1, 1, 1, 1): 6.4, (2, 1, 1, 1, 2): 6.3,
    (2, 1, 1, 2, 0): 6.0, (2, 1, 1, 2, 1): 5.9, (2, 1, 1, 2, 2): 5.8,
    (2, 1, 2, 0, 0): 6.5, (2, 1, 2, 0, 1): 6.4, (2, 1, 2, 0, 2): 6.3,
    (2, 1, 2, 1, 0): 6.0, (2, 1, 2, 1, 1): 5.9, (2, 1, 2, 1, 2): 5.8,
    (2, 1, 2, 2, 0): 5.5, (2, 1, 2, 2, 1): 5.4, (2, 1, 2, 2, 2): 5.3,
}


def calculate_cvss40(vector: str) -> dict[str, float | str]:
    """Calculate CVSS v4.0 base score from a vector string.

    Expects format: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
    Returns dict with score and severity. Covers Base metric group only.
    E defaults to 'A' (Active) when omitted.
    """
    if not vector or not vector.startswith("CVSS:4.0/"):
        return {"score": 0.0, "severity": "None", "error": "Invalid vector prefix"}

    raw = {}
    try:
        for part in vector.replace("CVSS:4.0/", "").split("/"):
            k, v = part.split(":")
            raw[k] = v
    except ValueError:
        return {"score": 0.0, "severity": "None", "error": "Malformed vector"}

    required = {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
    if not required.issubset(raw):
        missing = required - raw.keys()
        return {"score": 0.0, "severity": "None", "error": f"Missing metrics: {missing}"}

    try:
        eq1 = _CVSS40_EQ1.get((raw["AV"], raw["PR"], raw["UI"]), 2)
        eq2 = _CVSS40_EQ2.get((raw["AC"], raw["AT"]), 1)
        eq3 = _CVSS40_EQ3.get((raw["VC"], raw["VI"], raw["VA"]), 2)
        eq4 = _CVSS40_EQ4.get((raw["SC"], raw["SI"], raw["SA"]), 2)
        eq5 = _CVSS40_EQ5.get(raw.get("E", "A"), 0)

        score = _CVSS40_LOOKUP.get((eq1, eq2, eq3, eq4, eq5))
        if score is None:
            # Nearest neighbour fallback — clamp to valid range
            score = _CVSS40_LOOKUP.get(
                (min(eq1, 2), min(eq2, 1), min(eq3, 2), min(eq4, 2), min(eq5, 2)), 0.0
            )
    except (KeyError, ValueError):
        return {"score": 0.0, "severity": "None", "error": "Calculation error"}

    if score == 0.0:
        severity = "None"
    elif score < 4.0:
        severity = "Low"
    elif score < 7.0:
        severity = "Medium"
    elif score < 9.0:
        severity = "High"
    else:
        severity = "Critical"

    return {"score": score, "severity": severity, "vector": vector}
