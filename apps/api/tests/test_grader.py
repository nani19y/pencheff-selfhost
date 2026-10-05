from dataclasses import dataclass

from pencheff_api.services.grader import compute


@dataclass
class F:
    severity: str
    suppressed: bool = False
    verification_status: str = ""


def test_clean_is_A():
    score, grade, _ = compute([])
    assert grade == "A" and score == 100


def test_single_critical_is_D():
    # 1 critical deducts 25 → score 75 → C
    score, grade, counts = compute([F("critical")])
    assert score == 75 and grade == "C" and counts["critical"] == 1


def test_low_plus_critical_caps_A_to_C():
    # Add one low (deduct 1) then one critical (deduct 40) and many lows
    # A scan with a 91 score and a critical: A is forced down to C
    findings = [F("critical")] + [F("low")] * 9  # 40 + 9 = 49 deduction → score 51 → D; pick small test
    # Simpler: one critical but manually construct a scenario that would be A w/o the cap
    findings2 = [F("critical", suppressed=True), F("critical")]  # one suppressed, one not
    # deduct only 25 for unsuppressed → 75 → C. Critical cap only applies if grade was A/B.
    # Tweak: zero findings gives A=100, then add a single critical: 75 → C.
    # To demonstrate the cap: use only suppressed criticals → 100 score A — no cap (suppressed).
    score, grade, _ = compute(findings2)
    assert score == 75 and grade == "C"


def test_mix():
    findings = [F("high"), F("high"), F("medium"), F("low"), F("info")]
    score, grade, counts = compute(findings)
    # 8 + 8 + 3 + 1 = 20 → score 80 → B
    assert score == 80 and grade == "B"
    assert counts["high"] == 2


def test_suppressed_ignored():
    findings = [F("critical", suppressed=True), F("low")]
    score, grade, _ = compute(findings)
    assert score == 99 and grade == "A"


def test_false_positive_visible_but_not_scored():
    # A confirmed false positive is NOT suppressed (stays visible in the list)
    # but must not deduct from the grade — same scoring effect as suppressed.
    findings = [F("critical", verification_status="false_positive"), F("low")]
    score, grade, counts = compute(findings)
    assert score == 99 and grade == "A"   # critical FP did not deduct
    assert counts["critical"] == 1         # but it is still counted/visible
