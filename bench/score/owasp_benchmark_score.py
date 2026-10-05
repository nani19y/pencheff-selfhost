#!/usr/bin/env python3
"""Score normalised findings against OWASP BenchmarkJava expected results.

The Benchmark ships ``expectedresults-<version>.csv`` alongside its
test cases. Each row encodes whether a given ``BenchmarkTestNNNNN``
endpoint is truly vulnerable to a specific CWE or is a deliberate
false-positive trap.

This script:

  1. Reads the expected-results CSV (auto-discovered under
     ``targets/owasp-benchmark/BenchmarkJava/`` or supplied via
     ``--expected``).
  2. Reads every scanner's normalised findings CSV from ``results/``.
  3. Extracts ``BenchmarkTestNNNNN`` from each finding's URL.
  4. Classifies each expected entry as TP / FP / TN / FN.
  5. Emits per-scanner TPR, FPR, Youden Index to
     ``results/owasp-benchmark-summary-<date>.csv``.

The URL-to-test mapping is simple — the Benchmark's paths all look
like ``/benchmark/BenchmarkTest01234`` — but if the scanner doesn't
emit a CWE, we accept a test-name match alone (counted as TP against
the expected CWE). Conservative: missing CWE only costs you if the
scanner flagged a false-positive trap.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import pathlib
import re
import sys
from collections import defaultdict
from glob import glob

BENCH_ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS_DIR = BENCH_ROOT / "results"

_TEST_RE = re.compile(r"BenchmarkTest(\d{5})", re.IGNORECASE)


def find_expected_results_csv() -> pathlib.Path | None:
    candidates = list(
        (BENCH_ROOT / "targets" / "owasp-benchmark" / "BenchmarkJava").glob(
            "expectedresults-*.csv"
        )
    )
    if candidates:
        candidates.sort(reverse=True)
        return candidates[0]
    return None


def load_expected(path: pathlib.Path) -> dict[str, tuple[bool, str]]:
    """Return {test_name: (is_real_vuln, cwe)}."""
    mapping: dict[str, tuple[bool, str]] = {}
    with path.open() as f:
        reader = csv.reader(f)
        next(reader, None)  # header
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            # Column order: # test name , real vulnerability , cwe , category
            test = row[0].strip()
            is_real = row[1].strip().upper() == "TRUE"
            cwe = row[2].strip()
            mapping[test] = (is_real, cwe)
    return mapping


def load_findings(csv_path: pathlib.Path) -> list[dict]:
    rows = []
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows


def score_scanner(
    findings: list[dict], expected: dict[str, tuple[bool, str]]
) -> dict:
    # (test_name, cwe) keys the scanner flagged.
    flagged: set[tuple[str, str]] = set()
    for f in findings:
        url = f.get("url") or ""
        m = _TEST_RE.search(url)
        if not m:
            continue
        test = f"BenchmarkTest{m.group(1)}"
        cwe = (f.get("cwe") or "").strip().lstrip("CWE-")
        flagged.add((test, cwe))

    tp = fp = fn = tn = 0
    for test, (is_real, exp_cwe) in expected.items():
        matches = [c for (t, c) in flagged if t == test]
        # If scanner didn't specify a CWE, accept any flag as a match.
        matched = bool(matches) and (
            any(c == "" for c in matches) or exp_cwe in matches
        )
        if is_real and matched:
            tp += 1
        elif is_real and not matched:
            fn += 1
        elif (not is_real) and matched:
            fp += 1
        else:
            tn += 1

    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    youden = tpr - fpr
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "tpr": round(tpr, 4),
        "fpr": round(fpr, 4),
        "youden": round(youden, 4),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--expected", help="Path to expectedresults-*.csv")
    p.add_argument(
        "--findings-glob",
        default=str(RESULTS_DIR / "*-owasp-benchmark-*.csv"),
        help="Glob pattern for per-scanner normalised findings CSVs.",
    )
    args = p.parse_args()

    expected_path = pathlib.Path(args.expected) if args.expected else find_expected_results_csv()
    if expected_path is None or not expected_path.exists():
        print(
            "No expectedresults-*.csv found. Run "
            "bench/targets/owasp-benchmark/setup.sh first.",
            file=sys.stderr,
        )
        return 1

    expected = load_expected(expected_path)
    print(f"[owasp-benchmark] loaded {len(expected)} expected entries from {expected_path.name}")

    today = dt.date.today().isoformat()
    out = RESULTS_DIR / f"owasp-benchmark-summary-{today}.csv"
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["scanner", "target", "tp", "fp", "fn", "tn", "tpr", "fpr", "youden"])

        for path in sorted(glob(args.findings_glob)):
            findings_path = pathlib.Path(path)
            findings = load_findings(findings_path)
            if not findings:
                continue
            scanner = findings[0].get("scanner") or findings_path.stem.split("-")[0]
            result = score_scanner(findings, expected)
            w.writerow([
                scanner, "owasp-benchmark",
                result["tp"], result["fp"], result["fn"], result["tn"],
                result["tpr"], result["fpr"], result["youden"],
            ])
            print(
                f"[{scanner}] TP={result['tp']} FP={result['fp']} "
                f"FN={result['fn']} TN={result['tn']} "
                f"TPR={result['tpr']} FPR={result['fpr']} "
                f"Youden={result['youden']}"
            )

    print(f"[owasp-benchmark] summary → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
