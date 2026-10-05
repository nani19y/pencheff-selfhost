#!/usr/bin/env python3
"""Score every scanner against a Juice Shop instance.

Juice Shop exposes ``GET /api/challenges`` which returns the full list
of 100-ish challenges with a ``solved`` flag per entry. The flag is set
server-side when the app's monitor detects that a scanner's actual
exploit payload succeeded — not just that it was sent. Hence: the
solve count is the *truthful* measure of "did the scanner actually
break something".

This script:

  1. Restarts Juice Shop to zero the scoreboard.
  2. Runs each configured scanner runner in sequence.
  3. After each scanner, reads ``/api/challenges`` and records the solve
     delta attributable to that scanner.
  4. Writes ``results/juice-shop-summary-<date>.csv`` with one row per
     scanner.

Run ``./run_all.sh juice-shop`` which calls this at the end. You can
also invoke it in read-only mode with ``--read-only`` to just print the
current scoreboard without running anything.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import pathlib
import subprocess
import sys
import time

import requests

BENCH_ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS_DIR = BENCH_ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)

JUICE_SHOP_URL = os.environ.get("JUICE_SHOP_URL", "http://localhost:3001")


def get_scoreboard() -> list[dict]:
    r = requests.get(f"{JUICE_SHOP_URL}/api/challenges", timeout=10)
    r.raise_for_status()
    payload = r.json()
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload  # some versions return the bare array


def restart_juice_shop() -> None:
    """Zero the scoreboard by restarting the container."""
    compose = BENCH_ROOT / "docker-compose.targets.yml"
    subprocess.run(
        ["docker", "compose", "-f", str(compose), "restart", "juice-shop"],
        check=True,
    )
    # Wait for readiness.
    for _ in range(40):
        try:
            r = requests.get(f"{JUICE_SHOP_URL}/rest/admin/application-version", timeout=3)
            if r.ok:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise RuntimeError("Juice Shop did not come back up in 40 s")


def run_scanner(runner: str, target_url: str) -> int:
    """Execute ``bench/runners/<runner>.sh``. Returns its exit code."""
    path = BENCH_ROOT / "runners" / f"{runner}.sh"
    if not path.exists():
        print(f"[skip] no runner for {runner}", file=sys.stderr)
        return 127
    env = os.environ.copy()
    print(f"\n=== {runner} → {target_url} ===", file=sys.stderr)
    return subprocess.call([str(path), target_url, "juice-shop"], env=env)


def summarise(scanners: list[str], solves: dict[str, int], total: int) -> pathlib.Path:
    today = dt.date.today().isoformat()
    out = RESULTS_DIR / f"juice-shop-summary-{today}.csv"
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scanner", "target", "solved", "total", "solved_ratio"])
        for s in scanners:
            n = solves.get(s, 0)
            w.writerow([s, "juice-shop", n, total, f"{n/total:.4f}" if total else ""])
    return out


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--scanners",
        default="pencheff,zap",
        help="Comma-separated runner names.",
    )
    p.add_argument(
        "--target-url",
        default=os.environ.get(
            "TARGET_URL_JUICE_SHOP", "http://host.docker.internal:3001"
        ),
        help=(
            "URL the scanners should probe. Use host.docker.internal when "
            "the scanner runs in Docker (ZAP, Pencheff worker)."
        ),
    )
    p.add_argument(
        "--read-only",
        action="store_true",
        help="Skip restart + scanner runs; just print the current scoreboard.",
    )
    args = p.parse_args()

    scoreboard = get_scoreboard()
    total = len(scoreboard)
    solved_now = sum(1 for c in scoreboard if c.get("solved"))
    print(f"[juice-shop] {solved_now}/{total} challenges currently solved")

    if args.read_only:
        return 0

    scanners = [s.strip() for s in args.scanners.split(",") if s.strip()]
    per_scanner: dict[str, int] = {}

    for runner in scanners:
        restart_juice_shop()
        before = sum(1 for c in get_scoreboard() if c.get("solved"))
        run_scanner(runner, args.target_url)
        after = sum(1 for c in get_scoreboard() if c.get("solved"))
        delta = max(0, after - before)
        per_scanner[runner] = delta
        print(f"[juice-shop] {runner}: +{delta} challenges solved")

    summary_path = summarise(scanners, per_scanner, total)
    print(f"[juice-shop] summary → {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
