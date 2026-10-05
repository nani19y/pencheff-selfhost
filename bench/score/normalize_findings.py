#!/usr/bin/env python3
"""Normalise scanner output to the common benchmark CSV schema.

Reads the raw scanner output from stdin and writes CSV rows (no header
— the caller has already emitted the header) to stdout:

    scanner,target,severity,cwe,title,url,confidence,verified

Supported input formats (``--format``):

  * pencheff  — JSON array from ``GET /findings?scan_id=…``
  * zap       — JSON report from ``zap-baseline.py``
  * astra     — CSV export from the Astra dashboard (best-effort)
  * burp      — XML "Issue report" export from Burp Suite Pro

Unknown / missing fields are emitted as empty strings so pandas can
consume the file without surprises.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import xml.etree.ElementTree as ET
from typing import Any, Iterable


def _row(
    scanner: str,
    target: str,
    *,
    severity: str = "",
    cwe: str = "",
    title: str = "",
    url: str = "",
    confidence: str = "",
    verified: str = "false",
) -> list[str]:
    # Strip newlines / commas / quotes from free-text fields so the
    # resulting CSV stays on one line per finding without needing
    # full CSV quoting.
    def _clean(v: Any) -> str:
        s = "" if v is None else str(v)
        s = s.replace("\r", " ").replace("\n", " ").replace('"', "'")
        s = s.replace(",", " ")
        return s.strip()

    return [
        _clean(scanner),
        _clean(target),
        _clean(severity).lower(),
        _clean(cwe),
        _clean(title)[:240],
        _clean(url)[:400],
        _clean(confidence),
        _clean(verified).lower(),
    ]


def _write(out: csv.writer, rows: Iterable[list[str]]) -> int:
    n = 0
    for r in rows:
        out.writerow(r)
        n += 1
    return n


# --------------------------------------------------------------------------
# Pencheff
# --------------------------------------------------------------------------
def normalize_pencheff(blob: str, scanner: str, target: str) -> list[list[str]]:
    data = json.loads(blob) or []
    rows = []
    for f in data:
        severity = f.get("severity") or "info"
        cwe = f.get("cwe_id") or ""
        verified = (
            f.get("verification_status") == "true_positive"
            or not f.get("suppressed", False)
        )
        rows.append(
            _row(
                scanner,
                target,
                severity=severity,
                cwe=cwe,
                title=f.get("title") or "",
                url=f.get("endpoint") or "",
                confidence="high" if verified else "low",
                verified="true" if verified else "false",
            )
        )
    return rows


# --------------------------------------------------------------------------
# OWASP ZAP — baseline report JSON
# --------------------------------------------------------------------------
_SEVERITY_ZAP = {"0": "info", "1": "low", "2": "medium", "3": "high"}


def normalize_zap(blob: str, scanner: str, target: str) -> list[list[str]]:
    data = json.loads(blob)
    rows = []
    for site in data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            sev = _SEVERITY_ZAP.get(str(alert.get("riskcode", "")), alert.get("riskdesc", ""))
            cwe = alert.get("cweid") or ""
            title = alert.get("name") or ""
            for inst in alert.get("instances", []) or [{}]:
                rows.append(
                    _row(
                        scanner,
                        target,
                        severity=str(sev).split()[0].lower(),
                        cwe=str(cwe),
                        title=title,
                        url=inst.get("uri") or site.get("@name") or "",
                        confidence=alert.get("confidence") or "",
                    )
                )
    return rows


# --------------------------------------------------------------------------
# Astra — CSV export (best-effort; column names vary across Astra versions)
# --------------------------------------------------------------------------
_ASTRA_SEVERITY_COLS = ("severity", "Severity", "Risk", "risk")
_ASTRA_TITLE_COLS = ("title", "Title", "vulnerability", "Vulnerability", "Name", "name")
_ASTRA_URL_COLS = ("url", "URL", "Endpoint", "endpoint", "affected_url")
_ASTRA_CWE_COLS = ("cwe", "CWE", "cwe_id")


def _first(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return str(row[k])
    return ""


def normalize_astra(blob: str, scanner: str, target: str) -> list[list[str]]:
    reader = csv.DictReader(io.StringIO(blob))
    rows = []
    for r in reader:
        rows.append(
            _row(
                scanner,
                target,
                severity=_first(r, _ASTRA_SEVERITY_COLS),
                cwe=_first(r, _ASTRA_CWE_COLS).replace("CWE-", ""),
                title=_first(r, _ASTRA_TITLE_COLS),
                url=_first(r, _ASTRA_URL_COLS),
                confidence="high",
            )
        )
    return rows


# --------------------------------------------------------------------------
# Burp Suite Pro — "Issue report" XML export
# --------------------------------------------------------------------------
def normalize_burp(blob: str, scanner: str, target: str) -> list[list[str]]:
    root = ET.fromstring(blob)
    rows = []
    for issue in root.findall(".//issue"):
        sev_map = {"Information": "info", "Low": "low", "Medium": "medium", "High": "high"}
        sev = sev_map.get(issue.findtext("severity", "") or "", "info")
        rows.append(
            _row(
                scanner,
                target,
                severity=sev,
                cwe=issue.findtext("cweid", "") or "",
                title=issue.findtext("name", "") or "",
                url=issue.findtext("host", "") + issue.findtext("path", "") if issue.find("host") is not None else issue.findtext("location", "") or "",
                confidence=issue.findtext("confidence", "") or "",
            )
        )
    return rows


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
FORMATS = {
    "pencheff": normalize_pencheff,
    "zap": normalize_zap,
    "astra": normalize_astra,
    "burp": normalize_burp,
}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--scanner", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--format", required=True, choices=sorted(FORMATS))
    args = p.parse_args()

    raw = sys.stdin.read()
    if not raw.strip():
        # Silent: runners cope with empty output.
        return 0

    fn = FORMATS[args.format]
    rows = fn(raw, args.scanner, args.target)

    writer = csv.writer(sys.stdout, lineterminator="\n")
    n = _write(writer, rows)
    print(f"[normalise] {args.scanner}/{args.target} → {n} rows", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
