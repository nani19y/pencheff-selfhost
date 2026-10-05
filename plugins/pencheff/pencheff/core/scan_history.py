"""Scan history persistence and delta comparison.

Saves completed scan results to ~/.pencheff/history/ and provides
baseline comparison so you can see new/fixed/regressed findings
across consecutive scans of the same target.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_HISTORY_DIR = Path.home() / ".pencheff" / "history"


def _history_dir() -> Path:
    _HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    return _HISTORY_DIR


def _fingerprint(finding_dict: dict) -> str:
    """Stable identity key for a finding across sessions."""
    return "|".join([
        finding_dict.get("endpoint", ""),
        finding_dict.get("parameter") or "",
        finding_dict.get("category", ""),
        finding_dict.get("title", ""),
    ])


@dataclass
class ScanRecord:
    session_id: str
    target: str
    saved_at: str
    finding_count: int
    summary: dict[str, int]
    findings: list[dict]


def save_scan(session: Any) -> str:
    """Persist current session findings to disk. Returns the file path."""
    d = _history_dir()
    findings = [f.to_dict() for f in session.findings.get_all(include_suppressed=True)]
    attached_repos = [
        r.to_dict() for r in getattr(session, "attached_repos", []) or []
    ]
    record = {
        "session_id": session.id,
        "target": session.target.base_url,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "summary": session.findings.summary(),
        "findings": findings,
        "attached_repos": attached_repos,
        "sast_status": dict(getattr(session, "sast_task_state", {}) or {}),
    }
    # Use target hostname as part of the filename for grouping
    safe_host = session.target.base_url.replace("://", "_").replace("/", "_").replace(":", "_")[:60]
    filename = d / f"{safe_host}__{session.id}.json"
    filename.write_text(json.dumps(record, indent=2))
    return str(filename)


def list_scans(target_url: str | None = None) -> list[dict[str, Any]]:
    """List saved scans, optionally filtered by target URL."""
    d = _history_dir()
    results = []
    for p in sorted(d.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            data = json.loads(p.read_text())
            if target_url and target_url not in data.get("target", ""):
                continue
            results.append({
                "file": str(p),
                "session_id": data.get("session_id"),
                "target": data.get("target"),
                "saved_at": data.get("saved_at"),
                "finding_count": data.get("finding_count", 0),
                "summary": data.get("summary", {}),
            })
        except Exception:
            continue
    return results


def compare_scans(
    session_id_a: str,
    session_id_b: str,
) -> dict[str, Any]:
    """Compare two saved scans by session_id.

    Returns:
      - new: findings in B not present in A (regressions / new findings)
      - fixed: findings in A not present in B (resolved)
      - persisted: unchanged findings present in both
    """
    d = _history_dir()

    def _load(sid: str) -> dict | None:
        for p in d.glob("*.json"):
            try:
                data = json.loads(p.read_text())
                if data.get("session_id") == sid:
                    return data
            except Exception:
                continue
        return None

    scan_a = _load(session_id_a)
    scan_b = _load(session_id_b)

    if not scan_a:
        return {"error": f"Session '{session_id_a}' not found in history. Run save_scan first."}
    if not scan_b:
        return {"error": f"Session '{session_id_b}' not found in history. Run save_scan first."}

    fp_a = {_fingerprint(f): f for f in scan_a["findings"]}
    fp_b = {_fingerprint(f): f for f in scan_b["findings"]}

    keys_a = set(fp_a.keys())
    keys_b = set(fp_b.keys())

    new_findings = [fp_b[k] for k in sorted(keys_b - keys_a)]
    fixed_findings = [fp_a[k] for k in sorted(keys_a - keys_b)]
    persisted = [fp_b[k] for k in sorted(keys_a & keys_b)]

    # Detect regressions: same finding but higher severity in B
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    regressed = []
    for k in keys_a & keys_b:
        sev_a = severity_order.get(fp_a[k].get("severity", "info"), 0)
        sev_b = severity_order.get(fp_b[k].get("severity", "info"), 0)
        if sev_b > sev_a:
            regressed.append({
                "finding": fp_b[k],
                "previous_severity": fp_a[k].get("severity"),
                "current_severity": fp_b[k].get("severity"),
            })

    return {
        "baseline": {
            "session_id": session_id_a,
            "target": scan_a["target"],
            "saved_at": scan_a["saved_at"],
            "finding_count": scan_a["finding_count"],
        },
        "current": {
            "session_id": session_id_b,
            "target": scan_b["target"],
            "saved_at": scan_b["saved_at"],
            "finding_count": scan_b["finding_count"],
        },
        "new_count": len(new_findings),
        "fixed_count": len(fixed_findings),
        "persisted_count": len(persisted),
        "regressed_count": len(regressed),
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "regressions": regressed,
    }
