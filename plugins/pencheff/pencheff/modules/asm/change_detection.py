"""Diff current asset inventory against the last snapshot and emit Findings for new exposures."""

from __future__ import annotations

import json
import time
from pathlib import Path

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.asm import asset_inventory

SNAP_DIR = Path.home() / ".pencheff" / "asm_snapshots"


def snapshot_and_diff(org: str) -> list[Finding]:
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    current = {
        a.type + "|" + a.value: a
        for a in asset_inventory.list_assets(org)
    }
    prev_file = SNAP_DIR / f"{org}.json"
    prev: dict[str, dict] = {}
    if prev_file.exists():
        try:
            prev = json.loads(prev_file.read_text())
        except Exception:  # noqa: BLE001
            prev = {}

    findings: list[Finding] = []
    for key, a in current.items():
        if key not in prev:
            findings.append(_new_asset_finding(a))

    # persist
    try:
        prev_file.write_text(json.dumps({
            k: {"type": v.type, "value": v.value, "metadata": v.metadata}
            for k, v in current.items()
        }))
    except Exception:  # noqa: BLE001
        pass
    return findings


def _new_asset_finding(asset) -> Finding:
    return Finding(
        title=f"New asset appeared: {asset.type} {asset.value}",
        severity=Severity.INFO,
        category="misconfiguration",
        owasp_category="A05",
        description=(
            f"Attack surface management detected a new {asset.type} in scope: "
            f"{asset.value}. This may indicate a newly-deployed service, domain, "
            f"or certificate — confirm it is intentional and properly secured."
        ),
        remediation=(
            "Confirm the asset is intentional; if not, remove the exposure. If "
            "intentional, ensure it is monitored, patched, and covered by scans."
        ),
        endpoint=asset.value,
        evidence=[Evidence(
            request_method="ASM", request_url=asset.value,
            response_status=200,
            description=f"Discovered via passive inventory at {time.ctime(asset.first_seen)}",
        )],
    )
