# pencheff_api/services/security_lake/ingest.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import map_finding, validate_ocsf, LakeContext
from .lake_schema import to_lake_row
from .lake_writer import LakeWriter


@dataclass
class QuarantineItem:
    source: str
    error: str
    finding_repr: str


@dataclass
class IngestResult:
    appended: int = 0
    quarantined: list[QuarantineItem] = field(default_factory=list)


def ingest_findings(writer: LakeWriter, items: list[tuple[str, Any]], *,
                    org_id: str, asset_id: str, time_ms: int) -> IngestResult:
    """Map → validate → append valid; quarantine the rest. One Iceberg snapshot total.

    ``items`` is a list of ``(source, finding)`` pairs. A finding that fails mapping
    or OCSF validation is recorded in ``quarantined`` and skipped — never fatal.
    """
    rows: list[dict] = []
    result = IngestResult()
    for source, finding in items:
        try:
            ctx = LakeContext(org_id=org_id, asset_id=asset_id, source=source,
                              time_ms=time_ms, is_new=True)
            event = map_finding(source, finding, ctx)
            validate_ocsf(event)
            rows.append(to_lake_row(event, org_id=org_id, source=source, asset_id=asset_id))
        except Exception as exc:  # noqa: BLE001 — quarantine, never fail the batch
            result.quarantined.append(
                QuarantineItem(source=source, error=str(exc), finding_repr=repr(finding)[:500])
            )
    result.appended = writer.append_rows(rows)
    return result
