from __future__ import annotations

import hashlib
from dataclasses import dataclass

CATEGORY_FINDINGS = 2  # OCSF category_uid for Findings

# OCSF class_uid constants
CLASS_VULNERABILITY_FINDING = 2002
CLASS_COMPLIANCE_FINDING = 2003
CLASS_DETECTION_FINDING = 2004

# OCSF Finding activity_id
ACTIVITY_CREATE = 1
ACTIVITY_UPDATE = 2

# Single source of truth for the OCSF schema version. Stamped on every event's
# metadata.version (here) AND used to load the validation schema (validation.py
# imports this). Bumping OCSF = change this one line, then run the test suite.
OCSF_VERSION = "1.3.0"

_SEVERITY_ID = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


@dataclass(frozen=True)
class LakeContext:
    """Scope + timing for one mapped finding. No DB handles — pure data."""
    org_id: str
    asset_id: str          # repository_id or target_id
    source: str            # sast | sca | secret | iac | dast | runtime
    time_ms: int
    is_new: bool = True
    first_seen_ms: int | None = None


def severity_id(severity: str | None) -> int:
    return _SEVERITY_ID.get((severity or "").lower().strip(), 0)


def status_id(*, verification_status: str | None, suppressed: bool) -> int:
    if suppressed:  # suppression takes priority over all other states
        return 3  # Suppressed
    v = (verification_status or "").lower().strip()
    if v == "fixed":
        return 4  # Resolved
    if v in {"true_positive", "in_progress"}:
        return 2  # In Progress
    return 1      # New


def build_metadata() -> dict:
    return {
        "version": OCSF_VERSION,
        "product": {"name": "Pencheff", "vendor_name": "Pencheff"},
    }


def build_enrichments(*, epss: float | None, kev: bool | None) -> list[dict]:
    """OCSF enrichment objects require data+name+value; value must be a string."""
    out: list[dict] = []
    if epss is not None:
        out.append({"name": "epss", "value": str(epss), "type": "score",
                    "data": {"epss": epss}})
    if kev is not None:
        out.append({"name": "kev", "value": str(kev), "type": "flag",
                    "data": {"kev": kev}})
    return out


def build_unmapped(**fields) -> dict:
    """Pencheff-specific fields with no OCSF home. None values are dropped."""
    return {k: v for k, v in fields.items() if v is not None}


def fingerprint(*, org_id: str, asset_id: str, source: str,
                rule_or_cve: str | None, location: str,
                package: str | None = None) -> str:
    parts = [org_id, asset_id, source, rule_or_cve or "", location, package or ""]
    # NUL separator: never appears in ids/paths, so it cannot be forged by a
    # field that legitimately contains the separator char.
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()


def base_event(*, class_uid: int, activity_id: int, ctx: "LakeContext",
               finding_info: dict, sev_id: int, stat_id: int) -> dict:
    """Assemble the OCSF base-event skeleton shared by all finding classes.

    Class-specific required fields (vulnerabilities for 2002, compliance for
    2003) are added by the per-source mappers, not here.
    """
    return {
        "activity_id": activity_id,
        "category_uid": CATEGORY_FINDINGS,
        "class_uid": class_uid,
        "type_uid": class_uid * 100 + activity_id,
        "time": ctx.time_ms,
        "severity_id": sev_id,
        "status_id": stat_id,
        "metadata": build_metadata(),
        "finding_info": finding_info,
    }
