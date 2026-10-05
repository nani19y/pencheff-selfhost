from __future__ import annotations

from typing import Any

from ..primitives import (
    ACTIVITY_CREATE, ACTIVITY_UPDATE, CLASS_COMPLIANCE_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id, build_unmapped,
)
from ._common import field


def map_iac(row: Any, ctx: LakeContext) -> dict:
    uid = fingerprint(org_id=ctx.org_id, asset_id=ctx.asset_id, source="iac",
                      rule_or_cve=field(row, "rule_id"), location=field(row, "file_path") or "")
    fi = {"title": (field(row, "title") or "IaC misconfiguration")[:500], "uid": uid,
          "desc": field(row, "description") or ""}
    ev = base_event(class_uid=CLASS_COMPLIANCE_FINDING,
                    activity_id=ACTIVITY_CREATE if ctx.is_new else ACTIVITY_UPDATE,
                    ctx=ctx, finding_info=fi, sev_id=severity_id(field(row, "severity")),
                    stat_id=status_id(verification_status=None,
                                      suppressed=bool(field(row, "suppressed"))))
    ev["compliance"] = {"standards": [field(row, "scanner") or "iac"],
                        "control": field(row, "rule_id") or "unknown"}
    ev["unmapped"] = build_unmapped(scanner=field(row, "scanner"),
                                    file_path=field(row, "file_path"))
    return ev
