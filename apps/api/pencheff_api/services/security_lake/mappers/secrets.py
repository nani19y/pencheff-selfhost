from __future__ import annotations

from typing import Any

from ..primitives import (
    ACTIVITY_CREATE, ACTIVITY_UPDATE, CLASS_DETECTION_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id, build_unmapped,
)
from ._common import field


def map_secret(row: Any, ctx: LakeContext) -> dict:
    location = f"{field(row,'file_path') or ''}:{field(row,'line_start') or ''}"
    uid = fingerprint(org_id=ctx.org_id, asset_id=ctx.asset_id, source="secret",
                      rule_or_cve=field(row, "rule_id"), location=location)
    fi = {"title": (field(row, "title") or "Exposed secret")[:500], "uid": uid,
          "desc": field(row, "description") or ""}
    ev = base_event(class_uid=CLASS_DETECTION_FINDING,
                    activity_id=ACTIVITY_CREATE if ctx.is_new else ACTIVITY_UPDATE,
                    ctx=ctx, finding_info=fi, sev_id=severity_id(field(row, "severity")),
                    stat_id=status_id(verification_status=None,
                                      suppressed=bool(field(row, "suppressed"))))
    ev["unmapped"] = build_unmapped(scanner=field(row, "scanner"),
                                    rule_id=field(row, "rule_id"),
                                    file_path=field(row, "file_path"),
                                    line=field(row, "line_start"))
    return ev
