from __future__ import annotations

from typing import Any

from ..primitives import (
    ACTIVITY_CREATE, CLASS_DETECTION_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id, build_unmapped,
)
from ._common import field


def map_runtime(span: Any, ctx: LakeContext) -> dict:
    uid = fingerprint(org_id=ctx.org_id, asset_id=ctx.asset_id, source="runtime",
                      rule_or_cve=field(span, "detection_type"),
                      location=field(span, "span_id") or "")
    fi = {"title": (field(span, "title") or "Runtime detection")[:500], "uid": uid,
          "desc": field(span, "description") or ""}
    ev = base_event(class_uid=CLASS_DETECTION_FINDING, activity_id=ACTIVITY_CREATE,
                    ctx=ctx, finding_info=fi, sev_id=severity_id(field(span, "severity")),
                    stat_id=status_id(verification_status=None, suppressed=False))
    ev["unmapped"] = build_unmapped(detection_type=field(span, "detection_type"),
                                    span_id=field(span, "span_id"),
                                    trace_id=field(span, "trace_id"))
    return ev
