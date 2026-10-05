from __future__ import annotations

from typing import Any

from ..primitives import (
    ACTIVITY_CREATE, ACTIVITY_UPDATE, CLASS_VULNERABILITY_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id, build_unmapped,
)
from ._common import CWE_NONE, field


def map_sast(row: Any, ctx: LakeContext) -> dict:
    fp_loc = field(row, "file_path") or ""
    location = f"{fp_loc}:{field(row,'line_start') or ''}-{field(row,'line_end') or ''}"
    uid = fingerprint(org_id=ctx.org_id, asset_id=ctx.asset_id, source="sast",
                      rule_or_cve=field(row, "rule_id"), location=location)
    fi = {"title": (field(row, "title") or "SAST finding")[:500], "uid": uid,
          "desc": field(row, "description") or ""}
    ev = base_event(class_uid=CLASS_VULNERABILITY_FINDING,
                    activity_id=ACTIVITY_CREATE if ctx.is_new else ACTIVITY_UPDATE,
                    ctx=ctx, finding_info=fi, sev_id=severity_id(field(row, "severity")),
                    stat_id=status_id(verification_status=None,
                                      suppressed=bool(field(row, "suppressed"))))
    cwe_uid = (field(row, "raw") or {}).get("cwe") or CWE_NONE
    fp = field(row, "file_path") or ""
    line_start, line_end = field(row, "line_start"), field(row, "line_end")
    code_loc: dict = {"file": {"name": fp.rsplit("/", 1)[-1] or fp, "path": fp, "type_id": 1}}
    if line_start is not None:
        code_loc["start_line"] = line_start
    if line_end is not None:
        code_loc["end_line"] = line_end
    vuln = {
        "title": fi["title"],
        "cwe": {"uid": cwe_uid},
        "affected_code": [code_loc],
    }
    sev = field(row, "severity")
    if sev:
        vuln["severity"] = sev
    ev["vulnerabilities"] = [vuln]
    ev["unmapped"] = build_unmapped(scanner=field(row, "scanner"),
                                    rule_id=field(row, "rule_id"),
                                    code_snippet=field(row, "code_snippet"))
    return ev
