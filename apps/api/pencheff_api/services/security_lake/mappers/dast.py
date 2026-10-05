from __future__ import annotations

from typing import Any

from ..primitives import (
    ACTIVITY_CREATE, ACTIVITY_UPDATE, CLASS_VULNERABILITY_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id,
    build_unmapped, build_enrichments,
)
from ._common import CWE_NONE, field


def map_dast(row: Any, ctx: LakeContext) -> dict:
    endpoint, parameter = field(row, "endpoint"), field(row, "parameter")
    location = f"{endpoint or ''}|{parameter or ''}"
    uid = fingerprint(org_id=ctx.org_id, asset_id=ctx.asset_id, source="dast",
                      rule_or_cve=field(row, "category"), location=location)
    fi = {"title": (field(row, "title") or "Web finding")[:500], "uid": uid,
          "desc": field(row, "description") or ""}
    ev = base_event(class_uid=CLASS_VULNERABILITY_FINDING,
                    activity_id=ACTIVITY_CREATE if ctx.is_new else ACTIVITY_UPDATE,
                    ctx=ctx, finding_info=fi, sev_id=severity_id(field(row, "severity")),
                    stat_id=status_id(verification_status=field(row, "verification_status"),
                                      suppressed=bool(field(row, "suppressed"))))
    vuln = {"title": fi["title"], "cwe": {"uid": field(row, "cwe_id") or CWE_NONE}}
    sev = field(row, "severity")
    if sev:
        vuln["severity"] = sev
    ev["vulnerabilities"] = [vuln]
    ev["enrichments"] = build_enrichments(epss=field(row, "epss"), kev=field(row, "kev"))
    ev["unmapped"] = build_unmapped(
        endpoint=endpoint, parameter=parameter,
        owasp_category=field(row, "owasp_category"),
        cvss_score=field(row, "cvss_score"), cvss_vector=field(row, "cvss_vector"),
        reachability=field(row, "reachability"), risk_score=field(row, "risk_score"),
        ssvc_decision=field(row, "ssvc_decision"))
    return ev
