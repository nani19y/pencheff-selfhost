from __future__ import annotations

from typing import Any

from ..primitives import (
    ACTIVITY_CREATE, ACTIVITY_UPDATE, CLASS_VULNERABILITY_FINDING,
    LakeContext, base_event, fingerprint, severity_id, status_id, build_unmapped,
)
from ._common import CWE_NONE, field


def map_sca(row: Any, ctx: LakeContext) -> dict:
    uid = fingerprint(org_id=ctx.org_id, asset_id=ctx.asset_id, source="sca",
                      rule_or_cve=field(row, "cve"), location=field(row, "file_path") or "",
                      package=field(row, "package"))
    fi = {"title": (field(row, "title") or "Dependency vulnerability")[:500], "uid": uid,
          "desc": field(row, "description") or ""}
    ev = base_event(class_uid=CLASS_VULNERABILITY_FINDING,
                    activity_id=ACTIVITY_CREATE if ctx.is_new else ACTIVITY_UPDATE,
                    ctx=ctx, finding_info=fi, sev_id=severity_id(field(row, "severity")),
                    stat_id=status_id(verification_status=None,
                                      suppressed=bool(field(row, "suppressed"))))
    pkg = {
        "name": field(row, "package") or "unknown",
        "version": field(row, "installed_version") or "unknown",
    }
    # OCSF types fixed_in_version as a string — omit it when there's no known
    # fix (None) rather than emitting null, which fails strict validation.
    fixed = field(row, "fixed_version")
    if fixed:
        pkg["fixed_in_version"] = fixed
    vuln = {"title": fi["title"], "affected_packages": [pkg]}
    sev = field(row, "severity")
    if sev:
        vuln["severity"] = sev
    cve = field(row, "cve")
    if cve:
        vuln["cve"] = {"uid": cve}
    else:
        vuln["cwe"] = {"uid": CWE_NONE}  # satisfy OCSF anyOf(cve|cwe) when no CVE
    ev["vulnerabilities"] = [vuln]
    ev["unmapped"] = build_unmapped(scanner=field(row, "scanner"))
    return ev
