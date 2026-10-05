"""Cloud target orchestrator for Infrastructure & Cloud target kinds.

The cloud pipeline is read-only. It accepts provider/resource metadata from
``Target.kind_config`` plus encrypted provider credentials from
``Target.kind_credentials_encrypted`` and runs kind-specific posture checks.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from .cloud_scanners import run_cloud_checks

log = logging.getLogger("pencheff.cloud_orchestrator")

CLOUD_KINDS = frozenset({
    "cloud_account",
    "serverless_function",
    "cloud_storage",
    "load_balancer_cdn",
    "cloud_database",
    "secrets_manager",
})


async def run_cloud_orchestrator(
    *,
    scan_id: str,
    target: Any,
    Session: Any,
    kind_credentials: dict | None = None,
) -> None:
    """Drive read-only cloud posture checks for one cloud target."""
    from ...db.models import Finding as DbFinding
    from ...db.models import Scan
    from ...events import publish_scan_event

    kind = target.kind
    if kind not in CLOUD_KINDS:
        raise ValueError(
            f"run_cloud_orchestrator called with non-cloud kind={kind!r}",
        )

    cfg = dict(target.kind_config or {})
    provider = cfg.get("provider", "unknown")
    await _append_scan_log(
        scan_id,
        Session,
        f"[Cloud] starting read-only orchestrator for kind={kind} provider={provider}",
    )
    publish_scan_event(
        scan_id,
        {
            "type": "stage_start",
            "label": f"cloud: {kind} read-only posture checks",
            "pct": None,
        },
    )

    findings, scanner_stats = run_cloud_checks(
        kind=kind,
        cfg=cfg,
        kind_credentials=kind_credentials,
    )
    counts = _severity_counts(findings)

    def _clip(v, n):
        # Clamp bounded String() columns so an over-long owasp_category/cwe_id
        # can't abort the batch insert (StringDataRightTruncationError).
        return v[:n] if isinstance(v, str) and len(v) > n else v

    from types import SimpleNamespace

    from ..grader import compute as compute_grade
    score, grade, gcounts = compute_grade(
        [SimpleNamespace(severity=(f.get("severity") or "info"),
                         suppressed=False, verification_status=None) for f in findings],
        target_kind=kind,
    )
    async with Session() as db:
        for f in findings:
            endpoint, parameter, ui_evidence = _cloud_locus_and_evidence(f)
            db.add(DbFinding(
                scan_id=scan_id,
                title=_clip(f.get("title") or "(untitled)", 500),
                severity=_clip(f.get("severity") or "info", 16),
                category=_clip(f.get("category") or "cloud", 64),
                owasp_category=_clip(f.get("owasp_category"), 32),
                cwe_id=_clip(f.get("cwe_id"), 32),
                description=(f.get("description") or "")[:4000],
                remediation=(f.get("remediation") or "")[:4000] or None,
                endpoint=_clip(endpoint, 2048),
                parameter=_clip(parameter, 200),
                evidence=ui_evidence,
            ))
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        s.status = "done"
        s.progress_pct = 100
        s.current_stage = "complete"
        s.finished_at = datetime.now(timezone.utc)
        s.grade = grade
        s.score = score
        s.summary = {
            **(s.summary or {}),
            **gcounts,
            "kind": kind,
            "scanner_stats": scanner_stats,
            "counts": counts,
            "pipeline": "cloud",
        }
        from .trace import finding_lines
        log_list = list(s.log or [])
        log_list.extend(finding_lines("Cloud", kind, findings))
        log_list.append(f"[Cloud] complete · {len(findings)} findings · {counts}")
        s.log = log_list[-1000:]
        await db.commit()

    from .trace import enqueue_validation
    enqueue_validation(scan_id)
    publish_scan_event(
        scan_id,
        {"type": "finished", "scan_id": scan_id, "total_findings": len(findings)},
    )


async def _append_scan_log(scan_id: str, Session: Any, message: str) -> None:
    from ...db.models import Scan

    async with Session() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        log_list = list(s.log or [])
        log_list.append(message)
        s.log = log_list[-1000:]
        await db.commit()


def _cloud_locus_and_evidence(
    f: dict[str, Any],
) -> tuple[str | None, str | None, list[dict[str, Any]] | None]:
    """Adapt a cloud scanner finding to the DAST-shaped Finding fields the UI
    renders. Cloud findings have no HTTP request, so the finding-detail LOCUS
    (endpoint/parameter) and EVIDENCE panels render blank for the raw
    ``{provider, scope, agent, resource, ...}`` evidence dict. Surface the
    affected resource as the locus and a readable summary + detail block as the
    evidence item so the panels are populated.
    """
    ev = dict(f.get("evidence") or {})
    if not ev:
        return None, None, None
    resource = ev.get("resource") or ev.get("arn") or ev.get("scope")
    # the salient offending attribute → LOCUS "Parameter"
    if ev.get("secret_like_env_keys"):
        parameter = ", ".join(str(k) for k in ev["secret_like_env_keys"])
    elif ev.get("runtime"):
        parameter = str(ev["runtime"])
    elif ev.get("role"):
        parameter = str(ev["role"])
    elif ev.get("public_invocation"):
        parameter = "resource_policy"
    else:
        parameter = None
    details = {k: v for k, v in ev.items() if k not in ("provider", "scope", "agent")}
    item = {
        "request_url": str(resource) if resource else None,
        "description": f.get("description"),
        "response_body_snippet": json.dumps(details, indent=2, default=str) if details else None,
    }
    return (str(resource) if resource else None), parameter, [item]


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        if severity in counts:
            counts[severity] += 1
    return counts
