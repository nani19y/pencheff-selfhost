"""Fan-out lifecycle events to enabled, in-scope integrations.

The scan worker + the findings router enqueue ``notify_event`` for every
event that may interest an integration:

  * scan_started     — fired when the worker accepts a scan
  * scan_done        — fired when a scan finishes successfully
  * scan_failed      — fired when the worker hits an unhandled exception
  * finding_new      — fired once per persisted finding at scan completion
  * finding_changed  — fired by the findings router when an analyst
                        updates verification, suppresses, unsuppresses,
                        or rechecks a finding

This task is the single dispatch surface — every hook just calls
``notify_event.delay(...)`` and Celery handles ordering, retry, and
concurrency.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.models import Finding, Integration, Scan, Target
from ..services.credentials import decrypt_credentials
from ..services.integration_dispatch import (
    build_event_payload,
    dispatch_event,
    integration_matches,
)
from .celery_app import celery_app

log = logging.getLogger(__name__)


def _engine():
    return create_engine(get_settings().database_url.replace("+asyncpg", ""), future=True)


def _payload_for_finding(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "category": f.category,
        "owasp_category": f.owasp_category,
        "cwe_id": f.cwe_id,
        "cvss_score": f.cvss_score,
        "endpoint": f.endpoint,
        "parameter": f.parameter,
        "description": (f.description or "")[:2000],
        "remediation": (f.remediation or "")[:1000],
        "verification_status": f.verification_status,
        "suppressed": bool(f.suppressed),
    }


def _dispatch_to_all(
    integrations: list[Integration],
    scan: Scan,
    target: Target,
    event_type: str,
    *,
    finding: Finding | None = None,
    change_summary: str | None = None,
    error: str | None = None,
) -> int:
    """Render + send one event to every matching integration. Failures
    are logged but never raise — one bad webhook URL must not stop the
    rest. Returns the number of successful dispatches."""
    finding_payload = _payload_for_finding(finding) if finding else None
    # LLM-kind scans get an extra summary block so chat / webhook
    # consumers can render per-OWASP-LLM-category counts and the top
    # failed techniques without an additional DB roundtrip.
    llm_summary: dict[str, Any] = {}
    if getattr(target, "kind", None) == "llm":
        try:
            from sqlalchemy import select as _select
            from ..db.models import Finding as _Finding
            from pencheff.modules.llm_red_team.reporting import build_red_team_summary
            db_engine = _engine()
            with Session(db_engine) as _db:
                rows = _db.execute(
                    _select(_Finding).where(
                        _Finding.scan_id == scan.id,
                        _Finding.suppressed.is_(False),
                    )
                ).scalars().all()
            llm_summary = build_red_team_summary([
                {
                    "title": r.title,
                    "severity": r.severity,
                    "category": r.category,
                    "owasp_category": r.owasp_category,
                    "endpoint": r.endpoint,
                }
                for r in rows
            ])
        except Exception as exc:  # noqa: BLE001 — never block a notification
            log.warning("LLM-summary build failed: %s", exc)
            llm_summary = {}
    payload = build_event_payload(
        event_type=event_type,
        target_name=target.name or target.base_url,
        target_url=target.base_url,
        scan_id=scan.id,
        profile=getattr(scan, "profile", None),
        grade=getattr(scan, "grade", None),
        score=getattr(scan, "score", None),
        summary=getattr(scan, "summary", None) or {},
        error=error,
        finding=finding_payload,
        change_summary=change_summary,
        target_kind=getattr(target, "kind", None),
        llm_summary=llm_summary,
    )

    sent = 0
    for integ in integrations:
        if not integration_matches(
            integration_target_ids=integ.target_ids,
            integration_events=integ.events,
            integration_severity_filter=integ.severity_filter,
            integration_enabled=integ.enabled,
            target_id=target.id,
            event_type=event_type,
            finding_severity=(finding.severity if finding else None),
        ):
            continue
        cfg = json.loads(
            (decrypt_credentials(integ.config_encrypted) or {}).get("config", "{}")
        )
        try:
            res = asyncio.run(
                dispatch_event(kind=integ.kind, config=cfg, payload=payload)
            )
            if res.get("ok"):
                sent += 1
            else:
                log.warning(
                    "integration %s (%s) dispatch failed: %s",
                    integ.id, integ.kind, res.get("error") or res.get("status"),
                )
        except Exception as exc:  # noqa: BLE001
            log.warning("integration %s (%s) raised: %s", integ.id, integ.kind, exc)
    return sent


@celery_app.task(name="pencheff_api.tasks.integration_notify_task.notify_event")
def notify_event(
    scan_id: str,
    event_type: str,
    finding_id: str | None = None,
    change_summary: str | None = None,
    error: str | None = None,
) -> dict[str, int]:
    """Fan-out one lifecycle event to every matching integration."""
    with Session(_engine()) as db:
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            return {"dispatched": 0, "reason": "scan_not_found"}
        target = db.execute(
            select(Target).where(Target.id == scan.target_id)
        ).scalar_one_or_none()
        if not target:
            return {"dispatched": 0, "reason": "target_not_found"}

        finding = None
        if finding_id:
            finding = db.execute(
                select(Finding).where(Finding.id == finding_id)
            ).scalar_one_or_none()
            if not finding:
                return {"dispatched": 0, "reason": "finding_not_found"}

        integrations = list(db.execute(
            select(Integration).where(Integration.workspace_id == scan.workspace_id)
        ).scalars().all())

        sent = _dispatch_to_all(
            integrations, scan, target, event_type,
            finding=finding, change_summary=change_summary, error=error,
        )
        return {"dispatched": sent, "event": event_type, "scan_id": scan_id}


@celery_app.task(name="pencheff_api.tasks.integration_notify_task.notify_scan_findings")
def notify_scan_findings(scan_id: str) -> dict[str, int]:
    """Fire scan_done + one finding_new per persisted finding in a single
    Celery roundtrip so startup hooks don't need to know how many findings
    will land. Equivalent to:

        notify_event.delay(scan_id, "scan_done")
        for f in scan.findings:
            notify_event.delay(scan_id, "finding_new", finding_id=f.id)
    """
    dispatched = 0
    with Session(_engine()) as db:
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            return {"dispatched": 0}
        target = db.execute(
            select(Target).where(Target.id == scan.target_id)
        ).scalar_one_or_none()
        if not target:
            return {"dispatched": 0}
        integrations = list(db.execute(
            select(Integration).where(Integration.workspace_id == scan.workspace_id)
        ).scalars().all())

        # scan_done first — high-signal summary alert.
        dispatched += _dispatch_to_all(integrations, scan, target, "scan_done")

        findings = db.execute(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.suppressed.is_(False),
            )
        ).scalars().all()
        for f in findings:
            dispatched += _dispatch_to_all(
                integrations, scan, target, "finding_new", finding=f,
            )
        return {"dispatched": dispatched}
