from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from pyiceberg.expressions import EqualTo

from .celery_app import celery_app
from ..config import get_settings
from ..db.models import Org, RepoScan, RepoFinding, Scan, Finding, LakeIngestion, LakeQuarantine
from ..services.security_lake.ingest import ingest_findings, IngestResult
from ..services.security_lake.lake_writer import LakeWriter, build_catalog
from ..services.security_lake.toggle import purge_due
from ..services.unified_findings import _scanner_to_source

log = logging.getLogger(__name__)

# Delivery semantics: the Iceberg append (run_ingest) and the Postgres audit row
# (_record) are not a single transaction — they cannot be, since the Iceberg snapshot
# is committed to object storage independently of the DB. If the process dies after the
# append but before _record commits, a retry will NOT find a LakeIngestion row and will
# append again. This is intentional at-least-once delivery: the lake is append-only and
# every event carries a stable finding_uid (spec §4), so duplicate events from a retry
# are collapsed by the query layer's latest-event-per-finding_uid view. Raw event count
# may over-count; current-state queries are unaffected. (Slice 3 query layer MUST dedupe
# by finding_uid — see the carry-forward note in the Slice 2 plan.)


def run_ingest(items: list[tuple[str, Any]], *, scan_id: str, source_label: str,
               org_id: str | None, asset_id: str, time_ms: int, settings: Any) -> IngestResult:
    """DB-free core: build the writer from settings, ingest items, return the result."""
    writer = LakeWriter(build_catalog(settings),
                        namespace=settings.lake_namespace, table=settings.lake_table)
    writer.ensure_table()
    return ingest_findings(writer, items, org_id=org_id or "", asset_id=asset_id, time_ms=time_ms)


def _now_ms() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


def _record(db: Session, *, scan_id: str, source_label: str, org_id: str | None,
            res: IngestResult) -> None:
    status = "ok" if not res.quarantined else ("partial" if res.appended else "failed")
    db.add(LakeIngestion(scan_id=scan_id, source=source_label, org_id=org_id,
                         appended_count=res.appended, quarantined_count=len(res.quarantined),
                         status=status))
    for q in res.quarantined:
        db.add(LakeQuarantine(scan_id=scan_id, source=q.source, org_id=org_id,
                             error=q.error, finding_repr=q.finding_repr))
    db.commit()


@celery_app.task(name="pencheff_api.tasks.security_lake_ingest_task.ingest_repo_scan",
                 autoretry_for=(Exception,), max_retries=3, retry_backoff=True,
                 retry_backoff_max=300, retry_jitter=True)
def ingest_repo_scan(repo_scan_id: str) -> dict:
    settings = get_settings()
    engine = create_engine(settings.sync_database_url, future=True)
    with Session(engine) as db:
        # Idempotency: skip if this (scan, source) was already ingested — including
        # prior runs that recorded status="failed" (everything quarantined). A scan
        # that quarantines all findings will not auto-retry; re-ingestion after fixing
        # a mapper requires deleting its LakeIngestion row. This is deliberate (the
        # quarantine rows are preserved for investigation).
        if db.execute(select(LakeIngestion).where(
                LakeIngestion.scan_id == repo_scan_id,
                LakeIngestion.source == "repo")).first():
            return {"ok": True, "skipped": "already ingested"}
        scan = db.get(RepoScan, repo_scan_id)
        if scan is None:
            return {"ok": False, "error": "no such repo scan"}
        org = db.get(Org, scan.org_id)
        if org is None or not bool(org.security_lake_enabled):
            return {"ok": True, "skipped": "lake disabled"}
        findings = db.execute(
            select(RepoFinding).where(RepoFinding.repo_scan_id == repo_scan_id)).scalars().all()
        items = [(_scanner_to_source(f.scanner), f) for f in findings]
        time_ms = int(scan.completed_at.timestamp() * 1000) if scan.completed_at else _now_ms()
        res = run_ingest(items, scan_id=repo_scan_id, source_label="repo",
                         org_id=scan.org_id, asset_id=scan.repository_id,
                         time_ms=time_ms, settings=settings)
        _record(db, scan_id=repo_scan_id, source_label="repo", org_id=scan.org_id, res=res)
    return {"ok": True, "appended": res.appended, "quarantined": len(res.quarantined)}


@celery_app.task(name="pencheff_api.tasks.security_lake_ingest_task.ingest_dast_scan",
                 autoretry_for=(Exception,), max_retries=3, retry_backoff=True,
                 retry_backoff_max=300, retry_jitter=True)
def ingest_dast_scan(scan_id: str) -> dict:
    settings = get_settings()
    engine = create_engine(settings.sync_database_url, future=True)
    with Session(engine) as db:
        if db.execute(select(LakeIngestion).where(
                LakeIngestion.scan_id == scan_id,
                LakeIngestion.source == "dast")).first():
            return {"ok": True, "skipped": "already ingested"}
        scan = db.get(Scan, scan_id)
        if scan is None:
            return {"ok": False, "error": "no such scan"}
        org = db.get(Org, scan.org_id)
        if org is None or not bool(org.security_lake_enabled):
            return {"ok": True, "skipped": "lake disabled"}
        findings = db.execute(
            select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
        items = [("dast", f) for f in findings]
        time_ms = int(scan.finished_at.timestamp() * 1000) if getattr(scan, "finished_at", None) else _now_ms()
        res = run_ingest(items, scan_id=scan_id, source_label="dast",
                         org_id=scan.org_id, asset_id=scan.target_id,
                         time_ms=time_ms, settings=settings)
        _record(db, scan_id=scan_id, source_label="dast", org_id=scan.org_id, res=res)
    return {"ok": True, "appended": res.appended, "quarantined": len(res.quarantined)}


def enqueue_repo_ingest(repo_scan_id: str) -> bool:
    """Fire-and-forget enqueue of repo-scan lake ingestion. Never raises."""
    try:
        ingest_repo_scan.delay(repo_scan_id)
        return True
    except Exception:  # noqa: BLE001 — lake ingestion must never break a scan
        log.exception("failed to enqueue security-lake repo ingest for %s", repo_scan_id)
        return False


def enqueue_dast_ingest(scan_id: str) -> bool:
    """Fire-and-forget enqueue of DAST-scan lake ingestion. Never raises."""
    try:
        ingest_dast_scan.delay(scan_id)
        return True
    except Exception:  # noqa: BLE001
        log.exception("failed to enqueue security-lake DAST ingest for %s", scan_id)
        return False


def purge_org_lake(settings: Any, org_id: str) -> int:
    """Delete one org's rows from the lake table. Returns 1 if purged, 0 if no table.
    org_id is a partition column, so the delete prunes to that org's partition."""
    catalog = build_catalog(settings)
    identifier = f"{settings.lake_namespace}.{settings.lake_table}"
    try:
        table = catalog.load_table(identifier)
    except Exception:  # noqa: BLE001 — no table yet => nothing to purge
        return 0
    table.delete(delete_filter=EqualTo("org_id", str(org_id)))
    return 1


@celery_app.task(name="pencheff_api.tasks.security_lake_ingest_task.purge_disabled_lakes")
def purge_disabled_lakes() -> dict:
    """Daily: purge lake data for orgs disabled past the 7-day grace window."""
    settings = get_settings()
    now = datetime.now(tz=timezone.utc)
    engine = create_engine(settings.sync_database_url, future=True)
    purged: list[str] = []
    with Session(engine) as db:
        candidates = db.execute(
            select(Org).where(Org.security_lake_enabled.is_(False),
                              Org.security_lake_disabled_at.is_not(None))).scalars().all()
        due = [o for o in candidates
               if purge_due(enabled=o.security_lake_enabled,
                            disabled_at=o.security_lake_disabled_at, now=now)]
        for org in due:
            try:
                purge_org_lake(settings, org_id=org.id)
                org.security_lake_disabled_at = None
                purged.append(org.id)
            except Exception:  # noqa: BLE001 — one org's failure must not block others
                log.exception("security-lake purge failed for org %s", org.id)
        db.commit()
    return {"ok": True, "purged": purged}
