from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from pencheff_api.db.models import Scan, ScanSchedule
from pencheff_api.services.on_demand_scheduler import dispatch_due_scans_sync


ORG_ID = "00000000000000000000000000000001"
WORKSPACE_ID = "00000000000000000000000000000002"
TARGET_ID = "00000000000000000000000000000003"
USER_ID = "00000000000000000000000000000004"
SCHEDULE_ID = "00000000000000000000000000000005"


def _db_url(tmp_path) -> str:
    return f"sqlite:///{tmp_path / 'schedules.db'}"


def _create_minimal_schema(engine) -> None:
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """
            CREATE TABLE scan_schedules (
                id VARCHAR PRIMARY KEY,
                org_id VARCHAR NOT NULL,
                workspace_id VARCHAR NOT NULL,
                target_id VARCHAR NOT NULL,
                owner_user_id VARCHAR,
                name VARCHAR NOT NULL,
                cron_expression VARCHAR NOT NULL,
                timezone VARCHAR NOT NULL DEFAULT 'UTC',
                profile VARCHAR NOT NULL DEFAULT 'standard',
                policy_yaml TEXT,
                enabled BOOLEAN NOT NULL DEFAULT 1,
                last_run_at DATETIME,
                next_run_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE targets (
                id VARCHAR PRIMARY KEY,
                org_id VARCHAR NOT NULL,
                workspace_id VARCHAR NOT NULL,
                name VARCHAR NOT NULL,
                base_url VARCHAR,
                kind VARCHAR NOT NULL DEFAULT 'url',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE scans (
                id VARCHAR PRIMARY KEY,
                target_id VARCHAR NOT NULL,
                org_id VARCHAR NOT NULL,
                workspace_id VARCHAR NOT NULL,
                engagement_id VARCHAR,
                campaign_id VARCHAR,
                user_id VARCHAR,
                status VARCHAR NOT NULL DEFAULT 'queued',
                profile VARCHAR NOT NULL DEFAULT 'standard',
                pencheff_session_id VARCHAR,
                progress_pct INTEGER NOT NULL DEFAULT 0,
                current_stage VARCHAR,
                summary TEXT,
                consent_payload TEXT,
                grade VARCHAR,
                score INTEGER,
                log TEXT,
                error TEXT,
                started_at DATETIME,
                finished_at DATETIME,
                notify_emails TEXT,
                kind_payload TEXT,
                use_ai BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def _seed_due_schedule(engine) -> str:
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        # A target the schedule points at, so kind→category routing resolves.
        conn.execute(
            text(
                "INSERT INTO targets (id, org_id, workspace_id, name, base_url, kind)"
                " VALUES (:id, :org_id, :workspace_id, :name, :base_url, :kind)"
            ),
            {
                "id": TARGET_ID,
                "org_id": ORG_ID,
                "workspace_id": WORKSPACE_ID,
                "name": "web target",
                "base_url": "https://example.com",
                "kind": "web_app",
            },
        )
        conn.execute(
            text(
                """
                INSERT INTO scan_schedules (
                    id,
                    org_id,
                    workspace_id,
                    target_id,
                    owner_user_id,
                    name,
                    cron_expression,
                    timezone,
                    profile,
                    enabled,
                    next_run_at
                )
                VALUES (
                    :id,
                    :org_id,
                    :workspace_id,
                    :target_id,
                    :owner_user_id,
                    :name,
                    :cron_expression,
                    :timezone,
                    :profile,
                    :enabled,
                    :next_run_at
                )
                """
            ),
            {
                "id": SCHEDULE_ID,
                "org_id": ORG_ID,
                "workspace_id": WORKSPACE_ID,
                "target_id": TARGET_ID,
                "owner_user_id": USER_ID,
                "name": "Daily",
                "cron_expression": "0 0 * * *",
                "timezone": "UTC",
                "profile": "standard",
                "enabled": True,
                "next_run_at": now - timedelta(minutes=1),
            },
        )
    return SCHEDULE_ID


def test_dispatch_starts_worker_before_creating_due_scan(tmp_path, monkeypatch) -> None:
    engine = create_engine(_db_url(tmp_path), future=True)
    _create_minimal_schema(engine)
    _seed_due_schedule(engine)
    calls: list[str] = []

    monkeypatch.setattr(
        "pencheff_api.services.on_demand_scheduler.enqueue_full_scan",
        lambda scan_id, kind: calls.append(f"enqueue:{scan_id}:{kind}"),
    )

    result = dispatch_due_scans_sync(
        database_url=_db_url(tmp_path),
        start_worker=lambda service: calls.append(f"start:{service}"),
    )

    assert result == {"dispatched": 1}
    # web_app → Web & API category worker, started before the scan is enqueued.
    assert calls[0] == "start:worker-web-api"
    assert calls[1].startswith("enqueue:")
    assert calls[1].endswith(":web_app")
    with Session(engine) as db:
        assert db.execute(select(Scan)).scalars().one().status == "queued"


def test_dispatch_does_not_advance_schedule_when_worker_start_fails(
    tmp_path,
) -> None:
    engine = create_engine(_db_url(tmp_path), future=True)
    _create_minimal_schema(engine)
    schedule_id = _seed_due_schedule(engine)

    with pytest.raises(RuntimeError, match="controller down"):
        dispatch_due_scans_sync(
            database_url=_db_url(tmp_path),
            start_worker=lambda service: (_ for _ in ()).throw(
                RuntimeError("controller down")
            ),
        )

    with Session(engine) as db:
        schedule = db.get(ScanSchedule, schedule_id)
        assert schedule is not None
        assert schedule.last_run_at is None
        assert db.execute(select(Scan)).scalars().all() == []
