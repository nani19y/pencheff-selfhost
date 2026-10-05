import logging

from celery import Celery
from celery.schedules import crontab
from celery.signals import task_postrun, worker_process_init, worker_ready

from ..config import get_settings


log = logging.getLogger("pencheff.celery")
_settings = get_settings()


@worker_process_init.connect
def _init_observability_per_worker(sender=None, **_kwargs) -> None:
    """Initialise the OTel pipeline inside each forked worker process.

    Celery forks workers from the parent — TracerProvider state set up
    in the parent is invalidated after fork (the BatchSpanProcessor
    background thread is gone). Re-initialising in the
    ``worker_process_init`` signal gives every worker its own provider,
    exporter, and connection.

    No-op when ``PENCHEFF_OBSERVABILITY_ENABLED=false``.
    """
    try:
        from ..observability import init_observability
        init_observability("pencheff-celery-worker")
    except Exception as exc:  # noqa: BLE001
        log.warning("observability init failed in worker: %s", exc)

celery_app = Celery(
    "pencheff",
    broker=_settings.redis_url,
    backend=_settings.redis_url,
    include=[
        "pencheff_api.tasks.scan_task",
        "pencheff_api.tasks.recheck_task",
        "pencheff_api.tasks.report_task",
        # Extended scanning workflows
        "pencheff_api.tasks.scheduled_scan_task",
        "pencheff_api.tasks.asset_discovery_task",
        "pencheff_api.tasks.sla_monitor_task",
        "pencheff_api.tasks.integration_notify_task",
        # GitHub repo scanning
        "pencheff_api.tasks.repo_scan_task",
        # AI-agent finding verification (sets verification_status + hackable).
        # Without this include worker-core can't register validate_findings and
        # every auto-enqueued validation is dropped (KeyError: unregistered task),
        # leaving findings UNVERIFIED with no hackable label.
        "pencheff_api.tasks.validate_task",
        # Async bulk fix-all (router enqueues, worker processes,
        # frontend polls — keeps long batches off the request thread).
        "pencheff_api.tasks.bulk_fix_task",
        # Agentic fix-all (server runtime): the loop task the
        # agentic_fix router enqueues by name. Without this include the
        # worker can't register run_agentic_fix_task and the run stays
        # queued forever (KeyError: unregistered task).
        "pencheff_api.tasks.agentic_fix_task",
        # Engagements
        "pencheff_api.tasks.intruder_task",
        "pencheff_api.tasks.correlation_task",
        "pencheff_api.tasks.retention_task",
        # OpenTelemetry partition pre-create + retention pass
        "pencheff_api.tasks.observability_retention_task",
        # Transactional + scheduled email dispatch (Resend)
        "pencheff_api.tasks.email_task",
        # Security Lake — OCSF Iceberg ingestion after each scan
        "pencheff_api.tasks.security_lake_ingest_task",
        # SSO domain reverification
        # Support-portal outbound email notifications.
        # On-demand audit export to S3
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # The worker fleet is split one service per security category. Scan tasks
    # are enqueued with an explicit ``queue=cat_<category>`` (see
    # ``services.scan_dispatch``); everything else — reports, fixes, campaigns,
    # email, retention, beat — has no explicit queue and falls through here to
    # ``core``, served by ``worker-core``. Before the split this was the single
    # default ``celery`` queue.
    task_default_queue="core",
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    # Long scans: 1 hour soft, 1.5 hr hard
    task_soft_time_limit=3600,
    task_time_limit=5400,
    # ── Resilience to broker hiccups ─────────────────────────────────
    # The worker has historically died with
    #   redis.exceptions.ResponseError: UNBLOCKED force unblock from
    #   blocking operation, instance state changed (master -> replica?)
    # whenever Redis was restarted or failed over under a blocking
    # BRPOP. Combined with docker-compose's default no-restart policy
    # that left the container dead until manual intervention.
    # The flags below tell Celery to retry the broker connection on
    # startup AND on disconnect, do periodic health checks, and cancel
    # any long-running task whose broker connection was severed
    # (instead of crashing the whole worker process).
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=None,  # retry forever
    worker_cancel_long_running_tasks_on_connection_loss=True,
    broker_transport_options={
        "health_check_interval": 10,
        "socket_keepalive": True,
        "visibility_timeout": 5400,  # match task_time_limit
    },
    result_backend_transport_options={
        "health_check_interval": 10,
    },
)

# Periodic task schedule — drives recurring scans and SLA monitoring
celery_app.conf.beat_schedule = {
    "dispatch-due-scans": {
        "task": "pencheff_api.tasks.scheduled_scan_task.dispatch_due_scans",
        "schedule": 60.0,  # every minute
    },
    "sla-breach-monitor": {
        "task": "pencheff_api.tasks.sla_monitor_task.check_sla_breaches",
        "schedule": 3600.0,  # hourly
    },
    "prune-old-traffic": {
        "task": "pencheff.retention.prune_traffic",
        "schedule": 24 * 3600.0,  # nightly
    },
    "reap-closed-engagement-oast": {
        "task": "pencheff.retention.reap_oast",
        "schedule": 6 * 3600.0,  # every 6 hours
    },
    # Recover scans whose worker died mid-flight every 5 minutes.
    "recover-zombie-scans": {
        "task": "pencheff_api.tasks.scan_task.recover_zombie_scans",
        "schedule": 300.0,
    },
    # Pre-create + drop OTel day-partitions hourly. Runs even when
    # observability is disabled (the task short-circuits internally),
    # so flipping the kill-switch on doesn't require a beat restart.
    "prune-otel-partitions": {
        "task": "pencheff.observability.prune_partitions",
        "schedule": 3600.0,
    },
    # Weekly per-target + per-workspace digest. Mondays 09:00 UTC.
    # Walks Target.weekly_digest_emails and Workspace.weekly_digest_emails
    # and dispatches one email per non-empty subscription.
    "weekly-digest": {
        "task": "pencheff_api.tasks.email_task.run_weekly_digest",
        "schedule": crontab(hour=9, minute=0, day_of_week="mon"),
    },
    # Purge lake data for orgs disabled past the 7-day grace.
    "security-lake-retention": {
        "task": "pencheff_api.tasks.security_lake_ingest_task.purge_disabled_lakes",
        "schedule": 24 * 3600.0,  # daily
    },
}


# ── Worker-startup recovery ─────────────────────────────────────────


@worker_ready.connect
def _recover_zombies_on_boot(sender=None, **_kwargs) -> None:
    """When a worker boots, immediately reap any scans/repo-scans that
    were left in ``running`` state by a previous worker that died mid
    flight (rebuild, OOM kill, SIGKILL, …). Without this hook, a single
    container restart leaves dashboards stuck at "In progress · 42%"
    forever.

    The recovery itself is delegated to the scan-task module so the
    Celery app stays a thin import — it imports the task lazily and
    schedules it to run once the worker is up.
    """
    try:
        from .scan_task import recover_zombie_scans
        recover_zombie_scans.delay()
        log.info("queued zombie-scan recovery on worker startup")
    except Exception as exc:  # noqa: BLE001
        log.warning("could not queue zombie-scan recovery: %s", exc)


@task_postrun.connect
def _request_worker_stop_after_task(sender=None, task_id=None, **_kwargs) -> None:
    """Ask the controller to stop the heavy worker after work drains."""
    try:
        from ..services.worker_lifecycle import request_worker_stop_if_idle_sync

        request_worker_stop_if_idle_sync()
    except Exception as exc:  # noqa: BLE001
        log.warning("worker stop-if-idle postrun hook failed for %s: %s", task_id, exc)
