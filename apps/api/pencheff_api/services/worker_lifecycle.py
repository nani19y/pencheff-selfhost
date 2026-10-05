from __future__ import annotations

import asyncio
import http.client
import json
import logging
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import HTTPException, status
from redis import Redis
from sqlalchemy import create_engine, text

from ..config import Settings, get_settings


log = logging.getLogger("pencheff.worker_lifecycle")
DOCKER_REQUEST_TIMEOUT_SECONDS = 5.0


class WorkerLifecycleError(RuntimeError):
    """Raised when the on-demand worker lifecycle cannot fulfill a request."""


@dataclass(frozen=True)
class WorkerIdleState:
    idle: bool
    reasons: list[str]


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str) -> None:
        super().__init__("localhost", timeout=DOCKER_REQUEST_TIMEOUT_SECONDS)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(DOCKER_REQUEST_TIMEOUT_SECONDS)
        self.sock.connect(self.socket_path)


async def ensure_worker_started_for_enqueue(
    settings: Settings | None = None,
    service: str | None = None,
) -> None:
    settings = settings or get_settings()
    if settings.worker_always_on:
        return
    await asyncio.to_thread(_docker_start_worker, settings, service)


def ensure_worker_started_for_enqueue_sync(
    settings: Settings | None = None,
    service: str | None = None,
) -> None:
    settings = settings or get_settings()
    if settings.worker_always_on:
        return
    _docker_start_worker(settings, service)


async def ensure_worker_started_or_503(
    settings: Settings | None = None,
    service: str | None = None,
) -> None:
    try:
        await ensure_worker_started_for_enqueue(settings, service)
    except WorkerLifecycleError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


def request_worker_stop_if_idle_sync(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if settings.worker_always_on:
        return
    if not _docker_socket_available(settings):
        log.info(
            "worker stop-if-idle skipped; Docker socket unavailable at %s",
            settings.docker_socket_path,
        )
        return
    try:
        result = _docker_stop_worker_if_idle(settings)
        log.info("worker stop-if-idle result: %s", result)
    except WorkerLifecycleError as exc:
        log.warning("worker stop-if-idle request failed: %s", exc)


# ── Fleet idle-stop (per-category on-demand workers) ─────────────────
#
# The worker image is split one service per security category. Each category
# worker is started on enqueue (``ensure_worker_started_or_503(service=…)``) and
# stopped here, from the always-up API, when its own queue is drained AND no
# scan of its category is still queued/running. ``worker-core`` is intentionally
# NOT managed here — it stays resident (lean base image; runs beat + support
# tasks + drives this loop's host).


def _category_db_pending(settings: Settings, kinds: list[str]) -> int:
    """Count queued/running scans whose target kind is in ``kinds`` (+ repo
    scans when the category owns ``source_code``). Category-scoped so one
    worker stopping doesn't wait on another category's work."""
    if not kinds:
        return 0
    engine = create_engine(settings.sync_database_url, future=True)
    try:
        with engine.begin() as conn:
            scan_count = conn.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM scans s
                    JOIN targets t ON t.id = s.target_id
                    WHERE s.status IN ('queued', 'running')
                      AND COALESCE(s.kind_payload->>'source', '') != 'mcp'
                      AND t.kind = ANY(:kinds)
                    """
                ),
                {"kinds": kinds},
            ).scalar_one()
            repo_count = 0
            if "source_code" in kinds:
                repo_count = conn.execute(
                    text(
                        "SELECT COUNT(*) FROM repo_scans "
                        "WHERE status IN ('queued', 'running')"
                    )
                ).scalar_one()
        return int(scan_count or 0) + int(repo_count or 0)
    finally:
        engine.dispose()


def _redis_queue_len(settings: Settings, queue: str) -> int:
    client = Redis.from_url(settings.redis_url)
    try:
        return int(client.llen(queue) or 0)
    finally:
        client.close()


def request_fleet_stop_if_idle_sync(settings: Settings | None = None) -> None:
    """Stop every on-demand category worker whose queue + category work is idle.

    Best-effort per service — a lookup/stop failure for one worker is logged and
    the loop moves on to the next. No-op when workers are always-on or the
    Docker socket is unavailable.
    """
    settings = settings or get_settings()
    if settings.worker_always_on:
        return
    if not _docker_socket_available(settings):
        return
    from ..scan_categories import CATEGORY_KINDS, CATEGORY_QUEUE, CATEGORY_SERVICE

    for category, service in CATEGORY_SERVICE.items():
        queue = CATEGORY_QUEUE[category]
        kinds = CATEGORY_KINDS.get(category, [])
        if _redis_queue_len(settings, queue) or _category_db_pending(settings, kinds):
            continue
        try:
            # Stop the (possibly already-stopped) container; Docker returns 304
            # for a no-op, which _docker_request treats as success.
            container_id = _find_worker_container_id(settings, service)
            status_code, payload = _docker_request(
                settings, "POST", f"/containers/{container_id}/stop?t=10"
            )
            if status_code not in (204, 304):
                log.warning(
                    "fleet stop of %s failed with HTTP %s: %s",
                    service, status_code, payload.decode("utf-8", "replace"),
                )
        except WorkerLifecycleError as exc:
            log.warning("fleet stop of %s skipped: %s", service, exc)


async def run_worker_idle_stop_loop(interval_seconds: float | None = None) -> None:
    settings = get_settings()
    interval = interval_seconds
    if interval is None:
        interval = max(float(settings.worker_idle_grace_seconds), 1.0)

    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(request_fleet_stop_if_idle_sync, settings)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("worker idle-stop loop failed: %s", exc)


def is_worker_idle_sync(settings: Settings | None = None) -> WorkerIdleState:
    settings = settings or get_settings()
    reasons: list[str] = []
    db_pending = _count_pending_db_work(settings)
    redis_pending = _redis_pending_count(settings)
    if db_pending:
        reasons.append(f"database_pending={db_pending}")
    if redis_pending:
        reasons.append(f"redis_pending={redis_pending}")
    return WorkerIdleState(idle=not reasons, reasons=reasons)


def _count_pending_db_work(settings: Settings) -> int:
    engine = create_engine(settings.sync_database_url, future=True)
    try:
        with engine.begin() as conn:
            scan_count = conn.execute(text("""
                SELECT COUNT(*)
                FROM scans
                WHERE status IN ('queued', 'running')
                  AND COALESCE(kind_payload->>'source', '') != 'mcp'
            """)).scalar_one()
            repo_scan_count = conn.execute(text("""
                SELECT COUNT(*)
                FROM repo_scans
                WHERE status IN ('queued', 'running')
            """)).scalar_one()
        return int(scan_count or 0) + int(repo_scan_count or 0)
    finally:
        engine.dispose()


def _redis_pending_count(settings: Settings) -> int:
    client = Redis.from_url(settings.redis_url)
    try:
        # Check THIS worker's own queue (each category worker consumes a
        # distinct queue; core consumes "core"). ``unacked_*`` is fleet-wide,
        # so a worker also stays warm while any sibling has an in-flight task —
        # conservative but never stops a worker mid-scan.
        queued = int(client.llen(settings.worker_queue) or 0)
        unacked_index = int(client.zcard("unacked_index") or 0)
        unacked_hash = int(client.hlen("unacked") or 0)
        return queued + unacked_index + unacked_hash
    finally:
        client.close()


def _docker_socket_available(settings: Settings) -> bool:
    return Path(settings.docker_socket_path).exists()


def _docker_request(
    settings: Settings,
    method: str,
    path: str,
    body: bytes | None = None,
) -> tuple[int, bytes]:
    conn = UnixSocketHTTPConnection(settings.docker_socket_path)
    try:
        headers = {"Host": "docker"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        payload = response.read()
        return response.status, payload
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise WorkerLifecycleError(f"Docker request failed: {type(exc).__name__}") from exc
    finally:
        conn.close()


def _malformed_container_lookup() -> WorkerLifecycleError:
    return WorkerLifecycleError("Docker container lookup returned malformed data")


def _find_worker_container_id(settings: Settings, service: str | None = None) -> str:
    labels = [
        f"com.docker.compose.service={service or settings.worker_compose_service}",
        f"com.docker.compose.project={settings.worker_compose_project}",
    ]
    filters = quote(json.dumps({"label": labels}))
    status_code, payload = _docker_request(
        settings,
        "GET",
        f"/containers/json?all=1&filters={filters}",
    )
    if status_code != 200:
        raise WorkerLifecycleError(
            f"Docker container lookup failed with HTTP {status_code}",
        )
    try:
        containers = json.loads(payload.decode("utf-8") or "[]")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _malformed_container_lookup() from exc
    if not isinstance(containers, list):
        raise _malformed_container_lookup()
    if not containers:
        raise WorkerLifecycleError(
            "worker container not found; run docker compose up once so "
            "the worker service container exists",
        )
    container = containers[0]
    if not isinstance(container, dict):
        raise _malformed_container_lookup()
    container_id = container.get("Id")
    if not isinstance(container_id, str) or not container_id:
        raise _malformed_container_lookup()
    return container_id


def _docker_start_worker(settings: Settings, service: str | None = None) -> dict[str, Any]:
    container_id = _find_worker_container_id(settings, service)
    status_code, payload = _docker_request(
        settings,
        "POST",
        f"/containers/{container_id}/start",
    )
    if status_code in (204, 304):
        return {"started": True, "container_id": container_id, "docker_status": status_code}
    raise WorkerLifecycleError(
        f"Docker start failed with HTTP {status_code}: {payload.decode('utf-8', 'replace')}",
    )


def _docker_stop_worker_if_idle(settings: Settings) -> dict[str, Any]:
    idle = is_worker_idle_sync(settings)
    if not idle.idle:
        return {"stopped": False, "reasons": idle.reasons}
    container_id = _find_worker_container_id(settings)
    status_code, payload = _docker_request(
        settings,
        "POST",
        f"/containers/{container_id}/stop?t=10",
    )
    if status_code in (204, 304):
        return {"stopped": True, "container_id": container_id, "reasons": []}
    raise WorkerLifecycleError(
        f"Docker stop failed with HTTP {status_code}: {payload.decode('utf-8', 'replace')}",
    )
