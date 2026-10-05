# On-Demand Worker Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an env-gated on-demand lifecycle so the heavy Celery worker starts when scan or scan-adjacent work is queued and stops after that work drains.

**Architecture:** Keep `WORKER_ALWAYS_ON=true` as the default and no-op lifecycle mode. When `WORKER_ALWAYS_ON=false`, the API and API-side scheduler call a private `worker-controller` sidecar before queueing work; Celery `task_postrun` requests a debounced stop, and the controller stops only when database and Redis checks are idle. The controller reuses the lean API image and talks to Docker through `/var/run/docker.sock`, so the API container never receives Docker host control.

**Tech Stack:** FastAPI, Celery, SQLAlchemy, Redis, Docker Engine Unix socket API, Docker Compose, pytest.

---

## File Structure

- Create `apps/api/pencheff_api/services/worker_lifecycle.py`: public worker lifecycle client, idle detector, and 503 helper used by API routes and Celery.
- Create `apps/api/pencheff_api/worker_controller.py`: internal FastAPI app that starts/stops the Compose worker container through Docker's Unix socket API.
- Create `apps/api/pencheff_api/services/on_demand_scheduler.py`: API-side schedule loop for `WORKER_ALWAYS_ON=false`.
- Modify `apps/api/pencheff_api/config.py`: lifecycle settings.
- Modify `apps/api/pencheff_api/main.py`: start/stop API-side schedule loop.
- Modify `apps/api/pencheff_api/tasks/celery_app.py`: Celery post-run stop request.
- Modify `apps/api/pencheff_api/tasks/scheduled_scan_task.py`: move schedule dispatch into reusable sync function.
- Modify API enqueue sites in `apps/api/pencheff_api/routers/*.py`: call the lifecycle helper before queueing Celery work.
- Modify `docker-compose.yml`: add `worker-controller`, pass lifecycle env vars, and mount the Docker socket only into the controller.
- Modify `.env.example`: document lifecycle settings.
- Add focused tests under `apps/api/tests/`.

## Task 1: Settings and Env Contract

**Files:**
- Modify: `apps/api/pencheff_api/config.py`
- Modify: `.env.example`
- Test: `apps/api/tests/test_worker_lifecycle_config.py`

- [ ] **Step 1: Write the failing settings tests**

Create `apps/api/tests/test_worker_lifecycle_config.py`:

```python
from __future__ import annotations

from pencheff_api.config import Settings


def test_worker_lifecycle_defaults_preserve_always_on() -> None:
    settings = Settings()

    assert settings.worker_always_on is True
    assert settings.worker_controller_url == "http://worker-controller:8080"
    assert settings.worker_idle_grace_seconds == 30
    assert settings.worker_controller_token == ""
    assert settings.docker_socket_path == "/var/run/docker.sock"
    assert settings.worker_compose_project == "pencheff"
    assert settings.worker_compose_service == "worker"


def test_worker_lifecycle_env_can_disable_always_on(monkeypatch) -> None:
    monkeypatch.setenv("WORKER_ALWAYS_ON", "false")
    monkeypatch.setenv("WORKER_CONTROLLER_URL", "http://controller.local:9000")
    monkeypatch.setenv("WORKER_IDLE_GRACE_SECONDS", "7")
    monkeypatch.setenv("WORKER_CONTROLLER_TOKEN", "internal-token")
    monkeypatch.setenv("DOCKER_SOCKET_PATH", "/tmp/docker.sock")
    monkeypatch.setenv("WORKER_COMPOSE_PROJECT", "custom")
    monkeypatch.setenv("WORKER_COMPOSE_SERVICE", "scanner")

    settings = Settings()

    assert settings.worker_always_on is False
    assert settings.worker_controller_url == "http://controller.local:9000"
    assert settings.worker_idle_grace_seconds == 7
    assert settings.worker_controller_token == "internal-token"
    assert settings.docker_socket_path == "/tmp/docker.sock"
    assert settings.worker_compose_project == "custom"
    assert settings.worker_compose_service == "scanner"
```

- [ ] **Step 2: Run the settings tests and verify they fail**

Run:

```bash
cd apps/api && pytest tests/test_worker_lifecycle_config.py -q
```

Expected: FAIL because `Settings` has no `worker_always_on` field.

- [ ] **Step 3: Add lifecycle settings**

In `apps/api/pencheff_api/config.py`, add this block after `redis_url`:

```python
    # Heavy Celery worker lifecycle. Default preserves the current
    # self-hosted deployment where the worker is always running.
    worker_always_on: bool = Field(True, alias="WORKER_ALWAYS_ON")
    worker_controller_url: str = Field(
        "http://worker-controller:8080",
        alias="WORKER_CONTROLLER_URL",
    )
    worker_controller_token: str = Field("", alias="WORKER_CONTROLLER_TOKEN")
    worker_idle_grace_seconds: int = Field(30, alias="WORKER_IDLE_GRACE_SECONDS")
    docker_socket_path: str = Field("/var/run/docker.sock", alias="DOCKER_SOCKET_PATH")
    worker_compose_project: str = Field("pencheff", alias="WORKER_COMPOSE_PROJECT")
    worker_compose_service: str = Field("worker", alias="WORKER_COMPOSE_SERVICE")
```

Add this section to `.env.example` after `FREE_PLAN_OPTION_3_QUOTA=10`:

```env
# Heavy Celery worker lifecycle.
# true  = current behavior: keep the toolchain worker running.
# false = API/controller starts the worker only for queued work and stops it
#         after scans and scan-adjacent tasks drain.
WORKER_ALWAYS_ON=true
WORKER_CONTROLLER_URL=http://worker-controller:8080
WORKER_CONTROLLER_TOKEN=
WORKER_IDLE_GRACE_SECONDS=30
WORKER_COMPOSE_PROJECT=pencheff
WORKER_COMPOSE_SERVICE=worker
```

- [ ] **Step 4: Run the settings tests and verify they pass**

Run:

```bash
cd apps/api && pytest tests/test_worker_lifecycle_config.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/config.py .env.example apps/api/tests/test_worker_lifecycle_config.py
git commit -m "feat: add worker lifecycle settings"
```

## Task 2: Lifecycle Client and Idle Detector

**Files:**
- Create: `apps/api/pencheff_api/services/worker_lifecycle.py`
- Test: `apps/api/tests/test_worker_lifecycle_service.py`

- [ ] **Step 1: Write the failing service tests**

Create `apps/api/tests/test_worker_lifecycle_service.py`:

```python
from __future__ import annotations

import pytest

from pencheff_api.config import Settings
from pencheff_api.services import worker_lifecycle as wl


def _settings(**overrides):
    data = {
        "worker_always_on": True,
        "worker_controller_url": "http://worker-controller:8080",
        "worker_controller_token": "",
        "worker_idle_grace_seconds": 30,
        "database_url": "postgresql+asyncpg://u:p@db:5432/app",
        "redis_url": "redis://redis:6379/0",
    }
    data.update(overrides)
    return Settings(**data)


@pytest.mark.asyncio
async def test_start_noops_when_worker_is_always_on(monkeypatch) -> None:
    async def boom(*args, **kwargs):
        raise AssertionError("controller must not be called")

    monkeypatch.setattr(wl, "_post_controller_async", boom)

    await wl.ensure_worker_started_for_enqueue(
        _settings(worker_always_on=True),
    )


@pytest.mark.asyncio
async def test_start_calls_controller_when_worker_is_on_demand(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_post(settings, path):
        calls.append(path)
        return {"ok": True}

    monkeypatch.setattr(wl, "_post_controller_async", fake_post)

    await wl.ensure_worker_started_for_enqueue(
        _settings(worker_always_on=False),
    )

    assert calls == ["/worker/start"]


@pytest.mark.asyncio
async def test_start_surfaces_controller_failure(monkeypatch) -> None:
    async def fake_post(settings, path):
        raise wl.WorkerLifecycleError("worker controller unavailable")

    monkeypatch.setattr(wl, "_post_controller_async", fake_post)

    with pytest.raises(wl.WorkerLifecycleError, match="worker controller unavailable"):
        await wl.ensure_worker_started_for_enqueue(
            _settings(worker_always_on=False),
        )


def test_idle_detector_refuses_to_stop_when_database_has_work(monkeypatch) -> None:
    monkeypatch.setattr(wl, "_count_pending_db_work", lambda settings: 1)
    monkeypatch.setattr(wl, "_redis_pending_count", lambda settings: 0)

    state = wl.is_worker_idle_sync(_settings(worker_always_on=False))

    assert state.idle is False
    assert state.reasons == ["database_pending=1"]


def test_idle_detector_refuses_to_stop_when_redis_has_work(monkeypatch) -> None:
    monkeypatch.setattr(wl, "_count_pending_db_work", lambda settings: 0)
    monkeypatch.setattr(wl, "_redis_pending_count", lambda settings: 2)

    state = wl.is_worker_idle_sync(_settings(worker_always_on=False))

    assert state.idle is False
    assert state.reasons == ["redis_pending=2"]


def test_idle_detector_allows_stop_when_database_and_redis_are_idle(monkeypatch) -> None:
    monkeypatch.setattr(wl, "_count_pending_db_work", lambda settings: 0)
    monkeypatch.setattr(wl, "_redis_pending_count", lambda settings: 0)

    state = wl.is_worker_idle_sync(_settings(worker_always_on=False))

    assert state.idle is True
    assert state.reasons == []
```

- [ ] **Step 2: Run the service tests and verify they fail**

Run:

```bash
cd apps/api && pytest tests/test_worker_lifecycle_service.py -q
```

Expected: FAIL because `pencheff_api.services.worker_lifecycle` does not exist.

- [ ] **Step 3: Implement the lifecycle service**

Create `apps/api/pencheff_api/services/worker_lifecycle.py`:

```python
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import HTTPException, status
from redis import Redis
from sqlalchemy import create_engine, text

from ..config import Settings, get_settings


log = logging.getLogger("pencheff.worker_lifecycle")


class WorkerLifecycleError(RuntimeError):
    """Raised when the on-demand worker controller cannot fulfill a request."""


@dataclass(frozen=True)
class WorkerIdleState:
    idle: bool
    reasons: list[str]


def _headers(settings: Settings) -> dict[str, str]:
    if not settings.worker_controller_token:
        return {}
    return {"X-Worker-Controller-Token": settings.worker_controller_token}


async def _post_controller_async(settings: Settings, path: str) -> dict[str, Any]:
    url = settings.worker_controller_url.rstrip("/") + path
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, headers=_headers(settings))
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        raise WorkerLifecycleError(f"worker lifecycle request failed: {url}: {exc}") from exc
    if isinstance(data, dict):
        return data
    return {"ok": True}


def _post_controller_sync(settings: Settings, path: str) -> dict[str, Any]:
    url = settings.worker_controller_url.rstrip("/") + path
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(url, headers=_headers(settings))
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        raise WorkerLifecycleError(f"worker lifecycle request failed: {url}: {exc}") from exc
    if isinstance(data, dict):
        return data
    return {"ok": True}


async def ensure_worker_started_for_enqueue(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if settings.worker_always_on:
        return
    await _post_controller_async(settings, "/worker/start")


def ensure_worker_started_for_enqueue_sync(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if settings.worker_always_on:
        return
    _post_controller_sync(settings, "/worker/start")


async def ensure_worker_started_or_503(settings: Settings | None = None) -> None:
    try:
        await ensure_worker_started_for_enqueue(settings)
    except WorkerLifecycleError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


def request_worker_stop_if_idle_sync(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if settings.worker_always_on:
        return
    try:
        _post_controller_sync(settings, "/worker/stop-if-idle")
    except WorkerLifecycleError as exc:
        log.warning("worker stop-if-idle request failed: %s", exc)


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
    with engine.begin() as conn:
        scan_count = conn.execute(text("""
            SELECT COUNT(*)
            FROM scans
            WHERE status IN ('queued', 'running')
        """)).scalar_one()
        repo_scan_count = conn.execute(text("""
            SELECT COUNT(*)
            FROM repo_scans
            WHERE status IN ('queued', 'running')
        """)).scalar_one()
    return int(scan_count or 0) + int(repo_scan_count or 0)


def _redis_pending_count(settings: Settings) -> int:
    client = Redis.from_url(settings.redis_url)
    try:
        queued = int(client.llen("celery") or 0)
        unacked_index = int(client.zcard("unacked_index") or 0)
        unacked_hash = int(client.hlen("unacked") or 0)
        return queued + unacked_index + unacked_hash
    finally:
        client.close()
```

- [ ] **Step 4: Run the service tests and verify they pass**

Run:

```bash
cd apps/api && pytest tests/test_worker_lifecycle_service.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/services/worker_lifecycle.py apps/api/tests/test_worker_lifecycle_service.py
git commit -m "feat: add worker lifecycle service"
```

## Task 3: Worker Controller Sidecar App

**Files:**
- Create: `apps/api/pencheff_api/worker_controller.py`
- Test: `apps/api/tests/test_worker_controller.py`

- [ ] **Step 1: Write the failing controller tests**

Create `apps/api/tests/test_worker_controller.py`:

```python
from __future__ import annotations

from fastapi.testclient import TestClient

from pencheff_api import worker_controller as wc
from pencheff_api.config import Settings
from pencheff_api.services.worker_lifecycle import WorkerIdleState


def _settings(**overrides):
    data = {
        "worker_always_on": False,
        "worker_controller_token": "",
        "worker_idle_grace_seconds": 0,
        "worker_compose_project": "pencheff",
        "worker_compose_service": "worker",
        "docker_socket_path": "/tmp/docker.sock",
    }
    data.update(overrides)
    return Settings(**data)


def test_start_starts_worker_container(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    monkeypatch.setattr(wc, "settings", _settings())
    monkeypatch.setattr(
        wc,
        "_find_worker_container_id",
        lambda: "container-1",
    )
    monkeypatch.setattr(
        wc,
        "_docker_request",
        lambda method, path, body=None: calls.append((method, path)) or (204, b""),
    )

    response = TestClient(wc.app).post("/worker/start")

    assert response.status_code == 200
    assert response.json()["started"] is True
    assert calls == [("POST", "/containers/container-1/start")]


def test_stop_if_idle_schedules_debounced_stop(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    monkeypatch.setattr(wc, "settings", _settings())
    monkeypatch.setattr(wc, "_find_worker_container_id", lambda: "container-1")
    monkeypatch.setattr(
        wc,
        "is_worker_idle_sync",
        lambda settings: WorkerIdleState(idle=True, reasons=[]),
    )
    monkeypatch.setattr(
        wc,
        "_docker_request",
        lambda method, path, body=None: calls.append((method, path)) or (204, b""),
    )

    response = TestClient(wc.app).post("/worker/stop-now-for-test")

    assert response.status_code == 200
    assert response.json()["stopped"] is True
    assert calls == [("POST", "/containers/container-1/stop?t=10")]


def test_stop_if_idle_refuses_when_not_idle(monkeypatch) -> None:
    monkeypatch.setattr(wc, "settings", _settings())
    monkeypatch.setattr(
        wc,
        "is_worker_idle_sync",
        lambda settings: WorkerIdleState(idle=False, reasons=["database_pending=1"]),
    )

    response = TestClient(wc.app).post("/worker/stop-now-for-test")

    assert response.status_code == 200
    assert response.json() == {
        "stopped": False,
        "reasons": ["database_pending=1"],
    }


def test_token_is_required_when_configured(monkeypatch) -> None:
    monkeypatch.setattr(
        wc,
        "settings",
        _settings(worker_controller_token="secret"),
    )

    response = TestClient(wc.app).post("/worker/start")

    assert response.status_code == 401


def test_token_auth_accepts_configured_header(monkeypatch) -> None:
    monkeypatch.setattr(
        wc,
        "settings",
        _settings(worker_controller_token="secret"),
    )
    monkeypatch.setattr(wc, "_find_worker_container_id", lambda: "container-1")
    monkeypatch.setattr(
        wc,
        "_docker_request",
        lambda method, path, body=None: (204, b""),
    )

    response = TestClient(wc.app).post(
        "/worker/start",
        headers={"X-Worker-Controller-Token": "secret"},
    )

    assert response.status_code == 200
```

- [ ] **Step 2: Run the controller tests and verify they fail**

Run:

```bash
cd apps/api && pytest tests/test_worker_controller.py -q
```

Expected: FAIL because `pencheff_api.worker_controller` does not exist.

- [ ] **Step 3: Implement the controller**

Create `apps/api/pencheff_api/worker_controller.py`:

```python
from __future__ import annotations

import asyncio
import http.client
import json
import logging
import socket
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, Header, HTTPException, status

from .config import get_settings
from .services.worker_lifecycle import is_worker_idle_sync


log = logging.getLogger("pencheff.worker_controller")
settings = get_settings()
app = FastAPI(title="Pencheff Worker Controller")
_stop_task: asyncio.Task | None = None
_stop_lock = asyncio.Lock()


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str) -> None:
        super().__init__("localhost")
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)


def _authorize(token: str | None) -> None:
    expected = settings.worker_controller_token
    if expected and token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid worker controller token",
        )


def _docker_request(method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
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
    finally:
        conn.close()


def _find_worker_container_id() -> str:
    labels = [
        f"com.docker.compose.service={settings.worker_compose_service}",
        f"com.docker.compose.project={settings.worker_compose_project}",
    ]
    filters = quote(json.dumps({"label": labels}))
    status_code, payload = _docker_request(
        "GET",
        f"/containers/json?all=1&filters={filters}",
    )
    if status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Docker container lookup failed with HTTP {status_code}",
        )
    containers = json.loads(payload.decode("utf-8") or "[]")
    if not containers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "worker container not found; run docker compose up once so "
                "the worker service container exists"
            ),
        )
    return str(containers[0]["Id"])


def _docker_start_worker() -> dict[str, Any]:
    container_id = _find_worker_container_id()
    status_code, payload = _docker_request("POST", f"/containers/{container_id}/start")
    if status_code in (204, 304):
        return {"started": True, "container_id": container_id, "docker_status": status_code}
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"Docker start failed with HTTP {status_code}: {payload.decode('utf-8', 'replace')}",
    )


def _docker_stop_worker_if_idle() -> dict[str, Any]:
    idle = is_worker_idle_sync(settings)
    if not idle.idle:
        return {"stopped": False, "reasons": idle.reasons}
    container_id = _find_worker_container_id()
    status_code, payload = _docker_request("POST", f"/containers/{container_id}/stop?t=10")
    if status_code in (204, 304):
        return {"stopped": True, "container_id": container_id, "reasons": []}
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"Docker stop failed with HTTP {status_code}: {payload.decode('utf-8', 'replace')}",
    )


async def _delayed_stop() -> None:
    await asyncio.sleep(max(settings.worker_idle_grace_seconds, 0))
    try:
        result = await asyncio.to_thread(_docker_stop_worker_if_idle)
        log.info("worker stop-if-idle result: %s", result)
    except Exception as exc:
        log.warning("worker stop-if-idle failed: %s", exc)


@app.on_event("startup")
async def _stop_on_boot_when_on_demand() -> None:
    if settings.worker_always_on:
        return
    asyncio.create_task(_delayed_stop())


@app.get("/healthz")
async def healthz() -> dict[str, bool]:
    return {"ok": True}


@app.post("/worker/start")
async def start_worker(
    x_worker_controller_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _authorize(x_worker_controller_token)
    return await asyncio.to_thread(_docker_start_worker)


@app.post("/worker/stop-if-idle")
async def stop_worker_if_idle(
    x_worker_controller_token: str | None = Header(default=None),
) -> dict[str, bool]:
    _authorize(x_worker_controller_token)
    global _stop_task
    async with _stop_lock:
        if _stop_task and not _stop_task.done():
            _stop_task.cancel()
        _stop_task = asyncio.create_task(_delayed_stop())
    return {"scheduled": True}


@app.post("/worker/stop-now-for-test")
async def stop_worker_now_for_test(
    x_worker_controller_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _authorize(x_worker_controller_token)
    return await asyncio.to_thread(_docker_stop_worker_if_idle)
```

- [ ] **Step 4: Run the controller tests and verify they pass**

Run:

```bash
cd apps/api && pytest tests/test_worker_controller.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/worker_controller.py apps/api/tests/test_worker_controller.py
git commit -m "feat: add worker controller sidecar app"
```

## Task 4: Compose Wiring

**Files:**
- Modify: `docker-compose.yml`
- Test: `apps/api/tests/test_worker_lifecycle_compose.py`

- [ ] **Step 1: Write the failing Compose contract test**

Create `apps/api/tests/test_worker_lifecycle_compose.py`:

```python
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def test_compose_defines_worker_controller_without_publishing_port() -> None:
    text = (ROOT / "docker-compose.yml").read_text()

    assert "worker-controller:" in text
    assert "uvicorn pencheff_api.worker_controller:app --host 0.0.0.0 --port 8080" in text
    assert "/var/run/docker.sock:/var/run/docker.sock" in text
    controller_block = text.split("worker-controller:", 1)[1].split("\n  docs:", 1)[0]
    assert "ports:" not in controller_block


def test_compose_passes_worker_lifecycle_env_to_api_worker_and_controller() -> None:
    text = (ROOT / "docker-compose.yml").read_text()

    assert text.count("WORKER_ALWAYS_ON: ${WORKER_ALWAYS_ON:-true}") >= 3
    assert text.count("WORKER_CONTROLLER_URL: ${WORKER_CONTROLLER_URL:-http://worker-controller:8080}") >= 3
    assert text.count("WORKER_CONTROLLER_TOKEN: ${WORKER_CONTROLLER_TOKEN:-}") >= 3
    assert text.count("WORKER_IDLE_GRACE_SECONDS: ${WORKER_IDLE_GRACE_SECONDS:-30}") >= 3
```

- [ ] **Step 2: Run the Compose contract test and verify it fails**

Run:

```bash
cd apps/api && pytest tests/test_worker_lifecycle_compose.py -q
```

Expected: FAIL because `worker-controller` is not in Compose.

- [ ] **Step 3: Add lifecycle env vars to `api`**

In `docker-compose.yml`, add this block inside `api.environment` after `REDIS_URL`:

```yaml
      WORKER_ALWAYS_ON: ${WORKER_ALWAYS_ON:-true}
      WORKER_CONTROLLER_URL: ${WORKER_CONTROLLER_URL:-http://worker-controller:8080}
      WORKER_CONTROLLER_TOKEN: ${WORKER_CONTROLLER_TOKEN:-}
      WORKER_IDLE_GRACE_SECONDS: ${WORKER_IDLE_GRACE_SECONDS:-30}
      WORKER_COMPOSE_PROJECT: ${WORKER_COMPOSE_PROJECT:-pencheff}
      WORKER_COMPOSE_SERVICE: ${WORKER_COMPOSE_SERVICE:-worker}
```

- [ ] **Step 4: Add lifecycle env vars to `worker`**

In `docker-compose.yml`, add the same block inside `worker.environment` after `REDIS_URL`:

```yaml
      WORKER_ALWAYS_ON: ${WORKER_ALWAYS_ON:-true}
      WORKER_CONTROLLER_URL: ${WORKER_CONTROLLER_URL:-http://worker-controller:8080}
      WORKER_CONTROLLER_TOKEN: ${WORKER_CONTROLLER_TOKEN:-}
      WORKER_IDLE_GRACE_SECONDS: ${WORKER_IDLE_GRACE_SECONDS:-30}
      WORKER_COMPOSE_PROJECT: ${WORKER_COMPOSE_PROJECT:-pencheff}
      WORKER_COMPOSE_SERVICE: ${WORKER_COMPOSE_SERVICE:-worker}
```

- [ ] **Step 5: Add `worker-controller` service**

Insert this service after `worker` and before the web/docs comment:

```yaml
  worker-controller:
    restart: unless-stopped
    build:
      context: .
      dockerfile: apps/api/Dockerfile
    env_file:
      - path: .env
        required: false
      - path: apps/api/.env
        required: false
    environment:
      DATABASE_URL: postgresql+asyncpg://pencheff:pencheff@postgres:5432/pencheff
      REDIS_URL: redis://redis:6379/0
      WORKER_ALWAYS_ON: ${WORKER_ALWAYS_ON:-true}
      WORKER_CONTROLLER_URL: ${WORKER_CONTROLLER_URL:-http://worker-controller:8080}
      WORKER_CONTROLLER_TOKEN: ${WORKER_CONTROLLER_TOKEN:-}
      WORKER_IDLE_GRACE_SECONDS: ${WORKER_IDLE_GRACE_SECONDS:-30}
      WORKER_COMPOSE_PROJECT: ${WORKER_COMPOSE_PROJECT:-pencheff}
      WORKER_COMPOSE_SERVICE: ${WORKER_COMPOSE_SERVICE:-worker}
      DOCKER_SOCKET_PATH: /var/run/docker.sock
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: uvicorn pencheff_api.worker_controller:app --host 0.0.0.0 --port 8080
```

- [ ] **Step 6: Run the Compose contract test and verify it passes**

Run:

```bash
cd apps/api && pytest tests/test_worker_lifecycle_compose.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add docker-compose.yml apps/api/tests/test_worker_lifecycle_compose.py
git commit -m "feat: wire worker controller into compose"
```

## Task 5: API Enqueue Hooks

**Files:**
- Modify: `apps/api/pencheff_api/routers/scans.py`
- Modify: `apps/api/pencheff_api/routers/repos.py`
- Modify: `apps/api/pencheff_api/routers/github_webhooks.py`
- Modify: `apps/api/pencheff_api/routers/reports.py`
- Modify: `apps/api/pencheff_api/routers/findings.py`
- Modify: `apps/api/pencheff_api/routers/fix_proposals.py`
- Modify: `apps/api/pencheff_api/routers/agentic_fix.py`
- Modify: `apps/api/pencheff_api/routers/intruder.py`
- Modify: `apps/api/pencheff_api/routers/assets.py`
- Modify: `apps/api/pencheff_api/routers/registries.py`
- Test: `apps/api/tests/test_worker_lifecycle_enqueue_hooks.py`

- [ ] **Step 1: Write the failing enqueue hook tests**

Create `apps/api/tests/test_worker_lifecycle_enqueue_hooks.py`:

```python
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def _read(path: str) -> str:
    return (ROOT / path).read_text()


def test_manual_scan_router_starts_worker_before_delay() -> None:
    text = _read("apps/api/pencheff_api/routers/scans.py")
    assert "from ..services.worker_lifecycle import ensure_worker_started_or_503" in text
    assert text.index("await ensure_worker_started_or_503()") < text.index("run_full_scan.delay(scan.id)")


def test_repo_router_starts_worker_before_repo_scan_delay() -> None:
    text = _read("apps/api/pencheff_api/routers/repos.py")
    assert "from ..services.worker_lifecycle import ensure_worker_started_or_503" in text
    assert text.index("await ensure_worker_started_or_503()") < text.index("run_repo_scan.delay(scan.id)")


def test_api_enqueue_routes_use_lifecycle_helper() -> None:
    expected = {
        "apps/api/pencheff_api/routers/github_webhooks.py": "ensure_worker_started_or_503",
        "apps/api/pencheff_api/routers/reports.py": "ensure_worker_started_or_503",
        "apps/api/pencheff_api/routers/agentic_fix.py": "ensure_worker_started_or_503",
        "apps/api/pencheff_api/routers/intruder.py": "ensure_worker_started_or_503",
        "apps/api/pencheff_api/routers/assets.py": "ensure_worker_started_or_503",
        "apps/api/pencheff_api/routers/registries.py": "ensure_worker_started_or_503",
        "apps/api/pencheff_api/routers/findings.py": "ensure_worker_started_for_enqueue_sync",
        "apps/api/pencheff_api/routers/fix_proposals.py": "ensure_worker_started_for_enqueue_sync",
    }

    for path, helper_name in expected.items():
        assert helper_name in _read(path), path
```

- [ ] **Step 2: Run the enqueue hook tests and verify they fail**

Run:

```bash
cd apps/api && pytest tests/test_worker_lifecycle_enqueue_hooks.py -q
```

Expected: FAIL because route files do not import or call the lifecycle helper.

- [ ] **Step 3: Add hooks to async route handlers**

For each async route that enqueues a Celery task directly, import:

```python
from ..services.worker_lifecycle import ensure_worker_started_or_503
```

Insert this call after request validation and before creating a new queued row where the route creates one:

```python
    await ensure_worker_started_or_503()
```

Apply the call in:

- `apps/api/pencheff_api/routers/scans.py` before `scan = Scan(`.
- `apps/api/pencheff_api/routers/repos.py` before `scan = RepoScan(` in the manual repository scan endpoint.
- `apps/api/pencheff_api/routers/github_webhooks.py` before `scan = RepoScan(` in `_handle_push`.
- `apps/api/pencheff_api/routers/reports.py` before `report = Report(`.
- `apps/api/pencheff_api/routers/agentic_fix.py` before `run_agentic_fix_task.delay(run.id)`.
- `apps/api/pencheff_api/routers/intruder.py` before `a = IntruderAttack(`.
- `apps/api/pencheff_api/routers/assets.py` before `run_discovery.delay(workspace.org_id, workspace.id, body.root_domain)`.
- `apps/api/pencheff_api/routers/registries.py` before the existing `celery_app.send_task` call.

- [ ] **Step 4: Add hooks to sync best-effort enqueue helpers**

In `apps/api/pencheff_api/routers/findings.py`, import:

```python
from ..services.worker_lifecycle import ensure_worker_started_for_enqueue_sync
```

Inside `_fire_changed`, insert this line immediately before the existing `notify_event.delay` call:

```python
        ensure_worker_started_for_enqueue_sync()
```

In `apps/api/pencheff_api/routers/fix_proposals.py`, import:

```python
from ..services.worker_lifecycle import ensure_worker_started_for_enqueue_sync
```

Inside `_enqueue_bulk_fix`, insert this line immediately before `run_bulk_fix.delay(task_id)`:

```python
    ensure_worker_started_for_enqueue_sync()
```

- [ ] **Step 5: Run the enqueue hook tests and verify they pass**

Run:

```bash
cd apps/api && pytest tests/test_worker_lifecycle_enqueue_hooks.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/api/pencheff_api/routers apps/api/tests/test_worker_lifecycle_enqueue_hooks.py
git commit -m "feat: start worker before queued API work"
```

## Task 6: API-Side On-Demand Schedule Dispatch

**Files:**
- Create: `apps/api/pencheff_api/services/on_demand_scheduler.py`
- Modify: `apps/api/pencheff_api/tasks/scheduled_scan_task.py`
- Modify: `apps/api/pencheff_api/main.py`
- Test: `apps/api/tests/test_on_demand_schedule_dispatch.py`

- [ ] **Step 1: Write the failing schedule dispatch tests**

Create `apps/api/tests/test_on_demand_schedule_dispatch.py`:

```python
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from pencheff_api.db.base import Base
from pencheff_api.db.models import Scan, ScanSchedule, Target, User, Workspace
from pencheff_api.services.on_demand_scheduler import dispatch_due_scans_sync


def _db_url(tmp_path):
    return f"sqlite:///{tmp_path / 'schedules.db'}"


def _seed_due_schedule(engine):
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        user = User(email="owner@example.com", password_hash="x")
        workspace = Workspace(name="Default", org_id="org1")
        target = Target(
            org_id="org1",
            workspace_id="ws1",
            name="Target",
            url="https://example.com",
            kind="url",
        )
        db.add_all([user, workspace, target])
        db.flush()
        schedule = ScanSchedule(
            org_id="org1",
            workspace_id=workspace.id,
            target_id=target.id,
            owner_user_id=user.id,
            name="Daily",
            cron_expression="0 0 * * *",
            timezone="UTC",
            profile="standard",
            enabled=True,
            next_run_at=now - timedelta(minutes=1),
        )
        db.add(schedule)
        db.commit()
        return schedule.id


def test_dispatch_starts_worker_before_creating_due_scan(tmp_path, monkeypatch) -> None:
    engine = create_engine(_db_url(tmp_path), future=True)
    Base.metadata.create_all(engine)
    _seed_due_schedule(engine)
    calls: list[str] = []

    class _Task:
        def delay(self, scan_id):
            calls.append(f"delay:{scan_id}")

    monkeypatch.setattr(
        "pencheff_api.services.on_demand_scheduler.run_full_scan",
        _Task(),
    )

    result = dispatch_due_scans_sync(
        database_url=_db_url(tmp_path),
        start_worker=lambda: calls.append("start"),
    )

    assert result == {"dispatched": 1}
    assert calls[0] == "start"
    assert calls[1].startswith("delay:")
    with Session(engine) as db:
        assert db.execute(select(Scan)).scalars().one().status == "queued"


def test_dispatch_does_not_advance_schedule_when_worker_start_fails(tmp_path) -> None:
    engine = create_engine(_db_url(tmp_path), future=True)
    Base.metadata.create_all(engine)
    schedule_id = _seed_due_schedule(engine)

    with pytest.raises(RuntimeError, match="controller down"):
        dispatch_due_scans_sync(
            database_url=_db_url(tmp_path),
            start_worker=lambda: (_ for _ in ()).throw(RuntimeError("controller down")),
        )

    with Session(engine) as db:
        schedule = db.get(ScanSchedule, schedule_id)
        assert schedule is not None
        assert schedule.last_run_at is None
        assert db.execute(select(Scan)).scalars().all() == []
```

- [ ] **Step 2: Run the schedule tests and verify they fail**

Run:

```bash
cd apps/api && pytest tests/test_on_demand_schedule_dispatch.py -q
```

Expected: FAIL because `services.on_demand_scheduler` does not exist.

- [ ] **Step 3: Implement reusable schedule dispatch**

Create `apps/api/pencheff_api/services/on_demand_scheduler.py`:

```python
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.models import Scan, ScanSchedule
from ..tasks.scan_task import run_full_scan
from .scheduler import compute_next_run
from .worker_lifecycle import ensure_worker_started_for_enqueue_sync


log = logging.getLogger("pencheff.on_demand_scheduler")


def dispatch_due_scans_sync(
    *,
    database_url: str | None = None,
    start_worker: Callable[[], None] | None = None,
) -> dict[str, int]:
    settings = get_settings()
    db_url = database_url or settings.sync_database_url
    starter = start_worker or ensure_worker_started_for_enqueue_sync
    engine = create_engine(db_url, future=True)
    dispatched = 0

    with Session(engine) as db:
        now = datetime.now(timezone.utc)
        due = db.execute(
            select(ScanSchedule).where(
                ScanSchedule.enabled.is_(True),
                ScanSchedule.next_run_at.isnot(None),
                ScanSchedule.next_run_at <= now,
            )
        ).scalars().all()
        if not due:
            return {"dispatched": 0}

        starter()

        for schedule in due:
            scan = Scan(
                org_id=schedule.org_id,
                workspace_id=schedule.workspace_id,
                target_id=schedule.target_id,
                user_id=schedule.owner_user_id,
                status="queued",
                profile=schedule.profile,
            )
            db.add(scan)
            db.flush()
            run_full_scan.delay(scan.id)
            schedule.last_run_at = now
            schedule.next_run_at = compute_next_run(
                schedule.cron_expression,
                base=now,
                tz=getattr(schedule, "timezone", None) or "UTC",
            )
            dispatched += 1
        db.commit()

    return {"dispatched": dispatched}


async def run_on_demand_schedule_loop(interval_seconds: float = 60.0) -> None:
    while True:
        try:
            result = await asyncio.to_thread(dispatch_due_scans_sync)
            if result.get("dispatched"):
                log.info("dispatched due on-demand schedules: %s", result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("on-demand schedule dispatch failed: %s", exc)
        await asyncio.sleep(interval_seconds)
```

- [ ] **Step 4: Refactor the Celery scheduled task to use the shared dispatcher**

Replace the body of `apps/api/pencheff_api/tasks/scheduled_scan_task.py` with:

```python
"""Celery Beat-driven dispatcher that enqueues scans whose ``next_run_at`` is due."""

from __future__ import annotations

from ..services.on_demand_scheduler import dispatch_due_scans_sync
from .celery_app import celery_app


@celery_app.task(name="pencheff_api.tasks.scheduled_scan_task.dispatch_due_scans")
def dispatch_due_scans() -> dict[str, int]:
    return dispatch_due_scans_sync()
```

- [ ] **Step 5: Start the API-side schedule loop in on-demand mode**

In `apps/api/pencheff_api/main.py`, add this import near the top:

```python
import asyncio
```

Add a module global after `settings = get_settings()`:

```python
_on_demand_scheduler_task: asyncio.Task | None = None
```

Add these event handlers after `_production_safety_check`:

```python
@app.on_event("startup")
async def _start_on_demand_scheduler() -> None:
    global _on_demand_scheduler_task
    if settings.worker_always_on:
        return
    from .services.on_demand_scheduler import run_on_demand_schedule_loop

    _on_demand_scheduler_task = asyncio.create_task(run_on_demand_schedule_loop())
    log.info("started API-side on-demand schedule dispatcher")


@app.on_event("shutdown")
async def _stop_on_demand_scheduler() -> None:
    if _on_demand_scheduler_task is None:
        return
    _on_demand_scheduler_task.cancel()
    try:
        await _on_demand_scheduler_task
    except asyncio.CancelledError:
        pass
```

- [ ] **Step 6: Run the schedule tests and verify they pass**

Run:

```bash
cd apps/api && pytest tests/test_on_demand_schedule_dispatch.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add apps/api/pencheff_api/services/on_demand_scheduler.py apps/api/pencheff_api/tasks/scheduled_scan_task.py apps/api/pencheff_api/main.py apps/api/tests/test_on_demand_schedule_dispatch.py
git commit -m "feat: dispatch schedules from API in on-demand mode"
```

## Task 7: Celery Stop Requests After Task Completion

**Files:**
- Modify: `apps/api/pencheff_api/tasks/celery_app.py`
- Test: `apps/api/tests/test_worker_lifecycle_celery.py`

- [ ] **Step 1: Write the failing Celery hook test**

Create `apps/api/tests/test_worker_lifecycle_celery.py`:

```python
from __future__ import annotations

from pencheff_api.tasks import celery_app as celery_module


def test_task_postrun_requests_worker_stop(monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr(
        "pencheff_api.services.worker_lifecycle.request_worker_stop_if_idle_sync",
        lambda: calls.append("stop-if-idle"),
    )

    celery_module._request_worker_stop_after_task(task_id="task-1", task=None)

    assert calls == ["stop-if-idle"]
```

- [ ] **Step 2: Run the Celery hook test and verify it fails**

Run:

```bash
cd apps/api && pytest tests/test_worker_lifecycle_celery.py -q
```

Expected: FAIL because `_request_worker_stop_after_task` does not exist.

- [ ] **Step 3: Add the Celery postrun hook**

In `apps/api/pencheff_api/tasks/celery_app.py`, change the signals import to:

```python
from celery.signals import task_postrun, worker_process_init, worker_ready
```

Add this function after `_recover_zombies_on_boot`:

```python
@task_postrun.connect
def _request_worker_stop_after_task(sender=None, task_id=None, **_kwargs) -> None:
    """After any Celery task completes, ask the controller to stop the heavy
    worker if on-demand mode is active and no queued/running work remains."""
    try:
        from ..services.worker_lifecycle import request_worker_stop_if_idle_sync

        request_worker_stop_if_idle_sync()
    except Exception as exc:
        log.warning("worker stop-if-idle postrun hook failed for %s: %s", task_id, exc)
```

- [ ] **Step 4: Run the Celery hook test and verify it passes**

Run:

```bash
cd apps/api && pytest tests/test_worker_lifecycle_celery.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/api/pencheff_api/tasks/celery_app.py apps/api/tests/test_worker_lifecycle_celery.py
git commit -m "feat: stop on-demand worker after idle tasks"
```

## Task 8: End-to-End Verification

**Files:**
- No source changes unless a previous task reveals a defect.

- [ ] **Step 1: Run focused backend tests**

Run:

```bash
cd apps/api && pytest \
  tests/test_worker_lifecycle_config.py \
  tests/test_worker_lifecycle_service.py \
  tests/test_worker_controller.py \
  tests/test_worker_lifecycle_compose.py \
  tests/test_worker_lifecycle_enqueue_hooks.py \
  tests/test_on_demand_schedule_dispatch.py \
  tests/test_worker_lifecycle_celery.py \
  -q
```

Expected: PASS.

- [ ] **Step 2: Run existing scan and scheduler regression tests**

Run:

```bash
cd apps/api && pytest \
  tests/test_scans_router_kind_aware.py \
  tests/test_security_lake_enqueue_hook.py \
  tests/test_scan_runner_ai_gate.py \
  -q
```

Expected: PASS.

- [ ] **Step 3: Validate Compose config renders**

Run:

```bash
docker compose config >/tmp/pencheff-compose-rendered.yml
```

Expected: command exits 0 and `/tmp/pencheff-compose-rendered.yml` contains `worker-controller`.

- [ ] **Step 4: Verify always-on mode preserves current behavior**

Run:

```bash
WORKER_ALWAYS_ON=true docker compose up -d api worker worker-controller redis postgres
docker compose ps worker worker-controller
```

Expected: `worker` and `worker-controller` are both running.

- [ ] **Step 5: Verify on-demand mode stops the worker after boot**

Run:

```bash
WORKER_ALWAYS_ON=false docker compose up -d api worker worker-controller redis postgres
sleep 45
docker compose ps worker worker-controller
```

Expected: `worker-controller` is running and `worker` is stopped.

- [ ] **Step 6: Verify manual scan wakes the worker**

Use the application UI or API to commission a manual scan.

Run:

```bash
docker compose ps worker
```

Expected: `worker` is running while the scan is queued or running.

- [ ] **Step 7: Verify idle stop after scan drain**

Wait for the scan and post-scan tasks to finish.

Run:

```bash
sleep 60
docker compose ps worker
```

Expected: `worker` is stopped.

- [ ] **Step 8: Verify scheduled scan wakes the worker**

Set `WORKER_ALWAYS_ON=false`, create a schedule due within the next minute, and keep the API running.

Run:

```bash
docker compose logs --tail=200 api worker-controller
docker compose ps worker
```

Expected: API logs show due schedule dispatch, controller logs show worker start, and `worker` runs for the scheduled scan.

- [ ] **Step 9: Final status check**

Run:

```bash
git status --short
```

Expected: no uncommitted changes except user-owned changes that existed before this work.
