from __future__ import annotations

import json

import pytest
from fastapi import HTTPException, status
from sqlalchemy import create_engine, text

from pencheff_api.config import Settings
from pencheff_api.services import worker_lifecycle as wl


def _settings(**overrides):
    aliases = {
        "worker_always_on": "WORKER_ALWAYS_ON",
        "worker_idle_grace_seconds": "WORKER_IDLE_GRACE_SECONDS",
        "docker_socket_path": "DOCKER_SOCKET_PATH",
        "worker_compose_project": "WORKER_COMPOSE_PROJECT",
        "worker_compose_service": "WORKER_COMPOSE_SERVICE",
    }
    data = {
        "WORKER_ALWAYS_ON": True,
        "WORKER_IDLE_GRACE_SECONDS": 30,
        "DOCKER_SOCKET_PATH": "/tmp/docker.sock",
        "WORKER_COMPOSE_PROJECT": "pencheff",
        "WORKER_COMPOSE_SERVICE": "worker",
        "database_url": "postgresql+asyncpg://u:p@db:5432/app",
        "redis_url": "redis://redis:6379/0",
    }
    data.update({aliases.get(key, key): value for key, value in overrides.items()})
    return Settings(**data)


@pytest.mark.asyncio
async def test_start_noops_when_worker_is_always_on(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("docker must not be called")

    monkeypatch.setattr(wl, "_docker_start_worker", boom)

    await wl.ensure_worker_started_for_enqueue(
        _settings(worker_always_on=True),
    )


@pytest.mark.asyncio
async def test_start_calls_docker_when_worker_is_on_demand(monkeypatch) -> None:
    calls: list[str] = []

    def fake_start(settings, service=None):
        calls.append(service or settings.worker_compose_service)
        return {"started": True}

    monkeypatch.setattr(wl, "_docker_start_worker", fake_start)

    await wl.ensure_worker_started_for_enqueue(
        _settings(worker_always_on=False),
    )

    assert calls == ["worker"]


def test_sync_start_noops_when_worker_is_always_on(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("docker must not be called")

    monkeypatch.setattr(wl, "_docker_start_worker", boom)

    wl.ensure_worker_started_for_enqueue_sync(
        _settings(worker_always_on=True),
    )


def test_sync_start_calls_docker_when_worker_is_on_demand(monkeypatch) -> None:
    calls: list[str] = []

    def fake_start(settings, service=None):
        calls.append(service or settings.worker_compose_service)
        return {"started": True}

    monkeypatch.setattr(wl, "_docker_start_worker", fake_start)

    wl.ensure_worker_started_for_enqueue_sync(
        _settings(worker_always_on=False),
    )

    assert calls == ["worker"]


@pytest.mark.asyncio
async def test_start_surfaces_docker_failure(monkeypatch) -> None:
    def fake_start(settings, service=None):
        raise wl.WorkerLifecycleError("docker unavailable")

    monkeypatch.setattr(wl, "_docker_start_worker", fake_start)

    with pytest.raises(wl.WorkerLifecycleError, match="docker unavailable"):
        await wl.ensure_worker_started_for_enqueue(
            _settings(worker_always_on=False),
        )


@pytest.mark.asyncio
async def test_start_or_503_translates_worker_lifecycle_error(monkeypatch) -> None:
    async def fake_start(settings, service=None):
        raise wl.WorkerLifecycleError("docker unavailable")

    monkeypatch.setattr(wl, "ensure_worker_started_for_enqueue", fake_start)

    with pytest.raises(HTTPException) as exc_info:
        await wl.ensure_worker_started_or_503(_settings(worker_always_on=False))

    assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert exc_info.value.detail == "docker unavailable"


def test_request_worker_stop_if_idle_noops_when_worker_is_always_on(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("docker must not be called")

    monkeypatch.setattr(wl, "_docker_stop_worker_if_idle", boom)

    wl.request_worker_stop_if_idle_sync(
        _settings(worker_always_on=True),
    )


def test_request_worker_stop_if_idle_skips_when_docker_socket_is_unavailable(
    monkeypatch,
    tmp_path,
) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("docker must not be called without socket")

    monkeypatch.setattr(wl, "_docker_stop_worker_if_idle", boom)

    wl.request_worker_stop_if_idle_sync(
        _settings(worker_always_on=False, docker_socket_path=str(tmp_path / "missing.sock")),
    )


def test_request_worker_stop_if_idle_logs_and_swallows_docker_failure(
    monkeypatch,
    caplog,
    tmp_path,
) -> None:
    calls: list[str] = []
    docker_sock = tmp_path / "docker.sock"
    docker_sock.touch()

    def fake_stop(settings):
        calls.append(settings.worker_compose_service)
        raise wl.WorkerLifecycleError("docker unavailable")

    monkeypatch.setattr(wl, "_docker_stop_worker_if_idle", fake_stop)

    with caplog.at_level("WARNING", logger="pencheff.worker_lifecycle"):
        wl.request_worker_stop_if_idle_sync(
            _settings(worker_always_on=False, docker_socket_path=str(docker_sock)),
        )

    assert calls == ["worker"]
    assert "worker stop-if-idle request failed: docker unavailable" in caplog.text


def test_docker_start_worker_starts_compose_worker_container(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    monkeypatch.setattr(wl, "_find_worker_container_id", lambda settings, service=None: "container-1")
    monkeypatch.setattr(
        wl,
        "_docker_request",
        lambda settings, method, path, body=None: calls.append((method, path)) or (204, b""),
    )

    result = wl._docker_start_worker(_settings(worker_always_on=False))

    assert result["started"] is True
    assert calls == [("POST", "/containers/container-1/start")]


def test_docker_stop_worker_if_idle_refuses_when_work_remains(monkeypatch) -> None:
    monkeypatch.setattr(
        wl,
        "is_worker_idle_sync",
        lambda settings: wl.WorkerIdleState(idle=False, reasons=["database_pending=1"]),
    )

    result = wl._docker_stop_worker_if_idle(_settings(worker_always_on=False))

    assert result == {"stopped": False, "reasons": ["database_pending=1"]}


def test_docker_stop_worker_if_idle_stops_idle_worker(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    monkeypatch.setattr(
        wl,
        "is_worker_idle_sync",
        lambda settings: wl.WorkerIdleState(idle=True, reasons=[]),
    )
    monkeypatch.setattr(wl, "_find_worker_container_id", lambda settings, service=None: "container-1")
    monkeypatch.setattr(
        wl,
        "_docker_request",
        lambda settings, method, path, body=None: calls.append((method, path)) or (204, b""),
    )

    result = wl._docker_stop_worker_if_idle(_settings(worker_always_on=False))

    assert result == {"stopped": True, "container_id": "container-1", "reasons": []}
    assert calls == [("POST", "/containers/container-1/stop?t=10")]


@pytest.mark.parametrize(
    "payload",
    [
        b"{not-json",
        json.dumps({"Id": "container-1"}).encode("utf-8"),
        json.dumps(["container-1"]).encode("utf-8"),
        json.dumps([{"Id": None}]).encode("utf-8"),
    ],
)
def test_find_worker_container_id_rejects_malformed_docker_payload(
    monkeypatch,
    payload: bytes,
) -> None:
    monkeypatch.setattr(
        wl,
        "_docker_request",
        lambda settings, method, path, body=None: (200, payload),
    )

    with pytest.raises(wl.WorkerLifecycleError, match="malformed"):
        wl._find_worker_container_id(_settings(worker_always_on=False))


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


def test_count_pending_db_work_counts_queued_and_running_rows(tmp_path) -> None:
    db_path = tmp_path / "worker-lifecycle.db"
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE scans (status TEXT NOT NULL, kind_payload TEXT)"))
            conn.execute(text("CREATE TABLE repo_scans (status TEXT NOT NULL)"))
            conn.execute(
                text("INSERT INTO scans (status, kind_payload) VALUES (:status, :kind_payload)"),
                [
                    {"status": "queued", "kind_payload": None},
                    {"status": "running", "kind_payload": None},
                    {"status": "done", "kind_payload": None},
                    # MCP-originated scans have no Celery worker; must not
                    # count toward pending DB work.
                    {"status": "running", "kind_payload": '{"source": "mcp"}'},
                ],
            )
            conn.execute(
                text("INSERT INTO repo_scans (status) VALUES (:status)"),
                [{"status": "queued"}, {"status": "running"}, {"status": "done"}],
            )
    finally:
        engine.dispose()

    assert wl._count_pending_db_work(_settings(database_url=f"sqlite:///{db_path}")) == 4


def test_count_pending_db_work_disposes_engine(monkeypatch) -> None:
    class FakeResult:
        def __init__(self, value: int):
            self.value = value

        def scalar_one(self) -> int:
            return self.value

    class FakeConnection:
        def __init__(self):
            self.counts = iter([1, 2])

        def execute(self, statement):
            return FakeResult(next(self.counts))

    class FakeBegin:
        def __init__(self, conn: FakeConnection):
            self.conn = conn

        def __enter__(self) -> FakeConnection:
            return self.conn

        def __exit__(self, exc_type, exc, traceback) -> None:
            return None

    class FakeEngine:
        def __init__(self):
            self.conn = FakeConnection()
            self.disposed = False

        def begin(self) -> FakeBegin:
            return FakeBegin(self.conn)

        def dispose(self) -> None:
            self.disposed = True

    engine = FakeEngine()
    monkeypatch.setattr(wl, "create_engine", lambda *args, **kwargs: engine)

    assert wl._count_pending_db_work(_settings()) == 3
    assert engine.disposed is True


def test_redis_pending_count_sums_celery_and_unacked_keys(monkeypatch) -> None:
    class FakeRedis:
        def __init__(self):
            self.closed = False

        def llen(self, key: str) -> int:
            assert key == "celery"
            return 3

        def zcard(self, key: str) -> int:
            assert key == "unacked_index"
            return 5

        def hlen(self, key: str) -> int:
            assert key == "unacked"
            return 7

        def close(self) -> None:
            self.closed = True

    client = FakeRedis()
    urls: list[str] = []

    def fake_from_url(url: str) -> FakeRedis:
        urls.append(url)
        return client

    monkeypatch.setattr(wl.Redis, "from_url", staticmethod(fake_from_url))

    assert wl._redis_pending_count(_settings(redis_url="redis://redis:6379/1")) == 15
    assert urls == ["redis://redis:6379/1"]
    assert client.closed is True
