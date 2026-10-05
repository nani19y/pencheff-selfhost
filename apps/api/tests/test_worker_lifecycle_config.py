from __future__ import annotations

from pencheff_api.config import Settings


LIFECYCLE_ENV_VARS = (
    "WORKER_ALWAYS_ON",
    "WORKER_IDLE_GRACE_SECONDS",
    "DOCKER_SOCKET_PATH",
    "WORKER_COMPOSE_PROJECT",
    "WORKER_COMPOSE_SERVICE",
)


def test_worker_lifecycle_defaults_preserve_always_on(monkeypatch) -> None:
    for env_var in LIFECYCLE_ENV_VARS:
        monkeypatch.delenv(env_var, raising=False)

    settings = Settings(_env_file=None)

    assert settings.worker_always_on is True
    assert settings.worker_idle_grace_seconds == 30
    assert settings.docker_socket_path == "/var/run/docker.sock"
    assert settings.worker_compose_project == "pencheff"
    assert settings.worker_compose_service == "worker"


def test_worker_lifecycle_env_can_disable_always_on(monkeypatch) -> None:
    monkeypatch.setenv("WORKER_ALWAYS_ON", "false")
    monkeypatch.setenv("WORKER_IDLE_GRACE_SECONDS", "7")
    monkeypatch.setenv("DOCKER_SOCKET_PATH", "/tmp/docker.sock")
    monkeypatch.setenv("WORKER_COMPOSE_PROJECT", "custom")
    monkeypatch.setenv("WORKER_COMPOSE_SERVICE", "scanner")

    settings = Settings(_env_file=None)

    assert settings.worker_always_on is False
    assert settings.worker_idle_grace_seconds == 7
    assert settings.docker_socket_path == "/tmp/docker.sock"
    assert settings.worker_compose_project == "custom"
    assert settings.worker_compose_service == "scanner"
