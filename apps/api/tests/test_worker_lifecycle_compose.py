from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def test_compose_does_not_define_worker_controller_service() -> None:
    text = (ROOT / "docker-compose.yml").read_text()

    assert "worker-controller:" not in text
    assert "pencheff_api.worker_controller:app" not in text


def test_compose_mounts_docker_socket_only_into_api_for_worker_lifecycle() -> None:
    text = (ROOT / "docker-compose.yml").read_text()

    assert text.count("WORKER_ALWAYS_ON: ${WORKER_ALWAYS_ON:-true}") == 2
    assert "WORKER_CONTROLLER_URL" not in text
    assert "WORKER_CONTROLLER_TOKEN" not in text
    assert text.count("WORKER_IDLE_GRACE_SECONDS: ${WORKER_IDLE_GRACE_SECONDS:-30}") == 2
    api_block = text.split("\n  api:", 1)[1].split("\n  worker:", 1)[0]
    worker_block = text.split("\n  worker:", 1)[1].split("\n  docs:", 1)[0]
    assert "/var/run/docker.sock:/var/run/docker.sock" in api_block
    assert "/var/run/docker.sock:/var/run/docker.sock" not in worker_block
