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
