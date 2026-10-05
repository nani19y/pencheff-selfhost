from __future__ import annotations

from pencheff_api.tasks.security_lake_ingest_task import enqueue_repo_ingest


def test_enqueue_is_guarded_against_failure(monkeypatch):
    calls = {}

    class _Boom:
        def delay(self, *a, **k):
            raise RuntimeError("broker down")

    monkeypatch.setattr(
        "pencheff_api.tasks.security_lake_ingest_task.ingest_repo_scan", _Boom())
    # must swallow the error and return False, never raise
    assert enqueue_repo_ingest("rs1") is False


def test_enqueue_calls_delay_on_success(monkeypatch):
    seen = {}

    class _Ok:
        def delay(self, scan_id):
            seen["id"] = scan_id

    monkeypatch.setattr(
        "pencheff_api.tasks.security_lake_ingest_task.ingest_repo_scan", _Ok())
    assert enqueue_repo_ingest("rs1") is True
    assert seen["id"] == "rs1"
