from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def _read(path: str) -> str:
    return (ROOT / path).read_text()


def test_manual_scan_router_starts_worker_before_delay() -> None:
    text = _read("apps/api/pencheff_api/routers/scans.py")
    assert "from ..services.worker_lifecycle import ensure_worker_started_or_503" in text
    assert text.index("await ensure_worker_started_or_503()") < text.index(
        "run_full_scan.delay(scan.id)"
    )


def test_repo_router_starts_worker_before_repo_scan_delay() -> None:
    text = _read("apps/api/pencheff_api/routers/repos.py")
    assert "from ..services.worker_lifecycle import ensure_worker_started_or_503" in text
    assert text.index("await ensure_worker_started_or_503()") < text.index(
        "run_repo_scan.delay(scan.id)"
    )


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
