"""Enqueue scan tasks onto their category's Celery queue.

Since the worker image was split per security category, a scan must land on the
queue its category worker consumes (that image carries the right tools). These
helpers wrap ``apply_async(queue=...)`` so no call site has to know the queue
naming. Task imports are lazy to avoid a circular import (the task modules pull
in ``celery_app`` → ``config``).
"""
from __future__ import annotations

from ..scan_categories import category_queue


def enqueue_full_scan(scan_id: str, kind: str | None) -> None:
    """Enqueue ``run_full_scan`` onto the queue for ``kind``'s category."""
    from ..tasks.scan_task import run_full_scan

    run_full_scan.apply_async(args=[scan_id], queue=category_queue(kind))


def enqueue_repo_scan(scan_id: str) -> None:
    """Enqueue ``run_repo_scan`` — repo scans are always ``source_code`` (Code &
    Supply Chain), so they route to that category's worker."""
    from ..tasks.repo_scan_task import run_repo_scan

    run_repo_scan.apply_async(args=[scan_id], queue=category_queue("source_code"))
