"""Reusable progress capture for AI scans: stream every red-team/scan progress
line to SSE, persist only milestones to Scan.log. See spec
2026-06-27-ai-scan-assessment-logs."""
from __future__ import annotations

import asyncio
import contextlib
import logging

from sqlalchemy import select

from ..db.models import Scan
from ..events import publish_campaign_event, publish_scan_event

log = logging.getLogger("pencheff.ai_scan_progress")

_PREFIXES = ("llm_redteam_progress:", "scan_progress:")
_MILESTONE_STARTS = (
    "module_start", "module_done", "module_cases", "iterative_",
    "scan_progress", "connecting", "enumerated", "probing", "sampled",
)


def _is_milestone(clean: str) -> bool:
    c = clean.strip()
    if c.startswith("probe "):
        return False
    return any(c.startswith(p) for p in _MILESTONE_STARTS)


async def _persist(db_session_factory, scan_id: str, line: str) -> None:
    from .scan_runner import _append_log  # deferred: avoids circular import
    try:
        async with db_session_factory() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            _append_log(s, line)
            await db.commit()
    except Exception:  # noqa: BLE001
        log.debug("ai_scan_progress persist failed", exc_info=True)


def _publish(scan_id: str, stage: str, line: str, campaign_id: str | None = None) -> None:
    try:
        publish_scan_event(scan_id, {"type": "stage_progress", "stage": stage, "label": line})
        if campaign_id:
            publish_campaign_event(campaign_id, {
                "type": "target_progress", "target_scan_id": scan_id,
                "stage": stage, "label": line,
            })
    except Exception:  # noqa: BLE001
        log.debug("ai_scan_progress SSE publish failed", exc_info=True)


class _Progress:
    def __init__(
        self, scan_id: str, db_session_factory, stage: str, campaign_id: str | None = None
    ) -> None:
        self._scan_id, self._factory, self._stage = scan_id, db_session_factory, stage
        self._campaign_id = campaign_id

    async def milestone(self, text: str) -> None:
        line = f"stage_progress: {text}"
        await _persist(self._factory, self._scan_id, line)
        _publish(self._scan_id, self._stage, line, self._campaign_id)


async def _load_campaign_id(db_session_factory, scan_id: str) -> str | None:
    try:
        async with db_session_factory() as db:
            return (
                await db.execute(select(Scan.campaign_id).where(Scan.id == scan_id))
            ).scalar_one_or_none()
    except Exception:  # noqa: BLE001
        log.debug("ai_scan_progress campaign_id lookup failed", exc_info=True)
        return None


@contextlib.asynccontextmanager
async def ai_scan_progress(scan_id: str, db_session_factory, *, stage: str):
    q: asyncio.Queue[str] = asyncio.Queue()
    loop = asyncio.get_running_loop()
    campaign_id = await _load_campaign_id(db_session_factory, scan_id)

    class _Handler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            try:
                msg = record.getMessage()
            except Exception:  # noqa: BLE001
                return
            if not any(p in msg for p in _PREFIXES):
                return
            try:
                loop.call_soon_threadsafe(q.put_nowait, msg)
            except Exception:  # noqa: BLE001
                pass

    handler = _Handler(level=logging.INFO)
    handler.setFormatter(logging.Formatter("%(message)s"))
    plugin_logger = logging.getLogger("pencheff.modules")
    plugin_logger.addHandler(handler)
    prev_level = plugin_logger.level
    if plugin_logger.level > logging.INFO or plugin_logger.level == logging.NOTSET:
        plugin_logger.setLevel(logging.INFO)

    async def _forward() -> None:
        try:
            while True:
                msg = await q.get()
                try:
                    clean = msg
                    for p in _PREFIXES:
                        if p in clean:
                            clean = clean.split(p, 1)[-1].strip()
                            break
                    if not clean:
                        continue
                    line = f"stage_progress: {clean}"
                    _publish(scan_id, stage, line, campaign_id)  # stream: always
                    if _is_milestone(clean):                 # persist: milestones only
                        await _persist(db_session_factory, scan_id, line)
                finally:
                    q.task_done()
        except asyncio.CancelledError:
            return

    fwd = asyncio.create_task(_forward())
    try:
        yield _Progress(scan_id, db_session_factory, stage, campaign_id)
    finally:
        await asyncio.sleep(0)                      # flush call_soon_threadsafe callbacks onto q
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(q.join(), timeout=2.0)   # wait for queued items to persist
        fwd.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await fwd
        plugin_logger.removeHandler(handler)
        plugin_logger.setLevel(prev_level)
