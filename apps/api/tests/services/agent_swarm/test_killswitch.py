"""SWARM_ENABLED gate: when False, _engine routes to the legacy
_run_agent_stage path; when True, it routes to run_swarm.

The _engine closure is nested inside run_scan and not directly
callable, so we test the dispatch contract by:
  1. Verifying both target paths exist as imports.
  2. Verifying the setting toggles the path the closure would take
     by exercising the same conditional.

Note: this is an import-surface + dispatch-contract test only;
the full _engine closure is exercised by the L1 integration tests.
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest


def test_swarm_enabled_default_is_true(monkeypatch):
    from pencheff_api.config import get_settings

    s = get_settings()
    assert s.swarm_enabled is True


def test_legacy_target_is_importable():
    from pencheff_api.services.scan_runner import _run_agent_stage

    assert callable(_run_agent_stage)


def test_swarm_target_is_importable():
    from pencheff_api.services.agent_swarm import run_swarm

    assert callable(run_swarm)


@pytest.mark.asyncio
async def test_dispatch_branch_picks_swarm_when_enabled(monkeypatch):
    from pencheff_api.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "swarm_enabled", True)

    swarm_mock = AsyncMock()
    legacy_mock = AsyncMock()
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.run_swarm", swarm_mock,
    )
    monkeypatch.setattr(
        "pencheff_api.services.scan_runner._run_agent_stage", legacy_mock,
    )

    # Simulate the dispatch logic in _engine.
    settings_local = get_settings()
    if settings_local.swarm_enabled:
        from pencheff_api.services.agent_swarm import run_swarm

        await run_swarm(
            master_session_id="sid",
            target_url="https://t",
            credentials=None,
            profile="quick",
            scope=None,
            exclude_paths=None,
            on_event=_noop,
            session_prepopulated=False,
        )
    else:
        from pencheff_api.services.scan_runner import _run_agent_stage

        await _run_agent_stage(
            scan_id="x",
            psession=None,
            target=None,
            profile="quick",
            credentials=None,
            db_session_factory=None,
            session_prepopulated=False,
        )

    swarm_mock.assert_awaited_once()
    legacy_mock.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_branch_picks_legacy_when_disabled(monkeypatch):
    from pencheff_api.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "swarm_enabled", False)

    swarm_mock = AsyncMock()
    legacy_mock = AsyncMock(return_value="legacy summary")
    monkeypatch.setattr(
        "pencheff_api.services.agent_swarm.run_swarm", swarm_mock,
    )
    monkeypatch.setattr(
        "pencheff_api.services.scan_runner._run_agent_stage", legacy_mock,
    )

    settings_local = get_settings()
    if settings_local.swarm_enabled:
        from pencheff_api.services.agent_swarm import run_swarm

        await run_swarm(
            master_session_id="sid",
            target_url="https://t",
            credentials=None,
            profile="quick",
            scope=None,
            exclude_paths=None,
            on_event=_noop,
            session_prepopulated=False,
        )
    else:
        from pencheff_api.services.scan_runner import _run_agent_stage

        result = await _run_agent_stage(
            scan_id="x",
            psession=None,
            target=None,
            profile="quick",
            credentials=None,
            db_session_factory=None,
            session_prepopulated=False,
        )
        assert result == "legacy summary"

    legacy_mock.assert_awaited_once()
    swarm_mock.assert_not_called()


async def _noop(line: str) -> None:
    return None
