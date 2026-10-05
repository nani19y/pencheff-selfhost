"""Decision-table loader.

Reads YAML policy files shipped under ``pencheff/data/policies/`` and exposes
them as typed Pydantic models. Loading is cached at process start; tests can
call ``load_policies(reload=True)`` to pick up edits.

Every policy file has a ``version`` field; the loader records the tuple
``(name, version)`` per file so a session can be replayed against the same
policy set.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


_POLICY_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "policies"

_POLICY_FILES = (
    "tool_selection",
    "parameters",
    "chains",
    "fallbacks",
    "throttle",
    "cve_correlation",
    "confidence",
)


class PolicyError(RuntimeError):
    """Raised when a policy file is missing, malformed, or fails validation."""


@dataclass(frozen=True)
class Policies:
    tool_selection: dict[str, Any]
    parameters: dict[str, Any]
    chains: dict[str, Any]
    fallbacks: dict[str, Any]
    throttle: dict[str, Any]
    cve_correlation: dict[str, Any]
    confidence: dict[str, Any]

    @property
    def versions(self) -> dict[str, int]:
        return {
            name: getattr(self, name).get("version", 0)
            for name in _POLICY_FILES
        }


def _read_yaml(name: str) -> dict[str, Any]:
    path = _POLICY_DIR / f"{name}.yaml"
    if not path.is_file():
        raise PolicyError(f"missing policy file: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # pragma: no cover - format error
        raise PolicyError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"policy {path} must be a mapping at the top level")
    if "version" not in data:
        raise PolicyError(f"policy {path} missing required 'version' field")
    return data


@lru_cache(maxsize=1)
def _load_cached() -> Policies:
    payload = {name: _read_yaml(name) for name in _POLICY_FILES}
    return Policies(**payload)


def load_policies(*, reload: bool = False) -> Policies:
    """Return the in-memory Policies singleton.

    Pass ``reload=True`` to force a re-read (used by tests).
    """
    if reload:
        _load_cached.cache_clear()
    return _load_cached()
