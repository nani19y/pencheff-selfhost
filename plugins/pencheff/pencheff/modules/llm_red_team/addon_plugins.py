"""Add-on payload-pack registry — extends the OWASP-LLM modules.

The ten existing OWASP-LLM modules each load a single YAML pack from
``payloads/llm0[1-9]_*.yaml``. Add-on packs (bias, RAG-specific, MCP,
coding-agent) sit alongside in ``payloads/`` but are not tied to a
specific module. Each row carries its own ``category: LLM0X`` field;
``addon_cases(llm_config, category=...)`` is called once per OWASP
module's run and returns the rows that belong to that bucket.

Plug-in opt-out: a user can pass ``redteam.plugins: [bias, rag]`` to
limit the add-on packs that load. Default = all known packs.
"""
from __future__ import annotations

import logging
from importlib.resources import files
from typing import Any

import yaml

from pencheff.config import Severity

from .engine import TestCase

log = logging.getLogger(__name__)

# Public registry — adding a new plugin = one line here + a YAML file.
ADDON_PLUGINS: dict[str, str] = {
    "bias": "bias.yaml",
    "rag": "rag.yaml",
    "mcp": "mcp.yaml",
    "coding-agent": "coding_agent.yaml",
}

_CACHE: dict[str, list[TestCase]] = {}


def _to_case(entry: dict[str, Any], file_name: str) -> TestCase:
    try:
        sev = Severity(str(entry["severity"]).lower())
    except (KeyError, ValueError) as e:
        raise ValueError(
            f"{file_name}: entry {entry.get('id')!r} has invalid severity"
        ) from e
    return TestCase(
        id=str(entry["id"]),
        category=str(entry["category"]),
        technique=str(entry["technique"]),
        title=str(entry["title"]),
        severity=sev,
        prompt=str(entry["prompt"]),
        turns=[str(x) for x in list(entry.get("turns") or [])],
        system=entry.get("system"),
        success_indicators=list(entry.get("success_indicators") or []),
        refusal_patterns=list(entry.get("refusal_patterns") or []),
        success_embeddings=[str(x) for x in list(entry.get("success_embeddings") or [])],
        description=str(entry.get("description", "")),
        remediation=str(entry.get("remediation", "")),
        cwe=entry.get("cwe"),
        metadata=dict(entry.get("metadata") or {}),
    )


def _load(file_name: str) -> list[TestCase]:
    """Read and validate one add-on YAML, with caching."""
    if file_name in _CACHE:
        return _CACHE[file_name]
    base = files("pencheff.modules.llm_red_team").joinpath("payloads", file_name)
    try:
        text = base.read_text(encoding="utf-8")
    except FileNotFoundError:
        _CACHE[file_name] = []
        return []
    raw = yaml.safe_load(text) or []
    if not isinstance(raw, list):
        raise ValueError(f"{file_name}: expected a YAML list at the top level")
    out: list[TestCase] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError(f"{file_name}: every entry must be a mapping")
        out.append(_to_case(entry, file_name))
    _CACHE[file_name] = out
    return out


def addon_cases(llm_config: dict[str, Any] | None, *, category: str) -> list[TestCase]:
    """Return add-on cases matching ``category`` (e.g. ``"LLM06"``).

    ``redteam.plugins`` whitelists which packs to load — defaults to all.
    Unknown plugin names are ignored with a warning so config drift
    doesn't crash a scan.
    """
    redteam = llm_config.get("redteam", {}) if isinstance(llm_config, dict) else {}
    enabled = redteam.get("plugins")
    if enabled is None:
        enabled = list(ADDON_PLUGINS.keys())
    cases: list[TestCase] = []
    for raw_name in enabled:
        name = str(raw_name).lower()
        file_name = ADDON_PLUGINS.get(name)
        if not file_name:
            log.debug("unknown add-on plugin %r — ignored", raw_name)
            continue
        for case in _load(file_name):
            if case.category == category:
                cases.append(case)
    return cases


def reset_cache() -> None:
    """Test helper — discard cached payloads so a freshly-edited YAML is reloaded."""
    _CACHE.clear()
