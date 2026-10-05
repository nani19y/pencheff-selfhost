"""YAML-driven scan automation framework.

Schema v1 (``apiVersion: pencheff/v1``):

    apiVersion: pencheff/v1
    kind: ScanPolicy
    metadata:
      name: owasp-top10
      description: Balanced web assessment with OWASP Top 10 category mapping
    spec:
      targets:
        - url: https://example.com
          scope: [/api, /app]
          exclude_paths: [/logout]
      auth:
        kind: credentials  # or login_macro
        ref: default
      modules:
        - name: scan_injection
          depth: standard
          params: {}
      assertions:
        - id: no_critical
          condition: "findings.critical == 0"
      thresholds:
        fail_on: high
      reports:
        - format: docx
          path: ./reports/
      schedule:
        cron: "0 2 * * *"
        enabled: false
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from pencheff.config import SCAN_PROFILES
from pencheff.core.findings import FindingsDB
from pencheff.core.session import PentestSession, create_session


@dataclass
class PolicyModule:
    name: str
    depth: str = "standard"
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyAssertion:
    id: str
    condition: str


@dataclass
class ScanPolicy:
    api_version: str
    kind: str
    name: str
    description: str
    targets: list[dict[str, Any]]
    auth: dict[str, Any]
    modules: list[PolicyModule]
    assertions: list[PolicyAssertion]
    thresholds: dict[str, Any]
    reports: list[dict[str, Any]]
    schedule: dict[str, Any]
    raw: dict[str, Any]


def load(path: Path) -> ScanPolicy:
    data = yaml.safe_load(path.read_text())
    spec = data.get("spec", {}) or {}
    meta = data.get("metadata", {}) or {}
    modules = [
        PolicyModule(name=m["name"], depth=m.get("depth", "standard"),
                     params=m.get("params", {}) or {})
        for m in (spec.get("modules") or [])
    ]
    assertions = [
        PolicyAssertion(id=a.get("id", ""), condition=a.get("condition", ""))
        for a in (spec.get("assertions") or [])
    ]
    return ScanPolicy(
        api_version=data.get("apiVersion", "pencheff/v1"),
        kind=data.get("kind", "ScanPolicy"),
        name=meta.get("name", path.stem),
        description=meta.get("description", ""),
        targets=spec.get("targets", []) or [],
        auth=spec.get("auth", {}) or {},
        modules=modules,
        assertions=assertions,
        thresholds=spec.get("thresholds", {}) or {},
        reports=spec.get("reports", []) or [],
        schedule=spec.get("schedule", {}) or {},
        raw=data,
    )


@dataclass
class PolicyResult:
    policy: ScanPolicy
    session: PentestSession
    module_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    assertions: dict[str, bool] = field(default_factory=dict)
    failed: bool = False
    error: str = ""


async def run(policy: ScanPolicy) -> PolicyResult:
    # Create one session per target (first one becomes the primary)
    first = policy.targets[0] if policy.targets else {"url": ""}
    session = create_session(
        target_url=first.get("url", ""),
        credentials=_resolve_creds(policy.auth),
        scope=first.get("scope"),
        exclude_paths=first.get("exclude_paths"),
        depth=_top_depth(policy.modules),
    )
    result = PolicyResult(policy=policy, session=session)

    # Dispatch each module via a registry of callable entry-points.
    from pencheff.core.policy_engine_dispatcher import run_module
    for mod in policy.modules:
        try:
            result.module_results[mod.name] = await run_module(session, mod)
        except Exception as e:  # noqa: BLE001
            result.module_results[mod.name] = {"error": str(e)}

    # Evaluate assertions
    counts = session.findings.summary()
    ctx = {
        "findings": _DictAsObject(counts),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "total": sum(v for k, v in counts.items() if k != "suppressed"),
    }
    for a in policy.assertions:
        try:
            ok = bool(eval(a.condition, {"__builtins__": {}}, ctx))  # noqa: S307 — trusted YAML
        except Exception:  # noqa: BLE001
            ok = False
        result.assertions[a.id] = ok
        if not ok:
            result.failed = True

    # Threshold gate
    fail_on = policy.thresholds.get("fail_on")
    if fail_on and counts.get(fail_on, 0) > 0:
        result.failed = True

    return result


def _top_depth(modules: list[PolicyModule]) -> str:
    order = {"quick": 0, "standard": 1, "deep": 2}
    best = "quick"
    for m in modules:
        if order.get(m.depth, 0) > order.get(best, 0):
            best = m.depth
    return best


def _resolve_creds(auth: dict[str, Any]) -> dict[str, Any] | None:
    kind = auth.get("kind")
    if kind == "credentials":
        return auth.get("values") or None
    return None


class _DictAsObject:
    """Allow ``findings.critical`` style attribute access in assertion expressions."""

    def __init__(self, d: dict[str, Any]):
        self.__dict__.update(d)
