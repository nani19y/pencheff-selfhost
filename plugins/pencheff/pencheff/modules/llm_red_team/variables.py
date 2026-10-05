"""Variable substitution for red-team payloads."""
from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from .engine import TestCase


_VAR_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\}\}")


def _lookup(name: str, variables: dict[str, Any]) -> str:
    cur: Any = variables
    for part in name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return "{{" + name + "}}"
    return str(cur)


def render_text(text: str | None, variables: dict[str, Any]) -> str | None:
    if text is None:
        return None
    return _VAR_RE.sub(lambda m: _lookup(m.group(1), variables), text)


def apply_variables(cases: list[TestCase], variables: dict[str, Any] | None) -> list[TestCase]:
    if not variables:
        return list(cases)
    out: list[TestCase] = []
    for case in cases:
        out.append(replace(
            case,
            prompt=render_text(case.prompt, variables) or "",
            turns=[render_text(turn, variables) or "" for turn in case.turns],
            system=render_text(case.system, variables),
            success_indicators=[
                render_text(pattern, variables) or "" for pattern in case.success_indicators
            ],
            refusal_patterns=[
                render_text(pattern, variables) or "" for pattern in case.refusal_patterns
            ],
            description=render_text(case.description, variables) or "",
            remediation=render_text(case.remediation, variables) or "",
        ))
    return out
