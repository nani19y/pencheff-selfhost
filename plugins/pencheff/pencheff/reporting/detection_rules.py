"""Render detection rule files (Sigma / SPL / KQL) from findings.

This is the format-only path used by the ``pencheff detect`` CLI when no
session is in scope; the playbook-driven path lives in
:mod:`pencheff.playbooks.detection_engineer`.
"""

from __future__ import annotations

import uuid
from datetime import date
from pathlib import Path

from pencheff.playbooks.detection_engineer import render_template

_TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "data" / "detection_templates"


def render_for_finding(finding: dict, fmt: str = "sigma", target: str = "TARGET") -> list[str]:
    """Return rendered rule(s) for a finding, indexed by MITRE technique."""
    ext = {"sigma": ".yml", "spl": ".spl", "kql": ".kql"}.get(fmt, ".yml")
    mitre_field = finding.get("mitre") if isinstance(finding.get("mitre"), list) else finding.get("mitre_id")
    mids: list[str] = []
    if isinstance(mitre_field, list):
        mids = list(mitre_field)
    elif isinstance(mitre_field, str) and mitre_field:
        mids = [m.strip() for m in mitre_field.split(",") if m.strip()]
    out: list[str] = []
    for tid in mids:
        path = _TEMPLATE_DIR / fmt / f"{tid}{ext}"
        if not path.exists():
            continue
        ctx = {
            "rule_uuid": uuid.uuid4().hex[:12],
            "generated_date": date.today().isoformat(),
            "target": target,
            "indicator_paths": '\n      - "/admin"\n      - "/.env"\n      - "/.git/"',
        }
        out.append(render_template(path.read_text(), ctx))
    return out


def render_findings(findings: list[dict], fmt: str = "sigma", target: str = "TARGET") -> str:
    pieces: list[str] = []
    sep = "\n---\n" if fmt == "sigma" else "\n\n"
    for f in findings:
        for rule in render_for_finding(f, fmt=fmt, target=target):
            pieces.append(rule.rstrip())
    return sep.join(pieces) + ("\n" if pieces else "")
