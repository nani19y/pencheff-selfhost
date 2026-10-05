# SPDX-License-Identifier: AGPL-3.0-or-later
"""GitHub Check Runs + SARIF upload for Pencheff repo scans (Phase 3.3).

Two outbound surfaces:

* **Check Runs API** — ``POST /repos/{owner}/{repo}/check-runs`` posts
  a ``Pencheff`` check on the scanned commit with inline annotations
  per finding. Updates flip to ``in_progress`` → ``completed`` as the
  scan progresses.

* **Code Scanning SARIF upload** — ``POST /repos/{owner}/{repo}/code-scanning/sarifs``
  uploads the same findings as a SARIF document so they show up under
  the repo's *Security → Code scanning* tab. Independent of the
  Check Run path; both can run for the same scan.

Both endpoints are part of the **public** GitHub API and require
either an installation token (for the Pencheff App path) or a PAT
(for Personal Access Token repos). We never use a private API.

Inbound surface: ``parse_suppress_command`` extracts
``pencheff: suppress <finding-id> reason="..."`` directives from PR
comments so the Pencheff Suggest bot can flip a finding's
``suppressed`` flag via the existing
``POST /findings/{id}/suppress`` endpoint.

Naming note: the autofix bot is named **Pencheff Suggest** to avoid
GitHub's ``Copilot Autofix`` trademark. Final name pending the
trademark search in Phase 0.6.
"""
from __future__ import annotations

import base64
import gzip
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable

import httpx

from . import github_app

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

# SARIF severity buckets we map onto. SARIF v2.1.0 uses ``error /
# warning / note`` for the level; we additionally encode our finer-
# grained severity in ``properties.severity`` so the Code-Scanning UI
# can sort/filter.
_SARIF_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
}
# Inline annotation maxes — GitHub caps at 50 annotations per
# Check-Run POST; pages must follow.
_ANNOTATION_PAGE = 50


# ─── Pencheff finding → SARIF ────────────────────────────────────────


@dataclass
class _Finding:
    """Just the fields SARIF / Check-Run rendering needs.

    Decoupled from the SQLAlchemy models so this service is callable
    from the worker (sync) and the API (async) without dragging the
    full ORM along. Instantiate via ``_finding_from_row``.
    """
    id: str
    rule_id: str
    title: str
    description: str | None
    severity: str
    file_path: str | None
    line_start: int | None
    line_end: int | None
    code_snippet: str | None
    cve: str | None
    scanner: str


def _finding_from_row(row: Any) -> _Finding:
    return _Finding(
        id=str(row.id),
        rule_id=row.rule_id or "",
        title=row.title or "",
        description=row.description,
        severity=(row.severity or "info").lower(),
        file_path=row.file_path,
        line_start=row.line_start,
        line_end=row.line_end,
        code_snippet=row.code_snippet,
        cve=row.cve,
        scanner=row.scanner or "",
    )


def render_sarif(findings: Iterable[_Finding], commit_sha: str | None = None) -> dict[str, Any]:
    """Build a minimal SARIF v2.1.0 document.

    Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/. The
    ``runs[].tool.driver`` describes Pencheff itself; ``rules[]`` is
    de-duplicated across all findings; ``results[]`` is the per-row
    list with file / line locations.
    """
    findings = list(findings)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        rule_key = f.rule_id or f"{f.scanner}:unknown"
        if rule_key not in rules:
            rules[rule_key] = {
                "id": rule_key,
                "name": rule_key,
                "shortDescription": {"text": f.title[:120]},
                "fullDescription": {"text": (f.description or f.title)[:500]},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(f.severity, "warning"),
                },
                "properties": {"scanner": f.scanner},
            }
        result: dict[str, Any] = {
            "ruleId": rule_key,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.title or f.description or "Pencheff finding"},
            "properties": {
                "severity": f.severity,
                "scanner": f.scanner,
                "cve": f.cve or "",
                "pencheff_finding_id": f.id,
            },
        }
        if f.file_path:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {
                        "startLine": max(1, f.line_start or 1),
                        "endLine": max(1, f.line_end or f.line_start or 1),
                    },
                }
            }]
        if f.code_snippet and result.get("locations"):
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": f.code_snippet[:500],
            }
        results.append(result)

    rules_list = sorted(rules.values(), key=lambda r: r["id"])
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Pencheff",
                    "informationUri": "https://github.com/Magadha-IG/pencheff",
                    "version": "0.7.0",
                    "rules": rules_list,
                }
            },
            "results": results,
            **({"versionControlProvenance": [{
                "repositoryUri": "https://github.com",  # caller may overwrite
                "revisionId": commit_sha,
            }]} if commit_sha else {}),
        }],
    }


def render_check_run_annotations(findings: Iterable[_Finding]) -> list[dict[str, Any]]:
    """Per-finding ``annotations`` for the Check Runs API.

    GitHub caps at 50 per POST; the publisher (``post_check_run``) pages
    them automatically.
    """
    out: list[dict[str, Any]] = []
    for f in findings:
        if not f.file_path:
            continue
        annotation_level = {
            "critical": "failure", "high": "failure",
            "medium": "warning", "low": "notice", "info": "notice",
        }.get(f.severity, "warning")
        out.append({
            "path": f.file_path,
            "start_line": max(1, f.line_start or 1),
            "end_line": max(1, f.line_end or f.line_start or 1),
            "annotation_level": annotation_level,
            "title": f.title[:255],
            "message": (f.description or f.title)[:65_000],
            "raw_details": json.dumps({
                "scanner": f.scanner,
                "severity": f.severity,
                "cve": f.cve,
                "pencheff_finding_id": f.id,
            }),
        })
    return out


# ─── Outbound HTTP ──────────────────────────────────────────────────


async def post_check_run(
    *,
    full_name: str,
    head_sha: str,
    findings: Iterable[_Finding],
    installation_id: int | str | None = None,
    pat: str | None = None,
    name: str = "Pencheff",
    summary: str | None = None,
) -> dict[str, Any]:
    """Post a single completed Check Run with inline annotations.

    Either ``installation_id`` (GitHub App path) or ``pat`` (PAT path)
    must be supplied. GitHub returns the Check Run as JSON; we forward
    its id + URL to the caller so subsequent updates can target it.
    """
    findings = list(findings)
    counts = _severity_counts(findings)
    title = f"Pencheff: {counts['total']} findings"
    if summary is None:
        summary = (
            f"**{counts['critical']}** critical · "
            f"**{counts['high']}** high · "
            f"**{counts['medium']}** medium · "
            f"**{counts['low']}** low · "
            f"**{counts['info']}** info"
        )
    conclusion = "failure" if counts["critical"] + counts["high"] > 0 else "success"

    annotations = render_check_run_annotations(findings)
    first_page = annotations[:_ANNOTATION_PAGE]

    body = {
        "name": name,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary,
            "annotations": first_page,
        },
    }
    headers = await _build_headers(installation_id=installation_id, pat=pat)
    url = f"{GITHUB_API}/repos/{full_name}/check-runs"

    async with httpx.AsyncClient(timeout=20.0, headers=headers) as c:
        r = await c.post(url, json=body)
        if r.status_code >= 400:
            return {"ok": False, "status": r.status_code, "response": r.text[:500]}
        check_run = r.json()
        check_run_id = check_run.get("id")

        # Page remaining annotations via PATCH so we don't lose any.
        for offset in range(_ANNOTATION_PAGE, len(annotations), _ANNOTATION_PAGE):
            page = annotations[offset:offset + _ANNOTATION_PAGE]
            patch_body = {"output": {
                "title": title, "summary": summary, "annotations": page,
            }}
            await c.patch(
                f"{GITHUB_API}/repos/{full_name}/check-runs/{check_run_id}",
                json=patch_body,
            )
    return {
        "ok": True,
        "status": r.status_code,
        "check_run_id": check_run_id,
        "html_url": check_run.get("html_url"),
        "annotations_total": len(annotations),
        "conclusion": conclusion,
    }


async def upload_sarif(
    *,
    full_name: str,
    head_sha: str,
    sarif: dict[str, Any],
    installation_id: int | str | None = None,
    pat: str | None = None,
    ref: str | None = None,
) -> dict[str, Any]:
    """Upload a SARIF document to GitHub's code-scanning ingest API.

    Required scopes (when using a PAT): ``security_events`` (write) on
    the repo. The installation token path requires the GitHub App to
    have the ``security_events`` permission granted.
    """
    sarif_bytes = json.dumps(sarif, separators=(",", ":")).encode("utf-8")
    encoded = base64.b64encode(gzip.compress(sarif_bytes)).decode("ascii")
    body = {
        "commit_sha": head_sha,
        "ref": ref or f"refs/heads/{_default_ref(head_sha)}",
        "sarif": encoded,
        "tool_name": "Pencheff",
        "checkout_uri": f"https://github.com/{full_name}",
    }
    headers = await _build_headers(installation_id=installation_id, pat=pat)
    url = f"{GITHUB_API}/repos/{full_name}/code-scanning/sarifs"
    async with httpx.AsyncClient(timeout=30.0, headers=headers) as c:
        r = await c.post(url, json=body)
    if r.status_code >= 400:
        return {"ok": False, "status": r.status_code, "response": r.text[:500]}
    return {"ok": True, "status": r.status_code, "id": r.json().get("id")}


# ─── PR-comment suppression command parser ──────────────────────────


# Matches: ``pencheff: suppress <finding-id>`` with optional
# ``reason="..."`` and ``notes="..."`` keywords. Case-insensitive on
# the prefix; finding-id is the canonical UUID we store.
_SUPPRESS_RE = re.compile(
    r"""
    \bpencheff[:\s]\s*suppress\s+
    (?P<finding_id>[A-Za-z0-9_-]{4,64})     # finding id
    (?:\s+reason\s*=\s*"(?P<reason>[^"]{1,80})")?
    (?:\s+notes\s*=\s*"(?P<notes>[^"]{1,500})")?
    """,
    flags=re.IGNORECASE | re.VERBOSE | re.DOTALL,
)
_VALID_REASONS = {
    "accepted_risk", "wont_fix", "false_positive",
    "duplicate", "out_of_scope",
}


@dataclass
class SuppressCommand:
    finding_id: str
    reason: str
    notes: str | None = None


def parse_suppress_command(comment_body: str) -> SuppressCommand | None:
    """Extract the first ``pencheff: suppress …`` directive in a PR comment.

    Returns ``None`` when no command is present or the reason isn't on
    the allowlist (the underlying finding endpoint enforces the same
    list, so an unknown reason never reaches it).
    """
    if not comment_body:
        return None
    m = _SUPPRESS_RE.search(comment_body)
    if not m:
        return None
    reason = (m.group("reason") or "accepted_risk").lower()
    if reason not in _VALID_REASONS:
        return None
    return SuppressCommand(
        finding_id=m.group("finding_id"),
        reason=reason,
        notes=m.group("notes"),
    )


# ─── Internals ──────────────────────────────────────────────────────


async def _build_headers(
    *,
    installation_id: int | str | None,
    pat: str | None,
) -> dict[str, str]:
    if installation_id:
        token = await github_app.get_installation_token(installation_id)
    elif pat:
        token = pat
    else:
        raise ValueError("post_check_run/upload_sarif require installation_id or pat")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _severity_counts(findings: list[_Finding]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for f in findings:
        sev = f.severity if f.severity in out else "info"
        out[sev] += 1
        out["total"] += 1
    return out


def _default_ref(head_sha: str) -> str:
    """Fallback ref when the caller doesn't supply one. Code-scanning
    ingest requires *some* ref; ``refs/heads/main`` is the safest
    default for repos that pin to it."""
    return "main"
