"""Cross-reference DAST × SAST × SCA × IaC × secret findings.

This service runs after a scan finishes (or after a repo scan finishes) and
adds rows to ``unified_findings``. It is intentionally narrow: only edges
above a configurable confidence threshold are emitted.

Three correlation strategies, each cheap:
  1. shared-cwe   — DAST.cwe_id == SAST.rule's CWE
  2. shared-cve   — finding mentions the same CVE id
  3. semantic-match — DAST endpoint regex hits a SAST file path

Anything more is left to the agent's `exploit_chain_suggest` tool, which
already does richer reasoning.
"""
from __future__ import annotations

import re
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Finding, RepoFinding, UnifiedFinding


CONFIDENCE_THRESHOLD = 0.6


def _route_basename(path: str) -> str | None:
    """Pull a route-like token out of a file path.

    e.g. ``apps/api/routes/preview.ts`` → ``preview``;
    ``src/views/admin/users.tsx`` → ``users``.
    """
    if not path:
        return None
    base = path.rsplit("/", 1)[-1]
    base = base.split(".", 1)[0]
    base = base.replace("_", "-").lower()
    return base or None


def _scanner_to_kind(scanner: str) -> str:
    if scanner in ("osv", "ghsa"):
        return "sca"
    if scanner == "gitleaks":
        return "secret"
    if scanner in ("trivy_iac", "checkov"):
        return "iac"
    return "sast"


async def correlate_engagement_findings(
    session: AsyncSession, engagement_id: str
) -> int:
    """Compute correlation edges for an engagement. Returns rows added."""
    dast_rows = (await session.execute(
        select(Finding).where(Finding.engagement_id == engagement_id)
    )).scalars().all()
    sast_rows = (await session.execute(
        select(RepoFinding).where(RepoFinding.engagement_id == engagement_id)
    )).scalars().all()

    if not dast_rows or not sast_rows:
        return 0

    existing = (await session.execute(
        select(
            UnifiedFinding.primary_finding_kind,
            UnifiedFinding.primary_finding_id,
            UnifiedFinding.related_finding_kind,
            UnifiedFinding.related_finding_id,
            UnifiedFinding.link_kind,
        ).where(UnifiedFinding.engagement_id == engagement_id)
    )).all()
    have: set[tuple[str, str, str, str, str]] = set(existing)  # noqa: F841 — dedup tuples

    added = 0
    for d in dast_rows:
        d_cwe = d.cwe_id
        d_endpoint = (d.endpoint or "").lower()
        d_route_token = _route_basename(d_endpoint.rstrip("/").split("/")[-1])

        for r in sast_rows:
            r_kind = _scanner_to_kind(r.scanner)

            # 1) shared CWE
            if d_cwe and (r.raw or {}).get("metadata", {}).get("cwe") == d_cwe:
                key = ("dast", d.id, r_kind, r.id, "shared-cwe")
                if key not in have:
                    session.add(UnifiedFinding(
                        engagement_id=engagement_id,
                        primary_finding_kind="dast", primary_finding_id=d.id,
                        related_finding_kind=r_kind, related_finding_id=r.id,
                        link_kind="shared-cwe", confidence=0.7,
                        rationale=f"Both findings reference CWE {d_cwe}.",
                    ))
                    have.add(key)
                    added += 1

            # 2) shared CVE
            if r.cve and d.evidence:
                refs_text = "".join(str(e) for e in (d.evidence or []))
                if r.cve in refs_text:
                    key = ("dast", d.id, r_kind, r.id, "shared-cve")
                    if key not in have:
                        session.add(UnifiedFinding(
                            engagement_id=engagement_id,
                            primary_finding_kind="dast", primary_finding_id=d.id,
                            related_finding_kind=r_kind, related_finding_id=r.id,
                            link_kind="shared-cve", confidence=0.85,
                            rationale=f"Both findings reference {r.cve}.",
                        ))
                        have.add(key)
                        added += 1

            # 3) semantic-match: DAST endpoint includes a path token equal to
            # the SAST file basename. Cheap, surprisingly effective.
            if d_route_token and r.file_path:
                r_token = _route_basename(r.file_path)
                if r_token and r_token == d_route_token and len(r_token) >= 4:
                    key = ("dast", d.id, r_kind, r.id, "semantic-match")
                    if key not in have:
                        session.add(UnifiedFinding(
                            engagement_id=engagement_id,
                            primary_finding_kind="dast", primary_finding_id=d.id,
                            related_finding_kind=r_kind, related_finding_id=r.id,
                            link_kind="semantic-match", confidence=0.65,
                            rationale=(
                                f"DAST endpoint `{d_endpoint}` shares a route "
                                f"token with SAST file `{r.file_path}`."
                            ),
                        ))
                        have.add(key)
                        added += 1

    if added:
        await session.commit()
    return added
