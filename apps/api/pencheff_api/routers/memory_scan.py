# SPDX-License-Identifier: AGPL-3.0-or-later
"""Memory scanner endpoint — audit agent memory / vector-store items.

``POST /v1/memory/scan`` takes a batch of memory items (long-term memory
rows, RAG chunks, retrieved docs, context entries) and returns findings:
secrets / PII at rest (LLM02) and memory poisoning — injected instructions
hidden in stored content (LLM04). Stateless: scans and returns, no
persistence. Used by the SDK / CI and (optionally) a paste-and-scan UI.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ..auth.deps import get_active_workspace, require_scope
from ..db.models import Workspace

router = APIRouter(tags=["memory-scan"])


class MemoryFindingOut(BaseModel):
    item_id: str
    category: str
    detector: str
    severity: str
    reason: str
    matched_text: str
    risk_score: float


class MemoryScanOut(BaseModel):
    items_scanned: int
    clean: bool
    severity_counts: dict[str, int]
    findings: list[MemoryFindingOut]


@router.post(
    "/v1/memory/scan",
    response_model=MemoryScanOut,
    dependencies=[Depends(require_scope("proxy:read"))],
)
async def scan_memory_endpoint(
    body: dict[str, Any],
    workspace: Workspace = Depends(get_active_workspace),
) -> MemoryScanOut:
    try:
        from pencheff_sentry.memory import scan_memory
    except ImportError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "memory scanner unavailable (pencheff-sentry not installed)",
        )
    try:
        result = scan_memory(body.get("items"))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    return MemoryScanOut(
        items_scanned=result.items_scanned,
        clean=result.clean,
        severity_counts=result.severity_counts,
        findings=[
            MemoryFindingOut(
                item_id=f.item_id, category=f.category, detector=f.detector,
                severity=f.severity, reason=f.reason,
                matched_text=f.matched_text, risk_score=f.risk_score,
            )
            for f in result.findings
        ],
    )
