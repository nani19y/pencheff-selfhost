import asyncio
import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from ..auth.deps import get_active_workspace, get_current_user, require_scope
from ..db.base import get_session
from ..db.models import (
    Engagement,
    Finding as DbFinding,
    Repository,
    Scan,
    ScanLLMTrace,
    Target,
    TargetRepository,
    User,
    Workspace,
)
from ..events import async_subscriber, channel_for
from ..schemas.scans import (
    KIND_REQUIRED_DISCLOSED_ACTIONS,
    ArtifactTargetScanIn,
    ExternalScanIn,
    RepoScanIn,
    FindingInput,
    FindingsSyncIn,
    FindingsSyncOut,
    McpFinalizeIn,
    McpScanCreate,
    McpScanOut,
    ScanAiQuotaOut,
    ScanCreate,
    ScanOut,
)
from ..config import get_settings
from ..schemas.load_test import LoadTestConfig
from ..services import quota as quota_service
from ..scan_categories import category_service
from ..services.scan_dispatch import enqueue_full_scan
from ..services.scan_runner import _clip_finding_row
from ..services.worker_lifecycle import ensure_worker_started_or_503
from ..tasks.validate_task import validate_findings as _validate_task


def _required_disclosed_actions(target: Target) -> frozenset[str]:
    """Return the set of disclosed_actions required for this target's kind.

    Hybrid kinds (cicd_pipeline live-API, k8s_cluster live-cluster) extend
    the base required set when ``kind_config`` implies live-system probing.
    Per spec §10.6 + feature 001 GATE 2 S-03.
    """
    base = set(KIND_REQUIRED_DISCLOSED_ACTIONS.get(target.kind, frozenset()))
    cfg = target.kind_config or {}
    if target.kind == "cicd_pipeline" and cfg.get("live_api_enabled") is True:
        base.add("ci_api_read")
    if target.kind == "k8s_cluster" and cfg.get("target") == "live_cluster":
        base.add("k8s_api_read")
        if cfg.get("rbac_enum") is True:
            base.add("rbac_enumeration")
    if target.kind in ("mcp", "agent"):
        if cfg.get("dynamic_invocation") is True:
            base.add("mcp_tool_invocation")
            if cfg.get("destructive_opt_in") is True:
                base.add("mcp_destructive_tool_invocation")
    if target.kind == "rag":
        if cfg.get("query_probes") is True:
            base.add("rag_query_probe")
            if cfg.get("poison_injection_opt_in") is True:
                base.add("rag_poison_injection")
    if target.kind == "voice":
        if cfg.get("audio_probes") is True:
            base.add("voice_audio_probe")
            if cfg.get("source_type") == "voice_auth":
                base.add("voice_auth_probe")
    return frozenset(base)


# Backward-compat for a FE/BE deploy skew: a frontend that predates a kind's
# disclosure vocabulary falls back to the generic URL recon triple
# (passive_recon/active_recon/exploitation) in its consent modal. The `agent`
# kind was added after the currently-deployed frontend, so a real operator's
# consent payload carries that legacy triple instead of `agent_probe`. Until
# the frontend deploy catches up, accept the legacy disclosure as covering the
# new base action — the operator still saw three explicit actions, wrote a
# ≥50-char authorization, and acknowledged. Remove once the FE deploy lands.
_LEGACY_DISCLOSURE_ALIASES: dict[str, frozenset[str]] = {
    "agent_probe": frozenset({"passive_recon", "active_recon", "exploitation"}),
}


def _missing_required_actions(required: frozenset[str], supplied: set[str]) -> list[str]:
    """Required actions not covered by ``supplied`` — directly or via a legacy
    disclosure alias (FE/BE deploy-skew tolerance). Sorted for stable errors."""
    missing: list[str] = []
    for action in sorted(required - supplied):
        alias = _LEGACY_DISCLOSURE_ALIASES.get(action)
        if alias and alias <= supplied:
            continue
        missing.append(action)
    return missing


def _derive_kind_payload(target: Target, override: dict | None) -> dict | None:
    """Server-derives Scan.kind_payload from Target.kind_config at scan-creation.

    For the 11 new non-llm/non-repo/non-url kinds, the payload always carries
    the kind discriminator. Operator-supplied overrides (e.g. container_image
    digest_override) are merged on top per spec §10.5. Returns None for the
    3 legacy kinds + source_code (which uses RepoScan, not Scan).
    """
    if target.kind in {"url", "repo", "llm", "source_code"}:
        return None
    payload: dict = {"kind": target.kind}
    if override:
        # Override must discriminate to the same kind — router enforces this
        # before calling _derive_kind_payload.
        for k, v in override.items():
            if k == "kind":
                continue
            payload[k] = v
    return payload

router = APIRouter(prefix="/scans", tags=["scans"])


def _finding_to_dict(row: DbFinding) -> dict:
    """Project a DB Finding row into a dict shaped for the LLM
    red-team comparison helpers."""
    return {
        "id": row.id,
        "title": row.title,
        "severity": row.severity,
        "category": row.category,
        "owasp_category": row.owasp_category,
        "endpoint": row.endpoint,
        "parameter": row.parameter,
        "description": row.description,
        "remediation": row.remediation,
    }


def _to_out(s: Scan, *, target_kind: str | None = None) -> ScanOut:
    # ``has_threat_model`` is computed from the scan's summary metadata —
    # the dispatcher writes ``threat_model_source`` ∈ {"engagement",
    # "auto_engagement", "fly_by"} when it resolves a model. Only the
    # persisted variants ("engagement", "auto_engagement") are linkable;
    # fly-by lives on summary.threat_model_bias and is gone after the scan.
    src = (s.summary or {}).get("threat_model_source") if s.summary else None
    return ScanOut(
        id=s.id, target_id=s.target_id, status=s.status, profile=s.profile,
        progress_pct=s.progress_pct, current_stage=s.current_stage,
        grade=s.grade, score=s.score, summary=s.summary, log=s.log, error=s.error,
        started_at=s.started_at, finished_at=s.finished_at, created_at=s.created_at,
        consent_payload=s.consent_payload,
        has_threat_model=src in ("engagement", "auto_engagement"),
        target_kind=target_kind,
    )


async def _ensure_deep_engagement(
    session: AsyncSession,
    target: Target,
    workspace: Workspace,
    user: User,
) -> Engagement:
    """Find or create the canonical engagement for deep scans of ``target``.

    The slug ``deep-{target.id[:8]}`` deterministically maps a target to
    one engagement so repeated deep scans accumulate into the same
    container — findings, threat-model edits, and notes pile up over
    time rather than fragmenting across one-shot scans.

    Closed engagements with this slug are skipped (the operator decided
    to archive that engagement, so we open a new one), but only one
    *open* engagement per (workspace, target) is ever active.
    """
    slug = f"deep-{target.id[:8]}"
    eng = (await session.execute(
        select(Engagement).where(
            Engagement.workspace_id == workspace.id,
            Engagement.slug == slug,
            Engagement.status == "open",
        )
    )).scalar_one_or_none()
    if eng is not None:
        return eng

    eng = Engagement(
        workspace_id=workspace.id,
        org_id=workspace.org_id,
        name=f"Deep scans — {target.name or target.base_url or target.id[:8]}",
        slug=slug,
        description=(
            f"Auto-created on first deep-profile scan of "
            f"{target.base_url or target.name or target.id}. "
            f"Subsequent deep scans against this target reuse this "
            f"engagement; the threat model attached here drives module "
            f"priority biasing for every one of them."
        ),
        status="open",
        created_by_user_id=user.id,
    )
    session.add(eng)
    await session.flush()  # populate eng.id without committing yet
    return eng


@router.post(
    "",
    response_model=ScanOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("scans:write"))],
)
async def start_scan(
    body: ScanCreate,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ScanOut:
    target = (await session.execute(
        select(Target).where(Target.id == body.target_id, Target.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    # Repo-mirror Targets can't be DAST-scanned — the URL is github.com,
    # not the application itself. Route to the repo-scan endpoint, which
    # drives SAST/SCA over a clone of the repository.
    if target.kind == "repo" or target.repository_id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"This target is a repository mirror — DAST scans don't apply. "
            f"Use POST /repos/{target.repository_id}/scan instead.",
        )
    # Sub-project A: host-kind scanning ships in sub-project B (OSExploitAgent).
    # Until then, fail fast so no Scan row is created and no Celery task fires.
    # host targets run a live read-only TCP port-scan / network-exposure posture
    # check via host_orchestrator (kind-aware dispatch in scan_runner). OS-level
    # exploitation (the deferred OSExploitAgent, sub-project B) is still out of
    # scope, but network-exposure scanning is available.
    # Memory targets aren't scanned through the Celery /scans pipeline — they
    # use the stateless POST /v1/memory/scan endpoint (paste-and-scan / SDK /
    # the detail-page MemoryPanel). Reject here so a memory target can never
    # fall through to the URL/DAST runner, which would mis-scan "memory://…".
    if target.kind == "memory":
        raise HTTPException(
            status_code=409,
            detail={
                "error": "memory_kind_uses_dedicated_endpoint",
                "message": (
                    "Memory / vector-store targets are scanned via "
                    "POST /v1/memory/scan, not the assessment pipeline."
                ),
            },
        )
    # LLM targets need llm_config populated (the form enforces this on
    # create, but a partial update could in principle blank it). Bail
    # early rather than letting the worker crash with a confusing
    # message.
    if target.kind == "llm" and not target.llm_config:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "LLM target is missing llm_config; edit the target before commissioning a scan.",
        )
    # Per-feature-001: validate kind_payload (if supplied) discriminates to the
    # target's kind. Server still derives the actual payload below — the body
    # field is for operator overrides.
    if body.kind_payload is not None and body.kind_payload.kind != target.kind:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"kind_payload.kind ({body.kind_payload.kind!r}) must match "
            f"target kind ({target.kind!r})",
        )
    # Scans are no longer hard-blocked by quota. When an org is over its
    # monthly allotment the scan still runs, but the runner forces it into
    # deterministic-only mode (see services.quota.scan_ai_allowed).

    # ── Consent validation ────────────────────────────────────────────────
    # Pydantic already guarantees acknowledged=True, authorization_text≥50,
    # and disclosed_actions non-empty. We now enforce temporal freshness and
    # overwrite the user-id with the server-side authenticated identity.
    cp = body.consent_payload
    now_utc = datetime.now(tz=timezone.utc)
    if cp.consent_given_at is not None:
        # Normalise to UTC for comparison.
        given_at = cp.consent_given_at
        if given_at.tzinfo is None:
            given_at = given_at.replace(tzinfo=timezone.utc)
        else:
            given_at = given_at.astimezone(timezone.utc)
        age = now_utc - given_at
        if age > timedelta(minutes=5):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "consent_given_at is stale (more than 5 minutes old); "
                "please re-submit your consent.",
            )
        cp.consent_given_at = given_at
    else:
        cp.consent_given_at = now_utc
    # Server-side overwrite: never trust the client's claim about who consented.
    cp.consent_given_by_user_id = user.id
    # Ensure version is set.
    if cp.version is None:
        cp.version = 1

    # Per-feature-001 (S-03): enforce kind-aware disclosed_actions coverage.
    required = _required_disclosed_actions(target)
    # Load testing is DoS-adjacent — require an explicit disclosed action on top
    # of any kind-specific ones, regardless of target kind.
    if body.profile == "load":
        required = required | frozenset({"load_testing"})
    if required:
        supplied = {a.strip() for a in (cp.disclosed_actions or []) if a and a.strip()}
        missing = _missing_required_actions(required, supplied)
        if missing:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"consent_payload.disclosed_actions is missing required action(s) for "
                f"kind={target.kind!r}: {', '.join(missing)}",
            )

    # ── Engagement resolution + threat-model attachment ────────────────────
    #
    # Rules:
    #   1. If the caller pinned an engagement_id, verify it (cross-tenant
    #      safety) and use whatever model that engagement carries.
    #   2. Else, if profile == "deep", auto-create (or reuse) a target-
    #      pinned engagement and persist a DREAD threat model on it. This
    #      makes deep scans repeatable: the same target always lands in
    #      the same engagement, accumulating findings + a stable model.
    #   3. Else, synthesise a fly-by threat model from the target URL and
    #      use it for biasing only — no persistence. This still lets a
    #      quick / standard scan reorder modules toward the highest-impact
    #      categories without forcing engagement bookkeeping.
    #
    # Whatever path runs, ``threat_model_for_scan`` is the model that
    # drives ``module_priority_bias`` for THIS scan — stamped into
    # ``Scan.summary`` so the worker reorders + the dashboard can show
    # why a particular module fired first.
    from ..services.threat_model import (
        generate_threat_model,
        module_priority_bias,
    )

    engagement_id: str | None = None
    threat_model_for_scan: dict | None = None
    threat_model_source: str | None = None  # "engagement" | "auto_engagement" | "fly_by"

    if body.engagement_id:
        eng = (await session.execute(
            select(Engagement).where(
                Engagement.id == body.engagement_id,
                Engagement.workspace_id == workspace.id,
            )
        )).scalar_one_or_none()
        if eng is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        if eng.status != "open":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "engagement is closed")
        engagement_id = eng.id
        if eng.threat_model:
            threat_model_for_scan = eng.threat_model
            threat_model_source = "engagement"
        elif target.base_url:
            # Engagement supplied but no model on it — generate a fly-by
            # for this scan rather than mutating the engagement (the
            # operator's intent for that engagement may be model-free).
            threat_model_for_scan = generate_threat_model(
                target_url=target.base_url, method="dread"
            )
            threat_model_source = "fly_by"
    elif body.profile == "deep":
        eng = await _ensure_deep_engagement(session, target, workspace, user)
        engagement_id = eng.id
        if not eng.threat_model and target.base_url:
            eng.threat_model = generate_threat_model(
                target_url=target.base_url, method="dread"
            )
            eng.threat_model_updated_at = datetime.now(timezone.utc)
            # session.commit below picks this up.
        threat_model_for_scan = eng.threat_model
        threat_model_source = "auto_engagement"
    elif target.base_url:
        # Non-deep, no engagement: fly-by, no persistence.
        threat_model_for_scan = generate_threat_model(
            target_url=target.base_url, method="dread"
        )
        threat_model_source = "fly_by"

    threat_model_bias = (
        module_priority_bias(threat_model_for_scan) if threat_model_for_scan else []
    )

    initial_summary: dict | None = None
    if threat_model_bias:
        initial_summary = {
            "threat_model_bias": threat_model_bias,
            "threat_model_method": (threat_model_for_scan or {}).get("method"),
            "threat_model_source": threat_model_source,
        }

    # Sanitise notify_emails: strip whitespace, drop empties, dedupe,
    # cap to 10 to keep email blasts bounded.
    notify_emails: list[str] | None = None
    if body.notify_emails:
        seen: set[str] = set()
        clean: list[str] = []
        for raw in body.notify_emails:
            e = (raw or "").strip()
            if not e or "@" not in e or e in seen:
                continue
            seen.add(e)
            clean.append(e)
        notify_emails = clean[:10] or None

    await ensure_worker_started_or_503(service=category_service(target.kind))

    scan = Scan(
        target_id=target.id, org_id=workspace.org_id, workspace_id=workspace.id,
        engagement_id=engagement_id,
        user_id=user.id, profile=body.profile, status="queued",
        # Seed a stage immediately so the UI shows "waiting for a worker" from the
        # first render — before the ECS scaler's next tick narrates the cold start
        # (in VM mode a worker picks it up almost at once and this flashes briefly).
        current_stage="Waiting for a worker…",
        consent_payload=cp.model_dump(mode="json"),
        summary=initial_summary,
        notify_emails=notify_emails,
        # Operator AI toggle from the commission modal. The runner honours
        # this (deterministic-only when False); over-quota orgs still degrade
        # to deterministic regardless of this flag.
        use_ai=body.use_ai,
        # Per-feature-001: server-derived kind_payload (NULL for legacy
        # url/repo/llm/source_code). Operator overrides merged in.
        kind_payload=_derive_kind_payload(
            target,
            body.kind_payload.model_dump() if body.kind_payload else None,
        ),
    )
    # Load mode: stash the (bounded) load config on kind_payload so the runner
    # (_run_load_scan) reads it. Kept off the discriminated KindPayload union.
    if body.profile == "load":
        kp = dict(scan.kind_payload or {})
        kp["load_test"] = (body.load_test or LoadTestConfig()).clamped().model_dump()
        scan.kind_payload = kp
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    enqueue_full_scan(scan.id, target.kind)
    return _to_out(scan)


@router.post(
    "/mcp",
    response_model=McpScanOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("scans:write"))],
)
async def create_mcp_scan(
    body: McpScanCreate,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> McpScanOut:
    """Create (or return the existing) Scan row for a remote-MCP session.

    Target is auto-resolved/created by URL in the caller's workspace. status="running".
    NEVER dispatches the server-side scanning agent (that is the whole point of SP2)."""
    url = body.target_url.rstrip("/")

    # find-or-create Target by (workspace, base_url, kind="url")
    target = (await session.execute(
        select(Target).where(
            Target.workspace_id == workspace.id,
            Target.base_url == url,
            Target.kind == "url",
        )
    )).scalars().first()
    if target is None:
        target = Target(
            org_id=workspace.org_id, workspace_id=workspace.id, user_id=user.id,
            name=url[:200], base_url=url, kind="url",
        )
        session.add(target)
        await session.flush()

    # create-or-get Scan by mcp_session_id
    existing = (await session.execute(
        select(Scan).where(
            Scan.workspace_id == workspace.id,
            Scan.kind_payload["mcp_session_id"].astext == body.mcp_session_id,
        )
    )).scalars().first()
    if existing is not None:
        return McpScanOut(scan_id=existing.id, created=False)

    scan = Scan(
        target_id=target.id, org_id=workspace.org_id, workspace_id=workspace.id,
        user_id=user.id, status="running", profile=body.profile, use_ai=False,
        engagement_id=body.engagement_id,
        # MCP consent is handled client-side; skip start_scan's ConsentPayload/disclosed-action gating (SP2 spec).
        consent_payload={"source": "mcp", "actor": user.id},
        kind_payload={"source": "mcp", "mcp_session_id": body.mcp_session_id},
    )
    session.add(scan)
    await session.commit()
    return McpScanOut(scan_id=scan.id, created=True)


@router.post(
    "/{scan_id}/mcp-finalize",
    dependencies=[Depends(require_scope("scans:write"))],
)
async def finalize_mcp_scan(
    scan_id: str,
    body: McpFinalizeIn,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict:
    scan = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalars().first()
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_not_found")
    scan.status = "done"
    scan.finished_at = datetime.now(timezone.utc)
    if body.summary is not None:
        scan.summary = body.summary
    if body.grade is not None:
        scan.grade = body.grade
    if body.score is not None:
        scan.score = body.score
    await session.commit()
    return {"status": "done"}


def _mcp_finding_to_row(scan_id: str, fi: FindingInput) -> dict:
    """Map a FindingInput (JSON) → Finding DB row, reusing the same
    intelligence enrichment as the server-side pipeline."""
    evidence = list(fi.evidence or [])
    epss = None
    kev = False
    for ev in evidence:
        af = (ev or {}).get("autofix") or {}
        if af.get("epss") is not None:
            try:
                epss = float(af["epss"])
            except (TypeError, ValueError):
                pass
        if af.get("kev"):
            kev = True
    reachability_value = "unknown"
    try:
        from pencheff.intelligence import classify_reachability
        reachability_value = classify_reachability(
            finding_kind="dast", category=fi.category or "unknown",
            evidence=evidence, verification_notes=None,
            verification_status=fi.verification_status,
        ).value
    except Exception:
        pass
    ssvc_value = None
    risk_score = None
    try:
        from pencheff.intelligence import PriorityInputs, compute_priority
        out = compute_priority(PriorityInputs(
            cvss=fi.cvss_score, epss=epss, kev=kev,
            category=fi.category or "unknown", finding_kind="dast",
            reachability=reachability_value,
        ))
        ssvc_value = out.ssvc.value
        risk_score = out.score
    except Exception:
        pass
    return _clip_finding_row({
        "scan_id": scan_id,
        "pencheff_finding_id": fi.pencheff_finding_id,
        "title": fi.title or "Untitled",
        "severity": (fi.severity or "info").lower(),
        "category": fi.category or "unknown",
        "owasp_category": fi.owasp_category,
        "cwe_id": fi.cwe_id,
        "cvss_score": fi.cvss_score,
        "cvss_vector": fi.cvss_vector,
        "endpoint": fi.endpoint,
        "parameter": fi.parameter,
        "description": fi.description,
        "remediation": fi.remediation,
        "evidence": evidence,
        "references_": list(fi.references or []),
        "verification_status": fi.verification_status or "unverified",
        "suppressed": bool(fi.suppressed),
        "epss": epss,
        "kev": kev,
        "risk_score": risk_score,
        "ssvc_decision": ssvc_value,
        "reachability": reachability_value,
    })


@router.post(
    "/{scan_id}/mcp-findings",
    response_model=FindingsSyncOut,
    dependencies=[Depends(require_scope("scans:write"))],
)
async def sync_mcp_findings(
    scan_id: str,
    body: FindingsSyncIn,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FindingsSyncOut:
    scan = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalars().first()
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_not_found")

    existing = (await session.execute(
        select(DbFinding).where(DbFinding.scan_id == scan_id)
    )).scalars().all()
    by_ext = {f.pencheff_finding_id: f for f in existing if f.pencheff_finding_id}

    inserted = updated = 0
    for fi in body.findings:
        row = _mcp_finding_to_row(scan_id, fi)
        cur = by_ext.get(fi.pencheff_finding_id)
        if cur is None:
            session.add(DbFinding(**row))
            inserted += 1
        else:
            for k, v in row.items():
                if k == "scan_id":
                    continue
                setattr(cur, k, v)
            updated += 1
    await session.commit()
    return FindingsSyncOut(inserted=inserted, updated=updated)


@router.get(
    "",
    response_model=list[ScanOut],
    dependencies=[Depends(require_scope("scans:read"))],
)
async def list_scans(
    target_id: str | None = None,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[ScanOut]:
    q = select(Scan).where(Scan.workspace_id == workspace.id).order_by(Scan.created_at.desc()).limit(200)
    if target_id:
        q = q.where(Scan.target_id == target_id)
    rows = (await session.execute(q)).scalars().all()
    return [_to_out(s) for s in rows]


@router.get(
    "/ai-quota",
    response_model=ScanAiQuotaOut,
    dependencies=[Depends(require_scope("scans:read"))],
)
async def scan_ai_quota(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ScanAiQuotaOut:
    """Pre-flight scan-AI allowance for the commission modal. The 'Use AI for
    this scan' toggle is force-disabled when ``ai_available`` is False —
    either the org's plan has no AI access or its monthly AI quota is spent."""
    snap = await quota_service.scan_ai_snapshot(session, workspace.org_id)
    return ScanAiQuotaOut(**snap)


@router.get(
    "/{scan_id}",
    response_model=ScanOut,
    dependencies=[Depends(require_scope("scans:read"))],
)
async def get_scan(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ScanOut:
    s = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    # One extra query to expose the target kind on the response —
    # the assessment page uses it to gate LLM-only UI surfaces (e.g.
    # the Recommended Guardrails card).
    target = await session.get(Target, s.target_id)
    return _to_out(s, target_kind=target.kind if target else None)


@router.get(
    "/{scan_id}/linked-repos",
    dependencies=[Depends(require_scope("scans:read"))],
)
async def get_linked_repos(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    """Repos attached to this scan's URL target.

    The URL scan no longer mixes SAST findings into its own results —
    instead, this endpoint returns the linked repo IDs so the UI can
    render deep-links to ``/repos/{id}`` (where the repo's own SAST/SCA
    findings live).
    """
    s = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    rows = (await session.execute(
        select(Repository)
        .join(TargetRepository, TargetRepository.repository_id == Repository.id)
        .where(TargetRepository.target_id == s.target_id)
        .order_by(Repository.full_name)
    )).scalars().all()

    return [
        {
            "repository_id": r.id,
            "full_name": r.full_name,
            "provider": getattr(r, "provider", None),
            "scan_url": f"/repos/{r.id}",
        }
        for r in rows
    ]


@router.get(
    "/{scan_id}/llm-transcripts",
    dependencies=[Depends(require_scope("scans:read"))],
)
async def get_llm_transcripts(
    scan_id: str,
    format: str = Query("jsonl", regex="^(jsonl|json)$"),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Return the per-probe transcript file for an LLM red-team scan.

    The scan runner writes one JSONL line per probe (full request,
    full response, verdict, verdict_reason, latency, tokens, …) to
    ``$TMPDIR/pencheff-llm-transcripts/<scan_id>/probes.jsonl``. This
    endpoint streams that file back to authorised callers.

    ``format=jsonl`` (default) returns the raw JSONL stream.
    ``format=json`` returns a single JSON array — convenient for
    ad-hoc inspection in the browser.
    """
    s = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    path = Path(tempfile.gettempdir()) / "pencheff-llm-transcripts" / scan_id / "probes.jsonl"
    if not path.is_file():
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "transcript file not found — either the scan never ran the LLM "
            "red team stage, the file expired with the worker's tmpdir, or "
            "the scan was created before transcript dumping was enabled.",
        )
    if format == "jsonl":
        return FileResponse(
            path,
            media_type="application/x-ndjson",
            filename=f"pencheff-llm-transcripts-{scan_id[:8]}.jsonl",
        )
    # format=json: parse line-by-line and return as a JSON array.
    records: list[dict] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc))
    return Response(
        content=json.dumps({"scan_id": scan_id, "count": len(records), "records": records}),
        media_type="application/json",
    )


@router.get(
    "/{scan_id}/threat-model",
    dependencies=[Depends(require_scope("scans:read"))],
)
async def get_scan_threat_model(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Return the persisted STRIDE / DREAD threat model attached to a scan.

    The dispatcher ties every deep-profile scan (and any scan with an
    explicit container) to a persisted model. ``summary.threat_model_source``
    on the scan row records which path resolved the model:

      * ``engagement`` / ``auto_engagement`` — model is persisted; this
        endpoint returns it verbatim.
      * ``fly_by`` — model lives only on ``summary.threat_model_bias`` for
        module priority; this endpoint returns 404 since there is nothing
        durable to fetch.

    The response shape intentionally surfaces ``threat_model`` and
    ``threat_model_updated_at`` only — internal storage details (which
    container row owns it, retention policy, members) never leak through
    this scan-scoped endpoint.
    """
    # Workspace-scope check, then resolve the linked container internally.
    s = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    if not s.engagement_id:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "no persisted threat model for this scan",
        )

    eng = await session.get(Engagement, s.engagement_id)
    if eng is None or eng.workspace_id != workspace.id:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "no persisted threat model for this scan",
        )
    if eng.threat_model is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "no persisted threat model for this scan",
        )

    return {
        "scan_id": scan_id,
        "threat_model": eng.threat_model,
        "threat_model_updated_at": (
            eng.threat_model_updated_at.isoformat()
            if eng.threat_model_updated_at
            else None
        ),
    }


@router.get(
    "/{scan_id}/compliance",
    dependencies=[Depends(require_scope("scans:read"))],
)
async def get_scan_compliance(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Return the per-scan compliance rollup for a URL or LLM scan.

    Mirrors ``GET /scans/{id}/threat-model`` in shape and semantics but
    fans every Finding out across the framework set that matches the
    target's kind:

    * ``url`` targets → OWASP Top 10, PCI-DSS 4.0, NIST 800-53 Rev 5,
      SOC 2, ISO 27001:2022, HIPAA.
    * ``llm`` targets → OWASP LLM Top 10 (2025), MITRE ATLAS,
      NIST AI Risk Management Framework, EU AI Act.

    Repository scans use ``GET /repos/scans/{id}/compliance`` instead;
    the rollup model is the same but reads from ``repo_findings``.

    The response shape is documented in
    ``services.compliance.build_compliance_rollup`` and is the contract
    consumed by the web UI at ``/scans/[id]/compliance`` and by the
    DOCX/Markdown report generator's compliance appendix.
    """
    from ..services.compliance import build_compliance_rollup

    s = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    # ``Target.kind`` is one of {"url", "repo", "llm"} but in practice
    # only URL and LLM targets reach this endpoint — repo scans flow
    # through ``GET /repos/scans/{id}/compliance`` instead. Default to
    # "url" if a future kind appears or a row is missing.
    target = await session.get(Target, s.target_id)
    target_kind = target.kind if target and target.kind in ("url", "llm") else "url"

    rows = (await session.execute(
        select(DbFinding).where(
            DbFinding.scan_id == scan_id,
            DbFinding.suppressed.is_(False),
        )
    )).scalars().all()

    return build_compliance_rollup(
        scan_id=scan_id,
        target_kind=target_kind,
        findings=rows,
    )


@router.get(
    "/{scan_id}/llm-traces",
    dependencies=[Depends(require_scope("scans:read"))],
)
async def list_llm_traces(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Return every recorded LLM call for this scan in chronological order.

    Each row corresponds to one chat-completions round-trip made by a
    swarm agent (ReconAgent, a breaker, or ChainAgent). Rows are
    ordered by creation time so the caller can replay the agent's
    reasoning turn-by-turn.

    Returns 404 if the scan does not belong to the caller's workspace.
    Returns an empty ``traces`` list for scans that predate LLM trace
    persistence, or for scans where the swarm was not enabled.
    """
    # Workspace-scoping: mirror the exact pattern used in GET /{scan_id}.
    s = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    rows = (await session.execute(
        select(ScanLLMTrace)
        .where(ScanLLMTrace.scan_id == scan_id)
        .order_by(ScanLLMTrace.created_at.asc())
    )).scalars().all()

    return {
        "traces": [
            {
                "id": r.id,
                "agent_name": r.agent_name,
                "turn": r.turn,
                "request_messages": r.request_messages,
                "request_tools_count": r.request_tools_count,
                "response_content": r.response_content,
                "response_tool_calls": r.response_tool_calls,
                "response_reasoning": r.response_reasoning,
                "prompt_tokens": r.prompt_tokens,
                "completion_tokens": r.completion_tokens,
                "cached_tokens": r.cached_tokens,
                "reasoning_tokens": r.reasoning_tokens,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]
    }


@router.get(
    "/{scan_id}/evidence/{finding_id}.png",
    dependencies=[Depends(require_scope("scans:read"))],
)
async def get_evidence_screenshot(
    scan_id: str,
    finding_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FileResponse:
    """Serve an evidence screenshot captured by EvidenceCaptureAgent or
    AdminAccessAgent for a specific finding.

    Authentication and workspace-scoping are enforced: the scan must
    belong to the caller's active workspace. ``finding_id`` is validated
    to contain only URL-safe characters to prevent path traversal.
    """
    import os
    import re

    # Validate IDs to prevent path traversal.
    if not re.fullmatch(r"[A-Za-z0-9_-]+", scan_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", finding_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")

    # Workspace-scoping: mirror the exact pattern used in GET /{scan_id}.
    s = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    base = Path(os.path.expanduser("~/.pencheff/evidence")) / scan_id
    # EvidenceCaptureAgent writes <finding_id>.png;
    # AdminAccessAgent writes <finding_id>-admin.png.
    candidates = [
        base / f"{finding_id}.png",
        base / f"{finding_id}-admin.png",
    ]
    for path in candidates:
        if path.is_file():
            return FileResponse(path, media_type="image/png")
    raise HTTPException(status.HTTP_404_NOT_FOUND, "evidence not found")


@router.get(
    "/{a}/compare/{b}",
    dependencies=[Depends(require_scope("scans:read"))],
)
async def compare_scans(
    a: str,
    b: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Compare two scans of the same workspace.

    Returns regressions / fixes / common-failures plus per-side
    summaries. The diff key is stable (endpoint + parameter +
    technique + title), so re-running the same suite against the
    same target produces zero regressions when nothing changed."""
    rows = (await session.execute(
        select(Scan).where(Scan.id.in_([a, b]), Scan.workspace_id == workspace.id)
    )).scalars().all()
    by_id = {row.id: row for row in rows}
    scan_a = by_id.get(a)
    scan_b = by_id.get(b)
    if scan_a is None or scan_b is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "one or both scans not found")

    findings_a = (await session.execute(
        select(DbFinding).where(DbFinding.scan_id == a)
    )).scalars().all()
    findings_b = (await session.execute(
        select(DbFinding).where(DbFinding.scan_id == b)
    )).scalars().all()

    # Lazy import — comparison helpers live in the plugin package and
    # only need to be loaded for LLM scans.
    from pencheff.modules.llm_red_team.comparison import compare_red_team_runs

    payload = compare_red_team_runs(
        [_finding_to_dict(f) for f in findings_a],
        [_finding_to_dict(f) for f in findings_b],
        baseline_name=f"scan {a[:8]}",
        candidate_name=f"scan {b[:8]}",
    )
    payload["scan_a"] = {"id": scan_a.id, "target_id": scan_a.target_id, "profile": scan_a.profile,
                        "grade": scan_a.grade, "score": scan_a.score, "created_at": scan_a.created_at.isoformat()}
    payload["scan_b"] = {"id": scan_b.id, "target_id": scan_b.target_id, "profile": scan_b.profile,
                        "grade": scan_b.grade, "score": scan_b.score, "created_at": scan_b.created_at.isoformat()}
    return payload


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("scans:write"))],
)
async def delete_scan(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    s = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    await session.delete(s)
    await session.commit()


@router.post(
    "/{scan_id}/validate",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_scope("findings:write"))],
)
async def validate_scan(
    scan_id: str,
    mode: str = "standard",
    body: dict | None = Body(default=None),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
):
    scan = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    if mode not in ("standard", "deep"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "mode must be 'standard' or 'deep'")
    finding_ids = (body or {}).get("finding_ids")
    _validate_task.delay(scan_id, mode, finding_ids)
    return {"scan_id": scan_id, "mode": mode, "queued": True}


@router.get(
    "/{scan_id}/stream",
    dependencies=[Depends(require_scope("scans:read"))],
)
async def stream_scan(
    scan_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    workspace: Workspace = Depends(get_active_workspace),
):
    # get_active_workspace accepts both X-Workspace-Id headers and the
    # ?workspace_id= query parameter, so EventSource (which cannot set
    # headers) works.
    scan = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    async def event_generator():
        yield {"event": "snapshot", "data": json.dumps({
            "status": scan.status, "progress_pct": scan.progress_pct,
            "current_stage": scan.current_stage, "grade": scan.grade,
            "summary": scan.summary,
        })}
        redis_client = async_subscriber()
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(channel_for(scan_id))
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0), timeout=2.0)
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "1"}
                    continue
                if msg and msg.get("type") == "message":
                    yield {"event": "update", "data": msg["data"]}
                    try:
                        parsed = json.loads(msg["data"])
                        if parsed.get("type") in ("finished", "failed"):
                            break
                    except Exception:
                        pass
        finally:
            await pubsub.unsubscribe(channel_for(scan_id))
            await pubsub.close()
            await redis_client.close()

    return EventSourceResponse(event_generator())


@router.post(
    "/external",
    dependencies=[Depends(require_scope("scans:write"))],
    status_code=status.HTTP_201_CREATED,
)
async def ingest_external_scan(
    body: ExternalScanIn,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Record an externally-produced scan so its findings show in the UI.

    Used by the MCP ``ingest_findings`` tool: an IDE agent (driven by the
    pencheff MCP prompts) clones + SAST-scans a repo locally with its own
    tools, then POSTs the results here under the caller's org. The scan lands
    as ``status=done`` (no worker/AI involved) with the findings attached.
    """
    target = (
        await session.execute(
            select(Target).where(
                Target.workspace_id == workspace.id,
                Target.base_url == body.target_url,
                Target.kind == body.kind,
            )
        )
    ).scalar_one_or_none()
    if target is None:
        target = Target(
            org_id=workspace.org_id,
            workspace_id=workspace.id,
            name=(body.target_name or body.target_url)[:200],
            base_url=body.target_url,
            kind=body.kind,
        )
        session.add(target)
        await session.flush()

    now = datetime.now(timezone.utc)
    scan = Scan(
        target_id=target.id,
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        user_id=user.id,
        profile=body.profile,
        status="done",
        progress_pct=100,
        use_ai=False,
        started_at=now,
        finished_at=now,
        summary={"source": "external_mcp", "tool": body.tool or "mcp"},
        log=[f"external ingest: {len(body.findings)} finding(s) via {body.tool or 'mcp'}"],
    )
    session.add(scan)
    await session.flush()

    for f in body.findings:
        session.add(
            DbFinding(
                scan_id=scan.id,
                title=f.title[:500],
                severity=f.severity,
                category=(f.category or "sast")[:64],
                owasp_category=f.owasp_category,
                cwe_id=f.cwe_id,
                endpoint=(f.endpoint_str() or None),
                description=f.description,
                remediation=f.remediation,
                verification_status="unverified",
            )
        )
    await session.commit()

    base = get_settings().web_base_url.rstrip("/")
    return {
        "scan_id": scan.id,
        "target_id": target.id,
        "findings": len(body.findings),
        "url": f"{base}/scans/{scan.id}",
    }


@router.post(
    "/repository",
    dependencies=[Depends(require_scope("scans:write"))],
    status_code=status.HTTP_201_CREATED,
)
async def scan_repository(
    body: RepoScanIn,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Register a git repo as a source_code target and run a SAST scan on it.

    Used by the MCP ``scan_repository`` tool. The scan runs on the WORKER
    (which has git + the SAST toolchain) — not the MCP container — so 'scan
    this repo' via an IDE registers the target and its findings appear in the
    UI. Clones the URL server-side; no local filesystem access needed.
    """
    target = (
        await session.execute(
            select(Target).where(
                Target.workspace_id == workspace.id,
                Target.base_url == body.repo_url,
                Target.kind == "source_code",
            )
        )
    ).scalar_one_or_none()
    _host = body.repo_url.lower()
    _source = (
        "gitlab_url" if "gitlab" in _host
        else "bitbucket_url" if "bitbucket" in _host
        else "github_url"
    )
    # The artifact orchestrator clones from kind_config.repo_url (NOT base_url).
    _kind_config = {
        "kind": "source_code",
        "source": _source,
        "repo_url": body.repo_url,
        "git_ref": "HEAD",
    }
    if target is None:
        target = Target(
            org_id=workspace.org_id,
            workspace_id=workspace.id,
            name=(body.name or body.repo_url.rstrip("/").rsplit("/", 1)[-1] or body.repo_url)[:200],
            base_url=body.repo_url,
            kind="source_code",
            kind_config=_kind_config,
        )
        session.add(target)
        await session.flush()
    elif not (target.kind_config or {}).get("repo_url"):
        # Backfill an older target that predates kind_config.repo_url.
        target.kind_config = _kind_config

    now = datetime.now(timezone.utc)
    scan = Scan(
        target_id=target.id,
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        user_id=user.id,
        profile=body.profile,
        status="queued",
        use_ai=True,
        consent_payload={
            "acknowledged": True,
            "authorization_text": (
                "MCP-initiated SAST of a repository the caller registered for "
                "their own organisation via the authenticated Pencheff MCP server."
            ),
            "disclosed_actions": ["source_code_scan"],
            "consent_given_at": now.isoformat(),
            "consent_given_by_user_id": user.id,
            "version": 2,
        },
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    enqueue_full_scan(scan.id, target.kind)

    base = get_settings().web_base_url.rstrip("/")
    return {
        "scan_id": scan.id,
        "target_id": target.id,
        "status": "queued",
        "message": "Repository scan queued on the worker; findings will appear in the UI shortly.",
        "url": f"{base}/scans/{scan.id}",
    }


def _artifact_base_url(kind: str, kc: dict) -> str:
    """A stable, human-readable base_url for an artifact/hybrid target so it
    dedupes and reads sensibly in the UI."""
    if kind == "k8s_cluster":
        return kc.get("manifests_archive_url") or f"k8s://{kc.get('target', 'cluster')}"
    if kind == "package_registry":
        return f"pkg://{kc.get('ecosystem', 'npm')}"
    if kind == "container_image":
        return kc.get("image_ref") or "oci://image"
    if kind == "iac":
        return kc.get("repo_url") or "iac://source"
    if kind == "sbom":
        return str(kc.get("url") or "sbom://inline")
    return f"{kind}://target"


@router.post(
    "/artifact",
    dependencies=[Depends(require_scope("scans:write"))],
    status_code=status.HTTP_201_CREATED,
)
async def scan_artifact_target(
    body: ArtifactTargetScanIn,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Register an artifact/hybrid target (k8s manifests, package_registry,
    container_image, iac, sbom) and queue a scan on the worker.

    Used by the MCP ``scan_k8s_manifests`` / ``scan_package_registry`` tools so
    an IDE can register these kinds — which have no dedicated endpoint — the same
    way the UI does, so they appear in the workspace and scan through the
    artifact/hybrid orchestrators.
    """
    kc = dict(body.kind_config or {})
    kc["kind"] = body.kind

    # Minimal per-kind gate; the orchestrator does full validation at scan time.
    if body.kind == "k8s_cluster" and kc.get("target", "manifests_only") == "manifests_only" \
            and not kc.get("manifests_archive_url"):
        raise HTTPException(422, "k8s_cluster manifests_only requires manifests_archive_url")
    if body.kind == "package_registry" and not (kc.get("ecosystem") and kc.get("package_list")):
        raise HTTPException(422, "package_registry requires ecosystem and package_list")
    if body.kind == "container_image" and not kc.get("image_ref"):
        raise HTTPException(422, "container_image requires image_ref")

    base_url = _artifact_base_url(body.kind, kc)
    target = (
        await session.execute(
            select(Target).where(
                Target.workspace_id == workspace.id,
                Target.base_url == base_url,
                Target.kind == body.kind,
            )
        )
    ).scalar_one_or_none()
    default_name = {
        "k8s_cluster": "Kubernetes manifests",
        "package_registry": f"{kc.get('ecosystem', 'npm')} packages",
        "container_image": kc.get("image_ref", "container image"),
        "iac": "IaC source",
        "sbom": "SBOM",
    }.get(body.kind, body.kind)
    if target is None:
        target = Target(
            org_id=workspace.org_id,
            workspace_id=workspace.id,
            name=(body.name or default_name)[:200],
            base_url=base_url,
            kind=body.kind,
            kind_config=kc,
        )
        session.add(target)
        await session.flush()
    else:
        target.kind_config = kc  # refresh config on re-register

    now = datetime.now(timezone.utc)
    scan = Scan(
        target_id=target.id,
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        user_id=user.id,
        profile=body.profile,
        status="queued",
        use_ai=body.use_ai,
        consent_payload={
            "acknowledged": True,
            "authorization_text": (
                "MCP-initiated artifact scan of a target the caller registered "
                "for their own organisation via the authenticated Pencheff MCP server."
            ),
            "disclosed_actions": ["artifact_scan", "cve_scan", "manifest_audit"],
            "consent_given_at": now.isoformat(),
            "consent_given_by_user_id": user.id,
            "version": 2,
        },
        kind_payload=_derive_kind_payload(target, None),
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    enqueue_full_scan(scan.id, target.kind)

    base = get_settings().web_base_url.rstrip("/")
    return {
        "scan_id": scan.id,
        "target_id": target.id,
        "kind": body.kind,
        "status": "queued",
        "message": f"{body.kind} scan queued on the worker; findings will appear in the UI shortly.",
        "url": f"{base}/scans/{scan.id}",
    }
