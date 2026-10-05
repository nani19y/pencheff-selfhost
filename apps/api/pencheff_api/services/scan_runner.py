"""Drive a full pencheff scan against a target, stream progress, persist findings."""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..config import get_settings
from ..db.models import (
    Finding as DbFinding,
    LlmProvider,
    Org,
    RepoIntegration,
    Repository,
    Scan,
    Target,
    TargetRepository,
)
from ..events import publish_scan_event
from .active_verify import active_verify
from .ai_gate import org_has_ai
from .credentials import decrypt_credentials
from .dispatch_mode import increment_option_3_counter, resolve_dispatch_mode
from .fix_quota import DETERMINISTIC_FALLBACK_NOTICE
from .quota import scan_ai_allowed
from .grader import compute as compute_grade
from .llm import FindingInput, get_client as get_llm_client
from .llm_providers.resolver import resolve_chat_client

log = logging.getLogger(__name__)

# ── Scan-agent BYO-LLM override helpers ──────────────────────────────────────


_SCAN_AGENT_OPENAI_COMPATIBLE_KINDS = frozenset(
    {"openai", "openai_compatible", "azure_openai"}
)


def _enqueue_validation(scan_id: str, findings) -> None:
    """Best-effort: queue standard finding-validation after a scan completes."""
    try:
        from ..tasks.validate_task import validate_findings as _vf
        if findings:
            _vf.delay(scan_id, "standard")
    except Exception as exc:  # noqa: BLE001
        log.warning("auto-validate enqueue failed for %s: %s", scan_id, exc)


def _agent_override_for_provider(
    prov: LlmProvider,
) -> tuple[str, str, str] | None:
    """Return ``(base_url, api_key, model)`` when *prov* is OpenAI-tool-calling-
    compatible, otherwise ``None``.

    Only ``openai`` / ``openai_compatible`` / ``azure_openai`` providers accept
    the OpenAI-shaped tool-calling request the scan agent loop sends.
    ``anthropic`` and ``google`` are skipped — the caller logs once and the
    agent uses Pencheff's default.
    """
    if prov.provider not in _SCAN_AGENT_OPENAI_COMPATIBLE_KINDS:
        return None
    key = (
        (decrypt_credentials(prov.api_key_encrypted) or {}).get("api_key", "")
        if prov.api_key_encrypted
        else ""
    )
    if not key:
        return None
    base_url = (prov.base_url or "https://api.openai.com/v1").rstrip("/")
    return base_url, key, prov.model


async def _load_scan_agent_llm_override(
    org_id: str,
    db_session_factory,
) -> tuple[str, str, str] | None:
    """Load the org's active LLM provider and return an override triple, or None.

    Logs once if the active provider is anthropic/google (not tool-calling
    compatible) and returns None so the scan agent uses Pencheff's default.
    """
    async with db_session_factory() as db:
        org: Org | None = await db.get(Org, org_id)
        if org is None or not org.active_llm_provider_id:
            return None
        prov: LlmProvider | None = await db.get(LlmProvider, org.active_llm_provider_id)
    if prov is None:
        return None
    override = _agent_override_for_provider(prov)
    if override is None:
        log.info(
            "org provider %r is not tool-calling compatible; "
            "scan agent uses Pencheff default",
            prov.provider,
        )
    return override


# ─────────────────────────────────────────────────────────────────────────────

SCAN_STAGES: list[tuple[str, str]] = [
    ("recon_passive", "Passive recon"),
    ("recon_active", "Active recon"),
    ("recon_api_discovery", "API discovery"),
    ("scan_waf", "WAF fingerprinting"),
    ("scan_infrastructure", "Infrastructure scan"),
    ("scan_injection", "Injection scan"),
    ("scan_client_side", "Client-side scan"),
    ("scan_auth", "Auth scan"),
    ("scan_mfa_bypass", "MFA bypass scan"),
    ("scan_authz", "Authorization scan"),
    ("scan_oauth", "OAuth scan"),
    ("scan_advanced", "Advanced web attacks"),
    ("scan_api", "API vuln scan"),
    ("scan_business_logic", "Business logic scan"),
    ("scan_cloud", "Cloud misconfig scan"),
    ("scan_file_handling", "File handling scan"),
    ("scan_websocket", "WebSocket scan"),
    ("scan_grpc", "gRPC scan"),
    ("scan_subdomain_takeover", "Subdomain takeover"),
]

# ── Profile aliases ────────────────────────────────────────────────────
# The UI exposes only Quick / Standard / Deep, but legacy callers and
# older scan rows may carry one of the deprecated profile names. Coerce
# them here so the rest of the pipeline never sees the legacy values.
#
# Capability fold-in:
#   Quick    ← cicd                         (fail-fast, top-severity only)
#   Standard ← api-only, asm, sca, iac      (everything below "all modules")
#   Deep     ← engage, compliance,
#              compliance-full, supply-chain,
#              network-va, hackme, continuous (full coverage + swarm + orchestrator)
_PROFILE_ALIASES: dict[str, str] = {
    "quick": "quick",
    "standard": "standard",
    "deep": "deep",
    # legacy names → consolidated tier
    "cicd": "quick",
    "api-only": "standard",
    "asm": "standard",
    "sca": "standard",
    "iac": "standard",
    "engage": "deep",
    "compliance": "deep",
    "compliance-full": "deep",
    "supply-chain": "deep",
    "network-va": "deep",
    "hackme": "deep",
    "continuous": "deep",
}


def _canonical_profile(profile: str) -> str:
    """Map any historical profile name to {quick, standard, deep}."""
    return _PROFILE_ALIASES.get(profile, "standard")


# Single-stage scan flow for kind='llm' targets. The MCP tool
# orchestrates the per-OWASP-LLM-category modules itself; we only
# need to drive the one entrypoint, with profile mapped to a
# max_payloads cap.
LLM_SCAN_STAGES: list[tuple[str, str]] = [
    ("scan_llm_red_team", "LLM red team probe"),
]

# Profile → max_payloads cap for LLM scans. URL/repo profiles use
# the SCAN_PROFILES dict from pencheff.config; LLM ignores that
# table because the modules are entirely different.
#
# Numbers reflect the curated OWASP LLM Top 10 payload library plus
# optional strategy/language/custom-policy expansion. Quick profile
# fires a top-priority subset; standard runs the static library; deep
# leaves room for configured strategy variants and custom policies.
LLM_PROFILE_CAPS: dict[str, int] = {
    "quick": 25,
    "standard": 75,
    "deep": 250,
}

MCP_PROFILE_CAPS: dict[str, int] = {"quick": 0, "standard": 50, "deep": 200}
# 0 = static only (no dynamic tool calls); >0 caps dynamic probes (Plan 3 C/D).

RAG_PROFILE_CAPS: dict[str, int] = {"quick": 0, "standard": 50, "deep": 200}

# Depth-based stage pruning
QUICK_STAGES = {"recon_passive", "recon_active", "scan_waf", "scan_infrastructure", "scan_injection", "scan_client_side", "scan_auth"}


async def _resolve_attached_repo_source(repo: Repository, db: AsyncSession) -> str | None:
    """Resolve a Repository row to a clone source string usable by pencheff's
    repo_workspace.attach helpers.

    Returns:
      * absolute local path for ``provider == "local"``,
      * an authenticated HTTPS URL for token-protected GitHub repos,
      * the public clone URL for public GitHub repos,
      * ``None`` if we cannot safely produce a working source (caller logs).
    """
    if repo.provider == "local":
        return repo.local_path or None
    if repo.provider == "github":
        clone_url = f"https://github.com/{repo.full_name}.git"
        # App-installed: mint a fresh installation token.
        if repo.integration_id:
            from . import github_app
            integ = (await db.execute(
                select(RepoIntegration).where(RepoIntegration.id == repo.integration_id)
            )).scalar_one_or_none()
            if integ is None:
                return None
            try:
                token = await github_app.get_installation_token(integ.installation_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("attached repo %s: installation token fetch failed: %s",
                            repo.full_name, exc)
                return None
            return f"https://x-access-token:{token}@github.com/{repo.full_name}.git"
        # PAT-protected.
        if repo.token_encrypted:
            tok_blob = decrypt_credentials(repo.token_encrypted) or {}
            token = tok_blob.get("token") or ""
            if not token:
                log.warning("attached repo %s: PAT decryption returned empty",
                            repo.full_name)
                return None
            return f"https://x-access-token:{token}@github.com/{repo.full_name}.git"
        # Public clone.
        return clone_url
    return None


async def _list_attached_repos_for_link(
    *,
    target_id: str,
    db: AsyncSession,
) -> list[dict]:
    """Return a UI-friendly summary of repos attached to ``target_id``.

    No SAST is executed — this is purely metadata so the URL scan detail
    page can render a "Linked repositories" card with deep-links to each
    repo's own scan page. Repo-level vulnerabilities live on those repo
    pages, not embedded in the URL scan.
    """
    rows = (await db.execute(
        select(Repository)
        .join(TargetRepository, TargetRepository.repository_id == Repository.id)
        .where(TargetRepository.target_id == target_id)
        .order_by(Repository.full_name)
    )).scalars().all()
    return [
        {
            "repository_id": r.id,
            "full_name": r.full_name,
            "provider": getattr(r, "provider", None),
        }
        for r in rows
    ]


async def _hydrate_attached_repos(
    psession,
    *,
    target_id: str,
    db: AsyncSession,
) -> list[dict]:
    """Look up the URL target's attached repos and queue them on the pencheff
    session so SAST runs alongside DAST. Returns a list of attach summaries
    suitable for embedding in scan logs / events.
    """
    rows = (await db.execute(
        select(Repository)
        .join(TargetRepository, TargetRepository.repository_id == Repository.id)
        .where(TargetRepository.target_id == target_id)
        .order_by(Repository.full_name)
    )).scalars().all()
    if not rows:
        return []

    # Import lazily so a worker-only import error doesn't poison module load.
    from pencheff.server import _attach_repos_inline

    sources: list[dict] = []
    skipped: list[dict] = []
    for repo in rows:
        src = await _resolve_attached_repo_source(repo, db)
        if not src:
            skipped.append({
                "repository_id": repo.id,
                "full_name": repo.full_name,
                "reason": "could not resolve clone source (private without token, or local_path missing)",
            })
            continue
        sources.append({"source": src, "name": repo.full_name.replace("/", "-")})

    attached, errors = await _attach_repos_inline(
        psession, repos=sources, auto_scan=True,
    )
    summary = [
        {
            "repository_id": r.id,
            "full_name": r.full_name,
            "attached": any(a["origin"] == s["source"] for s, a in zip(sources, attached))
                if attached else False,
        }
        for r, s in zip(rows[:len(sources)], sources)
    ]
    if errors:
        for err in errors:
            log.warning("attached repo failed: %s", err)
    if skipped:
        for sk in skipped:
            log.warning("attached repo skipped: %s", sk)
    return summary


def _stages_for(profile: str) -> list[tuple[str, str]]:
    if profile == "quick":
        return [s for s in SCAN_STAGES if s[0] in QUICK_STAGES]
    return SCAN_STAGES


def _severity_summary(findings_db) -> dict:
    summary = findings_db.summary() if hasattr(findings_db, "summary") else {}
    # Normalize keys to lowercase
    return {str(k).lower(): int(v) for k, v in summary.items()}


def _stage_options(profile: str, tool_name: str) -> tuple[dict[str, Any], float]:
    """Return workflow-safe tool arguments and max runtime for a stage."""
    if tool_name != "recon_active":
        return {}, 180.0

    from pencheff.config import SCAN_PROFILES

    profile_cfg = SCAN_PROFILES.get(profile, {})
    depth = profile_cfg.get("depth") if isinstance(profile_cfg, dict) else None
    if depth not in {"quick", "standard", "deep"}:
        depth = profile if profile in {"quick", "standard", "deep"} else "standard"

    max_pages = int(profile_cfg.get("max_pages", 100) or 0) if isinstance(profile_cfg, dict) else 100
    crawl_depth = int(profile_cfg.get("crawl_depth", 3) or 0) if isinstance(profile_cfg, dict) else 3

    if depth == "quick":
        return {
            "port_range": "top-100",
            "crawl_depth": min(crawl_depth, 1),
            "max_pages": min(max_pages or 20, 20),
            "timing": 4,
            "udp_scan": False,
            "aggressive": False,
            "port_timeout_sec": 45,
        }, 90.0

    if depth == "deep":
        return {
            "port_range": "top-1000",
            "crawl_depth": crawl_depth,
            "max_pages": max_pages or 300,
            "timing": 4,
            "udp_scan": False,
            "aggressive": True,
            "port_timeout_sec": 150,
        }, 240.0

    return {
        "port_range": "top-1000",
        "crawl_depth": min(crawl_depth, 3),
        "max_pages": min(max_pages or 100, 100),
        "timing": 4,
        "udp_scan": False,
        "aggressive": False,
        "port_timeout_sec": 120,
    }, 180.0


async def _run_stage(tool_name: str, session_id: str, *, profile: str = "standard") -> tuple[int, str | None]:
    """Call one of the pencheff.server.scan_* async functions by name. Return new_findings."""
    import pencheff.server as srv
    fn = getattr(srv, tool_name, None)
    if fn is None:
        log.warning("no pencheff tool %s", tool_name)
        return 0, "tool unavailable"
    kwargs, timeout = _stage_options(profile, tool_name)
    try:
        result = await asyncio.wait_for(fn(session_id=session_id, **kwargs), timeout=timeout)
        if isinstance(result, dict):
            warning = result.get("warning")
            return int(result.get("new_findings", 0) or 0), str(warning) if warning else None
        return 0, None
    except asyncio.TimeoutError:
        log.warning("stage %s timed out after %.0fs", tool_name, timeout)
        return 0, f"timed out after {int(timeout)}s; continuing with the remaining stages"
    except Exception as e:
        log.warning("stage %s failed: %s", tool_name, e)
        return 0, f"failed: {type(e).__name__}: {e}"[:180]


# Bounded String() column widths on the Finding model. Scanner output (esp.
# SAST: a bandit test id like "subprocess_without_shell_equals_true" landing in
# cwe_id/owasp_category) can exceed these; clamp so one over-long value can't
# abort the whole batch insert with a StringDataRightTruncationError.
_FINDING_STR_CAPS = {
    "pencheff_finding_id": 64, "title": 500, "severity": 16, "category": 64,
    "owasp_category": 32, "cwe_id": 32, "cvss_vector": 200, "parameter": 200,
    "verification_status": 32, "suppress_reason": 64, "ssvc_decision": 16,
    "reachability": 16,
}


def _clip_finding_row(row: dict) -> dict:
    for col, cap in _FINDING_STR_CAPS.items():
        v = row.get(col)
        if isinstance(v, str) and len(v) > cap:
            row[col] = v[:cap]
    return row


def _finding_to_db_row(scan_id: str, f: Any) -> dict:
    """Convert pencheff Finding → dict for bulk DB insert."""
    evidence = []
    for ev in getattr(f, "evidence", None) or []:
        try:
            evidence.append({
                "request_method": getattr(ev, "request_method", None),
                "request_url": getattr(ev, "request_url", None),
                "request_headers": getattr(ev, "request_headers", None),
                "request_body": getattr(ev, "request_body", None),
                "response_status": getattr(ev, "response_status", None),
                "response_headers": getattr(ev, "response_headers", None),
                "response_body_snippet": getattr(ev, "response_body_snippet", None),
                "description": getattr(ev, "description", None),
                "autofix": getattr(ev, "autofix", None),
            })
        except Exception:
            continue
    sev = getattr(f, "severity", None)
    sev_value = sev.value if hasattr(sev, "value") else (str(sev).lower() if sev else "info")
    cvss = getattr(f, "cvss_score", None)
    category = getattr(f, "category", "unknown")
    # Pull EPSS / KEV from the SCA autofix payload if present (SCA findings
    # ride EPSS along; SAST/DAST findings have no EPSS by definition).
    epss: float | None = None
    kev = False
    for ev in evidence:
        af = ev.get("autofix") or {}
        if af.get("epss") is not None:
            try:
                epss = float(af["epss"])
            except (TypeError, ValueError):
                pass
        if af.get("kev"):
            kev = True
    # Reachability classification first (DAST findings come from the live
    # scan_runner, so finding_kind="dast" is the right call here). The
    # result feeds the priority computation and is persisted alongside
    # so the dashboard can render the badge without recomputing.
    reachability_value: str = "unknown"
    try:
        from pencheff.intelligence import Reachability, classify_reachability
        reachability_value = classify_reachability(
            finding_kind="dast",
            category=category,
            evidence=evidence,
            verification_notes=getattr(f, "verification_notes", None),
            verification_status=getattr(f, "verification_status", None),
        ).value
    except Exception:  # noqa: BLE001
        pass
    # Compute SSVC + unified priority score. Pure functions — fall back
    # gracefully if the intelligence module isn't on path (CI / partial deploys).
    ssvc_value: str | None = None
    risk_score: float | None = None
    try:
        from pencheff.intelligence import PriorityInputs, compute_priority
        out = compute_priority(PriorityInputs(
            cvss=cvss, epss=epss, kev=kev, category=category,
            finding_kind="dast",
            reachability=reachability_value,
        ))
        ssvc_value = out.ssvc.value
        risk_score = out.score
    except Exception:  # noqa: BLE001
        pass
    return _clip_finding_row({
        "scan_id": scan_id,
        "pencheff_finding_id": getattr(f, "id", None),
        "title": getattr(f, "title", "Untitled"),
        "severity": sev_value.lower(),
        "category": category,
        "owasp_category": getattr(f, "owasp_category", None),
        "cwe_id": getattr(f, "cwe_id", None),
        "cvss_score": cvss,
        "cvss_vector": getattr(f, "cvss_vector", None),
        "endpoint": getattr(f, "endpoint", None),
        "parameter": getattr(f, "parameter", None),
        "description": getattr(f, "description", None),
        "remediation": getattr(f, "remediation", None),
        "evidence": evidence,
        "references_": list(getattr(f, "references", None) or []),
        "verification_status": getattr(f, "verification_status", None) or "unverified",
        "suppressed": bool(getattr(f, "suppressed", False)),
        "suppress_reason": (
            (sr.value if hasattr(sr, "value") else str(sr))
            if (sr := getattr(f, "suppress_reason", None)) is not None
            else None
        ),
        "suppress_notes": getattr(f, "suppress_notes", None) or None,
        "epss": epss,
        "kev": kev,
        "risk_score": risk_score,
        "ssvc_decision": ssvc_value,
        "reachability": reachability_value,
    })


def _finding_fingerprint(row: "DbFinding") -> str:
    """Stable identity key for a finding across scans of the same target.

    Matches the dimensions used by the manual /compare endpoint and the CLI
    scan-history diff: endpoint + parameter + category + title. Re-running the
    same suite against an unchanged target yields the same fingerprints, so a
    no-op rescan reports zero new / zero fixed."""
    return "|".join([
        (row.endpoint or "").strip().lower(),
        (row.parameter or "").strip().lower(),
        (row.category or "").strip().lower(),
        (row.title or "").strip().lower(),
    ])


async def _compute_previous_comparison(
    db: AsyncSession,
    *,
    scan_id: str,
    target_id: str,
    created_at: datetime,
    current_rows: list["DbFinding"],
) -> dict | None:
    """Diff this scan against the target's most recent prior completed scan.

    Returns None on a target's first scan (nothing to compare). Otherwise
    returns new / fixed / persisted counts keyed by finding fingerprint, plus
    the previous scan's id and grade so the results view can link back to it.
    Only active (non-suppressed) findings on both sides are compared."""
    prev = (await db.execute(
        select(Scan).where(
            Scan.target_id == target_id,
            Scan.id != scan_id,
            Scan.status == "done",
            Scan.created_at < created_at,
        ).order_by(Scan.created_at.desc()).limit(1)
    )).scalar_one_or_none()
    if prev is None:
        return None
    prev_rows = (await db.execute(
        select(DbFinding).where(
            DbFinding.scan_id == prev.id, DbFinding.suppressed.is_(False)
        )
    )).scalars().all()
    prev_fps = {_finding_fingerprint(r) for r in prev_rows}
    cur_fps = {_finding_fingerprint(r) for r in current_rows if not r.suppressed}
    return {
        "previous_scan_id": prev.id,
        "previous_grade": prev.grade,
        "previous_score": prev.score,
        "previous_created_at": prev.created_at.isoformat() if prev.created_at else None,
        "counts": {
            "new": len(cur_fps - prev_fps),
            "fixed": len(prev_fps - cur_fps),
            "persisted": len(cur_fps & prev_fps),
        },
    }


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def _build_prior_findings_context(
    db: AsyncSession,
    *,
    scan_id: str,
    target_id: str,
    created_at: datetime,
    limit: int = 25,
) -> str | None:
    """Compact summary of the target's previous completed scan, for the agent.

    Fed into the AI engine before it runs so it re-verifies known issues and
    prioritises regressions. Returns None on a first scan. Kept deliberately
    small (top ``limit`` active findings, severity-ordered, one line each) so
    it primes the agent without bloating the prompt and destabilising it."""
    prev = (await db.execute(
        select(Scan).where(
            Scan.target_id == target_id,
            Scan.id != scan_id,
            Scan.status == "done",
            Scan.created_at < created_at,
        ).order_by(Scan.created_at.desc()).limit(1)
    )).scalar_one_or_none()
    if prev is None:
        return None
    rows = (await db.execute(
        select(DbFinding).where(
            DbFinding.scan_id == prev.id, DbFinding.suppressed.is_(False)
        )
    )).scalars().all()
    if not rows:
        return None
    rows = sorted(
        rows, key=lambda r: _SEVERITY_RANK.get((r.severity or "info").lower(), 5)
    )[:limit]
    lines = []
    for r in rows:
        loc = r.endpoint or ""
        if r.parameter:
            loc = f"{loc} (param: {r.parameter})" if loc else f"param: {r.parameter}"
        sev = (r.severity or "info").upper()
        lines.append(f"- [{sev}] {r.title}" + (f" @ {loc}" if loc else ""))
    when = prev.created_at.date().isoformat() if prev.created_at else "a prior run"
    header = (
        f"## Prior scan context ({when}, grade {prev.grade or '—'})\n\n"
        "This target was scanned before. The findings below were active in "
        "the previous scan. Re-verify whether each still reproduces (a fixed "
        "issue is a win to confirm), and prioritise any that regressed. Do not "
        "assume they are still present — confirm with live probes:\n\n"
    )
    return header + "\n".join(lines)


async def _resolve_rest_spec(cfg: dict) -> str | None:
    """Return raw OpenAPI/Swagger/Postman spec text for a rest_api target.

    Inline ``api_spec`` (a dict) is serialised to JSON; otherwise ``api_spec_url``
    is fetched server-side (http/https only, bounded size). Returns None when the
    target carries neither — the scan then falls back to crawl-based discovery.
    """
    import json as _json

    if cfg.get("api_spec"):
        return _json.dumps(cfg["api_spec"])
    url = cfg.get("api_spec_url")
    if not url:
        return None
    url = str(url)
    if not url.startswith(("http://", "https://")):
        log.warning("api_spec_url %r is not http(s); skipping", url)
        return None
    import httpx
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as cli:
            r = await cli.get(url)
        r.raise_for_status()
        return r.text[:5_000_000]  # cap: don't pull an unbounded body into memory
    except Exception as exc:  # noqa: BLE001 — best-effort; scan continues via crawl
        log.warning("api_spec_url fetch failed (%s): %s", url, exc)
        return None


async def _seed_api_surface(scan_id: str, target: Target, psession, db_session_factory) -> None:
    """Plumb the operator-supplied API spec / GraphQL schema into the scan session.

    rest_api / graphql targets carry their spec on ``Target.kind_config`` (collected
    and validated at registration), but the DAST pipeline never consumed it — so the
    documented attack surface never reached the kind-filtered breakers and they
    degraded to generic crawl-only DAST. Seeding ``discovered.endpoints`` here gives
    APIAgent / GraphQLFuzzAgent a real surface to test and keeps the swarm's
    zero-endpoints recon guard (recon.py) from bailing to deterministic-only.
    """
    import pencheff.server as srv

    cfg = dict(target.kind_config or {})
    # Bind the operator's transport/protocol config to the session so the
    # protocol tools (run_grpcurl plaintext/tls, run_graphql_cop introspection,
    # scan_websocket subprotocols/origin) can read it via _kind_config_for_session.
    # recon carries this into the snapshot so per-breaker sessions re-apply it.
    set_cfg = getattr(srv, "set_kind_config_for_session", None)
    if set_cfg:
        try:
            # Stamp the kind so protocol tools + recon can gate on it (e.g.
            # recon_active skips the host port-scan for endpoint-kinds — a
            # single graphql/websocket/rest_api/grpc endpoint is not a host to
            # enumerate, and the port findings are pure FP noise there).
            set_cfg(psession.id, {**cfg, "base_url": target.base_url, "kind": target.kind})
        except Exception as exc:  # noqa: BLE001 — never block the scan
            log.warning("set_kind_config_for_session failed: %s", exc)
    notes: list[str] = []

    if target.kind == "rest_api":
        spec_text = await _resolve_rest_spec(cfg)
        if not spec_text:
            notes.append("rest_api: no api_spec/api_spec_url provided — using crawl discovery only")
        else:
            try:
                res = await srv.import_api_spec(
                    session_id=psession.id,
                    spec_content=spec_text,
                    hint=str(cfg.get("api_spec_format", "auto")),
                )
                if isinstance(res, dict) and res.get("error"):
                    notes.append(f"api spec import failed: {res['error']}")
                else:
                    notes.append(
                        f"imported {res.get('spec_type', '?')} spec "
                        f"'{res.get('api_title', '')}': "
                        f"{res.get('imported_endpoints', 0)} endpoints seeded"
                    )
            except Exception as exc:  # noqa: BLE001 — never block the scan
                notes.append(f"api spec import error: {type(exc).__name__}: {exc}")

    elif target.kind == "graphql":
        # GraphqlConfig has no path field — base_url IS the GraphQL endpoint.
        ep = target.base_url
        if ep and ep not in {e.get("url") for e in psession.discovered.endpoints}:
            psession.discovered.endpoints.append(
                {"url": ep, "method": "POST", "source": "graphql", "params": ["query"]}
            )
        sdl = cfg.get("schema_sdl")
        introspection = bool(cfg.get("introspection_enabled", True))
        psession.discovered.api_specs.append({
            "type": "graphql",
            "url": ep,
            "introspection": introspection,
            **({"schema_sdl": sdl} if sdl else {}),
        })
        notes.append(
            "graphql endpoint seeded; introspection runs at breaker time (run_inql/run_graphql_cop)"
            if introspection
            else "graphql endpoint seeded from pasted SDL (introspection disabled)"
        )

    elif target.kind == "websocket":
        # base_url IS the ws:// / wss:// endpoint. Seed it so recon doesn't bail
        # on an unreachable HTTP crawl and APIAgent's scan_websocket gets a surface.
        ep = target.base_url
        if ep and ep not in {e.get("url") for e in psession.discovered.endpoints}:
            psession.discovered.endpoints.append(
                {"url": ep, "method": "GET", "source": "websocket", "params": []}
            )
        psession.discovered.api_specs.append({
            "type": "websocket",
            "url": ep,
            "subprotocols": cfg.get("subprotocols") or [],
            "origin_header": cfg.get("origin_header"),
            "auth_token_in_query": cfg.get("auth_token_in_query"),
        })
        notes.append("websocket endpoint seeded; scan_websocket runs at breaker time")

    elif target.kind == "grpc":
        # base_url IS the gRPC host:port. Seed it so the swarm dispatches
        # GrpcReflectionAgent (run_grpcurl/parse_proto) against a real surface.
        ep = target.base_url
        if ep and ep not in {e.get("url") for e in psession.discovered.endpoints}:
            psession.discovered.endpoints.append(
                {"url": ep, "method": "POST", "source": "grpc", "params": []}
            )
        protos = cfg.get("proto_files")
        reflection = bool(cfg.get("reflection_enabled", True))
        psession.discovered.api_specs.append({
            "type": "grpc",
            "url": ep,
            "reflection": reflection,
            "tls_verify": bool(cfg.get("tls_verify", True)),
            **({"proto_files": protos} if protos else {}),
        })
        notes.append(
            "grpc endpoint seeded; reflection enumerated at breaker time (run_grpcurl)"
            if reflection
            else "grpc endpoint seeded from uploaded .proto files (reflection disabled)"
        )

    if notes:
        async with db_session_factory() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            for n in notes:
                _append_log(s, n)
            await db.commit()


async def run_scan(scan_id: str) -> None:
    """Entrypoint invoked by the Celery worker (which runs this via asyncio.run)."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url, future=True)
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    from pencheff.core.session import create_session as pencheff_create_session

    async with Session() as db:
        scan: Scan | None = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        if not scan:
            log.error("scan %s not found", scan_id)
            return
        target: Target | None = (await db.execute(select(Target).where(Target.id == scan.target_id))).scalar_one_or_none()
        if not target:
            scan.status = "failed"
            scan.error = "target not found"
            await db.commit()
            return
        creds = decrypt_credentials(target.credentials_encrypted)
        # Operator AI toggle chosen at commission time. When False the runner
        # forces deterministic-only mode below — no agent/swarm, no AI triage,
        # no AI grading — regardless of plan or quota.
        use_ai = bool(getattr(scan, "use_ai", True))
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

    publish_scan_event(scan_id, {"type": "started", "scan_id": scan_id})

    # ── Load-test mode (profile="load") ────────────────────────────────
    # A kind-aware load generator instead of the security pipeline. Returns
    # before any security stage runs.
    if scan.profile == "load":
        await _run_load_scan(scan_id, target, Session)
        return

    # ── Feature 001 kind-aware dispatch ────────────────────────────────
    # Artifact + hybrid clusters route through dedicated orchestrators
    # (container_image, iac, package_registry, sbom → artifact_orchestrator;
    # cicd_pipeline, k8s_cluster → hybrid_orchestrator). DAST-cluster kinds
    # (web_app, rest_api, graphql, websocket, grpc) FALL THROUGH the existing
    # url-scan path — run_swarm receives target.kind and filters the breaker
    # roster via KIND_TO_BREAKER_NAMES (spec §6.1). source_code is handled
    # in repo_scan_task (not here) because it reuses RepoScan. Legacy
    # url/repo/llm flow through the existing path below — backward compat
    # preserved per AC-0.3.
    _NON_DAST_NEW_KINDS = {
        "container_image", "iac", "package_registry", "sbom",
        "cicd_pipeline", "k8s_cluster",
        "cloud_account", "serverless_function", "cloud_storage",
        "load_balancer_cdn", "cloud_database", "secrets_manager",
        # host — live TCP port-scan / network-exposure posture (host_orchestrator).
        "host",
        # network group — TLS/SSL, DNS, email-auth, VPN exposure (network_orchestrator).
        "tls_ssl", "dns", "email_security", "vpn",
        # identity/data group — IdP config + data-store exposure (identity_data_orchestrator).
        "idp", "data_store",
        # source_code can be registered via API (kind="source_code" Targets);
        # those rows route through artifact_orchestrator's SAST allowlist.
        # The legacy /repos/github flow continues to create kind="repo" mirror
        # Targets handled by repo_scan_task — that path is untouched.
        "source_code",
    }
    if target.kind in _NON_DAST_NEW_KINDS:
        try:
            await _run_kind_aware_scan(scan_id, target, Session)
        except Exception as exc:  # noqa: BLE001
            log.exception("kind-aware scan failed for scan %s (kind=%s)", scan_id, target.kind)
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                s.status = "failed"
                s.error = f"kind-aware scan failed: {exc}"
                s.finished_at = datetime.now(timezone.utc)
                await db.commit()
            publish_scan_event(scan_id, {
                "type": "failed", "scan_id": scan_id, "error": str(exc),
            })
        return

    # Fire the scan_started lifecycle event to every matching integration
    # (per-target scoped, per-event filtered). Best-effort enqueue —
    # integration delivery must never block scan progress.
    try:
        from ..tasks.integration_notify_task import notify_event as _ne
        _ne.delay(scan_id, "scan_started")
    except Exception as _exc:  # noqa: BLE001
        log.warning("integration scan_started enqueue failed: %s", _exc)

    try:
        # The UI now sends only quick/standard/deep, but legacy rows may
        # still carry "engage", "compliance", etc. Coerce here so the
        # rest of the function only deals with the canonical 3 tiers.
        _depth = _canonical_profile(scan.profile)

        psession = pencheff_create_session(
            target_url=target.base_url,
            credentials=creds,
            scope=list(target.scope or []) or None,
            exclude_paths=list(target.exclude_paths or []) or None,
            depth=_depth,
            # LLM targets carry their non-secret config dict here.
            # The pencheff session is the single source of truth used
            # by the llm_red_team modules at scan time.
            llm_config=dict(target.llm_config) if target.llm_config else None,
            mcp_config=dict(target.kind_config) if (target.kind in ("mcp", "agent") and target.kind_config) else None,
            rag_config=dict(target.kind_config) if (target.kind == "rag" and target.kind_config) else None,
            ml_config=dict(target.kind_config) if (target.kind == "ml_model" and target.kind_config) else None,
            # Merge decrypted creds so the voice transport can authenticate
            # (build_live_transport reads cfg["credentials"]).
            voice_config=(
                {**dict(target.kind_config), "credentials": creds}
                if (target.kind == "voice" and target.kind_config) else None
            ),
        )

        async with Session() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            s.pencheff_session_id = psession.id
            await db.commit()

        # ── Seed operator-supplied API surface (rest_api / graphql / websocket / grpc) ─
        # These DAST-cluster kinds carry an OpenAPI / GraphQL spec on
        # kind_config that the pipeline previously dropped, leaving the
        # kind-filtered breakers with nothing API-specific to test. Seed
        # it before recon + the swarm so the documented surface — not just
        # whatever the crawler stumbles onto — gets exercised.
        if target.kind in ("rest_api", "graphql", "websocket", "grpc"):
            try:
                await _seed_api_surface(scan_id, target, psession, Session)
            except Exception as exc:  # noqa: BLE001 — never block the scan
                log.warning("api-surface seed failed for scan %s: %s", scan_id, exc)

        # ── Attach source repos (URL targets only) ─────────────────
        # We DO NOT fold SAST findings into the URL scan anymore —
        # mixing them produced a confusing detail page where DAST and
        # SAST findings shared the same list. The URL scan now only
        # records *which* repos are attached and emits a sidebar event
        # so the UI can render a "Linked repositories → see assessment"
        # card. SAST runs on the repo's own /repos/{id}/scan page.
        if target.kind == "url":
            try:
                async with Session() as db:
                    attached_summary = await _list_attached_repos_for_link(
                        target_id=target.id, db=db,
                    )
                if attached_summary:
                    async with Session() as db:
                        s = (await db.execute(
                            select(Scan).where(Scan.id == scan_id)
                        )).scalar_one()
                        _append_log(
                            s,
                            f"linked repos: {len(attached_summary)} attached "
                            f"(SAST runs separately at /repos/<id>/scan)",
                        )
                        await db.commit()
                    publish_scan_event(scan_id, {
                        "type": "linked_repos",
                        "scan_id": scan_id,
                        "repos": attached_summary,
                    })
            except Exception as exc:  # noqa: BLE001 — never block DAST
                log.warning("list_attached_repos failed for scan %s: %s",
                            scan_id, exc)

        # ── LLM red-team kind ───────────────────────────────────────
        # Bypass the URL-target pipeline entirely. LLM targets don't
        # have an HTML surface to crawl, no auth-form to log into, no
        # subdomains to fan out across — they have one chat endpoint
        # and a payload library. Run the single-stage LLM scan, then
        # let the rest of run_scan (findings persist + grading) run
        # unmodified.
        if target.kind == "llm":
            await _run_llm_scan(
                scan_id=scan_id,
                psession=psession,
                profile=scan.profile,
                db_session_factory=Session,
            )
            # Fall through to findings persistence below.
            # ``include_suppressed=True`` is critical — the agent may have
            # suppressed inherited findings, and we want those rows in the
            # DB (flagged as suppressed) so the UI's "Show false
            # positives" toggle can surface them.
            all_findings = (
                list(psession.findings.get_all(include_suppressed=True))
                if hasattr(psession.findings, "get_all")
                else []
            )
            if not all_findings and hasattr(psession.findings, "findings"):
                all_findings = list(psession.findings.findings)
            async with Session() as db:
                for f in all_findings:
                    db.add(DbFinding(**_finding_to_db_row(scan_id, f)))
                await db.commit()
            # Skip the URL-pipeline triage + grading below; LLM
            # findings are already deduped at the module level and
            # have no SPA-404 false-positive class to triage. The
            # LLM curve in compute_grade applies wider caps so a
            # "5 high" scan does not show the same F as a
            # "70 high + 3 critical" scan.
            score, grade, counts = compute_grade(
                [_DbFindingProxy(_) for _ in await _read_back_findings(scan_id, Session)],
                target_kind="llm",
            )
            summary_payload = dict(counts)
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                s.status = "done"
                s.progress_pct = 100
                s.current_stage = "complete"
                s.finished_at = datetime.now(timezone.utc)
                # Merge with anything earlier helpers wrote (e.g. swarm telemetry).
                existing = dict(s.summary or {})
                existing.update(summary_payload)
                s.summary = existing
                s.grade = grade
                s.score = score
                _append_log(s, f"finished: grade {grade} · score {score}")
                await db.commit()
            publish_scan_event(scan_id, {
                "type": "finished", "scan_id": scan_id, "grade": grade, "score": score,
                "summary": counts, "total_findings": len(all_findings),
            })
            try:
                from ..tasks.integration_notify_task import notify_scan_findings as _nsf
                _nsf.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("integration scan_done enqueue failed: %s", exc)
            try:
                from ..tasks.email_task import send_scan_complete_email_task as _scet
                _scet.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("scan-complete email enqueue failed: %s", exc)
            _enqueue_validation(scan_id, all_findings)
            return

        # ── MCP / AI-agent kind ─────────────────────────────────────
        # Mirrors the LLM branch above: run the dedicated MCP scanner,
        # persist findings, grade, finalize. Does not enter the
        # URL/DAST pipeline.
        if target.kind == "mcp":
            from .ai_scan_progress import ai_scan_progress
            async with ai_scan_progress(scan_id, Session, stage="scan_mcp") as progress:
                await progress.milestone(f"connecting to {target.kind} target {target.base_url}")
                mcp_error = await _run_mcp_scan(
                    scan_id=scan_id,
                    psession=psession,
                    profile=scan.profile,
                    db_session_factory=Session,
                )
                completed = list(getattr(psession.discovered, "completed_modules", []) or [])
                summ = psession.findings.summary() if hasattr(psession.findings, "summary") else {}
                await progress.milestone(
                    f"{target.kind} scan complete · modules: {', '.join(completed) or 'none'} · "
                    f"findings: {sum(summ.values()) if isinstance(summ, dict) else 0}"
                )
            all_findings = (
                list(psession.findings.get_all(include_suppressed=True))
                if hasattr(psession.findings, "get_all")
                else []
            )
            if not all_findings and hasattr(psession.findings, "findings"):
                all_findings = list(psession.findings.findings)
            # Honest failure: a target that never completed the MCP handshake
            # (wrong URL, not an MCP server, auth rejected) must NOT be graded
            # "A / clean" — that's a false all-clear. Surface it as failed.
            if mcp_error and not all_findings:
                async with Session() as db:
                    s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                    s.status = "failed"
                    s.error = mcp_error
                    s.current_stage = "failed"
                    s.finished_at = datetime.now(timezone.utc)
                    _append_log(s, f"failed: {mcp_error}")
                    await db.commit()
                publish_scan_event(scan_id, {
                    "type": "failed", "scan_id": scan_id, "error": mcp_error,
                })
                return
            async with Session() as db:
                for f in all_findings:
                    db.add(DbFinding(**_finding_to_db_row(scan_id, f)))
                await db.commit()
            score, grade, counts = compute_grade(
                [_DbFindingProxy(_) for _ in await _read_back_findings(scan_id, Session)],
                target_kind="mcp",
            )
            summary_payload = dict(counts)
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                s.status = "done"
                s.progress_pct = 100
                s.current_stage = "complete"
                s.finished_at = datetime.now(timezone.utc)
                existing = dict(s.summary or {})
                existing.update(summary_payload)
                s.summary = existing
                s.grade = grade
                s.score = score
                _append_log(s, f"finished: grade {grade} · score {score}")
                await db.commit()
            publish_scan_event(scan_id, {
                "type": "finished", "scan_id": scan_id, "grade": grade, "score": score,
                "summary": counts, "total_findings": len(all_findings),
            })
            try:
                from ..tasks.integration_notify_task import notify_scan_findings as _nsf
                _nsf.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("integration scan_done enqueue failed: %s", exc)
            try:
                from ..tasks.email_task import send_scan_complete_email_task as _scet
                _scet.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("scan-complete email enqueue failed: %s", exc)
            _enqueue_validation(scan_id, all_findings)
            return

        # ── Agent / agent-HTTP kind ─────────────────────────────────
        # Mirrors the MCP branch above: _run_mcp_scan routes agent_http
        # source_type to agent_probe inside the plugin. Does not enter
        # the URL/DAST pipeline.
        if target.kind == "agent":
            from .ai_scan_progress import ai_scan_progress
            async with ai_scan_progress(scan_id, Session, stage="scan_agent") as progress:
                await progress.milestone(f"connecting to {target.kind} target {target.base_url}")
                mcp_error = await _run_mcp_scan(
                    scan_id=scan_id,
                    psession=psession,
                    profile=scan.profile,
                    db_session_factory=Session,
                )
                completed = list(getattr(psession.discovered, "completed_modules", []) or [])
                summ = psession.findings.summary() if hasattr(psession.findings, "summary") else {}
                await progress.milestone(
                    f"{target.kind} scan complete · modules: {', '.join(completed) or 'none'} · "
                    f"findings: {sum(summ.values()) if isinstance(summ, dict) else 0}"
                )
            all_findings = (
                list(psession.findings.get_all(include_suppressed=True))
                if hasattr(psession.findings, "get_all")
                else []
            )
            if not all_findings and hasattr(psession.findings, "findings"):
                all_findings = list(psession.findings.findings)
            # Honest failure: a target that never completed the agent handshake
            # (wrong URL, not an agent, auth rejected) must NOT be graded
            # "A / clean" — that's a false all-clear. Surface it as failed.
            if mcp_error and not all_findings:
                async with Session() as db:
                    s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                    s.status = "failed"
                    s.error = mcp_error
                    s.current_stage = "failed"
                    s.finished_at = datetime.now(timezone.utc)
                    _append_log(s, f"failed: {mcp_error}")
                    await db.commit()
                publish_scan_event(scan_id, {
                    "type": "failed", "scan_id": scan_id, "error": mcp_error,
                })
                return
            async with Session() as db:
                for f in all_findings:
                    db.add(DbFinding(**_finding_to_db_row(scan_id, f)))
                await db.commit()
            score, grade, counts = compute_grade(
                [_DbFindingProxy(_) for _ in await _read_back_findings(scan_id, Session)],
                target_kind="agent",
            )
            summary_payload = dict(counts)
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                s.status = "done"
                s.progress_pct = 100
                s.current_stage = "complete"
                s.finished_at = datetime.now(timezone.utc)
                existing = dict(s.summary or {})
                existing.update(summary_payload)
                s.summary = existing
                s.grade = grade
                s.score = score
                _append_log(s, f"finished: grade {grade} · score {score}")
                await db.commit()
            publish_scan_event(scan_id, {
                "type": "finished", "scan_id": scan_id, "grade": grade, "score": score,
                "summary": counts, "total_findings": len(all_findings),
            })
            try:
                from ..tasks.integration_notify_task import notify_scan_findings as _nsf
                _nsf.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("integration scan_done enqueue failed: %s", exc)
            try:
                from ..tasks.email_task import send_scan_complete_email_task as _scet
                _scet.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("scan-complete email enqueue failed: %s", exc)
            _enqueue_validation(scan_id, all_findings)
            return

        # ── RAG / vector-DB kind ────────────────────────────────────
        # Mirrors the MCP branch above: run the dedicated RAG scanner,
        # persist findings, grade, finalize. Does not enter the
        # URL/DAST pipeline.
        if target.kind == "rag":
            from .ai_scan_progress import ai_scan_progress
            async with ai_scan_progress(scan_id, Session, stage="scan_rag") as progress:
                await progress.milestone(f"connecting to {target.kind} target {target.base_url}")
                await _run_rag_scan(
                    scan_id=scan_id,
                    psession=psession,
                    profile=scan.profile,
                    db_session_factory=Session,
                )
                completed = list(getattr(psession.discovered, "completed_modules", []) or [])
                summ = psession.findings.summary() if hasattr(psession.findings, "summary") else {}
                await progress.milestone(
                    f"{target.kind} scan complete · modules: {', '.join(completed) or 'none'} · "
                    f"findings: {sum(summ.values()) if isinstance(summ, dict) else 0}"
                )
            all_findings = (
                list(psession.findings.get_all(include_suppressed=True))
                if hasattr(psession.findings, "get_all")
                else []
            )
            if not all_findings and hasattr(psession.findings, "findings"):
                all_findings = list(psession.findings.findings)
            async with Session() as db:
                for f in all_findings:
                    db.add(DbFinding(**_finding_to_db_row(scan_id, f)))
                await db.commit()
            score, grade, counts = compute_grade(
                [_DbFindingProxy(_) for _ in await _read_back_findings(scan_id, Session)],
                target_kind="rag",
            )
            summary_payload = dict(counts)
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                s.status = "done"
                s.progress_pct = 100
                s.current_stage = "complete"
                s.finished_at = datetime.now(timezone.utc)
                existing = dict(s.summary or {})
                existing.update(summary_payload)
                s.summary = existing
                s.grade = grade
                s.score = score
                _append_log(s, f"finished: grade {grade} · score {score}")
                await db.commit()
            publish_scan_event(scan_id, {
                "type": "finished", "scan_id": scan_id, "grade": grade, "score": score,
                "summary": counts, "total_findings": len(all_findings),
            })
            try:
                from ..tasks.integration_notify_task import notify_scan_findings as _nsf
                _nsf.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("integration scan_done enqueue failed: %s", exc)
            try:
                from ..tasks.email_task import send_scan_complete_email_task as _scet
                _scet.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("scan-complete email enqueue failed: %s", exc)
            _enqueue_validation(scan_id, all_findings)
            return

        # ── ML model kind ───────────────────────────────────────────
        # Mirrors the RAG branch: run the static ML scanner (never loads
        # the model), persist findings, grade, finalize. No DAST pipeline.
        if target.kind == "ml_model":
            await _run_ml_scan(
                scan_id=scan_id,
                psession=psession,
                profile=scan.profile,
                db_session_factory=Session,
            )
            all_findings = (
                list(psession.findings.get_all(include_suppressed=True))
                if hasattr(psession.findings, "get_all")
                else []
            )
            if not all_findings and hasattr(psession.findings, "findings"):
                all_findings = list(psession.findings.findings)
            async with Session() as db:
                for f in all_findings:
                    db.add(DbFinding(**_finding_to_db_row(scan_id, f)))
                await db.commit()
            score, grade, counts = compute_grade(
                [_DbFindingProxy(_) for _ in await _read_back_findings(scan_id, Session)],
                target_kind="ml_model",
            )
            summary_payload = dict(counts)
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                s.status = "done"
                s.progress_pct = 100
                s.current_stage = "complete"
                s.finished_at = datetime.now(timezone.utc)
                existing = dict(s.summary or {})
                existing.update(summary_payload)
                s.summary = existing
                s.grade = grade
                s.score = score
                _append_finding_trace(s, "ML", all_findings)
                _append_log(s, f"finished: grade {grade} · score {score}")
                await db.commit()
            publish_scan_event(scan_id, {
                "type": "finished", "scan_id": scan_id, "grade": grade, "score": score,
                "summary": counts, "total_findings": len(all_findings),
            })
            try:
                from ..tasks.integration_notify_task import notify_scan_findings as _nsf
                _nsf.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("integration scan_done enqueue failed: %s", exc)
            try:
                from ..tasks.email_task import send_scan_complete_email_task as _scet
                _scet.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("scan-complete email enqueue failed: %s", exc)
            _enqueue_validation(scan_id, all_findings)
            return

        # ── Voice / speech-AI kind ──────────────────────────────────
        # Mirrors the ML branch: run the voice scanner (transport posture +
        # consented audio probes), persist findings, grade, finalize. No
        # DAST pipeline.
        if target.kind == "voice":
            from .ai_scan_progress import ai_scan_progress
            async with ai_scan_progress(scan_id, Session, stage="scan_voice") as progress:
                await progress.milestone(f"connecting to {target.kind} target {target.base_url}")
                await _run_voice_scan(
                    scan_id=scan_id,
                    psession=psession,
                    profile=scan.profile,
                    db_session_factory=Session,
                )
                completed = list(getattr(psession.discovered, "completed_modules", []) or [])
                summ = psession.findings.summary() if hasattr(psession.findings, "summary") else {}
                await progress.milestone(
                    f"{target.kind} scan complete · modules: {', '.join(completed) or 'none'} · "
                    f"findings: {sum(summ.values()) if isinstance(summ, dict) else 0}"
                )
            all_findings = (
                list(psession.findings.get_all(include_suppressed=True))
                if hasattr(psession.findings, "get_all")
                else []
            )
            if not all_findings and hasattr(psession.findings, "findings"):
                all_findings = list(psession.findings.findings)
            async with Session() as db:
                for f in all_findings:
                    db.add(DbFinding(**_finding_to_db_row(scan_id, f)))
                await db.commit()
            score, grade, counts = compute_grade(
                [_DbFindingProxy(_) for _ in await _read_back_findings(scan_id, Session)],
                target_kind="voice",
            )
            summary_payload = dict(counts)
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                s.status = "done"
                s.progress_pct = 100
                s.current_stage = "complete"
                s.finished_at = datetime.now(timezone.utc)
                existing = dict(s.summary or {})
                existing.update(summary_payload)
                s.summary = existing
                s.grade = grade
                s.score = score
                _append_log(s, f"finished: grade {grade} · score {score}")
                await db.commit()
            publish_scan_event(scan_id, {
                "type": "finished", "scan_id": scan_id, "grade": grade, "score": score,
                "summary": counts, "total_findings": len(all_findings),
            })
            try:
                from ..tasks.integration_notify_task import notify_scan_findings as _nsf
                _nsf.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("integration scan_done enqueue failed: %s", exc)
            try:
                from ..tasks.email_task import send_scan_complete_email_task as _scet
                _scet.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("scan-complete email enqueue failed: %s", exc)
            _enqueue_validation(scan_id, all_findings)
            return

        # ── Mobile & Client Security kinds (spec 002) ───────────────
        # Mirrors the ML branch: download the uploaded artifact (sha256-
        # verified), run the matching static analyzer (APK/IPA mobile modules,
        # CRX/XPI extension scorer, desktop/Electron scanner), persist findings,
        # grade, finalize. The artifact is NEVER executed — no device/emulator.
        if target.kind in _CLIENT_ARTIFACT_TOOLS:
            _tool = _CLIENT_ARTIFACT_TOOLS[target.kind][0]
            await _log_milestone(scan_id, Session,
                                 f"probing {target.kind}: static analysis via {_tool} "
                                 "(manifest, secrets, crypto, dangerous calls)")
            await _run_client_artifact_scan(
                scan_id=scan_id,
                psession=psession,
                profile=scan.profile,
                kind=target.kind,
                kind_config=dict(target.kind_config or {}),
                db_session_factory=Session,
            )
            all_findings = (
                list(psession.findings.get_all(include_suppressed=True))
                if hasattr(psession.findings, "get_all")
                else []
            )
            if not all_findings and hasattr(psession.findings, "findings"):
                all_findings = list(psession.findings.findings)
            async with Session() as db:
                for f in all_findings:
                    db.add(DbFinding(**_finding_to_db_row(scan_id, f)))
                await db.commit()
            score, grade, counts = compute_grade(
                [_DbFindingProxy(_) for _ in await _read_back_findings(scan_id, Session)],
                target_kind=target.kind,
            )
            summary_payload = dict(counts)
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                s.status = "done"
                s.progress_pct = 100
                s.current_stage = "complete"
                s.finished_at = datetime.now(timezone.utc)
                existing = dict(s.summary or {})
                existing.update(summary_payload)
                s.summary = existing
                s.grade = grade
                s.score = score
                _append_finding_trace(s, target.kind, all_findings)
                _append_log(s, f"finished: grade {grade} · score {score}")
                await db.commit()
            publish_scan_event(scan_id, {
                "type": "finished", "scan_id": scan_id, "grade": grade, "score": score,
                "summary": counts, "total_findings": len(all_findings),
            })
            try:
                from ..tasks.integration_notify_task import notify_scan_findings as _nsf
                _nsf.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("integration scan_done enqueue failed: %s", exc)
            try:
                from ..tasks.email_task import send_scan_complete_email_task as _scet
                _scet.delay(scan_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("scan-complete email enqueue failed: %s", exc)
            _enqueue_validation(scan_id, all_findings)
            return

        # ---- SPA-fallback fingerprint --------------------------------
        # Probe two random non-existent paths so brute-force modules can
        # tell "real 200 OK" from "SPA index.html catchall". Cheap (~2
        # round-trips) but eliminates dozens of false positives on SPA
        # targets. Failure is non-fatal — modules then preserve their
        # historical "treat every 200 as real" behaviour.
        try:
            from pencheff.core.http_client import PencheffHTTPClient
            from pencheff.core.spa_detector import establish_spa_fingerprint
            _fp_http = PencheffHTTPClient(psession)
            try:
                await establish_spa_fingerprint(psession, _fp_http)
            finally:
                try:
                    await _fp_http.close()
                except Exception:
                    pass
        except Exception as exc:  # noqa: BLE001 — never block the scan
            log.warning("SPA fingerprint probe failed: %s", exc)

        # Three-tier profile coercion. Older clients (or migrated scan
        # rows) may carry "engage", "compliance", "api-only", … — collapse
        # them now so the branches below only see quick/standard/deep.
        canonical_profile = _canonical_profile(scan.profile)

        # ---- Authenticated login (path-independent) ------------------
        # Skipped for the deep profile — the swarm orchestrator now owns
        # its own crawl + auth phases (CrawlFirstPlaybook +
        # ApiAuthenticatorPlaybook) so auth runs *after* the real login
        # surface has been crawled, against a discovered login URL
        # rather than a hardcoded probe list.
        #
        # For Quick / Standard we still pre-run authenticated_crawl
        # before the deterministic stages, with discover_first=True
        # so it crawls first and points ApiLoginModule at a real URL.
        if (
            canonical_profile != "deep"
            and creds
            and creds.get("username")
            and creds.get("password")
        ):
            await _run_authenticated_crawl(
                scan_id=scan_id,
                psession=psession,
                db_session_factory=Session,
            )

        # ---- Reconnaissance & scanning -------------------------------
        # Three-mode dispatch resolved in services/dispatch_mode.py:
        #   deterministic_then_agent → populator runs first (engage for
        #     deep / deterministic stages for quick+standard), then the
        #     autonomous engine takes the populated session and verifies,
        #     exploits and chains.
        #   agent_only → engine drives the scan; deterministic populator
        #     runs only as a fallback when the engine errors out.
        #   deterministic_only → no engine credentials configured; only
        #     the populator runs.
        agent_summary: str | None = None
        async with Session() as db:
            ai_enabled = await org_has_ai(db, target.org_id)
            dispatch = await resolve_dispatch_mode(db, target.org_id)
            ai_allowed = await scan_ai_allowed(db, target.org_id)

        # Operator turned AI off at commission time: run deterministic-only
        # regardless of plan/quota. Honoured before the quota check so the
        # log reflects the operator's explicit choice rather than a quota cap.
        if ai_enabled and not use_ai:
            ai_enabled = False
            dispatch = "deterministic_only"
            notice = "AI disabled for this scan by operator — running deterministic-only."
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                _append_log(s, notice)
                await db.commit()
            try:
                publish_scan_event(scan_id, {
                    "type": "update", "event": "ai_disabled", "label": notice,
                })
            except Exception:
                pass

        # Over the monthly AI allotment: don't block the scan — run it
        # deterministic-only (no AI triage / agent) and tell the user.
        if ai_enabled and not ai_allowed:
            ai_enabled = False
            dispatch = "deterministic_only"
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                _append_log(s, DETERMINISTIC_FALLBACK_NOTICE)
                await db.commit()
            try:
                publish_scan_event(scan_id, {
                    "type": "update", "event": "ai_quota",
                    "label": DETERMINISTIC_FALLBACK_NOTICE,
                })
            except Exception:
                pass

        # Prior-scan context for the AI engine — fetched once, before the
        # engine runs. Only when AI is actually engaged (skip the query for
        # deterministic-only scans, which can't use it). None on a first scan.
        prior_context: str | None = None
        if ai_enabled:
            try:
                async with Session() as db:
                    cur = (await db.execute(
                        select(Scan).where(Scan.id == scan_id)
                    )).scalar_one()
                    prior_context = await _build_prior_findings_context(
                        db,
                        scan_id=scan_id,
                        target_id=cur.target_id,
                        created_at=cur.created_at,
                    )
                if prior_context:
                    async with Session() as db:
                        s = (await db.execute(
                            select(Scan).where(Scan.id == scan_id)
                        )).scalar_one()
                        _append_log(
                            s,
                            "Priming AI engine with previous scan findings for "
                            "re-verification.",
                        )
                        await db.commit()
            except Exception as exc:  # noqa: BLE001 — context is best-effort
                log.warning("prior-findings context build failed: %s", exc)

        # BYO-LLM override for the scan agent — only for OpenAI-compatible
        # providers.  anthropic/google are not compatible with the OpenAI-shaped
        # tool-calling loop; for those we log once and keep Pencheff's default.
        scan_agent_llm_override: tuple[str, str, str] | None = None
        if ai_enabled:
            try:
                scan_agent_llm_override = await _load_scan_agent_llm_override(
                    target.org_id, Session
                )
            except Exception as exc:  # noqa: BLE001 — override is best-effort
                log.warning("scan agent LLM override lookup failed: %s", exc)

        async def _populator() -> str | None:
            if canonical_profile == "deep":
                return await _run_engage_pipeline(
                    scan_id=scan_id,
                    psession=psession,
                    target=target,
                    db_session_factory=Session,
                    port_range="top-1000",
                    max_subdomains=100,
                )
            await _run_deterministic_stages(
                scan_id=scan_id,
                psession=psession,
                profile=canonical_profile,
                db_session_factory=Session,
                credentials=creds,
            )
            return None

        async def _engine(session_prepopulated: bool = False) -> str | None:
            settings_local = get_settings()
            if settings_local.swarm_enabled:
                from .agent_swarm import run_swarm
                from .agent_swarm.telemetry import persist_swarm_telemetry

                # Shared on_event: mirrors the same DB-persistence + SSE
                # pattern used by _run_agent_stage so the UI progress bar
                # and log stream behave identically on both paths.
                async def _on_event(line: str) -> None:
                    async with Session() as db:
                        s = (await db.execute(
                            select(Scan).where(Scan.id == scan_id)
                        )).scalar_one()
                        _append_log(s, line)
                        if s.progress_pct < 95:
                            s.progress_pct = min(95, s.progress_pct + 2)
                        # Swarm path emits "[AgentName] tool: ..."; legacy emits "tool: ...".
                        # Match either by looking for "tool: " anywhere in the line.
                        if "tool: " in line:
                            after = line.split("tool: ", 1)[1]
                            s.current_stage = after.split(" ", 1)[0][:64]
                        await db.commit()
                    publish_scan_event(
                        scan_id,
                        {"type": "stage_start", "label": line[:160], "pct": None},
                    )

                outcome = await run_swarm(
                    master_session_id=psession.id,
                    target_url=target.base_url,
                    credentials=creds,
                    profile=canonical_profile,
                    scope=list(target.scope or []) or None,
                    exclude_paths=list(target.exclude_paths or []) or None,
                    on_event=_on_event,
                    session_prepopulated=session_prepopulated,
                    scan_id=scan_id,
                    db_session_factory=Session,
                    # Feature 001: pass Target.kind so run_swarm filters the
                    # breaker roster via KIND_TO_BREAKER_NAMES. For legacy url
                    # targets, kind="url" keeps the original 13-breaker roster.
                    kind=str(getattr(target, "kind", "url") or "url"),
                    # Re-scan priming: previous-scan findings for the breakers
                    # to re-verify / prioritise. None on a first scan.
                    prior_context=prior_context,
                    llm_override=scan_agent_llm_override,
                )
                await persist_swarm_telemetry(
                    scan_id=scan_id,
                    outcome=outcome,
                    db_session_factory=Session,
                )
                return outcome.summary

            return await _run_agent_stage(
                scan_id=scan_id,
                psession=psession,
                target=target,
                profile=canonical_profile,
                credentials=creds,
                db_session_factory=Session,
                session_prepopulated=session_prepopulated,
                prior_context=prior_context,
                llm_override=scan_agent_llm_override,
            )

        if dispatch == "deterministic_then_agent":
            populator_summary = await _populator()
            engine_summary = await _engine(session_prepopulated=True)
            agent_summary = engine_summary or populator_summary
            async with Session() as db_count:
                await increment_option_3_counter(db_count, target.org_id)
                await db_count.commit()
        elif dispatch == "agent_only":
            try:
                agent_summary = await _engine(session_prepopulated=False)
            except Exception as exc:  # noqa: BLE001 — fall back to deterministic
                log.warning("engine path failed (%s); falling back to populator", exc)
                agent_summary = await _populator()
            # After the agent_loop fix that promotes non-429/5xx HTTP errors
            # to _TransientLLMError, the swarm's _catastrophic_fallback runs
            # the legacy single-agent loop — which can ALSO fail silently if
            # the LLM is broken (run_agent catches all exceptions and returns
            # AgentOutcome(summary="")). That path doesn't raise, so the
            # try/except above doesn't fire. Detect the empty-summary case
            # and run the deterministic populator as the architectural
            # ``deterministic-only fallback when the AI fails`` (feature 001
            # spec §0). For ``deterministic_then_agent`` this is unnecessary
            # — the populator already ran first; for ``deterministic_only``
            # it never reaches this branch.
            if not agent_summary:
                log.warning(
                    "engine returned empty summary; running populator as "
                    "deterministic fallback"
                )
                agent_summary = await _populator()
        else:  # deterministic_only
            agent_summary = await _populator()

        # For Standard: append the rule-based orchestrator (bug_bounty +
        # cve_intel + red_team) so this tier covers what the old
        # api-only / asm / sca profiles used to cover separately. Deep
        # already gets the orchestrator inside _run_engage_pipeline.
        if canonical_profile == "standard":
            try:
                ds = await _run_deterministic_orchestrator_phase(
                    scan_id=scan_id,
                    psession=psession,
                    target=target,
                    db_session_factory=Session,
                )
                if ds and not agent_summary:
                    agent_summary = ds
            except Exception as exc:  # noqa: BLE001
                log.warning("standard orchestrator phase failed: %s", exc)

        # Persist findings — include suppressed ones so the UI's "Show
        # false positives" toggle can surface them. The agent may have
        # suppressed half the populator's findings; without this flag
        # those rows would never reach the DB.
        all_findings = (
            list(psession.findings.get_all(include_suppressed=True))
            if hasattr(psession.findings, "get_all")
            else []
        )
        if not all_findings and hasattr(psession.findings, "findings"):
            all_findings = list(psession.findings.findings)

        async with Session() as db:
            for f in all_findings:
                db.add(DbFinding(**_finding_to_db_row(scan_id, f)))
            await db.commit()

        # --- Triage pipeline ------------------------------------------
        # Three stages, each narrowing the false-positive surface. All
        # mutations happen on DB rows; the raw findings remain the source
        # of truth. Any stage failure is logged and the next stage runs
        # against whatever survived.
        #
        #   1. Rule-based pre-filter (every plan) — cheap deterministic
        #      heuristics; currently catches SPA-404 admin paths.
        #   2. Active verification (every plan) — actually probe each
        #      finding's endpoint and either suppress as a false positive
        #      (no value extractable) or append confirming evidence.
        #   3. LLM classification (Pro+) — nuanced classification for
        #      what's still unsuppressed.
        await _rule_based_triage(
            scan_id=scan_id,
            db_session_factory=Session,
        )
        try:
            await active_verify(
                scan_id=scan_id,
                db_session_factory=Session,
            )
        except Exception as exc:  # noqa: BLE001 — never block the pipeline
            log.exception("active_verify pass failed: %s", exc)
        await _llm_triage(
            scan_id=scan_id,
            org_id=target.org_id,
            db_session_factory=Session,
            ai_enabled=ai_enabled,
        )

        # Re-read findings so compute_grade sees AI-applied suppressions.
        async with Session() as db:
            db_rows = (
                await db.execute(
                    select(DbFinding).where(DbFinding.scan_id == scan_id)
                )
            ).scalars().all()

        graded_inputs = [_DbFindingProxy(row) for row in db_rows]
        # ``target_kind`` selects the right severity curve. URL/Repo
        # share the conservative DAST/SAST profile; LLM never reaches
        # this path (its grading is computed earlier in the LLM-only
        # branch above).
        score, grade, counts = compute_grade(
            graded_inputs,
            target_kind=str(getattr(target, "kind", "url") or "url"),
        )
        summary_payload: dict[str, Any] = dict(counts)

        # --- LLM audit-style grading ---------------------------------
        # Pro+ only: ask the LLM for an executive grade + rationale and
        # surface the LLM-attributed rationale on the scan summary. Free
        # orgs keep the heuristic grade above and never get any AI
        # rationale / agent summary attached. The whole block (including
        # the rule-based-suppression elif and the agent_summary branch)
        # is gated together because the elif's "ai_model" attribution
        # would otherwise be misleading on Free scans whose rule-based
        # SPA-404 pre-filter happened to suppress something.
        #
        # BYO exception: an org with an active BYO provider bypasses the
        # plan gate — grading routes through their provider (fail-closed).
        byo_active: bool = False
        try:
            async with Session() as db:
                _byo_org = await db.get(Org, target.org_id)
                byo_active = bool(_byo_org and _byo_org.active_llm_provider_id)
        except Exception:  # noqa: BLE001 — best-effort; grading is non-blocking
            pass
        if ai_enabled or byo_active:
            ai_grade = await _maybe_ai_grade(
                target_url=target.base_url,
                org_id=target.org_id,
                db_session_factory=Session,
                db_rows=db_rows,
                severity_counts=counts,
            )
            if ai_grade is not None:
                grade = ai_grade.grade
                score = ai_grade.score
                summary_payload["executive_summary"] = ai_grade.rationale
            elif any(
                r.suppressed and r.suppress_reason == "ai_false_positive"
                for r in db_rows
            ):
                summary_payload["executive_summary"] = (
                    "Heuristic grade retained. False positives were "
                    "suppressed by the automated review pass."
                )

            # When the autonomous engine drove the scan, prefer its
            # executive summary — it has far richer attack context than
            # the grader's rationale.
            if agent_summary:
                summary_payload["operator_summary"] = agent_summary
                if not summary_payload.get("executive_summary"):
                    summary_payload["executive_summary"] = agent_summary

        # --- Delta vs the target's previous completed scan ------------
        # On a target's 2nd+ scan, diff against the most recent prior 'done'
        # scan so the results view leads with what changed (new / fixed /
        # persisted) before the current findings. None on a first scan.
        previous_comparison: dict | None = None
        try:
            async with Session() as db:
                cur = (await db.execute(
                    select(Scan).where(Scan.id == scan_id)
                )).scalar_one()
                previous_comparison = await _compute_previous_comparison(
                    db,
                    scan_id=scan_id,
                    target_id=cur.target_id,
                    created_at=cur.created_at,
                    current_rows=db_rows,
                )
        except Exception as exc:  # noqa: BLE001 — comparison is best-effort
            log.warning("previous-scan comparison failed: %s", exc)
        if previous_comparison:
            summary_payload["previous_comparison"] = previous_comparison

        async with Session() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            s.status = "done"
            s.progress_pct = 100
            s.current_stage = "complete"
            s.finished_at = datetime.now(timezone.utc)
            # Merge with anything earlier helpers wrote (e.g. swarm telemetry).
            existing = dict(s.summary or {})
            existing.update(summary_payload)
            s.summary = existing
            s.grade = grade
            s.score = score
            _append_log(s, f"finished: grade {grade} · score {score}")
            await db.commit()

        publish_scan_event(scan_id, {
            "type": "finished", "scan_id": scan_id, "grade": grade, "score": score,
            "summary": counts, "total_findings": len(all_findings),
            "previous_comparison": previous_comparison,
        })
        # Fan-out scan_done + finding_new for every persisted finding to
        # every matching integration (per-target scoped, per-event filtered,
        # severity-gated). Single Celery roundtrip — the notify task
        # iterates findings server-side so we don't issue ~N delays.
        try:
            from ..tasks.integration_notify_task import notify_scan_findings as _nsf
            _nsf.delay(scan_id)
        except Exception as exc:  # noqa: BLE001
            log.warning("integration scan_done enqueue failed: %s", exc)
        # One-shot scan-complete email for any caller-supplied recipients.
        try:
            from ..tasks.email_task import send_scan_complete_email_task as _scet
            _scet.delay(scan_id)
        except Exception as exc:  # noqa: BLE001
            log.warning("scan-complete email enqueue failed: %s", exc)
        # If this scan is tied to an engagement, kick off cross-reference
        # correlation so the unified findings view picks up DAST↔SAST/SCA/IaC
        # edges within seconds. Lazy import to avoid celery_app cycle.
        try:
            async with Session() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
                eid = s.engagement_id if s is not None else None
            if eid:
                from ..tasks.correlation_task import run_correlation
                run_correlation.delay(eid)
        except Exception as exc:  # noqa: BLE001
            log.warning("correlation enqueue failed: %s", exc)
        # Security Lake ingestion — fire-and-forget. enqueue_dast_ingest is itself
        # guarded, but wrap at the call site too so a future refactor can never let
        # an exception reach the outer handler and mis-mark a completed scan as failed.
        try:
            from ..tasks.security_lake_ingest_task import enqueue_dast_ingest
            enqueue_dast_ingest(scan_id)
        except Exception as exc:  # noqa: BLE001
            log.warning("security-lake enqueue failed: %s", exc)
        _enqueue_validation(scan_id, all_findings)
    except Exception as e:
        log.exception("scan failed")
        async with Session() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
            if s:
                s.status = "failed"
                s.error = f"{type(e).__name__}: {e}\n{traceback.format_exc()[-2000:]}"
                s.finished_at = datetime.now(timezone.utc)
                _append_log(s, f"failed: {type(e).__name__}: {e}"[:200])
                await db.commit()
        publish_scan_event(scan_id, {"type": "failed", "scan_id": scan_id, "error": str(e)})
        # Fire scan_failed to integrations. Best-effort — never raise from here.
        try:
            from ..tasks.integration_notify_task import notify_event as _ne
            _ne.delay(scan_id, "scan_failed", error=f"{type(e).__name__}: {e}"[:500])
        except Exception as exc:  # noqa: BLE001
            log.warning("integration scan_failed enqueue failed: %s", exc)
        # One-shot scan-failed email — same recipient list as scan-complete.
        try:
            from ..tasks.email_task import send_scan_complete_email_task as _scet
            _scet.delay(scan_id)
        except Exception as exc:  # noqa: BLE001
            log.warning("scan-failed email enqueue failed: %s", exc)


def run_scan_sync(scan_id: str) -> None:
    asyncio.run(run_scan(scan_id))


# ---------------------------------------------------------------------------
# Agent-driven path
# ---------------------------------------------------------------------------


async def _run_engage_pipeline(
    *,
    scan_id: str,
    psession: Any,
    target: Target,
    db_session_factory: async_sessionmaker,
    port_range: str = "top-1000",
    max_subdomains: int = 100,
) -> str | None:
    """Drive the pentest-ai-agents swarm orchestrator from the API.

    Equivalent of ``pencheff engage --target ... --tier 2 --port-range top-1000
    --max-subdomains 100``: runs all 7 phases (scope → recon → vuln → exploit
    → postex → detect → report), fans out to discovered subdomains, persists
    the engagement to the SQLite engagement DB, and streams phase progress
    into the scan log so the UI bar moves.

    Returns a short human-readable summary for the scan's executive summary.
    """
    from urllib.parse import urlparse

    from pencheff.core.engagement_db import EngagementDB
    from pencheff.core.scope_guard import ScopeGuard, set_scope
    from pencheff.playbooks.swarm_orchestrator import SwarmOrchestratorPlaybook

    base_host = urlparse(target.base_url).hostname or ""
    # Build the scope from the Target's own data so subdomain fan-out
    # validates against ``*.<host>``. This matches what the CLI does when
    # given a YAML scope file.
    scope = ScopeGuard.from_dict({
        "client": target.name or base_host,
        "type": "webapp",
        "domains": [base_host, f"*.{base_host}"] if base_host else [],
        "urls": [target.base_url] + list(target.scope or []),
        "ip_ranges": [],
        "allow_destructive": False,
        "authorized_by": f"workspace:{target.workspace_id}",
    })
    set_scope(scope)

    eng_db = EngagementDB()
    engagement_id = eng_db.init_engagement(
        client=target.name or base_host or "scan",
        engagement_type="webapp",
        scope=scope.to_dict(),
        notes=f"API scan {scan_id} — engage profile",
    )

    # Push start log + initial progress.
    async with db_session_factory() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        creds_loaded = psession.credentials.count
        creds_note = f" creds=loaded ({creds_loaded})" if creds_loaded else " creds=none"
        _append_log(s, f"engage: starting swarm — scope={base_host}, "
                       f"port_range={port_range}, max_subdomains={max_subdomains},"
                       f"{creds_note}")
        s.current_stage = "engage:scope"
        s.progress_pct = 5
        await db.commit()
    publish_scan_event(scan_id, {"type": "stage_start", "label": "engage: swarm starting"})

    # The orchestrator drives phases serially; we wire a progress callback
    # so the scan log + SSE stream reflect each phase + each playbook as
    # they complete (the swarm's own session_log only flushes at the end,
    # which gave the UI a frozen 5% progress bar for the whole 5–15min run).
    # Phase boundaries map to fractional progress so the bar moves visibly.
    _PHASE_ORDER = ["scope", "crawl", "auth", "recon", "vuln", "exploit",
                    "postex", "detect", "report"]

    def _label_for(event: str, payload: dict[str, Any]) -> str:
        """Build the human-readable line that goes into BOTH the persisted
        scan log and the SSE event's ``label`` field. Single source of
        truth so the live stream and a post-refresh fetch show identical
        text."""
        if event == "phase_start":
            phase = payload.get("phase", "?")
            pbs = payload.get("playbooks") or []
            return (f"engage:{phase} starting "
                    f"({len(pbs)} playbook(s): {', '.join(pbs)})")
        if event == "playbook_done":
            name = payload.get("playbook", "?")
            err = payload.get("error")
            skipped = payload.get("skipped")
            if err:
                return f"  {name} ✗ {err[:200]}"
            if skipped:
                return f"  {name} skipped ({skipped})"
            summary = payload.get("summary") or ""
            added = payload.get("findings_added") or 0
            suffix = f" (+{added} finding{'s' if added != 1 else ''})" if added else ""
            return f"  {name} ✓ {summary[:160]}{suffix}"
        if event == "subdomain_start":
            return f"subdomain fan-out → {payload.get('subdomain', '?')}"
        if event == "subdomain_done":
            sd = payload.get("subdomain", "?")
            n = payload.get("findings", 0)
            return f"subdomain {sd} complete ({n} findings)"
        if event == "phase_done":
            return f"engage:{payload.get('phase', '?')} done"
        return f"{event}: {payload.get('phase') or payload.get('subdomain') or ''}"

    async def _on_progress(event: str, payload: dict[str, Any]) -> None:
        label = _label_for(event, payload)
        try:
            async with db_session_factory() as db:
                s2 = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                if event == "phase_start":
                    phase = payload.get("phase", "?")
                    s2.current_stage = f"engage:{phase}"
                    # Spread phase progress over 5..90; reserve the last 10
                    # for triage / grading after the swarm returns.
                    if phase in _PHASE_ORDER:
                        idx = _PHASE_ORDER.index(phase)
                        s2.progress_pct = max(s2.progress_pct or 0,
                                              5 + int((idx / len(_PHASE_ORDER)) * 85))
                elif event == "subdomain_start":
                    s2.current_stage = f"engage:subdomain:{payload.get('subdomain', '?')}"
                if label and event != "phase_done":  # phase_done is implicit, no log line
                    _append_log(s2, label)
                await db.commit()
        except Exception:
            return  # progress UX must never break the scan
        try:
            # The UI renders SSE entries as `${d.type}: ${d.label || d.stage}` —
            # so we MUST include ``label`` here (otherwise the live stream
            # shows blank ``stage_start:`` / ``update:`` lines until the user
            # refreshes and the page re-reads the persisted scan.log array).
            publish_scan_event(scan_id, {
                "type": "stage_start" if event == "phase_start" else "update",
                "event": event,
                "label": label,
                **payload,
            })
        except Exception:
            pass

    pb = SwarmOrchestratorPlaybook()
    try:
        result = await pb.run(
            psession, eng_db, engagement_id,
            scope=scope.to_dict(),
            tier=2,
            phases=None,                # all 9 phases
            parallel_recon=True,
            include_subdomains=True,
            max_subdomains=max_subdomains,
            port_range=port_range,
            noise_ceiling=None,         # no OPSEC ceiling — full coverage
            progress_cb=_on_progress,
        )
    except Exception as exc:
        async with db_session_factory() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            _append_log(s, f"engage failed: {type(exc).__name__}: {exc}")
            await db.commit()
        raise

    # Push the orchestrator's session_log into the scan log so the UI's
    # SSE stream reflects every phase + every playbook + every subdomain.
    log_rows = eng_db.session_log(engagement_id)
    async with db_session_factory() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        s.current_stage = "engage:complete"
        for row in log_rows:
            _append_log(s, f"{row.get('agent','-')}: "
                           f"{row.get('action','-')} — {row.get('summary','')}")
        await db.commit()

    artifacts = result.artifacts or {}
    sub_runs = artifacts.get("subdomain_runs", [])
    summary_lines = [
        f"engage complete — {len(artifacts.get('runs', []))} playbook run(s) "
        f"on base, {len(sub_runs)} subdomain(s) fanned out.",
    ]
    for sr in sub_runs:
        summary_lines.append(f"  · {sr.get('subdomain')}: {sr.get('findings', 0)} finding(s)")

    # ── Deterministic-orchestrator phase ───────────────────────────────
    # After the LLM-driven swarm finishes, run the rule-based workflow
    # layer too: bug_bounty (extra surface enum + verified scans), cve_intel
    # (offline + live CVE correlation), red_team (MITRE narrative). All
    # decisions come from pencheff/data/policies/*.yaml — no LLM in this
    # phase. Findings merge into the same scan, narrative is appended to
    # the executive summary so the UI shows it natively.
    deterministic_summary = await _run_deterministic_orchestrator_phase(
        scan_id=scan_id,
        psession=psession,
        target=target,
        db_session_factory=db_session_factory,
    )
    if deterministic_summary:
        summary_lines.append("")
        summary_lines.append(deterministic_summary)

    return "\n".join(summary_lines)


async def _run_deterministic_orchestrator_phase(
    *,
    scan_id: str,
    psession: Any,
    target: Target,
    db_session_factory: async_sessionmaker,
) -> str | None:
    """Run pencheff's deterministic workflow layer as the final engage phase.

    Wires bug_bounty + cve_intel + red_team into the same scan record so
    the UI sees their findings, chains, and narrative without any new
    plumbing. Failures here are logged but never abort the scan — the LLM
    swarm has already completed by the time we get here.
    """
    async with db_session_factory() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        s.current_stage = "engage:orchestrator"
        s.progress_pct = max(s.progress_pct or 0, 92)
        _append_log(s, "engage:orchestrator starting (deterministic workflows: "
                       "bug_bounty + cve_intel + red_team)")
        await db.commit()
    publish_scan_event(scan_id, {
        "type": "stage_start",
        "label": "engage: deterministic orchestrator starting",
    })

    try:
        from pencheff.workflows.auto_pentest import run as run_auto
    except Exception as exc:  # pragma: no cover — import failure means feature unavailable
        async with db_session_factory() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            _append_log(s, f"engage:orchestrator skipped — import error: {exc}")
            await db.commit()
        return None

    try:
        result = await run_auto(target.base_url, intensity="default")
    except Exception as exc:
        async with db_session_factory() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            _append_log(s, f"engage:orchestrator failed: "
                           f"{type(exc).__name__}: {exc}")
            await db.commit()
        return None

    new_findings = result.get("findings", []) or []
    chains = result.get("chains", []) or []
    narrative_md = result.get("narrative_md", "") or ""

    # Merge orchestrator findings into the live PentestSession so they land
    # in the API's normal finding pipeline (dedupe + grading + UI render).
    merged = 0
    for raw in new_findings:
        if isinstance(raw, dict):
            try:
                merged += _merge_dict_finding_into_session(psession, raw)
            except Exception:  # noqa: BLE001
                continue
        else:
            try:
                psession.findings.add(raw)
                merged += 1
            except Exception:  # noqa: BLE001
                continue

    async with db_session_factory() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        _append_log(
            s,
            f"engage:orchestrator done — +{merged} finding(s), "
            f"{len(chains)} attack chain(s), narrative="
            f"{'yes' if narrative_md else 'no'}",
        )
        for chain_id in chains[:25]:
            _append_log(s, f"  chain → {chain_id}")
        if narrative_md:
            # Persist the narrative as a separate log block so the UI
            # finding-detail page can render it. We chunk by line to avoid
            # blowing past the per-log-line UI truncation.
            _append_log(s, "── MITRE narrative (deterministic) ──")
            for line in narrative_md.splitlines():
                if line.strip():
                    _append_log(s, line[:240])
        s.current_stage = "engage:orchestrator:done"
        s.progress_pct = max(s.progress_pct or 0, 95)
        await db.commit()
    publish_scan_event(scan_id, {
        "type": "stage_done",
        "label": f"engage: orchestrator complete (+{merged} findings, "
                 f"{len(chains)} chains)",
    })

    summary = (
        f"deterministic orchestrator: +{merged} finding(s), "
        f"{len(chains)} chain(s). Policy versions: "
        f"{result.get('policy_versions', {})}."
    )
    return summary


def _merge_dict_finding_into_session(psession: Any, raw: dict) -> int:
    """Best-effort coercion of a workflow's dict-shaped finding into the
    session's Finding model. Returns 1 if added, 0 otherwise.
    """
    from pencheff.config import Severity
    from pencheff.core.findings import Evidence, Finding

    sev_value = (raw.get("severity") or "info")
    if hasattr(sev_value, "value"):
        sev_value = sev_value.value
    sev = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }.get(str(sev_value).lower(), Severity.INFO)

    f = Finding(
        title=str(raw.get("title") or "orchestrator finding"),
        severity=sev,
        category=str(raw.get("category") or "orchestrator"),
        owasp_category=str(raw.get("owasp_category") or "A05"),
        description=str(raw.get("description") or ""),
        remediation=str(raw.get("remediation") or "See linked references."),
        endpoint=str(raw.get("endpoint") or ""),
        mitre_id=list(raw.get("mitre_id") or []),
        references=list(raw.get("linked_cves") or []) + list(raw.get("references") or []),
        evidence=[Evidence(
            request_method="N/A",
            request_url=str(raw.get("endpoint") or ""),
            response_body_snippet=str(raw.get("description") or "")[:500],
            description="deterministic orchestrator",
        )],
    )
    try:
        psession.findings.add(f)
        return 1
    except Exception:  # noqa: BLE001
        return 0


async def _run_agent_stage(
    *,
    scan_id: str,
    psession: Any,
    target: Target,
    profile: str,
    credentials: dict | None,
    db_session_factory: async_sessionmaker,
    session_prepopulated: bool = False,
    prior_context: str | None = None,
    llm_override: tuple[str, str, str] | None = None,
) -> str | None:
    """Hand the scan over to the LLM penetration-testing agent.

    The agent drives the pencheff toolkit via tool-use — reconnoitring,
    probing, and verifying — and returns an executive summary which we
    persist on the scan row. Any crash here falls back to the
    deterministic stages so the scan still completes.
    """
    from .agent_runner import run_agent

    # Forward every agent action into the live scan log + SSE stream so
    # the UI shows exactly what the agent is doing in real time.
    async def on_event(line: str) -> None:
        # Coarse progress hint: bump progress_pct by a fraction per tool
        # call so the bar actually moves during the agent run.
        async with db_session_factory() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            _append_log(s, line)
            # Keep progress somewhere between 5 and 95 while the agent
            # works; the final 100 comes from the grading block.
            if s.progress_pct < 95:
                s.progress_pct = min(95, s.progress_pct + 2)
            # Extract a short "current stage" label if we can.
            # Swarm path emits "[AgentName] tool: ..."; legacy emits "tool: ...".
            # Match either by looking for "tool: " anywhere in the line.
            if "tool: " in line:
                after = line.split("tool: ", 1)[1]
                s.current_stage = after.split(" ", 1)[0][:64]
            await db.commit()
        publish_scan_event(
            scan_id,
            {"type": "stage_start", "label": line[:160], "pct": None},
        )

    await on_event("stage_start: Agent reconnaissance")

    try:
        outcome = await run_agent(
            session_id=psession.id,
            target_url=target.base_url,
            credentials=credentials,
            profile=profile,
            scope=list(target.scope or []) or None,
            exclude_paths=list(target.exclude_paths or []) or None,
            on_event=on_event,
            session_prepopulated=session_prepopulated,
            prior_context=prior_context,
            llm_override=llm_override,
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("agent failed — falling back to deterministic stages")
        await on_event(f"agent failed: {exc}"[:500])
        await _run_deterministic_stages(
            scan_id=scan_id,
            psession=psession,
            profile=profile,
            db_session_factory=db_session_factory,
        )
        return None

    await on_event(
        f"agent {'finished' if outcome.finished_cleanly else 'stopped'}: "
        f"{outcome.tool_calls} tool calls, {outcome.turns} turns, reason={outcome.reason}"
    )

    return outcome.summary or None


async def _run_deterministic_stages(
    *,
    scan_id: str,
    psession: Any,
    profile: str,
    db_session_factory: async_sessionmaker,
    credentials: dict | None = None,
) -> None:
    """Legacy path: walk the fixed stage list. Used when the agent is
    disabled or crashes. Authenticated login is performed at the
    ``run_scan`` level so it covers both the agent and deterministic
    paths — see the call to ``_run_authenticated_crawl`` there."""
    stages = _stages_for(profile)
    total = len(stages)
    for i, (tool, label) in enumerate(stages):
        publish_scan_event(
            scan_id,
            {"type": "stage_start", "stage": tool, "label": label, "pct": int(i / total * 100)},
        )
        async with db_session_factory() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            s.current_stage = label
            s.progress_pct = int(i / total * 100)
            _append_log(s, f"stage_start: {label}")
            if tool == "recon_active":
                opts, timeout = _stage_options(profile, tool)
                _append_log(
                    s,
                    "stage_detail: Active recon "
                    f"({opts['port_range']} TCP, UDP {'on' if opts['udp_scan'] else 'off'}, "
                    f"aggressive {'on' if opts['aggressive'] else 'off'}, max {int(timeout)}s)",
                )
            await db.commit()
        new, warning = await _run_stage(tool, psession.id, profile=profile)
        publish_scan_event(
            scan_id,
            {"type": "stage_done", "stage": tool, "label": label,
             "pct": int((i + 1) / total * 100), "new_findings": new},
        )
        async with db_session_factory() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            if warning:
                _append_log(s, f"stage_warning: {label} ({warning})")
            _append_log(s, f"stage_done: {label}")
            await db.commit()


async def _run_llm_scan(
    *,
    scan_id: str,
    psession: Any,
    profile: str,
    db_session_factory: async_sessionmaker,
) -> None:
    """Drive the single-stage LLM red-team probe.

    Profile maps to a max_payloads cap (LLM_PROFILE_CAPS). The MCP
    tool internally fans out across the five OWASP LLM categories;
    we report progress at the wrapper level only — the individual
    category timings are short enough that finer-grained progress
    isn't worth the wiring."""
    cap = LLM_PROFILE_CAPS.get(profile, LLM_PROFILE_CAPS["standard"])
    label = f"LLM red team ({profile} · max {cap} payloads)"
    async with db_session_factory() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        s.current_stage = label
        s.progress_pct = 5
        _append_log(s, f"stage_start: {label}")
        await db.commit()
    publish_scan_event(
        scan_id,
        {"type": "stage_start", "stage": "scan_llm_red_team", "label": label, "pct": 5},
    )

    import pencheff.server as srv
    fn = getattr(srv, "scan_llm_red_team", None)
    if fn is None:
        # Plugin not loaded — surface clearly rather than crashing.
        async with db_session_factory() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            _append_log(s, "stage_warning: scan_llm_red_team tool not available")
            await db.commit()
        return

    # ── Per-scan transcript dump ──────────────────────────────────────
    # The LLM red team plugin writes one JSONL line per probe (full
    # request, full response, verdict, reason — unredacted) when
    # ``PENCHEFF_LLM_DUMP_TRANSCRIPTS`` is set. Wire it to a per-scan
    # directory so users can read the entire transcript after the run
    # via the ``GET /scans/{id}/llm-transcripts`` endpoint.
    transcripts_dir = Path(tempfile.gettempdir()) / "pencheff-llm-transcripts" / scan_id
    try:
        transcripts_dir.mkdir(parents=True, exist_ok=True)
        os.environ["PENCHEFF_LLM_DUMP_TRANSCRIPTS"] = str(transcripts_dir)
        # Clear the dumper's cached file handle so a previous scan's
        # path doesn't bleed into this one.
        try:
            from pencheff.modules.llm_red_team.base import _DUMP_PATH_CACHE  # type: ignore[attr-defined]
            _DUMP_PATH_CACHE.clear()
        except Exception:  # noqa: BLE001
            pass
        async with db_session_factory() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            _append_log(s, f"transcripts: {transcripts_dir}/probes.jsonl")
            await db.commit()
    except Exception:  # noqa: BLE001 — never block the scan on transcript-dir setup
        log.warning("failed to set up LLM transcript dir", exc_info=True)

    from .ai_scan_progress import ai_scan_progress
    # ── Heartbeat ─────────────────────────────────────────────────────
    # ``scan_llm_red_team`` is a single MCP-style call that internally
    # fans out across all 10 OWASP-LLM modules and may take 1–5 minutes
    # at default rate limits. Without a heartbeat the UI just sits at
    # 5% with one ``stage_start`` log line until the call returns —
    # users (rightly) assume the scan has stalled.
    #
    # We tick every 10 seconds, bump ``progress_pct`` linearly toward
    # 90% over the timeout, and append a ``stage_progress`` log line +
    # SSE event so the UI has something to render.
    #
    # Timeout is profile-aware. After tier-4 the technique surface is
    # significantly wider — bias (20) + RAG (12) + MCP (10) +
    # coding-agent (33) = 75 extra payloads on top of the 10 OWASP-LLM
    # base modules, plus strategy fan-out (base64 / rot13 / jailbreak
    # / leetspeak / crescendo) multiplies each by ~5×.
    #
    # The round-robin cap caps each module at ~max_payloads/10 cases
    # AFTER fan-out, so a deep scan dispatches ~250 cases. Slow models
    # (free-tier endpoints, reasoning models with long <think> traces)
    # average 10–30s per probe with retries, which means deep can need
    # 60+ minutes of wall clock to complete LLM01..LLM10.
    #
    # Old budget (2400s for deep) was calibrated for ~5s/probe and
    # cut LLM09/LLM10 off mid-module, dropping any partial findings
    # because aggregation happens at ``module_done``. Bumping to
    # 5400s gives ~9 min/module, enough for the worst common case.
    _HEARTBEAT_PERIOD_S = 10.0
    _HEARTBEAT_TIMEOUT_S = {
        "quick":    600.0,    # 10 min — 25 total probes
        "standard": 1800.0,   # 30 min — 75 total probes
        "deep":     7200.0,   # 2 hours — 250 total probes × tier-4 fan-out
                              # (TAP / GOAT / Hydra always-on when an
                              # attacker is configured ⇒ each base
                              # case spawns 3 attacker-driven variants
                              # whose per-case wall-clock is 5–10× a
                              # plain probe, hence the wider budget).
    }.get(profile, 1200.0)
    _PCT_FLOOR = 5
    _PCT_CEIL = 90  # cap heartbeat at 90; the real stage_done bumps to 95.
    heartbeat_started = asyncio.get_event_loop().time()

    async def _heartbeat() -> None:
        try:
            while True:
                await asyncio.sleep(_HEARTBEAT_PERIOD_S)
                elapsed = asyncio.get_event_loop().time() - heartbeat_started
                # Linear interpolation toward _PCT_CEIL over the timeout.
                pct = min(
                    _PCT_CEIL,
                    int(_PCT_FLOOR + (elapsed / _HEARTBEAT_TIMEOUT_S) * (_PCT_CEIL - _PCT_FLOOR)),
                )
                line = f"stage_progress: {label} — running ({int(elapsed)}s elapsed)"
                try:
                    async with db_session_factory() as hb_db:
                        hb_s = (
                            await hb_db.execute(
                                select(Scan).where(Scan.id == scan_id)
                            )
                        ).scalar_one()
                        # Don't ratchet backwards if some other writer
                        # has already advanced the bar past our linear
                        # estimate.
                        hb_s.progress_pct = max(int(hb_s.progress_pct or 0), pct)
                        _append_log(hb_s, line)
                        await hb_db.commit()
                except Exception:  # noqa: BLE001 — heartbeat must not crash the scan
                    log.debug("LLM red team heartbeat write failed", exc_info=True)
                try:
                    publish_scan_event(
                        scan_id,
                        {
                            "type": "stage_progress",
                            "stage": "scan_llm_red_team",
                            "label": line,
                            "pct": pct,
                            "elapsed_s": int(elapsed),
                        },
                    )
                except Exception:  # noqa: BLE001
                    log.debug("LLM red team heartbeat publish failed", exc_info=True)
        except asyncio.CancelledError:
            return

    async with ai_scan_progress(scan_id, db_session_factory, stage="scan_llm_red_team"):
        heartbeat_task = asyncio.create_task(_heartbeat())
        try:
            try:
                # 5 minute hard ceiling per scan — LLM10 probes can drag if
                # the endpoint streams long responses with no caps.
                result = await asyncio.wait_for(
                    fn(session_id=psession.id, max_payloads=cap),
                    timeout=_HEARTBEAT_TIMEOUT_S,
                )
            except asyncio.TimeoutError:
                async with db_session_factory() as db:
                    s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                    _append_log(s, f"stage_warning: scan_llm_red_team timed out after {int(_HEARTBEAT_TIMEOUT_S)}s")
                    await db.commit()
                return
            except Exception as exc:  # noqa: BLE001 — log + continue
                log.warning("scan_llm_red_team raised: %s", exc)
                async with db_session_factory() as db:
                    s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                    _append_log(s, f"stage_warning: scan_llm_red_team failed: {type(exc).__name__}: {exc}")
                    await db.commit()
                return
        finally:
            # Always stop the heartbeat — success, timeout, or unexpected error.
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    new = int((result or {}).get("new_findings", 0) or 0)
    redteam_summary = (result or {}).get("redteam_summary") or {}
    by_category_raw = redteam_summary.get("by_category") or {}
    # Coerce to {LLMxx: int} so the guardrails recommender can read it
    # back via _failure_counts_from_summary without re-validating shape.
    by_category: dict[str, int] = {}
    for k, v in by_category_raw.items():
        if not str(k).startswith("LLM"):
            continue
        try:
            by_category[str(k)] = int(v)
        except (TypeError, ValueError):
            continue
    async with db_session_factory() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        s.progress_pct = 95
        _append_log(s, f"stage_done: {label} (+{new} finding{'s' if new != 1 else ''})")
        # Persist the OWASP-LLM by-category breakdown into scan.summary so
        # GET /scans/{id}/recommended-guardrails has data to act on. The
        # final summary write in run_scan merges severity counts on top
        # of this dict — it doesn't clear sibling keys.
        if by_category or redteam_summary:
            existing = dict(s.summary or {})
            if by_category:
                existing["llm_redteam_by_category"] = by_category
            if redteam_summary:
                existing["llm_redteam_summary"] = redteam_summary
            s.summary = existing
        await db.commit()
    publish_scan_event(
        scan_id,
        {"type": "stage_done", "stage": "scan_llm_red_team", "label": label,
         "pct": 95, "new_findings": new},
    )


async def _run_mcp_scan(
    *,
    scan_id: str,
    psession: Any,
    profile: str,
    db_session_factory: async_sessionmaker,
) -> str | None:
    """Invoke the pencheff scan_mcp tool in-process (mirrors _run_llm_scan).

    Returns None on success, or a human-readable error string when the MCP
    scan could not run (scanner unavailable, timeout, or — most commonly — the
    target failed the MCP handshake because it isn't an MCP server). The caller
    surfaces this as a failed scan instead of grading an unreachable target A."""
    import pencheff.server as srv
    fn = getattr(srv, "scan_mcp", None)
    if fn is None:
        log.warning("pencheff scan_mcp tool unavailable for scan %s", scan_id)
        return "MCP scanner is unavailable on this deployment."
    _timeout_s = {
        "quick":    600.0,
        "standard": 1800.0,
        "deep":     7200.0,
    }.get(profile, 1200.0)
    try:
        await asyncio.wait_for(
            fn(session_id=psession.id, mcp_config=psession.mcp_config),
            timeout=_timeout_s,
        )
        return None
    except asyncio.TimeoutError:
        log.warning("scan_mcp timed out for scan %s", scan_id)
        return f"MCP scan timed out after {_timeout_s:.0f}s."
    except Exception as e:  # noqa: BLE001
        log.warning("scan_mcp failed for scan %s: %s", scan_id, e)
        return f"Could not scan the MCP target: {e}"


async def _run_rag_scan(
    *,
    scan_id: str,
    psession: Any,
    profile: str,
    db_session_factory: async_sessionmaker,
) -> None:
    """Invoke the pencheff scan_rag tool in-process (mirrors _run_mcp_scan)."""
    import pencheff.server as srv
    fn = getattr(srv, "scan_rag", None)
    if fn is None:
        log.warning("pencheff scan_rag tool unavailable for scan %s", scan_id)
        return
    _timeout_s = {
        "quick":    600.0,
        "standard": 1800.0,
        "deep":     7200.0,
    }.get(profile, 1200.0)
    try:
        await asyncio.wait_for(
            fn(session_id=psession.id, rag_config=psession.rag_config),
            timeout=_timeout_s,
        )
    except asyncio.TimeoutError:
        log.warning("scan_rag timed out for scan %s", scan_id)
    except Exception as e:  # noqa: BLE001
        log.warning("scan_rag failed for scan %s: %s", scan_id, e)


async def _run_ml_scan(
    *,
    scan_id: str,
    psession: Any,
    profile: str,
    db_session_factory: async_sessionmaker,
) -> None:
    """Invoke the pencheff scan_ml_model tool in-process (mirrors _run_rag_scan)."""
    import pencheff.server as srv
    fn = getattr(srv, "scan_ml_model", None)
    if fn is None:
        log.warning("pencheff scan_ml_model tool unavailable for scan %s", scan_id)
        return
    _timeout_s = {
        "quick":    600.0,
        "standard": 1800.0,
        "deep":     7200.0,
    }.get(profile, 1200.0)
    try:
        await asyncio.wait_for(
            fn(session_id=psession.id, ml_config=psession.ml_config),
            timeout=_timeout_s,
        )
    except asyncio.TimeoutError:
        log.warning("scan_ml_model timed out for scan %s", scan_id)
    except Exception as e:  # noqa: BLE001
        log.warning("scan_ml_model failed for scan %s: %s", scan_id, e)


async def _run_voice_scan(
    *,
    scan_id: str,
    psession: Any,
    profile: str,
    db_session_factory: async_sessionmaker,
) -> None:
    """Invoke the pencheff scan_voice tool in-process (mirrors _run_ml_scan)."""
    import pencheff.server as srv
    fn = getattr(srv, "scan_voice", None)
    if fn is None:
        log.warning("pencheff scan_voice tool unavailable for scan %s", scan_id)
        return
    _timeout_s = {
        "quick":    600.0,
        "standard": 1800.0,
        "deep":     7200.0,
    }.get(profile, 1200.0)
    try:
        await asyncio.wait_for(
            fn(session_id=psession.id, voice_config=psession.voice_config),
            timeout=_timeout_s,
        )
    except asyncio.TimeoutError:
        log.warning("scan_voice timed out for scan %s", scan_id)
    except Exception as e:  # noqa: BLE001
        log.warning("scan_voice failed for scan %s: %s", scan_id, e)


# Mobile & Client Security kinds (spec 002): pencheff tool name, download
# filename, and the path kwarg the tool expects. All static, no execution.
_CLIENT_ARTIFACT_TOOLS: dict[str, tuple[str, str, str]] = {
    "android_app":       ("scan_mobile_static", "app.apk", "apk_path"),
    "ios_app":           ("scan_mobile_static", "app.ipa", "ipa_path"),
    "browser_extension": ("scan_extension", "extension.crx", "extension_path"),
    "desktop_app":       ("scan_desktop", "app.bundle", "app_path"),
    "firmware":          ("scan_firmware", "firmware.bin", "firmware_path"),
    "iot_device":        ("scan_firmware", "firmware.bin", "firmware_path"),
    "ot_ics_scada":      ("scan_firmware", "firmware.bin", "firmware_path"),
}


async def _run_client_artifact_scan(
    *,
    scan_id: str,
    psession: Any,
    profile: str,
    kind: str,
    kind_config: dict,
    db_session_factory: async_sessionmaker,
) -> None:
    """Static analysis of an uploaded client artifact — Android APK, iOS IPA,
    browser extension (CRX/XPI), or desktop bundle (spec 002).

    Downloads the operator-registered ``file_url`` (sha256-verified) into the
    session working dir via the existing ``artifact_download`` verb, then runs
    the matching pencheff static tool over the local path. The artifact is
    NEVER executed (no device/emulator/sandbox). Mirrors ``_run_ml_scan``:
    fetch, scan statically, leave findings on the session for the caller to
    persist.
    """
    from urllib.parse import urlparse

    import pencheff.server as srv

    tool_spec = _CLIENT_ARTIFACT_TOOLS.get(kind)
    download = getattr(srv, "artifact_download", None)
    if tool_spec is None or download is None:
        log.warning("client-artifact scan %s: unsupported kind/tool (%s)", scan_id, kind)
        return
    tool_name, filename, path_kwarg = tool_spec
    scan_tool = getattr(srv, tool_name, None)
    if scan_tool is None:
        log.warning("pencheff %s tool unavailable for scan %s", tool_name, scan_id)
        return

    file_url = (kind_config or {}).get("file_url")
    sha256 = (kind_config or {}).get("sha256")
    if not file_url or not sha256:
        log.warning("client-artifact scan %s missing file_url/sha256", scan_id)
        return

    # Allow the operator-registered artifact host through artifact_download's
    # host guard (it reads allowed_hosts off the session's kind_config).
    set_cfg = getattr(srv, "set_kind_config_for_session", None)
    host = urlparse(str(file_url)).hostname or ""
    if set_cfg and host:
        # Preserve the real kind_config (esp. ``kind``) alongside the host
        # allowlist — scan_firmware reads ``kind`` off the session config to
        # pick the iot_device (Mirai) / ot_ics_scada (ICS) pass. Overwriting it
        # with only allowed_hosts made every artifact scan look like plain
        # 'firmware', so the kind-specific findings never ran.
        set_cfg(psession.id, {**(kind_config or {}), "kind": kind, "allowed_hosts": [host]})

    try:
        acquired = await asyncio.wait_for(
            download(session_id=psession.id, url=str(file_url), sha256=str(sha256), filename=filename),
            timeout=600.0,
        )
    except asyncio.TimeoutError:
        log.warning("client artifact download timed out for scan %s", scan_id)
        return
    except Exception as e:  # noqa: BLE001
        log.warning("client artifact download failed for scan %s: %s", scan_id, e)
        return
    if not isinstance(acquired, dict) or acquired.get("error") or not acquired.get("local_path"):
        log.warning("client artifact download refused/failed for scan %s: %s", scan_id, acquired)
        return

    _timeout_s = {"quick": 600.0, "standard": 1800.0, "deep": 7200.0}.get(profile, 1800.0)
    kwargs: dict[str, Any] = {path_kwarg: acquired["local_path"]}
    if kind == "android_app" and (kind_config or {}).get("use_mobsf"):
        kwargs["use_mobsf"] = True
    try:
        await asyncio.wait_for(
            scan_tool(session_id=psession.id, **kwargs),
            timeout=_timeout_s,
        )
    except asyncio.TimeoutError:
        log.warning("%s timed out for scan %s", tool_name, scan_id)
    except Exception as e:  # noqa: BLE001
        log.warning("%s failed for scan %s: %s", tool_name, scan_id, e)


async def _read_back_findings(
    scan_id: str,
    db_session_factory: async_sessionmaker,
) -> list:
    """Return the persisted DbFinding rows for a scan, in scan order."""
    async with db_session_factory() as db:
        rows = (
            await db.execute(
                select(DbFinding).where(DbFinding.scan_id == scan_id)
            )
        ).scalars().all()
    return list(rows)


async def _run_authenticated_crawl(
    *,
    scan_id: str,
    psession: Any,
    db_session_factory: async_sessionmaker,
) -> None:
    """Fire ``pencheff.server.authenticated_crawl`` so the Playwright login
    macro fills username/password, then extracts cookies + bearer tokens
    back into the session credentials for later stages."""
    import pencheff.server as srv

    async with db_session_factory() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        s.current_stage = "Authenticated login"
        _append_log(s, "stage_start: Authenticated login")
        await db.commit()
    publish_scan_event(
        scan_id,
        {
            "type": "stage_start",
            "stage": "authenticated_crawl",
            "label": "Authenticated login",
            "pct": 0,
        },
    )

    line: str
    try:
        # discover_first=True: crawl HTTP routes BEFORE attempting login,
        # then pick the highest-scoring login-shaped URL among them. Beats
        # the static 14-path probe on real-world targets where login lives
        # at a path nobody guessed.
        result = await srv.authenticated_crawl(
            session_id=psession.id, discover_first=True,
        )
        authed = bool(result.get("authenticated"))
        # Surface what the crawl found in the scan log so the UI explains
        # *why* auth picked the URL it did (or why it fell back).
        disc = result.get("discovery") or {}
        if disc.get("crawled_endpoints") is not None:
            chosen = disc.get("discovered_login_url") or "(none — fell back to static probe list)"
            async with db_session_factory() as db:
                s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
                _append_log(
                    s,
                    f"crawl: {disc['crawled_endpoints']} useful route(s); "
                    f"login candidate: {chosen}"
                )
                await db.commit()
        if authed:
            line = "stage_done: Authenticated login (session established)"
        else:
            # Pull the most recent failure detail off the in-session
            # findings so the log line tells the user what to fix
            # (otherwise they have to dig into the scan's findings list).
            hint = ""
            try:
                fdb = getattr(psession, "findings", None)
                items = []
                if fdb is not None:
                    if hasattr(fdb, "get_all"):
                        items = list(fdb.get_all())
                    elif hasattr(fdb, "findings"):
                        items = list(fdb.findings)
                for f in reversed(items):
                    if "Login Macro" in (getattr(f, "title", "") or ""):
                        # Take just the URL + what happened — full
                        # diagnostic lives in the finding itself.
                        desc = (getattr(f, "description", "") or "")
                        for marker in (
                            "Final URL", "Password field after submit",
                            "click_first ✗", "fill_first ✗", "wait_for `",
                        ):
                            idx = desc.find(marker)
                            if idx >= 0:
                                snippet = desc[idx:idx + 140].replace("\n", " ")
                                hint = f" — {snippet}"
                                break
                        break
            except Exception:
                pass
            line = (
                "stage_done: Authenticated login (auto-login failed — "
                f"see HIGH-severity 'Login Macro Failed' finding for diagnostics{hint})"
            )
    except Exception as exc:  # noqa: BLE001 — never fail the scan on login hiccup
        log.warning("authenticated_crawl raised: %s", exc)
        line = f"stage_done: Authenticated login (error: {type(exc).__name__}: {exc})"[:300]

    async with db_session_factory() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        _append_log(s, line)
        await db.commit()
    publish_scan_event(
        scan_id,
        {"type": "stage_done", "stage": "authenticated_crawl", "label": line[:160]},
    )


# Maximum log lines persisted per scan. Dropping the oldest keeps the
# JSONB column bounded without affecting the live tail (which is what the
# UI shows). Generous because LLM red team scans now emit one log line
# per probe (up to ~250 in the deep profile) plus per-module start/done
# plus heartbeats — at the old 200-line cap, the early modules' lines
# would roll out before the user could see them.
_LOG_MAX = 1000


def _append_log(scan: Scan, entry: str) -> None:
    """Append a progress line to ``scan.log``. The caller commits."""
    current = list(scan.log or [])
    current.append(entry)
    if len(current) > _LOG_MAX:
        current = current[-_LOG_MAX:]
    scan.log = current


async def _log_milestone(scan_id: str, Session, text: str) -> None:
    """Persist a single progress milestone to scan.log (own commit) and stream it —
    for non-ai_scan_progress branches (static-artifact scans) that lack a live
    progress context. Never raises."""
    try:
        async with Session() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            _append_log(s, f"stage_progress: {text}")
            await db.commit()
        publish_scan_event(scan_id, {"type": "stage_progress", "label": f"stage_progress: {text}"})
    except Exception:  # noqa: BLE001
        pass


def _append_finding_trace(scan: Scan, tag: str, findings: list, *, limit: int = 50) -> None:
    """Append a per-finding trace (``[tag] → SEV: title``) so static-artifact scans
    (mobile/ml) show what they surfaced instead of a single 'finished' line.
    Findings are pencheff Finding OBJECTS here (attribute access). Caller commits."""
    _append_log(scan, f"[{tag}] {len(findings)} finding(s)" + ("" if findings else " — clean"))
    for f in findings[:limit]:
        sev = str(getattr(f, "severity", "?") or "?").upper()
        title = str(getattr(f, "title", "") or "")[:120]
        _append_log(scan, f"[{tag}] → {sev}: {title}")
    if len(findings) > limit:
        _append_log(scan, f"[{tag}] … {len(findings) - limit} more finding(s) (see register)")


# ---------------------------------------------------------------------------
# LLM — false-positive triage + executive grading
# ---------------------------------------------------------------------------


class _DbFindingProxy:
    """Thin read-only shim so ``services.grader.compute`` can consume the
    updated DB rows (with AI-applied suppressions) via the same attribute
    names it uses for in-memory pencheff findings."""

    __slots__ = ("severity", "suppressed")

    def __init__(self, row: DbFinding) -> None:
        self.severity = (row.severity or "info").lower()
        self.suppressed = bool(row.suppressed)


def _evidence_excerpt(row: DbFinding) -> str | None:
    """Short textual summary of the first evidence item for LLM context.

    We include response headers (content-type) and the first 400 chars of
    any response body snippet so the model can distinguish a real admin
    page from a SPA's client-side 404 (same HTTP 200, completely
    different body).
    """
    ev = row.evidence or []
    if not ev:
        return None
    first = ev[0] if isinstance(ev, list) else ev
    if not isinstance(first, dict):
        return None
    parts: list[str] = []
    if first.get("request_method") and first.get("request_url"):
        parts.append(f"{first['request_method']} {first['request_url']}")
    if first.get("response_status") is not None:
        parts.append(f"→ {first['response_status']}")

    headers = first.get("response_headers") or {}
    if isinstance(headers, dict):
        ctype = headers.get("content-type") or headers.get("Content-Type")
        if ctype:
            parts.append(f"content-type={ctype}")

    body = first.get("response_body_snippet")
    if body:
        parts.append(f"body: {str(body)[:400]}")
    elif first.get("description"):
        parts.append(str(first["description"])[:400])
    return " · ".join(p for p in parts if p)


_SPA_404_NEEDLES = (
    "404",
    "not found",
    "page does not exist",
    "does not exist or has been moved",
    "nothing to see here",
)


def _pre_filter_spa_404(rows: list[DbFinding]) -> list[str]:
    """Return DB ids of findings that look like SPA 404 false-positives.

    Heuristic: any ``Admin Path Accessible`` / sensitive-path finding where
    the first evidence either has no body (scanner only recorded HTTP
    status) or whose body clearly contains a "page not found" marker.
    These are auto-suppressed before the LLM call so the model can focus
    on higher-signal findings.
    """
    out: list[str] = []
    for row in rows:
        title = (row.title or "").lower()
        if not (
            "admin path" in title
            or "sensitive path" in title
            or "path accessible" in title
        ):
            continue
        evidence = row.evidence or []
        first = evidence[0] if isinstance(evidence, list) and evidence else None
        body = ""
        if isinstance(first, dict):
            body = (first.get("response_body_snippet") or "").lower()
        if not body:
            # Scanner only proved "HTTP 2xx". That's a SPA 404 on any
            # modern JS framework — not evidence of admin exposure.
            out.append(row.id)
            continue
        if any(needle in body for needle in _SPA_404_NEEDLES):
            out.append(row.id)
    return out


def _row_to_finding_input(row: DbFinding) -> FindingInput:
    return FindingInput(
        id=row.id,
        title=row.title,
        severity=(row.severity or "info").lower(),
        category=row.category or "",
        endpoint=row.endpoint,
        parameter=row.parameter,
        description=row.description,
        evidence_excerpt=_evidence_excerpt(row),
        cvss_score=row.cvss_score,
    )


async def _rule_based_triage(
    *,
    scan_id: str,
    db_session_factory: async_sessionmaker,
) -> None:
    """Suppress obvious false positives via cheap deterministic rules.

    Currently catches the SPA-404 admin-path class, where a single-page app
    serves index.html with HTTP 200 for every path and the scanner's
    status-only heuristic misfires. Runs for every plan."""
    async with db_session_factory() as db:
        rows: list[DbFinding] = (
            await db.execute(
                select(DbFinding).where(
                    DbFinding.scan_id == scan_id,
                    DbFinding.suppressed.is_(False),
                )
            )
        ).scalars().all()

    if not rows:
        return

    auto_suppressed_ids = _pre_filter_spa_404(rows)
    if not auto_suppressed_ids:
        return

    log.info(
        "rule-based triage suppressing %d/%d findings as SPA-404 false positive",
        len(auto_suppressed_ids),
        len(rows),
    )
    async with db_session_factory() as db:
        fresh = (
            await db.execute(
                select(DbFinding).where(
                    DbFinding.scan_id == scan_id,
                    DbFinding.id.in_(auto_suppressed_ids),
                )
            )
        ).scalars().all()
        for row in fresh:
            row.suppressed = True
            row.suppress_reason = "rule_based_false_positive"
            row.suppress_notes = (
                "[rule: spa-404] Admin-path probe matched a Single-Page "
                "Application 404 response (HTTP 2xx with no admin "
                "content or explicit \"Not Found\" text). This is the "
                "scanner's HTTP-status-only heuristic misfiring on SPAs."
            )[:2000]
            row.verification_status = "false_positive"
        await db.commit()


async def _llm_triage(
    *,
    scan_id: str,
    org_id: str,
    db_session_factory: async_sessionmaker,
    ai_enabled: bool = True,
) -> None:
    """Pro+ only: send still-unsuppressed findings to the LLM for nuanced
    false-positive classification.

    ``ai_enabled`` is the runner's resolved AI signal — it already folds in
    the operator's per-scan AI toggle and the monthly quota cap. When False
    we skip the model entirely, so 'disable AI' (and the over-quota fallback)
    truly fire no LLM calls during a scan."""
    if not ai_enabled:
        # Even when the plan gate says "no AI", a BYO client bypasses it.
        # Resolve once here; if absent we exit immediately.
        async with db_session_factory() as db:
            org_llm = await resolve_chat_client(org_id, db)
        if org_llm is None:
            return
    else:
        org_llm = None  # resolved below after the plan check

    async with db_session_factory() as db:
        # BYO bypasses the plan gate; non-BYO orgs still need the plan check.
        if org_llm is None and not await org_has_ai(db, org_id):
            return
        rows: list[DbFinding] = (
            await db.execute(
                select(DbFinding).where(
                    DbFinding.scan_id == scan_id,
                    DbFinding.suppressed.is_(False),
                )
            )
        ).scalars().all()
        # Resolve BYO for ai_enabled orgs (not yet resolved above).
        if org_llm is None:
            org_llm = await resolve_chat_client(org_id, db)

    if not rows:
        return

    client = get_llm_client()
    # Inject the BYO provider when present; _chat routes through it (fail-closed).
    if org_llm is not None:
        client.set_org_client(org_llm)
    elif not client.enabled:
        return

    inputs = [_row_to_finding_input(r) for r in rows]
    try:
        # Offload the blocking HTTP calls to a worker thread so we don't
        # starve the event loop.
        verdicts = await asyncio.to_thread(client.classify_findings, inputs)
    except Exception as exc:  # never let an LLM hiccup fail a scan
        log.exception("LLM triage failed: %s", exc)
        return

    if not verdicts:
        return

    # Severity ceiling for auto-suppression. Anything medium / high /
    # critical stays visible even if the triage LLM is confident it's a
    # false positive — those issues affect material security posture and
    # should be reviewed by a human, not silently hidden. The LLM verdict
    # for those still gets recorded as ``verification_status`` so an
    # operator can still see what the model thought without losing the
    # finding from the active list.
    _AUTO_SUPPRESS_SEVERITIES = {"info", "low"}
    _MIN_CONFIDENCE = 0.85  # was 0.7 — too liberal, killed real misconfigs

    sev_by_id: dict[str, str] = {
        r.id: (r.severity or "info").lower() for r in rows
    }

    suppressed_ids: list[str] = []
    annotated_ids: list[str] = []
    for v_id, verdict in verdicts.items():
        if not verdict.is_false_positive or verdict.confidence < _MIN_CONFIDENCE:
            continue
        if sev_by_id.get(v_id, "info") in _AUTO_SUPPRESS_SEVERITIES:
            suppressed_ids.append(v_id)
        else:
            # Medium+ severity — record the LLM's "FP" verdict on the row
            # but do NOT hide it. Operator decides.
            annotated_ids.append(v_id)

    if not suppressed_ids and not annotated_ids:
        log.info("LLM triage kept all %d findings", len(rows))
        return

    log.info(
        "LLM triage: %d/%d auto-suppressed (info+low FP), %d/%d annotated FP-only (medium+ kept visible)",
        len(suppressed_ids), len(rows),
        len(annotated_ids), len(rows),
    )

    target_ids = suppressed_ids + annotated_ids
    async with db_session_factory() as db:
        fresh = (
            await db.execute(
                select(DbFinding).where(
                    DbFinding.scan_id == scan_id,
                    DbFinding.id.in_(target_ids),
                )
            )
        ).scalars().all()
        for row in fresh:
            verdict = verdicts.get(row.id)
            if not verdict:
                continue
            note = (
                f"[{client.label} · confidence {verdict.confidence:.0%}] "
                f"{verdict.reason}"
            )[:2000]
            if row.id in suppressed_ids:
                row.suppressed = True
                row.suppress_reason = "ai_false_positive"
                row.suppress_notes = note
                row.verification_status = "false_positive"
            else:
                # Medium+ — keep visible, just tag the verdict.
                row.verification_status = "false_positive"
                row.suppress_notes = (
                    "Triage flagged as likely FP but kept visible due to "
                    f"severity ≥ medium. {note}"
                )[:2000]
        await db.commit()


async def _maybe_ai_grade(
    *,
    target_url: str,
    org_id: str,
    db_session_factory: async_sessionmaker,
    db_rows: list[DbFinding],
    severity_counts: dict[str, int],
):
    """Best-effort LLM grading. Returns ``GradeVerdict | None``."""
    client = get_llm_client()
    # Resolve the org's BYO provider; when set, grading routes through it
    # (fail-closed — a provider error yields None, never Pencheff's key).
    async with db_session_factory() as db:
        org_llm = await resolve_chat_client(org_id, db)
    if org_llm is not None:
        client.set_org_client(org_llm)
    elif not client.enabled:
        return None

    kept = [
        _row_to_finding_input(r)
        for r in db_rows
        if not r.suppressed
    ]

    def _do_grade():
        return client.grade_assessment(
            target_url=target_url,
            kept_findings=kept,
            severity_counts=severity_counts,
        )

    try:
        # Offload the blocking HTTP call to a worker thread (mirrors
        # _llm_triage) so we don't starve the event loop.
        return await asyncio.to_thread(_do_grade)
    except Exception as exc:
        log.exception("LLM grading failed: %s", exc)
        return None


# ============================================================================
# Load testing (profile="load") — kind-aware load generation
# ============================================================================

def _load_grade(report) -> str:
    """Coarse perf letter grade from error rate + p95 latency.

    Agentic reports (breaking_point/threshold_results/stages populated by the
    orchestrator's SLA ladder) are graded off the breaking point instead —
    simple-mode reports never populate those fields, so this is a safe gate.
    """
    bp = getattr(report, "breaking_point", None)
    thr = getattr(report, "threshold_results", None)
    if bp is not None or thr or getattr(report, "stages", None):
        if bp is None:
            return "A"  # held SLA through the whole ladder
        # Grade on the REAL load-failure rate (5xx/timeouts/429) when present,
        # so benign 4xx (auth/not-found/CDN blocks) don't tank the grade.
        er = float(
            (bp or {}).get("load_error_rate")
            if (bp or {}).get("load_error_rate") is not None
            else (bp or {}).get("error_rate") or 0.0
        )
        if er >= 0.10:
            return "F"
        if er >= 0.02:
            return "D"
        return "C"  # broke on latency only
    er = report.error_rate
    p95 = report.latency_ms.get("p95", 0.0)
    if er >= 0.10 or p95 >= 3000:
        return "F"
    if er >= 0.05 or p95 >= 1500:
        return "D"
    if er >= 0.02 or p95 >= 800:
        return "C"
    if er >= 0.005 or p95 >= 300:
        return "B"
    return "A"


async def _run_load_scan(scan_id: str, target: Target, Session) -> None:
    """Run a kind-aware load test and store the report on Scan.summary.

    Config comes from Scan.kind_payload['load_test'] when present (bounded),
    else per-kind defaults. Read-only requests only; DoS-adjacent so all limits
    are hard-clamped in LoadTestConfig.clamped()."""
    from ..schemas.load_test import DEFAULT_LOAD_CONFIG, LoadTestConfig
    from .load_test import run_load_test

    cfg = DEFAULT_LOAD_CONFIG
    async with Session() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        raw = (s.kind_payload or {}).get("load_test") if s.kind_payload else None
        if isinstance(raw, dict):
            try:
                cfg = LoadTestConfig(**raw)
            except Exception:  # noqa: BLE001 — fall back to defaults on bad input
                cfg = DEFAULT_LOAD_CONFIG
        cfg = cfg.clamped()
        if cfg.mode == "agentic":
            _append_log(
                s,
                f"agentic load test starting: kind={target.kind} · AI "
                f"performance-engineer authoring an adaptive scenario "
                f"(≤{cfg.max_stages} stages, ≤{cfg.concurrency} VUs, "
                f"{cfg.profile_shape} profile)",
            )
        else:
            _append_log(
                s,
                f"load test starting: kind={target.kind} · {cfg.concurrency} VUs · "
                f"{cfg.duration_s}s"
                + (f" · target {cfg.target_rps} rps" if cfg.target_rps else ""),
            )
        await db.commit()

    report = None
    err: str | None = None
    try:
        report = await run_load_test(target, cfg)
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
        log.exception("load test failed for scan %s", scan_id)

    async with Session() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        if report is None:
            s.status = "failed"
            s.error = (err or "load test failed")[:1000]
        elif not report.ok:
            s.status = "failed"
            s.error = (report.error or "load test not applicable")[:1000]
            s.summary = {**(s.summary or {}), "load_report": report.model_dump()}
        else:
            s.summary = {**(s.summary or {}), "load_report": report.model_dump()}
            s.grade = _load_grade(report)
            s.status = "done"
            if report.stages:
                # Agentic run — surface the AI performance-engineer's work so the
                # assessment log reflects that the agent actually ran.
                personas = (report.extra or {}).get("personas") or []
                _append_log(
                    s,
                    f"AI agent authored & ran an adaptive load ladder · "
                    f"{len(report.stages)} stage(s) executed"
                    + (f" · personas: {', '.join(map(str, personas))}"
                       if personas else ""),
                )
                _ep_t = (report.extra or {}).get("endpoints_tested")
                _ep_d = (report.extra or {}).get("endpoints_discovered")
                if _ep_d:
                    _append_log(
                        s,
                        f"  endpoint pre-flight: load-testing {_ep_t}/{_ep_d} "
                        f"endpoints that return 2xx under auth (dropped the rest — "
                        f"they need a resource id, query params, or elevated scope)",
                    )
                for i, st in enumerate(report.stages, 1):
                    sb = st.get("status_buckets") or {}
                    bd = " ".join(f"{k}={v}" for k, v in sb.items() if v)
                    _append_log(
                        s,
                        f"  stage {i}: {st.get('vus')} VUs → "
                        f"{st.get('total_requests', 0)} reqs · "
                        f"{round(st.get('rps', 0), 1)} rps · "
                        f"p95 {round(st.get('p95_ms', 0))}ms · "
                        f"{st.get('load_error_rate', 0) * 100:.1f}% load-err "
                        f"({st.get('error_rate', 0) * 100:.1f}% non-2xx"
                        + (f"; {bd}" if bd else "") + ") · "
                        f"SLA {'PASS' if st.get('sla_hold') else 'BREACH'}",
                    )
                bp = report.breaking_point
                if bp:
                    _append_log(
                        s,
                        f"breaking point: {bp.get('vus')} VUs "
                        f"(load errors "
                        f"{(bp.get('load_error_rate') or bp.get('error_rate') or 0) * 100:.1f}%, "
                        f"p95 {round(bp.get('p95_ms') or 0)}ms)",
                    )
                else:
                    _append_log(
                        s, "held SLA through the full ladder — no breaking point"
                    )
                if report.agent_narrative:
                    _append_log(s, f"verdict: {report.agent_narrative[:220]}")
                if report.cost_cents:
                    _append_log(s, f"agent cost: ${report.cost_cents / 100:.2f}")
            else:
                _append_log(
                    s,
                    f"load test done: {report.total_requests} reqs · "
                    f"{report.rps} rps · p95 {report.latency_ms.get('p95')}ms · "
                    f"{report.error_rate * 100:.1f}% errors",
                )
        s.finished_at = datetime.now(timezone.utc)
        await db.commit()
    publish_scan_event(scan_id, {"type": "finished", "scan_id": scan_id})


# ============================================================================
# Feature 001 — multi-target-scan-pipelines kind-aware dispatch
# ============================================================================

async def _run_kind_aware_scan(scan_id: str, target: Target, Session) -> None:
    """Dispatch the 10 new non-legacy non-source_code kinds to their pipeline.

    Decrypts ``target.kind_credentials_encrypted`` (when present) and passes the
    plaintext blob to the orchestrator, which binds it to the pencheff session
    via ``set_kind_credentials_for_session`` for the lifetime of the scan.

    Routes by cluster:
      * DAST cluster (web_app, rest_api, graphql, websocket, grpc) →
        existing agent_swarm.run_swarm with kind-filtered breaker roster.
      * Artifact cluster (container_image, iac, package_registry, sbom) →
        services.agent_swarm.artifact_orchestrator.run_artifact_orchestrator.
      * Hybrid cluster (cicd_pipeline, k8s_cluster) →
        services.agent_swarm.hybrid_orchestrator.run_hybrid_orchestrator.

    source_code is handled inside repo_scan_task (uses RepoScan table).
    Legacy url/repo/llm kinds reach the existing pipeline below in run_scan.

    Until per-cluster scanner wrappers fully land, this raises NotImplementedError
    with a clear, structured error so the scan rows mark themselves failed with
    a useful message rather than spinning silently. Per-kind implementations
    layer on top of this scaffold by replacing each branch with a real call.
    """
    kind = target.kind
    _DAST_KINDS = {"web_app", "rest_api", "graphql", "websocket", "grpc"}
    # source_code reaches this branch when registered via API as a kind=source_code
    # Target (the legacy /repos/github flow still creates kind=repo mirror rows
    # handled by repo_scan_task).
    _ARTIFACT_KINDS = {"source_code", "container_image", "iac", "package_registry", "sbom"}
    _HYBRID_KINDS = {"cicd_pipeline", "k8s_cluster"}
    _CLOUD_KINDS = {
        "cloud_account", "serverless_function", "cloud_storage",
        "load_balancer_cdn", "cloud_database", "secrets_manager",
    }

    if kind in _DAST_KINDS:
        # DAST cluster — reuses existing agent_swarm. M1+ wires per-kind
        # breaker filter via KIND_TO_BREAKER_NAMES in breakers.py.
        raise NotImplementedError(
            f"DAST cluster pipeline for kind={kind!r} is scaffolded but not yet "
            f"wired to agent_swarm. Tracking: spec §6.1, plan.md M1 US-1 and M2 US-2."
        )
    # Decrypt kind_credentials once (when present) so the orchestrators don't
    # each repeat the Fernet step. The plaintext blob lives only in memory
    # for the duration of this coroutine and the orchestrator's finally block.
    kind_creds: dict | None = None
    if getattr(target, "kind_credentials_encrypted", None):
        kind_creds = decrypt_credentials(target.kind_credentials_encrypted)

    # GitHub App fallback for cicd_pipeline Phase B: if the operator enabled
    # live probing but attached no PAT, mint a short-lived installation token
    # from the platform's GitHub App (works wherever the App is installed).
    # Removes the PAT-only limitation; PAT still wins when present.
    if kind == "cicd_pipeline":
        _cfg = target.kind_config or {}
        if (_cfg.get("provider") == "github_actions" and _cfg.get("live_api_enabled")
                and not (kind_creds or {}).get("token")):
            from .github_app import token_for_repo, is_configured
            if is_configured():
                from urllib.parse import urlparse
                _parts = (urlparse(_cfg.get("repo_url", "")).path or "").strip("/").split("/")
                if len(_parts) >= 2:
                    try:
                        _tok = await token_for_repo(_parts[0], _parts[1].removesuffix(".git"))
                    except Exception:  # noqa: BLE001 — App auth is best-effort; fall through to no-token
                        _tok = None
                    if _tok:
                        kind_creds = {**(kind_creds or {}), "kind": "cicd_pipeline",
                                      "provider": "github_actions", "token": _tok}

    if kind in _ARTIFACT_KINDS:
        from .agent_swarm.artifact_orchestrator import run_artifact_orchestrator
        await run_artifact_orchestrator(
            scan_id=scan_id, target=target, Session=Session, kind_credentials=kind_creds,
        )
        return
    if kind in _HYBRID_KINDS:
        from .agent_swarm.hybrid_orchestrator import run_hybrid_orchestrator
        await run_hybrid_orchestrator(
            scan_id=scan_id, target=target, Session=Session, kind_credentials=kind_creds,
        )
        return
    if kind in _CLOUD_KINDS:
        from .agent_swarm.cloud_orchestrator import run_cloud_orchestrator
        await run_cloud_orchestrator(
            scan_id=scan_id, target=target, Session=Session, kind_credentials=kind_creds,
        )
        return

    if kind == "host":
        from .agent_swarm.host_orchestrator import run_host_orchestrator
        await run_host_orchestrator(
            scan_id=scan_id, target=target, Session=Session, kind_credentials=kind_creds,
        )
        return

    from .agent_swarm.network_orchestrator import NETWORK_KINDS
    if kind in NETWORK_KINDS:
        from .agent_swarm.network_orchestrator import run_network_orchestrator
        await run_network_orchestrator(
            scan_id=scan_id, target=target, Session=Session, kind_credentials=kind_creds,
        )
        return

    from .agent_swarm.identity_data_orchestrator import IDENTITY_DATA_KINDS
    if kind in IDENTITY_DATA_KINDS:
        from .agent_swarm.identity_data_orchestrator import run_identity_data_orchestrator
        await run_identity_data_orchestrator(
            scan_id=scan_id, target=target, Session=Session, kind_credentials=kind_creds,
        )
        return

    raise ValueError(f"_run_kind_aware_scan called with unsupported kind={kind!r}")
