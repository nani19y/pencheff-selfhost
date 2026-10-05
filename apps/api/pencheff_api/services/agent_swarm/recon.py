"""Phase 1 — ReconAgent runs against the master session and produces
a frozen ReconSnapshot for the breaker fan-out."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...config import get_settings
from .agent_loop import Agent, _run_single_agent, _TransientLLMError, LogSink
from .prompts import build_recon_prompt
from .snapshot import (
    DiscoveredEndpoint, ReconFailed, ReconSnapshot,
)
from .tools import recon_tools, select_tools


def _recon_budget(profile: str) -> int:
    s = get_settings()
    return {
        "quick": s.swarm_turns_recon_quick,
        "standard": s.swarm_turns_recon_standard,
        "deep": s.swarm_turns_recon_deep,
    }.get(profile, s.swarm_turns_recon_standard)


async def run_recon_phase(
    *,
    master_session_id: str,
    target_url: str,
    credentials: dict[str, Any] | None,
    profile: str,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    on_event: LogSink,
    scan_id: str | None = None,
    db_session_factory: Any = None,
    llm_override: tuple[str, str, str] | None = None,
) -> ReconSnapshot:
    """Run ReconAgent and freeze its output into a ReconSnapshot.

    Raises ReconFailed if the agent crashed or produced an empty surface.
    """
    agent = Agent(
        name="ReconAgent",
        system_prompt=build_recon_prompt(),
        tools=select_tools(profile, recon_tools()),
        max_turns=_recon_budget(profile),
    )
    settings = get_settings()
    max_attempts = 1 + max(0, settings.swarm_breaker_retry_attempts)
    last_transient_exc: Exception | None = None
    outcome = None

    for attempt in range(max_attempts):
        try:
            outcome = await _run_single_agent(
                agent=agent,
                session_id=master_session_id,
                target_url=target_url,
                credentials=credentials,
                profile=profile,
                scope=scope,
                exclude_paths=exclude_paths,
                on_event=on_event,
                session_prepopulated=False,
                scan_id=scan_id,
                db_session_factory=db_session_factory,
                llm_override=llm_override,
            )
            break  # success
        except _TransientLLMError as exc:
            last_transient_exc = exc
            if attempt < max_attempts - 1:
                await on_event(
                    f"recon hit transient error ({exc}); retrying once"
                )
                continue
            # Retry exhausted — fall through to graceful-degrade check.
            await on_event(
                f"recon transient retry exhausted ({exc}); "
                "checking session for partial discovery"
            )
            break
        except Exception as exc:
            # Non-transient error — propagate as ReconFailed (no degradation).
            raise ReconFailed(f"recon agent crashed: {exc}") from exc

    # If outcome is None, recon never produced an AgentOutcome. We can
    # still degrade if the master session has at least one endpoint
    # (some recon tools persist results before _run_single_agent returns).
    try:
        snapshot = await _freeze_snapshot(
            master_session_id=master_session_id,
            target_url=target_url,
            profile=profile,
            scope=scope,
            exclude_paths=exclude_paths,
            recon_summary=(
                outcome.summary if outcome else
                f"recon partial (transient error: {last_transient_exc})"
            ),
        )
    except ReconFailed:
        # No endpoints — propagate the original transient context if there was one.
        if last_transient_exc is not None:
            raise ReconFailed(
                f"recon agent crashed: {last_transient_exc}"
            ) from last_transient_exc
        raise

    # If outcome is None or had zero tool calls but the session DOES have
    # endpoints, we still proceed — the populator may have pre-seeded the
    # discovery. Only fall back if BOTH outcome was missing/empty AND the
    # snapshot somehow ended up empty (handled by _freeze_snapshot above).
    return snapshot


async def _freeze_snapshot(
    *,
    master_session_id: str,
    target_url: str,
    profile: str,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    recon_summary: str,
) -> ReconSnapshot:
    """Read pencheff session state into the frozen ReconSnapshot.

    Attribute paths confirmed from session.py (C2, commit 216bd7a):

    Top-level on PentestSession:
      - s.auth_cookies        list[tuple[str, str]]
      - s.auth_tokens         dict[str, str]
      - s.authenticated       bool
      - s.oast_handle         str | None

    Via s.discovered (DiscoveredState):
      - s.discovered.endpoints        list[dict]
      - s.discovered.subdomains       list[str]
      - s.discovered.tech_stack       dict[str, list[str]]
      - s.discovered.api_specs        list[dict]
      - s.discovered.waf_detected     dict[str, Any]

    Fields with no matching session attribute (robots_txt, sitemap_urls,
    security_txt, auth_login_url) are left as None / empty.
    """
    from pencheff.core.session import get_session as _gsess

    sess = _gsess(master_session_id)
    if sess is None:
        raise ReconFailed("master session vanished after recon")

    # ── Endpoints ────────────────────────────────────────────────────────
    endpoint_dicts = list(getattr(sess.discovered, "endpoints", ()) or ())
    eps: list[DiscoveredEndpoint] = []
    for ep in endpoint_dicts:
        eps.append(DiscoveredEndpoint(
            url=str(ep.get("url", "")),
            method=str(ep.get("method", "GET")),
            status=ep.get("status"),
            content_type=ep.get("content_type"),
            parameters=tuple(ep.get("parameters") or ()),
        ))
    if not eps:
        raise ReconFailed("recon produced zero endpoints")

    # ── Subdomains ───────────────────────────────────────────────────────
    # Stored on DiscoveredState, not top-level PentestSession.
    subdomains = tuple(getattr(sess.discovered, "subdomains", ()) or ())

    # ── Tech stack ───────────────────────────────────────────────────────
    # DiscoveredState.tech_stack is dict[str, list[str]].
    # ReconSnapshot.tech_stack is Mapping[str, str] — flatten each list.
    raw_tech: dict[str, list[str]] = dict(getattr(sess.discovered, "tech_stack", {}) or {})
    tech_stack: dict[str, str] = {
        k: ", ".join(v) if isinstance(v, list) else str(v)
        for k, v in raw_tech.items()
    }

    # ── WAF ──────────────────────────────────────────────────────────────
    # DiscoveredState.waf_detected is dict[str, Any]; pull "vendor" key.
    waf_detected: dict[str, Any] = dict(getattr(sess.discovered, "waf_detected", {}) or {})
    waf_vendor: str | None = waf_detected.get("vendor") or waf_detected.get("name") or None

    # ── API spec URLs ─────────────────────────────────────────────────────
    # DiscoveredState.api_specs is list[dict]; extract "url" from each.
    raw_specs: list[dict[str, Any]] = list(getattr(sess.discovered, "api_specs", ()) or ())
    api_spec_urls = tuple(
        str(s.get("url", "")) for s in raw_specs if s.get("url")
    )

    # ── Auth (top-level PentestSession fields) ────────────────────────────
    auth_cookies = tuple(
        (k, v) for k, v in (getattr(sess, "auth_cookies", ()) or ())
    )
    auth_tokens: dict[str, str] = dict(getattr(sess, "auth_tokens", {}) or {})
    authenticated: bool = bool(getattr(sess, "authenticated", False))

    # ── Findings IDs ─────────────────────────────────────────────────────
    finding_ids = tuple(f.id for f in sess.findings.get_all())

    # ── Operator kind_config ──────────────────────────────────────────────
    # Carried so per-breaker sessions can re-apply transport config (grpc
    # plaintext, graphql introspection, …) — the protocol tools read it via
    # _kind_config_for_session, which is per-session.
    kind_config: dict[str, Any] = {}
    try:
        from pencheff.artifact_tools import _kind_config_for_session
        kind_config = dict(_kind_config_for_session(master_session_id) or {})
    except Exception:  # noqa: BLE001 - best-effort
        pass

    return ReconSnapshot(
        target_base_url=target_url,
        profile=profile,  # type: ignore[arg-type]
        scope_include=tuple(scope or ()),
        scope_exclude=tuple(exclude_paths or ()),
        endpoints=tuple(eps),
        api_spec_urls=api_spec_urls,
        subdomains=subdomains,
        # No matching session attribute — default to None/empty.
        robots_txt=getattr(sess, "robots_txt", None),
        sitemap_urls=tuple(getattr(sess, "sitemap_urls", ()) or ()),
        security_txt=getattr(sess, "security_txt", None),
        tech_stack=tech_stack,
        waf_vendor=waf_vendor,
        authenticated=authenticated,
        auth_login_url=getattr(sess, "auth_login_url", None),
        auth_cookies=auth_cookies,
        auth_tokens=auth_tokens,
        oast_session_handle=getattr(sess, "oast_handle", None),
        recon_agent_summary=recon_summary,
        recon_findings_ids=finding_ids,
        snapshot_built_at=datetime.now(tz=timezone.utc),
        kind_config=kind_config,
    )
