"""Pentest session state management."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pencheff.config import TestDepth
from pencheff.core.credentials import CredentialStore
from pencheff.core.findings import FindingsDB


@dataclass
class RequestRecord:
    """Audit trail entry for an HTTP request."""

    method: str
    url: str
    status: int | None
    timestamp: datetime
    module: str
    duration_ms: float = 0.0


@dataclass
class TargetInfo:
    """Information about the pentest target."""

    base_url: str
    scope: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    # Set by ``pencheff.core.spa_detector.establish_spa_fingerprint`` once at
    # scan start. ``None`` means the target serves proper 404s (or the
    # probe failed) and brute-force modules should treat every 200 as real.
    fallback_signature: Any | None = None


@dataclass
class AttachedRepo:
    """A source repository attached to a URL pentest for parallel SAST coverage."""

    path: str                          # absolute local path to the working tree
    origin: str                        # original input — local path or git URL
    name: str                          # short label used in finding endpoints / status keys
    branch: str | None = None
    cloned: bool = False               # True when pencheff cloned it (drives cleanup)
    attached_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "origin": self.origin,
            "branch": self.branch,
            "cloned": self.cloned,
            "attached_at": self.attached_at.isoformat(),
        }


@dataclass
class DiscoveredState:
    """Dynamic state discovered during testing."""

    endpoints: list[dict[str, Any]] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    tech_stack: dict[str, list[str]] = field(default_factory=dict)
    api_specs: list[dict[str, Any]] = field(default_factory=list)
    completed_modules: list[str] = field(default_factory=list)
    running_module: str | None = None
    # Advanced discovery state
    websocket_endpoints: list[dict[str, Any]] = field(default_factory=list)
    oauth_endpoints: list[dict[str, Any]] = field(default_factory=list)
    waf_detected: dict[str, Any] = field(default_factory=dict)
    exploit_chains: list[dict[str, Any]] = field(default_factory=list)
    cname_records: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PentestSession:
    """Central state object for a penetration test."""

    id: str
    target: TargetInfo
    credentials: CredentialStore
    depth: TestDepth
    findings: FindingsDB
    discovered: DiscoveredState
    request_log: list[RequestRecord] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # LLM red-team targets carry a non-secret config dict here
    # (provider, model, system prompt baseline, custom request
    # template, response JSONPath). Empty / None for url/repo
    # sessions; the llm_red_team modules require it.
    llm_config: dict[str, Any] | None = None
    # MCP / AI-agent targets carry their connection + probe config here.
    # Empty / None for all other session kinds.
    mcp_config: dict[str, Any] | None = None
    # RAG / vector-DB targets carry their connection + probe config here.
    # Empty / None for all other session kinds.
    rag_config: dict[str, Any] | None = None
    # ML-model targets carry their MlModelConfig dict here (source_type,
    # url/hf_repo/local_path, ...). Empty / None for all other session kinds.
    ml_config: dict[str, Any] | None = None
    # Voice / speech-AI targets carry their VoiceConfig dict here (source_type,
    # url, audio_format, ...). Empty / None for all other session kinds.
    voice_config: dict[str, Any] | None = None
    # Repos attached for parallel SAST coverage. Each entry tracks
    # local path, origin (path or git URL), and whether pencheff cloned it.
    attached_repos: list[AttachedRepo] = field(default_factory=list)
    # Per-repo SAST task state. Shape per key (repo name):
    # {"status": "pending|running|done|error", "started_at": iso,
    #  "finished_at": iso|None, "finding_count": int, "tools_run": [..],
    #  "tools_skipped": [..], "error": str|None}
    sast_task_state: dict[str, dict[str, Any]] = field(default_factory=dict)

    # ── Agent-swarm orchestrator state ─────────────────────────────────
    # Injected auth cookies: list of (name, value) tuples.
    auth_cookies: list[tuple[str, str]] = field(default_factory=list)
    # Injected bearer/API tokens: {"bearer": "...", "api_key": "..."} etc.
    auth_tokens: dict[str, str] = field(default_factory=dict)
    # True once set_auth_state has been called with cookies or tokens.
    authenticated: bool = False
    # OAST handle re-used from the master session (set by attach_oast).
    oast_handle: str | None = None
    # Remote-MCP webapp sync state (see core.webapp_sync).
    webapp_scan_id: str | None = None
    _last_synced_sig: str | None = None

    def log_request(self, method: str, url: str, status: int | None, module: str, duration_ms: float = 0.0):
        self.request_log.append(RequestRecord(
            method=method, url=url, status=status,
            timestamp=datetime.now(timezone.utc),
            module=module, duration_ms=duration_ms,
        ))

    def status_summary(self) -> dict[str, Any]:
        return {
            "session_id": self.id,
            "target": self.target.base_url,
            "depth": self.depth.value,
            "credentials": self.credentials.count,
            "endpoints_discovered": len(self.discovered.endpoints),
            "subdomains_discovered": len(self.discovered.subdomains),
            "open_ports": len(self.discovered.open_ports),
            "tech_stack": self.discovered.tech_stack,
            "completed_modules": self.discovered.completed_modules,
            "running_module": self.discovered.running_module,
            "findings": self.findings.summary(),
            "total_findings": self.findings.count,
            "total_requests": len(self.request_log),
            "websocket_endpoints": len(self.discovered.websocket_endpoints),
            "oauth_endpoints": len(self.discovered.oauth_endpoints),
            "waf_detected": self.discovered.waf_detected or None,
            "exploit_chains": len(self.discovered.exploit_chains),
            "attached_repos": [r.to_dict() for r in self.attached_repos],
            "sast_status": dict(self.sast_task_state),
        }


# In-process session store (one per MCP client session)
_sessions: dict[str, PentestSession] = {}


def create_session(
    target_url: str,
    credentials: dict[str, Any] | None = None,
    scope: list[str] | None = None,
    exclude_paths: list[str] | None = None,
    depth: str = "standard",
    llm_config: dict[str, Any] | None = None,
    mcp_config: dict[str, Any] | None = None,
    rag_config: dict[str, Any] | None = None,
    ml_config: dict[str, Any] | None = None,
    voice_config: dict[str, Any] | None = None,
) -> PentestSession:
    session_id = uuid.uuid4().hex[:12]
    cred_store = CredentialStore()
    if credentials:
        cred_store.add_from_dict("default", credentials)

    target = TargetInfo(
        base_url=target_url.rstrip("/"),
        scope=scope or [target_url],
        exclude_paths=exclude_paths or [],
    )

    session = PentestSession(
        id=session_id,
        target=target,
        credentials=cred_store,
        depth=TestDepth(depth),
        findings=FindingsDB(),
        discovered=DiscoveredState(),
        llm_config=llm_config,
        mcp_config=mcp_config,
        rag_config=rag_config,
        ml_config=ml_config,
        voice_config=voice_config,
    )
    _sessions[session_id] = session
    return session


def get_session(session_id: str) -> PentestSession | None:
    return _sessions.get(session_id)
