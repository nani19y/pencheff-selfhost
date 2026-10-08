import os
from functools import lru_cache
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = "development"
    api_base_url: str = "http://localhost:8000"
    web_base_url: str = "http://localhost:3000"
    allowed_origins: list[str] = ["http://localhost:3000"]

    # Open-beta master switch. While True, the metered plan limits (monthly
    # scan cap and monthly AI-fix cap) are NOT enforced — every org runs
    # unmetered. Flip to False to turn on the free/pro caps defined in
    # services/quota.py (scans) and services/fix_quota.py (fixes).
    beta: bool = True

    database_url: str = "postgresql+asyncpg://pencheff:pencheff@localhost:5432/pencheff"
    redis_url: str = "redis://localhost:6379/0"

    # Heavy Celery worker lifecycle. Default preserves the current
    # self-hosted deployment where the worker is always running.
    worker_always_on: bool = Field(True, alias="WORKER_ALWAYS_ON")
    worker_idle_grace_seconds: int = Field(30, alias="WORKER_IDLE_GRACE_SECONDS")
    docker_socket_path: str = Field("/var/run/docker.sock", alias="DOCKER_SOCKET_PATH")
    worker_compose_project: str = Field("pencheff", alias="WORKER_COMPOSE_PROJECT")
    worker_compose_service: str = Field("worker", alias="WORKER_COMPOSE_SERVICE")
    worker_queue: str = Field("celery", alias="WORKER_QUEUE")
    source_upload_max_bytes: int = 100 * 1024 * 1024

    jwt_secret: str = Field(default="change-me-in-prod-please-change-me-32b!")
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 30

    # OIDC / Keycloak authentication. When enabled, browser/API requests must
    # carry a signed Bearer access token from this issuer. Authorization is
    # resolved from Keycloak realm/client roles and groups; Pencheff never
    # stores or receives the user's IDP password.
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""

    fernet_key: str = Field(default="")  # generate with Fernet.generate_key(); base64 url-safe 32 bytes

    # Triage / grading backend — used for false-positive filtering and
    # executive grading. Operator-supplied chat-completions endpoint.
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model: str = "MiniMaxAI/MiniMax-M2.7"
    llm_model_label: str = "MiniMax M2.7"  # display-only; used in UI
    llm_enabled: bool = True
    llm_request_timeout: float = 60.0
    llm_batch_size: int = 15
    # Optional OpenRouter attribution headers (ignored by other providers).
    llm_http_referer: str = "https://pencheff.local"
    llm_app_title: str = "Pencheff"

    # --- Agentic Fixer (OpenAI-compatible chat completions + tool use) ---
    # Drives the agentic Fix-all workflow modelled on Claude Code /
    # Cursor Agent mode. Defaults to Sarvam AI's sarvam-105b — the
    # same provider the scan-agent fallback already uses, so we know
    # function-calling works on this endpoint. Override via
    # AGENTIC_FIX_BASE_URL / AGENTIC_FIX_MODEL for any
    # OpenAI-compatible provider. Falls back to disabled when the key
    # is empty.
    agentic_fix_enabled: bool = True
    agentic_fix_api_key: str = ""  # bearer token for the chat-completions endpoint
    agentic_fix_base_url: str = ""
    agentic_fix_model: str = "sarvam-105b"
    agentic_fix_max_iterations: int = 60
    # Sarvam's starter tier caps max_tokens at 4096 for sarvam-105b
    # (DatatypeMismatchError above that). Operators on a higher tier
    # override via AGENTIC_FIX_MAX_TOKENS_PER_CALL.
    agentic_fix_max_tokens_per_call: int = 4096
    agentic_fix_request_timeout: float = 180.0
    # Per-1M-token prices (USD) for cost computation. Sarvam-105b
    # placeholder; replace with actual contract prices for accurate
    # billing. Operators using a different backend override these
    # via env to reflect that backend's prices.
    agentic_fix_price_input_per_1m_usd: float = 0.50
    agentic_fix_price_output_per_1m_usd: float = 1.50
    agentic_fix_price_cache_read_per_1m_usd: float = 0.05

    # --- Fix-proposal LLM (OpenAI-compatible) ---
    # Used by fix_proposer.py for every fix proposal — SAST + DAST,
    # all plans. Kept separate from the classify/grade LLM so the two
    # can be sized differently. Defaults to DeepSeek v4-flash via its
    # OpenAI-compatible chat-completions endpoint.
    fix_llm_api_key: str = ""
    fix_llm_base_url: str = ""
    # Default / fallback model. Kept for callers without plan context
    # (e.g. triage_llm). Per-plan fix routing uses the two fields below.
    fix_llm_model: str = "deepseek-v4-flash"
    # Per-plan fix-proposer routing: free orgs get the cheap Instant model,
    # paid orgs get the Expert model. Resolved per request from org.plan in
    # fix_proposer._fix_model_for_plan().
    fix_llm_model_free: str = "deepseek-v4-flash"
    fix_llm_model_pro: str = "deepseek-v4-pro"
    fix_llm_request_timeout: float = 60.0
    # AI Triage 2.0 — DeepSeek-backed per-finding walkthroughs. Uses the
    # same API key / base URL as the fix proposer; the model defaults to
    # the chattier ``deepseek-chat`` since triage benefits from longer-form
    # narrative output. Override per-tenant via env.
    triage_llm_model: str = "deepseek-chat"
    # DAST patches need real code-rewrite skill (not just a one-shot
    # diff edit), so they default to the chattier ``deepseek-chat`` —
    # the lighter ``v4-flash`` consistently degrades to comment-only
    # diffs on this task class. Override via env if you have a
    # stronger model wired up (e.g. ``deepseek-coder``).
    dast_patch_llm_model: str = "deepseek-chat"
    # When ``true``, AI features (AI Triage 2.0) are unlocked for orgs
    # on the Free plan. The fix-proposer is already free-for-all when
    # ``FIX_LLM_API_KEY`` is configured, so this flag mainly controls
    # the triage endpoint. Operators flip this on to evaluate the AI
    # surfaces without plumbing a paid plan.
    ai_free_tier_enabled: bool = False
    # Per-1k-token prices used to compute pay-as-you-go cost in usage
    # records. Override via env when the upstream changes pricing.
    fix_llm_price_input_per_1k_usd: float = 0.0001
    fix_llm_price_output_per_1k_usd: float = 0.0004
    # Free quotas. SAST = N LLM fixes per scan, capped to M scans per period.
    # DAST = total LLM provenance lookups per period.
    fix_free_sast_per_scan: int = 25
    fix_free_sast_max_scans: int = 5
    fix_free_dast_per_period: int = 10

    # --- Pencheff scanning engine ---
    # Operator-supplied credentials for the chat-completions backend that
    # drives the autonomous scan stage. The engine talks to any
    # chat-completions endpoint that accepts the OpenAI tool-calling
    # request shape; the operator points it at whichever backend they
    # have access to. End-user surfaces never reference the backend.
    agent_llm_api_key: str = ""
    agent_llm_base_url: str = ""
    agent_llm_model: str = "kimi-k2.6:cloud"
    agent_llm_max_tokens: int = 8192
    agent_llm_usage_mode: str = "tokens"
    agent_llm_usage_url: str = ""
    agent_llm_usage_session_percent_field: str = "session_usage_percent"
    agent_llm_usage_weekly_percent_field: str = "weekly_usage_percent"
    agent_llm_usage_threshold_percent: float = 90.0
    agent_llm_usage_poll_interval_sec: float = 120.0
    agent_llm_usage_request_timeout: float = 10.0
    agent_llm_session_window_sec: float = 18000.0
    agent_llm_weekly_window_sec: float = 604800.0
    agent_llm_session_tokens_per_percent: float = 260954.0
    agent_llm_weekly_tokens_per_percent: float = 1565722.0
    agent_fallback_llm_api_key: str = ""
    agent_fallback_llm_base_url: str = ""
    agent_fallback_llm_model: str = "sarvam-105b"
    # Sarvam's ``starter`` subscription tier caps max_tokens at 4096 for
    # sarvam-105b. Sending a higher value yields HTTP 400 on every chat
    # completion (DatatypeMismatchError-style failure for every breaker +
    # ChainAgent). Default to 4096 so a fresh deploy works out of the box;
    # operators on a higher Sarvam tier override to 8192 via
    # AGENT_FALLBACK_LLM_MAX_TOKENS.
    agent_fallback_llm_max_tokens: int = 4096
    # Cap the number of tool-use turns per scan so a runaway agent
    # cannot spin indefinitely. 30 turns has empirically been enough
    # for verify → exploit → chain on an already-populated session.
    # Override via env (``AGENT_MAX_TURNS``) when running deep
    # multi-target engagements.
    agent_max_turns: int = 30
    agent_request_timeout: float = 180.0

    # --- Dispatch tuning ---
    # When true, every scan runs the deterministic populator first and
    # then hands the populated session to the autonomous engine, regardless
    # of plan tier. Beta default = true so every operator gets the full
    # combined treatment while the engine is being tuned.
    agent_dispatch_beta_override: bool = True
    # When the beta override is off, free-plan orgs get this many combined
    # (deterministic + autonomous) scans before they are downgraded to the
    # autonomous-only path with deterministic fallback on engine failure.
    free_plan_option_3_quota: int = 10

    # ── Paid integrations gate (GitHub / Jira / GitLab apps) ───────────
    # Routers are still importable but only registered when True.
    integrations_enabled: bool = Field(False, alias="INTEGRATIONS_ENABLED")

    # ── Observability ingest gate (OTLP receivers + read API) ───────────
    # Routers are still importable but only registered when True.
    observability_ingest_enabled: bool = Field(False, alias="OBSERVABILITY_INGEST_ENABLED")

    # ── Swarm orchestrator (parallel multi-agent) ──────────────
    swarm_enabled: bool = Field(True, alias="SWARM_ENABLED")

    swarm_turns_recon_quick: int = Field(8, alias="SWARM_TURNS_RECON_QUICK")
    swarm_turns_recon_standard: int = Field(12, alias="SWARM_TURNS_RECON_STANDARD")
    swarm_turns_recon_deep: int = Field(18, alias="SWARM_TURNS_RECON_DEEP")

    swarm_turns_breaker_quick: int = Field(6, alias="SWARM_TURNS_BREAKER_QUICK")
    swarm_turns_breaker_standard: int = Field(10, alias="SWARM_TURNS_BREAKER_STANDARD")
    swarm_turns_breaker_deep: int = Field(16, alias="SWARM_TURNS_BREAKER_DEEP")

    swarm_turns_chain_quick: int = Field(8, alias="SWARM_TURNS_CHAIN_QUICK")
    swarm_turns_chain_standard: int = Field(12, alias="SWARM_TURNS_CHAIN_STANDARD")
    swarm_turns_chain_deep: int = Field(20, alias="SWARM_TURNS_CHAIN_DEEP")

    swarm_breaker_retry_attempts: int = Field(1, alias="SWARM_BREAKER_RETRY_ATTEMPTS")
    swarm_breaker_retry_backoff_sec: int = Field(2, alias="SWARM_BREAKER_RETRY_BACKOFF_SEC")

    # ── Security Lake (OCSF Iceberg) ─────────────────────────────────
    # "sql" = local SQLite catalog + filesystem warehouse (dev/tests).
    # "rest" = Cloudflare R2 Data Catalog (prod); requires the r2_* values.
    lake_catalog_type: str = "sql"
    lake_catalog_uri: str = "sqlite:////tmp/pencheff_lake/catalog.db"
    lake_warehouse: str = "file:///tmp/pencheff_lake/warehouse"
    lake_namespace: str = "pencheff"
    lake_table: str = "findings"
    # R2 (prod, catalog_type="rest") — sourced from env in deployment.
    lake_catalog_token: str | None = None
    r2_endpoint_url: str | None = None
    r2_access_key_id: str | None = None
    r2_secret_access_key: str | None = None

    report_storage_dir: str = "/tmp/pencheff-reports"

    scan_default_profile: str = "standard"

    # ── Observability (OpenTelemetry → native Postgres) ─────────────────
    # Master kill-switch. ``False`` keeps every observability hook
    # (init_observability, exporter, audit middleware, OTLP receivers) in
    # a no-op state so vanilla deployments pay zero overhead. Operators
    # opt in by flipping this to ``true``; everything below only applies
    # when this is true.
    observability_enabled: bool = Field(False, alias="PENCHEFF_OBSERVABILITY_ENABLED")
    # Head sampler ratio (0.0–1.0). ParentBased so the root ``scan.execute``
    # span is always sampled even when child sampling is dialed down.
    observability_sample_ratio: float = Field(
        1.0, alias="PENCHEFF_OBSERVABILITY_SAMPLE_RATIO"
    )
    # Day-partition horizon for ``otel_spans`` / ``otel_logs`` /
    # ``otel_metrics``. The Celery beat ``pencheff.observability.prune_partitions``
    # (hourly) DROPs partitions older than this. 7 keeps storage bounded;
    # bump for longer incident-retro windows.
    observability_retention_days: int = Field(
        7, alias="PENCHEFF_OBSERVABILITY_RETENTION_DAYS"
    )
    # Audit-log retention is a SEPARATE knob because compliance frameworks
    # (SOC2 / ISO 27001) typically require longer than telemetry. The
    # ``audit_logs`` table is hash-chained and append-only (REVOKE
    # UPDATE,DELETE on app role) — only the retention task can prune.
    audit_retention_days: int = Field(7, alias="PENCHEFF_AUDIT_RETENTION_DAYS")
    # Resource attribute attached to every emitted signal.
    observability_service_name: str = Field(
        "pencheff-api", alias="PENCHEFF_OBSERVABILITY_SERVICE_NAME"
    )
    # Plugin-side: where the MCP plugin ships traces over OTLP/HTTP. Empty
    # means "no shipping; plugin writes to ``~/.pencheff/logs/`` only".
    observability_otlp_url: str = Field(
        "", alias="PENCHEFF_OBSERVABILITY_OTLP_URL"
    )

    # Transactional email via Resend (https://resend.com). Leaving the API
    # key empty disables outbound email — invite flows fall back to returning
    # the raw token in the POST response so admins can copy-share the link.
    resend_api_key: str = ""
    email_from: str = "Pencheff <no-reply@pencheff.com>"
    # Public URL the invite email should link to. Defaults to web_base_url
    # when unset, but in a split-host setup you usually want the app
    # subdomain (e.g. https://app.pencheff.com).
    email_app_url: str = ""

    # docker-compose passes ``${VAR:-}`` for several env-overridable settings,
    # which arrives as an empty string in the container when the operator's
    # .env doesn't supply a value. Without this validator, that empty string
    # clobbers the in-code default. Run early so every consumer sees the
    # populated value.
    @field_validator(
        "agent_llm_base_url",
        "agent_llm_model",
        "agent_llm_usage_mode",
        "agent_llm_usage_url",
        "agent_llm_usage_session_percent_field",
        "agent_llm_usage_weekly_percent_field",
        "agent_fallback_llm_base_url",
        "agent_fallback_llm_model",
        "llm_base_url",
        "llm_model",
        "fix_llm_base_url",
        "fix_llm_model",
        mode="before",
    )
    @classmethod
    def _empty_str_means_default(cls, v, info):
        if v == "" or v is None:
            return cls.model_fields[info.field_name].default
        return v

    @property
    def ai_available(self) -> bool:
        return bool(self.llm_api_key)

    @property
    def sync_database_url(self) -> str:
        return self.database_url.replace("+asyncpg", "")

    # ── Agentic-fix effective config (with fallback) ────────────────
    #
    # The agentic fixer can use a dedicated config (``AGENTIC_FIX_*``
    # env) or fall back to the scan-agent's fallback config
    # (``AGENT_FALLBACK_LLM_*`` env). Most deployments already have
    # the latter set to Sarvam; the agentic flow piggy-backs on that
    # without needing a separate env var. Set ``AGENTIC_FIX_API_KEY``
    # explicitly to point the agentic flow at a different backend.

    @property
    def agentic_fix_effective_api_key(self) -> str:
        return self.agentic_fix_api_key or self.agent_fallback_llm_api_key

    @property
    def agentic_fix_effective_base_url(self) -> str:
        # Compare against the field's default so a stale ``=""`` in
        # env doesn't suppress the fallback. The validator above
        # already coerces ``""`` to the default for these specific
        # *_base_url fields, but ``agentic_fix_base_url`` isn't in
        # that list — keep the guard local here.
        chosen = self.agentic_fix_base_url.strip()
        if chosen and chosen != "https://api.sarvam.ai/v1":
            return chosen
        return self.agent_fallback_llm_base_url or chosen

    @property
    def agentic_fix_effective_model(self) -> str:
        chosen = self.agentic_fix_model.strip()
        if chosen and chosen != "sarvam-105b":
            return chosen
        return self.agent_fallback_llm_model or chosen


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if not s.fernet_key:
        key_file = os.environ.get("FERNET_KEY_FILE")
        if key_file:
            from pathlib import Path
            from fcntl import flock, LOCK_EX
            from cryptography.fernet import Fernet

            path = Path(key_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            lock_path = path.with_name(path.name + ".lock")
            with lock_path.open("a+", encoding="utf-8") as lock:
                os.chmod(lock_path, 0o600)
                flock(lock.fileno(), LOCK_EX)
                if path.exists():
                    key = path.read_text(encoding="utf-8").strip()
                    if not key:
                        raise RuntimeError(
                            f"Fernet key file {path} is empty; refusing to replace it"
                        )
                    try:
                        Fernet(key.encode("ascii"))
                    except (ValueError, TypeError) as exc:
                        raise RuntimeError(
                            f"Fernet key file {path} is invalid; refusing to replace it"
                        ) from exc
                else:
                    key = Fernet.generate_key().decode("ascii")
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as key_handle:
                        key_handle.write(key + "\n")
                        key_handle.flush()
                        os.fsync(key_handle.fileno())
                s.fernet_key = key
        else:
            # Development fallback when no persistent key store was configured.
            from cryptography.fernet import Fernet
            s.fernet_key = Fernet.generate_key().decode()
    return s
