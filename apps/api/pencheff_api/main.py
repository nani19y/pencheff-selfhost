import asyncio
import logging
import traceback

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from .config import get_settings
# Initialise OpenTelemetry pipeline BEFORE FastAPI() is constructed so
# the FastAPIInstrumentor patches the class globally and our app picks
# up auto-instrumentation. When PENCHEFF_OBSERVABILITY_ENABLED=false
# (the default), this is a hard no-op — zero overhead.
from .observability import init_observability
init_observability("pencheff-api")

from .routers import (
    capabilities,
    findings, reports, scans, targets,
    # Workspace / membership
    workspaces,
    # Extended scanning workflows
    schedules, assets, integrations, sboms, dependencies, proxy, comments,
    # Phase 1.1c — advisory lookup + AI walkthrough on top of the
    # bulk-feed registry (RustSec / GoVulnDB / EPSS / KEV).
    advisories,
    # Phase 4.1 — container registry push webhook receivers
    # (DockerHub / ECR / GCR / ACR → Trivy image scan).
    registries,
    # Per-target LLM guardrail config + recommended-guardrails compute
    # + the hosted guardrail proxy that runs the configured detector
    # chain on every chat-completions request.
    guardrails as guardrails_router,
    llm_proxy, llm_providers,
    # Runtime-protection tracing: SDK ingest + viewer read API.
    traces,
    # Memory scanner: audit agent memory / vector-store items.
    memory_scan,
    # GitHub repo scanning
    repos, github_webhooks,
    # Propose-fix → open-PR flow
    fix_proposals,
    # Agentic Fix-all (multi-turn tool-use agent)
    agentic_fix,
    # LLM proxy that the desktop agentic runtime uses to reach
    # Pencheff's Sarvam key without ever seeing it raw.
    llm_proxy_agentic,
    # Collaboration (engagement routers removed; ws/proxy_ingest/traffic/etc survive)
    proxy_ingest, traffic, repeater, intruder, notes, ws,
    # LLM red-team share-by-link (public route, token-encoded)
    share as llm_share,
    # Unified finding stream — sortable single queue across all scan kinds
    unified_findings,
    # OpenTelemetry/HTTP ingest endpoints (used by the MCP plugin when
    # PENCHEFF_OBSERVABILITY_OTLP_URL points here).
    otlp_ingest,
    # Observability read endpoints powering the /observability/* UI pages.
    observability as observability_router,
    # Workspace-scoped aggregation endpoints powering /dashboard/executive
    # and the per-target trend dashboard at /targets/{id}.
    dashboard,
    # Compliance mapping (findings → GDPR / ISO 42001 / OWASP controls).
    compliance,
    # Source-artifact uploads (mobile APK/IPA, client artifacts, firmware).
    uploads,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("pencheff_api")

settings = get_settings()
_on_demand_scheduler_task: asyncio.Task | None = None
_worker_idle_stop_task: asyncio.Task | None = None

app = FastAPI(
    title="Pencheff API",
    description="Pentest-as-a-Service HTTP API",
    version="0.1.0",
)


def custom_openapi() -> dict:
    """Advertise the API-key auth scheme so Swagger UI (``/docs``) shows an
    Authorize button and includes the key in every "Try it out" request.

    Auth is enforced in ``auth/deps.py`` by reading the raw ``Authorization``
    header, so no route declares a FastAPI ``Security`` dependency — which
    means the generated schema has no security scheme by default. We inject
    it here at the document level instead of touching every route.

    - ``PencheffApiKey`` → HTTP bearer; Swagger sends
      ``Authorization: Bearer <pcf_live_…>``, matching ``get_current_user``.
    - ``WorkspaceId`` → optional ``X-Workspace-Id`` header, needed only for
      org-scoped keys (workspace-pinned keys force their own).
    """
    from fastapi.openapi.utils import get_openapi

    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=(
            f"{app.description}\n\n"
            "**Authenticating in this page:** click **Authorize**, paste a "
            "Pencheff API key (`pcf_live_…`, created at "
            "`app.pencheff.com/settings/api-keys`) into **PencheffApiKey**, "
            "and (only for org-scoped keys) set **WorkspaceId** to a workspace "
            "UUID. Then use **Try it out** on any endpoint."
        ),
        routes=app.routes,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {}).update(
        {
            "PencheffApiKey": {
                "type": "http",
                "scheme": "bearer",
                "description": (
                    "Your Pencheff API key, sent as "
                    "`Authorization: Bearer <key>`."
                ),
            },
            "WorkspaceId": {
                "type": "apiKey",
                "in": "header",
                "name": "X-Workspace-Id",
                "description": (
                    "Target workspace UUID. Required only for org-scoped "
                    "keys; leave blank for workspace-pinned keys."
                ),
            },
        }
    )
    # Document-level default so every operation shows the lock + applies the
    # key in Try it out. Public routes (e.g. /health, /auth/*) ignore the
    # header server-side, so the only cost is a cosmetic lock icon on them.
    schema["security"] = [{"PencheffApiKey": [], "WorkspaceId": []}]
    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi  # type: ignore[method-assign]

app.add_middleware(SessionMiddleware, secret_key=settings.jwt_secret)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Tamper-evident audit middleware. Internally short-circuits when
# observability is disabled, so this add_middleware call is cheap
# regardless of the kill-switch state. Mounted AFTER auth (which is a
# per-route dependency, not middleware) — Starlette runs middleware in
# reverse-registration order so the audit path executes after the
# route handler, by which point ``request.state`` is populated.
from .middleware.audit import AuditMiddleware
app.add_middleware(AuditMiddleware)


from fastapi import HTTPException
from starlette.exceptions import HTTPException as StarletteHTTPException


@app.on_event("startup")
async def _production_safety_check() -> None:
    if settings.environment == "production":
        default_jwt = "change-me-in-prod-please-change-me-32b!"
        if settings.jwt_secret == default_jwt:
            raise RuntimeError(
                "JWT_SECRET is set to the insecure default. "
                "Set a strong random value before running in production."
            )
        if not settings.fernet_key:
            raise RuntimeError(
                "FERNET_KEY is not configured. "
                "Generate one with Fernet.generate_key() and set it before running in production."
            )


@app.on_event("startup")
async def _seed_single_tenant() -> None:
    from .auth.single_tenant import ensure_single_tenant
    from .db.base import SessionLocal

    async with SessionLocal() as session:
        await ensure_single_tenant(session)
    log.info("single-tenant seed ensured")


@app.on_event("startup")
async def _start_on_demand_scheduler() -> None:
    global _on_demand_scheduler_task, _worker_idle_stop_task
    if settings.worker_always_on:
        return
    from .services.on_demand_scheduler import run_on_demand_schedule_loop
    from .services.worker_lifecycle import run_worker_idle_stop_loop

    _on_demand_scheduler_task = asyncio.create_task(run_on_demand_schedule_loop())
    _worker_idle_stop_task = asyncio.create_task(run_worker_idle_stop_loop())
    log.info("started API-side on-demand schedule dispatcher")
    log.info("started API-side on-demand worker idle-stop loop")


@app.on_event("shutdown")
async def _stop_on_demand_scheduler() -> None:
    tasks = [
        task
        for task in (_on_demand_scheduler_task, _worker_idle_stop_task)
        if task is not None
    ]
    for task in tasks:
        task.cancel()
    for task in tasks:
        try:
            await task
        except asyncio.CancelledError:
            pass


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Let FastAPI/Starlette handle intentional HTTP exceptions normally.
    if isinstance(exc, (HTTPException, StarletteHTTPException)):
        raise exc
    log.exception("unhandled %s on %s %s", type(exc).__name__, request.method, request.url.path)
    if settings.environment == "production":
        detail = "Internal server error."
    else:
        detail = f"{type(exc).__name__}: {exc}"
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": detail},
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()},
    )


app.include_router(capabilities.router)
app.include_router(llm_providers.router)
app.include_router(workspaces.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(llm_share.router)
app.include_router(findings.router)
app.include_router(unified_findings.router)
app.include_router(reports.router)
# Extended scanning workflows
app.include_router(schedules.router)
app.include_router(assets.router)
if settings.integrations_enabled:
    app.include_router(integrations.router)
app.include_router(sboms.router)
app.include_router(dependencies.router)
app.include_router(advisories.router)
app.include_router(registries.router)
app.include_router(guardrails_router.router)
app.include_router(llm_proxy.router)
app.include_router(traces.router)
app.include_router(memory_scan.router)
app.include_router(proxy.router)
app.include_router(comments.router)
# GitHub repo scanning
app.include_router(repos.router)
if settings.integrations_enabled:
    app.include_router(github_webhooks.router)
# Propose-fix → open-PR flow
app.include_router(fix_proposals.router)
app.include_router(agentic_fix.router)
app.include_router(llm_proxy_agentic.router)
# Collaboration
app.include_router(proxy_ingest.router)
app.include_router(traffic.router)
app.include_router(repeater.router)
app.include_router(intruder.router)
app.include_router(notes.router)
app.include_router(ws.router)
# OpenTelemetry-related routers (see config.py observability_* knobs).
if settings.observability_ingest_enabled:
    app.include_router(otlp_ingest.router)
    app.include_router(observability_router.router)
app.include_router(dashboard.router)
app.include_router(compliance.router)
app.include_router(uploads.router)


@app.get("/")
async def root():
    return {"service": "pencheff-api", "version": "0.1.0", "environment": settings.environment}


@app.get("/health")
async def health():
    return {"ok": True}
