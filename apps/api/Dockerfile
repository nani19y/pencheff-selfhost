# syntax=docker/dockerfile:1.7
#
# Multi-stage lean image for both the API (uvicorn) and the worker
# (Celery). Splitting builder ↦ runtime drops ~250 MB of build tools
# (build-essential, *-dev headers, git) from the final image, while
# keeping every runtime capability intact.
#
# Layer order is tuned for cache hit-rate: stable base layers (apt,
# pip cache key) come first; the source COPY (which changes most
# often) is last so iterative rebuilds reuse the heavy Playwright /
# pip layers.

# ────────────────────── Stage 1 — builder ──────────────────────
FROM python:3.12-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Build deps only — these stay in the builder stage and never
# reach the runtime image.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl ca-certificates git \
      libpq-dev libffi-dev libssl-dev \
      libxml2-dev libxslt1-dev libjpeg-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# Install Python deps into an isolated prefix so we can copy the
# entire site-packages tree in one shot to the runtime stage.
ENV PIP_PREFIX=/opt/pkgs \
    PYTHONUSERBASE=/opt/pkgs

WORKDIR /build
COPY plugins/pencheff /build/plugins/pencheff
COPY plugins/sentry /build/plugins/sentry
COPY apps/api /build/apps/api
COPY README.md /build/README.md

# Plugin engine first (its deps form the base layer). API on top.
# [cloud] extras pull in boto3 / azure-identity / azure-mgmt-containerservice /
# google-cloud-container so the scan worker can derive EKS/AKS/GKE kubeconfigs
# and exchange AWS IAM keys for ECR registry tokens at scan time.
# pencheff-sentry is the runtime-protection core (guardrail detectors +
# agent firewall + memory scanner) the API imports from llm_proxy /
# services.guardrails / services.agent_firewall. WITHOUT it those controls
# fail OPEN (ImportError → allow), so it must be in the image.
RUN pip install --prefix=/opt/pkgs "/build/plugins/pencheff[cloud]" \
 && pip install --prefix=/opt/pkgs /build/plugins/sentry \
 && pip install --prefix=/opt/pkgs /build/apps/api

# Strip __pycache__, .pyc, tests, and locale dirs from the bundled
# packages — these add ~30–50 MB and serve no purpose at runtime.
RUN find /opt/pkgs -type d -name "__pycache__" -exec rm -rf {} + \
 && find /opt/pkgs -type d -name "tests" -exec rm -rf {} + \
 && find /opt/pkgs -type d -name "test" -exec rm -rf {} + \
 && find /opt/pkgs -name "*.pyc" -delete \
 && find /opt/pkgs -name "*.pyo" -delete

# ────────────────────── Stage 2 — runtime ──────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Runtime libraries only — the *unversioned* shared objects that
# the Python packages link against. No -dev headers, no compilers.
# (libpq5 ↔ libpq-dev, libffi8 ↔ libffi-dev, libssl3 ↔ libssl-dev.)
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git bash \
      libpq5 libffi8 libssl3 \
      libcairo2 libpango-1.0-0 libpangoft2-1.0-0 \
      libxml2 libxslt1.1 libjpeg62-turbo zlib1g \
      fonts-liberation fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

# Bring across the pre-built Python packages from the builder.
COPY --from=builder /opt/pkgs /usr/local

# Source COPY for the editable plugin install. Done in the runtime
# stage so the plugin mount point stays at /app/plugins/pencheff
# (same path the package metadata recorded). bench/ is needed by the
# repo-scan task at runtime.
WORKDIR /app
COPY plugins/pencheff /app/plugins/pencheff
COPY plugins/sentry /app/plugins/sentry
COPY apps/api /app/apps/api
COPY README.md /app/README.md
COPY bench /app/bench

# Re-link the plugins in editable mode against the source tree we just
# copied (compiled deps already present from the builder stage, so this
# is metadata-only — no compile). pencheff_sentry MUST be here or the
# guardrail / firewall / memory-scan controls silently fail open.
RUN pip install --no-deps -e /app/plugins/pencheff \
 && pip install --no-deps -e /app/plugins/sentry

# Playwright browser binaries are large (~300 MB) and rarely change.
# Install them last so changes to /app source don't invalidate the
# Chromium-download layer. `playwright` itself ships in site-packages
# from the builder stage already.
ENV PLAYWRIGHT_BROWSERS_PATH=/root/.cache/ms-playwright
RUN playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app/apps/api
ENV PYTHONPATH=/app/apps/api

EXPOSE 8000

# CMD is overridden by docker-compose.yml — the API runs `alembic
# upgrade head && uvicorn …`, the worker runs `celery -A …`. This
# default exists for direct `docker run` invocations and CI smoke
# tests.
CMD ["uvicorn", "pencheff_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
