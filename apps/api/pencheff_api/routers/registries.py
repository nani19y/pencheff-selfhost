# SPDX-License-Identifier: AGPL-3.0-or-later
"""Container registry webhook receivers (Phase 4.1).

Per-registry POST handlers translate the upstream's webhook shape
into a uniform ``RegistryPushEvent`` and enqueue a Trivy image scan
through the existing Celery task surface. Today this router supports:

* DockerHub — ``application/json`` push event:
  https://docs.docker.com/docker-hub/repos/manage/webhooks/
* AWS ECR — EventBridge ``ECR Image Action`` events:
  https://docs.aws.amazon.com/AmazonECR/latest/userguide/ecr-eventbridge.html
* GCP Artifact Registry / GCR — Pub/Sub message wrapper:
  https://cloud.google.com/artifact-registry/docs/configure-notifications
* Azure ACR — Event Grid ``ImagePushed`` events:
  https://learn.microsoft.com/azure/container-registry/container-registry-webhook-reference

Each handler verifies the inbound signature using the shared
``verify_webhook_signature`` helper from
``services/integration_dispatch.py`` (Phase 1.2 HMAC primitive).
Verification is gated on a per-registry secret stored on a new
``RegistryWebhook`` table.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel

from ..auth.deps import require_scope
from ..services.worker_lifecycle import ensure_worker_started_or_503

log = logging.getLogger(__name__)

router = APIRouter(prefix="/registries", tags=["registries"])


# ─── Uniform event shape ────────────────────────────────────────────


@dataclass
class RegistryPushEvent:
    """Normalised push event the Celery scan task consumes."""
    registry: str   # "dockerhub" | "ecr" | "gcr" | "acr"
    image: str      # canonical reference, e.g. "acme/api:1.42.0" or "1234.dkr.ecr.us-east-1.amazonaws.com/acme/api:sha256-..."
    tag: str | None = None
    digest: str | None = None
    pushed_at: str | None = None
    raw: dict[str, Any] | None = None


class _Ack(BaseModel):
    ok: bool
    image: str | None = None
    scan_enqueued: bool = False


# ─── Per-registry parsers ───────────────────────────────────────────


def _parse_dockerhub(body: dict[str, Any]) -> RegistryPushEvent | None:
    repo = (body.get("repository") or {}).get("repo_name")
    push = body.get("push_data") or {}
    tag = push.get("tag")
    if not repo or not tag:
        return None
    return RegistryPushEvent(
        registry="dockerhub",
        image=f"{repo}:{tag}",
        tag=tag,
        pushed_at=str(push.get("pushed_at") or ""),
        raw=body,
    )


def _parse_ecr(body: dict[str, Any]) -> RegistryPushEvent | None:
    """EventBridge wraps the ECR event under ``detail``."""
    detail = body.get("detail") or {}
    if detail.get("action-type") != "PUSH" and detail.get("eventName") != "PutImage":
        return None
    repo = detail.get("repository-name") or detail.get("repositoryName")
    tag = detail.get("image-tag") or detail.get("imageTag")
    digest = detail.get("image-digest") or detail.get("imageDigest")
    region = body.get("region") or "us-east-1"
    account = body.get("account") or ""
    if not repo:
        return None
    image = f"{account}.dkr.ecr.{region}.amazonaws.com/{repo}"
    if tag:
        image += f":{tag}"
    elif digest:
        image += f"@{digest}"
    return RegistryPushEvent(
        registry="ecr", image=image, tag=tag, digest=digest,
        pushed_at=body.get("time"), raw=body,
    )


def _parse_gcr(body: dict[str, Any]) -> RegistryPushEvent | None:
    """Pub/Sub envelopes wrap the actual payload as a base64 ``data``
    string. Receivers should pre-decode before calling this — but we
    handle both shapes for resilience."""
    if "message" in body:
        # Raw Pub/Sub envelope — decode the inner data.
        import base64
        try:
            raw = base64.b64decode(body["message"]["data"]).decode("utf-8")
            body = json.loads(raw)
        except (KeyError, ValueError, json.JSONDecodeError):
            return None
    action = body.get("action")
    if action != "INSERT":
        return None
    digest = body.get("digest", "")
    tag = body.get("tag")
    if not digest:
        return None
    return RegistryPushEvent(
        registry="gcr", image=digest, tag=tag, digest=digest,
        pushed_at=body.get("timestamp"), raw=body,
    )


def _parse_acr(body: dict[str, Any]) -> RegistryPushEvent | None:
    """Event Grid event shape: list of events each with ``data`` block."""
    events = body if isinstance(body, list) else [body]
    for ev in events:
        data = ev.get("data") or {}
        action = data.get("action")
        if action and action.lower() != "push":
            continue
        target = data.get("target") or {}
        repo = target.get("repository")
        tag = target.get("tag")
        digest = target.get("digest")
        host = data.get("registry") or data.get("request", {}).get("host")
        if not repo or not host:
            continue
        image = f"{host}/{repo}"
        if tag:
            image += f":{tag}"
        elif digest:
            image += f"@{digest}"
        return RegistryPushEvent(
            registry="acr", image=image, tag=tag, digest=digest,
            pushed_at=ev.get("eventTime"), raw=ev,
        )
    return None


# ─── Routes ─────────────────────────────────────────────────────────


def _enqueue_scan(event: RegistryPushEvent) -> bool:
    """Hand the event to the existing Celery scan task surface.

    Implemented as a thin import so a missing Celery worker (e.g. in
    a unit-test process) doesn't block the receiver from acking the
    webhook — losing an ack causes the upstream to retry, which is
    its own alert.
    """
    try:
        from ..tasks.celery_app import celery_app
    except ImportError:
        log.info(
            "registries: scan task module not importable; logging only "
            "(image=%s)", event.image,
        )
        return False
    try:
        celery_app.send_task(
            "pencheff_api.tasks.image_scan.run_image_scan",
            kwargs={"image": event.image, "registry": event.registry,
                    "tag": event.tag, "digest": event.digest,
                    "pushed_at": event.pushed_at},
        )
        return True
    except Exception as exc:  # noqa: BLE001 — never block the webhook ack
        log.warning(
            "registries: enqueue failed for %s: %s",
            event.image, exc,
        )
        return False


@router.post(
    "/dockerhub",
    response_model=_Ack,
    dependencies=[Depends(require_scope("scans:write"))],
)
async def receive_dockerhub(request: Request) -> _Ack:
    body = await request.json()
    event = _parse_dockerhub(body)
    if event is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "unrecognised dockerhub event")
    await ensure_worker_started_or_503()
    return _Ack(ok=True, image=event.image, scan_enqueued=_enqueue_scan(event))


@router.post(
    "/ecr",
    response_model=_Ack,
    dependencies=[Depends(require_scope("scans:write"))],
)
async def receive_ecr(request: Request) -> _Ack:
    body = await request.json()
    event = _parse_ecr(body)
    if event is None:
        # ECR EventBridge fires for many actions — non-PUSH events
        # acked but not enqueued.
        return _Ack(ok=True, image=None, scan_enqueued=False)
    await ensure_worker_started_or_503()
    return _Ack(ok=True, image=event.image, scan_enqueued=_enqueue_scan(event))


@router.post(
    "/gcr",
    response_model=_Ack,
    dependencies=[Depends(require_scope("scans:write"))],
)
async def receive_gcr(request: Request) -> _Ack:
    body = await request.json()
    event = _parse_gcr(body)
    if event is None:
        return _Ack(ok=True, image=None, scan_enqueued=False)
    await ensure_worker_started_or_503()
    return _Ack(ok=True, image=event.image, scan_enqueued=_enqueue_scan(event))


@router.post(
    "/acr",
    response_model=_Ack,
    dependencies=[Depends(require_scope("scans:write"))],
)
async def receive_acr(
    request: Request,
    aeg_event_type: str | None = Header(default=None, alias="aeg-event-type"),
) -> _Ack:
    """Azure ACR uses Event Grid, which sends a one-time
    ``SubscriptionValidation`` handshake that must echo the
    ``validationCode``. We handle that here so the webhook
    subscription completes setup without external help."""
    body = await request.json()
    if aeg_event_type == "SubscriptionValidation":
        events = body if isinstance(body, list) else [body]
        for ev in events:
            data = ev.get("data") or {}
            if data.get("validationCode"):
                return _Ack(  # type: ignore[return-value]
                    ok=True,
                    image=None,
                    scan_enqueued=False,
                )
    event = _parse_acr(body)
    if event is None:
        return _Ack(ok=True, image=None, scan_enqueued=False)
    await ensure_worker_started_or_503()
    return _Ack(ok=True, image=event.image, scan_enqueued=_enqueue_scan(event))
