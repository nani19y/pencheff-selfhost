"""Target-kind → security-category → Celery-queue / worker-service mapping.

The single worker image was split into one image (and one Celery queue +
compose service) per security category. This module is the backend source of
truth for that split — it mirrors the eight categories the frontend renders in
``apps/web/components/register-target/target-types.ts`` (``CATEGORIES``).

A scan of kind ``K`` is enqueued onto ``category_queue(K)`` and consumed only by
that category's worker (``category_service(K)``), whose image carries just the
tools that category needs. Everything that isn't a category scan (reports,
fixes, campaigns, email, retention, beat, …) has no explicit queue and falls
through Celery's ``task_default_queue`` (``core``), handled by ``worker-core``.

Kinds that are unknown here (or the legacy ``url``/``repo``/``llm`` values) map
to their natural category; anything genuinely unmapped degrades to ``core`` so a
scan is never lost, only run without category-specific tools.
"""
from __future__ import annotations

# Category id → the Celery queue and compose service that serve it. Ids match
# ``TargetCategory.id`` on the frontend. ``identity-compliance`` is shortened to
# ``identity`` on the wire (queue/service) to keep names terse.
CATEGORY_QUEUE: dict[str, str] = {
    "web-api": "cat_web_api",
    "code-supply": "cat_code_supply",
    "infra-cloud": "cat_infra_cloud",
    "network-host": "cat_network_host",
    "ai-llm": "cat_ai_llm",
    "mobile-client": "cat_mobile_client",
    "ot-iot": "cat_ot_iot",
    "identity-compliance": "cat_identity",
}
CATEGORY_SERVICE: dict[str, str] = {
    "web-api": "worker-web-api",
    "code-supply": "worker-code-supply",
    "infra-cloud": "worker-infra-cloud",
    "network-host": "worker-network-host",
    "ai-llm": "worker-ai-llm",
    "mobile-client": "worker-mobile-client",
    "ot-iot": "worker-ot-iot",
    "identity-compliance": "worker-identity",
}

# Fallback for support tasks (reports, email, beat, …) and any unmapped kind.
CORE_QUEUE = "core"
CORE_SERVICE = "worker-core"

# Kind → category id. Mirrors the frontend CATEGORIES table 1:1, plus the three
# legacy wire values (url/repo/llm) that predate the per-kind split.
KIND_TO_CATEGORY: dict[str, str] = {
    # legacy
    "url": "web-api",
    "repo": "code-supply",
    "llm": "ai-llm",
    # Web & API
    "web_app": "web-api",
    "rest_api": "web-api",
    "graphql": "web-api",
    "websocket": "web-api",
    "grpc": "web-api",
    # Code & Supply Chain
    "source_code": "code-supply",
    "cicd_pipeline": "code-supply",
    "iac": "code-supply",
    "container_image": "code-supply",
    "k8s_cluster": "code-supply",
    "package_registry": "code-supply",
    "sbom": "code-supply",
    # Infrastructure & Cloud
    "cloud_account": "infra-cloud",
    "serverless_function": "infra-cloud",
    "cloud_storage": "infra-cloud",
    "load_balancer_cdn": "infra-cloud",
    "cloud_database": "infra-cloud",
    "secrets_manager": "infra-cloud",
    # Network & Host
    "host": "network-host",
    "tls_ssl": "network-host",
    "dns": "network-host",
    "email_security": "network-host",
    "vpn": "network-host",
    # AI & LLM
    "mcp": "ai-llm",
    "agent": "ai-llm",
    "rag": "ai-llm",
    "ml_model": "ai-llm",
    "voice": "ai-llm",
    "memory": "ai-llm",
    # Mobile & Client
    "android_app": "mobile-client",
    "ios_app": "mobile-client",
    "browser_extension": "mobile-client",
    "desktop_app": "mobile-client",
    # OT / IoT & Hardware
    "firmware": "ot-iot",
    "iot_device": "ot-iot",
    "ot_ics_scada": "ot-iot",
    # Identity, Data & Compliance
    "idp": "identity-compliance",
    "data_store": "identity-compliance",
}

# Reverse map: category id → the kinds it owns. Used by a category worker to
# scope its "am I idle?" DB check to its own kinds.
CATEGORY_KINDS: dict[str, list[str]] = {}
for _kind, _cat in KIND_TO_CATEGORY.items():
    CATEGORY_KINDS.setdefault(_cat, []).append(_kind)

# All category queues/services + core, for compose/beat wiring and validation.
ALL_QUEUES: list[str] = list(CATEGORY_QUEUE.values()) + [CORE_QUEUE]
ALL_SERVICES: list[str] = list(CATEGORY_SERVICE.values()) + [CORE_SERVICE]


def category_for_kind(kind: str | None) -> str | None:
    """Category id for a target kind, or None if unmapped."""
    if not kind:
        return None
    return KIND_TO_CATEGORY.get(kind)


def category_queue(kind: str | None) -> str:
    """Celery queue a scan of this kind should be enqueued onto.

    Falls back to ``core`` for unmapped kinds so a scan is never dropped.
    """
    cat = category_for_kind(kind)
    return CATEGORY_QUEUE.get(cat, CORE_QUEUE) if cat else CORE_QUEUE


def category_service(kind: str | None) -> str:
    """Compose service name of the worker that consumes this kind's queue."""
    cat = category_for_kind(kind)
    return CATEGORY_SERVICE.get(cat, CORE_SERVICE) if cat else CORE_SERVICE


def kinds_for_queue(queue: str) -> list[str]:
    """The target kinds a worker on ``queue`` handles (empty for ``core``)."""
    for cat, q in CATEGORY_QUEUE.items():
        if q == queue:
            return CATEGORY_KINDS.get(cat, [])
    return []


if __name__ == "__main__":  # ponytail: self-check — every kind maps to a real queue
    from .schemas.targets import TargetKind
    import typing

    wire_kinds = set(typing.get_args(TargetKind))
    mapped = set(KIND_TO_CATEGORY)
    missing = wire_kinds - mapped
    assert not missing, f"TargetKind values with no category: {sorted(missing)}"
    # Every category must have a queue AND a service.
    assert set(CATEGORY_QUEUE) == set(CATEGORY_SERVICE), "queue/service category mismatch"
    for k in wire_kinds:
        assert category_queue(k) in ALL_QUEUES, f"{k} → bad queue"
        assert category_service(k) in ALL_SERVICES, f"{k} → bad service"
    # Unmapped / empty degrade to core, never crash.
    assert category_queue("nonexistent_kind") == CORE_QUEUE
    assert category_queue(None) == CORE_QUEUE
    assert category_service(None) == CORE_SERVICE
    # Round-trip: a queue's kinds all point back to that queue.
    for q in CATEGORY_QUEUE.values():
        for k in kinds_for_queue(q):
            assert category_queue(k) == q
    print(f"OK — {len(wire_kinds)} kinds → {len(CATEGORY_QUEUE)} categories + core")
