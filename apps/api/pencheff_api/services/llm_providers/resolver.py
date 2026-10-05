from __future__ import annotations

from ...db.models import LlmProvider, Org
from .base import ChatClient
from .factory import build_client


async def resolve_chat_client(org_id: str | None, session) -> ChatClient | None:
    """Return the org's active provider as a ChatClient, or None to signal
    'use Pencheff defaults'. Never raises for the common cases (missing org,
    no active provider, deleted provider)."""
    if not org_id:
        return None
    org = await session.get(Org, org_id)
    if org is None or not org.active_llm_provider_id:
        return None
    p = await session.get(LlmProvider, org.active_llm_provider_id)
    if p is None:
        return None
    return build_client(p)
