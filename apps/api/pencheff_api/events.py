import json

import redis
import redis.asyncio as aioredis

from .config import get_settings

_settings = get_settings()


def sync_publisher() -> redis.Redis:
    return redis.Redis.from_url(_settings.redis_url, decode_responses=True)


def async_subscriber() -> aioredis.Redis:
    return aioredis.from_url(_settings.redis_url, decode_responses=True)


def channel_for(scan_id: str) -> str:
    return f"scan:{scan_id}"


def engagement_channel(engagement_id: str) -> str:
    return f"engagement:{engagement_id}"


def publish_scan_event(scan_id: str, event: dict) -> None:
    sync_publisher().publish(channel_for(scan_id), json.dumps(event))


def publish_engagement_event(engagement_id: str, event: dict) -> None:
    """Publish a real-time event to all members of an engagement.

    Used by the WebSocket router (`routers/ws.py`) and any service that
    mutates engagement state and wants peers to see it without polling.
    """
    sync_publisher().publish(engagement_channel(engagement_id), json.dumps(event))
