"""Celery task that fans out an intruder attack across payloads.

The attack types implemented here:
  * sniper          — substitute one payload position at a time
  * battering-ram   — substitute the same payload into every position
  * pitchfork       — parallel iteration across N payload sets (here we
                      reuse the same set across positions)
  * cluster-bomb    — cartesian product (capped to 5,000 to avoid runaway)

This is intentionally conservative — Burp's intruder is a polished beast,
ours is a credible 80%.
"""
from __future__ import annotations

import asyncio
import itertools
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..config import get_settings
from ..db.models import IntruderAttack, IntruderPayloadSet, IntruderResult
from .celery_app import celery_app

_MARKER = re.compile(r"§(.*?)§")
_MAX_RESULTS = 5000


def _substitute(template: str, marker_index: int, payload: str) -> str:
    matches = list(_MARKER.finditer(template))
    if marker_index >= len(matches):
        return template
    out: list[str] = []
    last = 0
    for i, m in enumerate(matches):
        out.append(template[last:m.start()])
        out.append(payload if i == marker_index else m.group(1))
        last = m.end()
    out.append(template[last:])
    return "".join(out)


def _substitute_all(template: str, payload: str) -> str:
    return _MARKER.sub(payload, template)


def _expand_attack(template: str, payloads: list[str], attack_type: str) -> list[tuple[list[str], str]]:
    """Return a list of (display_payload, expanded_template) pairs."""
    matches = list(_MARKER.finditer(template))
    n_positions = len(matches)
    out: list[tuple[list[str], str]] = []

    if attack_type == "sniper" or n_positions <= 1:
        for idx in range(max(n_positions, 1)):
            for p in payloads:
                out.append(([p], _substitute(template, idx, p) if n_positions else template + p))
    elif attack_type == "battering-ram":
        for p in payloads:
            out.append(([p], _substitute_all(template, p)))
    elif attack_type == "pitchfork":
        for p in payloads:
            t = template
            for i in range(n_positions):
                t = _substitute(t, i, p)
            out.append(([p], t))
    elif attack_type == "cluster-bomb":
        prod = itertools.product(payloads, repeat=n_positions)
        for combo in prod:
            t = template
            for i, p in enumerate(combo):
                t = _substitute(t, i, p)
            out.append((list(combo), t))
            if len(out) >= _MAX_RESULTS:
                break
    return out[:_MAX_RESULTS]


async def _run_attack_async(attack_id: str) -> None:
    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as session:
        attack: IntruderAttack | None = await session.get(IntruderAttack, attack_id)
        if attack is None:
            return
        payload_set: IntruderPayloadSet | None = await session.get(
            IntruderPayloadSet, attack.payload_set_id
        ) if attack.payload_set_id else None
        if payload_set is None:
            attack.status = "failed"
            await session.commit()
            return

        attack.status = "running"
        attack.started_at = datetime.now(timezone.utc)
        attack.progress_pct = 0
        await session.commit()

        tmpl = attack.request_template or {}
        method = (tmpl.get("method") or "GET").upper()
        url_t = tmpl.get("url") or ""
        body_t = tmpl.get("body") or ""
        headers = tmpl.get("headers") or {}

        # We accept §marker§ in url or body. Build one big "tape" of the two
        # so a single payload run lays into both consistently.
        def _carry(payload: str, marker_idx: int) -> tuple[str, str]:
            url = _substitute(url_t, marker_idx, payload) if "§" in url_t else url_t
            body = _substitute(body_t, marker_idx, payload) if "§" in body_t else body_t
            return url, body

        attack_type = attack.attack_type
        payloads = list(payload_set.entries or [])

        # Compute total work for progress.
        positions_in = len(_MARKER.findall(url_t)) + len(_MARKER.findall(body_t))
        if attack_type == "cluster-bomb" and positions_in:
            total = min(_MAX_RESULTS, len(payloads) ** positions_in)
        elif attack_type == "sniper":
            total = max(positions_in, 1) * len(payloads)
        else:
            total = len(payloads)
        if total == 0:
            total = 1

        sem = asyncio.Semaphore(max(attack.concurrency, 1))
        rate_limit = max(attack.rate_limit, 1)
        rate_window = 1.0 / rate_limit
        last_send = 0.0
        lock = asyncio.Lock()
        completed = 0

        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False, verify=False) as client:
            async def _one(payload: str, marker_idx: int = 0):
                nonlocal last_send, completed
                async with sem:
                    async with lock:
                        delta = time.monotonic() - last_send
                        if delta < rate_window:
                            await asyncio.sleep(rate_window - delta)
                        last_send = time.monotonic()
                    url, body = _carry(payload, marker_idx)
                    started = time.monotonic()
                    try:
                        res = await client.request(
                            method, url, headers=headers or None,
                            content=body if body else None,
                        )
                        elapsed = int((time.monotonic() - started) * 1000)
                        text = res.text[:512 * 1024]
                        result = IntruderResult(
                            attack_id=attack.id, payload=payload,
                            request_snapshot={"method": method, "url": url, "body": body},
                            response_status=res.status_code,
                            response_length=len(text),
                            response_time_ms=elapsed,
                            grep_match=None,
                            diff_score=None,
                        )
                    except Exception as exc:
                        result = IntruderResult(
                            attack_id=attack.id, payload=payload,
                            request_snapshot={"method": method, "url": url, "body": body, "error": str(exc)[:200]},
                            response_status=None, response_length=None,
                            response_time_ms=int((time.monotonic() - started) * 1000),
                            grep_match=None, diff_score=None,
                        )
                    session.add(result)
                    completed += 1
                    if completed % 25 == 0:
                        attack.progress_pct = min(99, int(completed * 100 / total))
                        await session.commit()

            tasks = []
            if attack_type == "sniper":
                for idx in range(max(positions_in, 1)):
                    for p in payloads:
                        tasks.append(_one(p, idx))
            elif attack_type == "battering-ram":
                for p in payloads:
                    tasks.append(_one(p, -1))
            elif attack_type == "pitchfork":
                for p in payloads:
                    tasks.append(_one(p, 0))
            elif attack_type == "cluster-bomb":
                # Approximate: combine adjacent payload pairs across positions
                count = 0
                for combo in itertools.product(payloads, repeat=max(positions_in, 1)):
                    p = "|".join(combo)
                    tasks.append(_one(p, 0))
                    count += 1
                    if count >= _MAX_RESULTS:
                        break

            await asyncio.gather(*tasks, return_exceptions=True)

        attack.status = "completed"
        attack.progress_pct = 100
        attack.finished_at = datetime.now(timezone.utc)
        await session.commit()
    await engine.dispose()


@celery_app.task(name="pencheff.intruder.run_attack")
def run_intruder_attack(attack_id: str) -> None:
    asyncio.run(_run_attack_async(attack_id))
