"""Request-template parameter fuzzer.

Caller supplies:
  - a request template ``{url, method, headers, body}``
  - the parameter(s) to fuzz, each with a wordlist identifier
  - optional transformation encoders (url, base64, case-flip, ...)

The fuzzer replaces ``FUZZ`` markers in the template with each payload (also
supports JSON-path-style parameter injection into body) and records the
response. Differential analysis then flags anomalies.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from pencheff.modules.fuzzing import payload_engine

WORDLIST_DIR = Path(__file__).parent / "wordlists"


@dataclass
class FuzzResult:
    payload: str
    status: int
    resp_length: int
    resp_hash: str
    latency_ms: float
    reflected: bool = False
    interesting: bool = False
    reason: str = ""


@dataclass
class FuzzRun:
    template: dict[str, Any]
    param: str
    wordlist: str
    encoders: list[str]
    baseline: FuzzResult | None = None
    results: list[FuzzResult] = field(default_factory=list)


def list_wordlists() -> list[str]:
    if not WORDLIST_DIR.exists():
        return []
    return sorted(p.stem for p in WORDLIST_DIR.glob("*.txt"))


def load_wordlist(name: str) -> list[str]:
    path = WORDLIST_DIR / f"{name}.txt"
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]


async def run(
    template: dict[str, Any],
    param: str,
    wordlist: str,
    encoders: list[str] | None = None,
    concurrency: int = 8,
    timeout: float = 10.0,
) -> FuzzRun:
    words = load_wordlist(wordlist)
    encs = tuple(encoders or [])
    payloads: list[str] = []
    for w in words:
        payloads.extend(payload_engine.apply(w, encs))
    run_obj = FuzzRun(template=template, param=param, wordlist=wordlist, encoders=list(encs))

    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=True,
    ) as client:
        run_obj.baseline = await _send(client, template, param, _canary_payload())

        async def one(p: str) -> None:
            async with sem:
                r = await _send(client, template, param, p)
                _classify(r, run_obj.baseline, p)
                run_obj.results.append(r)

        await asyncio.gather(*(one(p) for p in payloads))
    return run_obj


async def _send(
    client: httpx.AsyncClient, template: dict[str, Any], param: str, payload: str
) -> FuzzResult:
    url = _inject(template.get("url", ""), param, payload)
    method = (template.get("method") or "GET").upper()
    headers = {k: _inject(v, param, payload) for k, v in (template.get("headers") or {}).items()}
    body_in = template.get("body")
    body = _inject_body(body_in, param, payload)

    import time
    start = time.monotonic()
    try:
        resp = await client.request(method, url, headers=headers, content=body)
    except Exception as e:  # noqa: BLE001
        return FuzzResult(payload=payload, status=0, resp_length=0, resp_hash="",
                          latency_ms=(time.monotonic() - start) * 1000,
                          reason=f"request-error: {type(e).__name__}")
    latency = (time.monotonic() - start) * 1000
    body_text = resp.text
    reflected = payload in body_text and len(payload) >= 4
    return FuzzResult(
        payload=payload,
        status=resp.status_code,
        resp_length=len(resp.content),
        resp_hash=hashlib.sha1(resp.content, usedforsecurity=False).hexdigest()[:16],
        latency_ms=latency,
        reflected=reflected,
    )


def _canary_payload() -> str:
    # Distinctive token to establish a baseline response
    return "pencheff_baseline_XyZ123"


def _inject(value: str, param: str, payload: str) -> str:
    if not isinstance(value, str):
        return value
    if "FUZZ" in value:
        return value.replace("FUZZ", payload)
    # If ?param= appears, replace its value up to the next & or end
    if f"{param}=" in value:
        import re
        return re.sub(rf"({re.escape(param)}=)[^&]*", r"\1" + payload, value)
    return value


def _inject_body(body: Any, param: str, payload: str) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, dict):
        out = dict(body)
        if param in out:
            out[param] = payload
        return json.dumps(out).encode()
    if isinstance(body, str):
        return _inject(body, param, payload).encode()
    if isinstance(body, bytes):
        return body
    return None


def _classify(
    r: FuzzResult, baseline: FuzzResult | None, payload: str
) -> None:
    if r.status == 0:
        r.interesting = True
        r.reason = "network-error"
        return
    if r.reflected:
        r.interesting = True
        r.reason = "payload-reflected"
        return
    if baseline:
        if r.status != baseline.status:
            r.interesting = True
            r.reason = f"status-diff baseline={baseline.status} got={r.status}"
            return
        if r.resp_hash != baseline.resp_hash and abs(r.resp_length - baseline.resp_length) > 50:
            r.interesting = True
            r.reason = f"length-diff {r.resp_length - baseline.resp_length:+d}"
            return
        if r.latency_ms > baseline.latency_ms * 3 and r.latency_ms > 1000:
            r.interesting = True
            r.reason = f"latency-spike {r.latency_ms:.0f}ms vs baseline {baseline.latency_ms:.0f}ms"
            return
