"""Best-effort httpx-backed live transport for voice probes. Returns three async
callables (http_get, http_post, submit_audio). Each returns None on failure so
the probe layers (which already handle None) degrade gracefully. v1 assumes a
simple JSON/multipart endpoint; custom shapes (request_template/response_path)
are honored when present, else a sensible default is used."""
from __future__ import annotations

import json
import logging

import httpx

log = logging.getLogger("pencheff.modules.voice_scan.live_transport")
_TIMEOUT = 30.0


def _audio_multipart(cfg: dict) -> tuple[str, dict]:
    """Resolve the multipart shape for the audio POST: the file field NAME and any
    extra form fields. Real STT APIs differ — Sarvam wants ``file`` + ``model`` +
    ``language_code``, others just ``audio``. Sourced from a JSON ``request_template``
    ({"audio_field": "file", "form_fields": {"model": "...", ...}}); defaults to a
    bare ``audio`` field which fits the simplest endpoints."""
    field, form = "audio", {}
    tmpl = cfg.get("request_template")
    if isinstance(tmpl, str) and tmpl.strip():
        try:
            spec = json.loads(tmpl)
        except (ValueError, TypeError):
            spec = None
        if isinstance(spec, dict):
            if isinstance(spec.get("audio_field"), str) and spec["audio_field"]:
                field = spec["audio_field"]
            if isinstance(spec.get("form_fields"), dict):
                form = {str(k): str(v) for k, v in spec["form_fields"].items()}
    return field, form


def _extract_transcript(body, path: str | None):
    """Pull the transcript out of a JSON response via a simple ``$.a.b`` path so the
    verdicts see the spoken text, NOT the whole JSON envelope (which always carries a
    request_id → would false-trigger the hallucination/number probes). Falls back to
    common transcript keys; returns None when nothing matches (caller keeps raw text)."""
    if not isinstance(body, dict):
        return None
    if isinstance(path, str) and path.strip():
        p = path.strip().lstrip("$").lstrip(".")
        cur = body
        for part in [seg for seg in p.split(".") if seg]:
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        if cur is not None:
            return cur if isinstance(cur, str) else json.dumps(cur)
    for k in ("transcript", "text", "transcription", "result"):
        if isinstance(body.get(k), str):
            return body[k]
    return None


def build_live_transport(cfg: dict):
    # Auth headers come from the target's credentials. Support both an arbitrary
    # header map (``credentials.headers`` — e.g. Sarvam's ``api-subscription-key``)
    # and the legacy ``api_key`` shorthand (→ ``Authorization: Bearer``). Probes
    # that need to test the *unauthenticated* posture pass ``auth=False``.
    headers: dict[str, str] = {}
    cred = (cfg.get("credentials") or {}) if isinstance(cfg, dict) else {}
    hdrs = cred.get("headers")
    if isinstance(hdrs, dict):
        headers.update({str(k): str(v) for k, v in hdrs.items()})
    if cred.get("api_key") and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {cred['api_key']}"

    def _hdrs(auth: bool) -> dict[str, str]:
        return dict(headers) if auth else {}

    async def http_get(url, *, auth: bool = True, **kw):
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=_TIMEOUT) as c:
                return await c.get(url, headers=_hdrs(auth), **kw)
        except Exception as e:  # noqa: BLE001
            log.warning("voice http_get failed: %s", e)
            return None

    async def http_post(url, *, auth: bool = True, **kw):
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=_TIMEOUT) as c:
                return await c.post(url, headers=_hdrs(auth), **kw)
        except Exception as e:  # noqa: BLE001
            log.warning("voice http_post failed: %s", e)
            return None

    async def submit_audio(wav_bytes: bytes, kind: str):
        """POST WAV bytes; return {status_code, text, json, raw_text}. ``text`` is the
        extracted transcript (via response_path) so the verdicts judge the spoken
        words, not the JSON envelope; ``raw_text`` keeps the full body for debugging."""
        url = cfg.get("url") or ""
        field, form = _audio_multipart(cfg)
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=_TIMEOUT) as c:
                resp = await c.post(
                    url, headers=headers,
                    files={field: ("probe.wav", wav_bytes, "audio/wav")},
                    data=form or None,
                )
            body = None
            try:
                body = resp.json()
            except Exception:
                body = None
            transcript = _extract_transcript(body, cfg.get("response_path"))
            text = transcript if transcript is not None else resp.text
            return {"status_code": resp.status_code, "text": text,
                    "json": body, "raw_text": resp.text}
        except Exception as e:  # noqa: BLE001
            log.warning("voice submit_audio failed: %s", e)
            return None

    return http_get, http_post, submit_audio
