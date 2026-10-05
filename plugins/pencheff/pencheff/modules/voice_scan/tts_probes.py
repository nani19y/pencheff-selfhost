# pencheff/modules/voice_scan/tts_probes.py
"""Consent-gated TTS-endpoint probes (text input → SSML attacks). http_post/oast
are injected by the live transport; None → no-op (unit-test mode). Never raises.

TTS endpoints take TEXT, so these use http_post (not submit_audio)."""
from __future__ import annotations

import logging

from pencheff.config import Severity
from pencheff.core.findings import Finding

log = logging.getLogger("pencheff.modules.voice_scan.tts_probes")


def _post_body(cfg: dict, ssml: str) -> dict:
    """Honor cfg['request_template'] when present (substitute {{prompt}} with the
    SSML); else default to {'text': ssml} JSON — mirrors live_transport posture."""
    tmpl = cfg.get("request_template")
    if isinstance(tmpl, str) and "{{prompt}}" in tmpl:
        return {"content": tmpl.replace("{{prompt}}", ssml)}
    return {"json": {"text": ssml}}


async def run_tts_probes(cfg: dict, http_post=None, oast=None) -> list[Finding]:
    if http_post is None:
        return []
    url = cfg.get("url") or ""
    out: list[Finding] = []

    # 1. SSML external-resource injection → SSRF (OAST-gated)
    if oast is not None:
        try:
            canary = oast.new_url() if hasattr(oast, "new_url") else None
            if canary:
                ssml = f'<speak>Hello <audio src="{canary}">fallback</audio> world.</speak>'
                await http_post(url, **_post_body(cfg, ssml))
                hit = oast.poll() if hasattr(oast, "poll") else None
                if hit:
                    out.append(Finding(
                        title="TTS endpoint fetches external SSML <audio src> (SSRF)",
                        severity=Severity.HIGH, category="voice_ssml_injection",
                        owasp_category="LLM01", cwe_id="CWE-918",
                        description=(
                            "The TTS engine fetched an attacker-controlled URL referenced from "
                            f"SSML <audio src> ({canary}). SSML markup is processed as a fetch "
                            "instruction — server-side request forgery via speech markup."
                        ),
                        remediation=(
                            "Disallow external resource references in SSML (<audio src>, lexicon "
                            "URIs); restrict to an allowlist; block internal address ranges."
                        ),
                        endpoint=url, metadata={"technique": "voice:ssml-injection"},
                    ))
        except Exception as e:  # noqa: BLE001
            log.warning("voice ssml-injection probe failed: %s", e)

    # 2. SSML parse / resource abuse (malformed, deeply-nested markup)
    try:
        malformed = "<speak>" + ("<prosody rate='x-fast'>" * 200) + "boom"  # unbalanced/nested
        resp = await http_post(url, **_post_body(cfg, malformed))
        if resp is not None and int(getattr(resp, "status_code", 0)) >= 500:
            out.append(Finding(
                title="TTS endpoint mishandles malformed/nested SSML",
                severity=Severity.MEDIUM, category="voice_ssml_parse_abuse",
                owasp_category="LLM01", cwe_id="CWE-400",
                description=(
                    "Deeply-nested/unbalanced SSML caused a server error — missing markup "
                    "validation, a parser-resource-exhaustion vector."
                ),
                remediation="Validate and bound SSML depth/size before parsing; add parser timeouts/quotas.",
                endpoint=url, metadata={"technique": "voice:ssml-parse-abuse"},
            ))
    except Exception as e:  # noqa: BLE001
        log.warning("voice ssml-parse-abuse probe failed: %s", e)

    return out
