# pencheff/modules/voice_scan/module.py
"""Voice/Speech-AI scan module: static transport probes (always, best-effort) +
consent-gated dynamic audio probes. Mirrors the mcp_scan best-effort pattern."""
from __future__ import annotations

import logging

from pencheff.core.findings import Finding
from pencheff.modules.base import BaseTestModule

from .dynamic_probes import run_dynamic_probes
from .transport_probes import run_transport_probes
from .tts_probes import run_tts_probes

log = logging.getLogger("pencheff.modules.voice_scan.module")


class VoiceScanModule(BaseTestModule):
    name = "voice_scan"
    category = "Voice / Speech AI Security"
    owasp_categories = ["LLM01"]
    description = ("Probe an STT/TTS/voice-bot/voice-auth endpoint for transport "
                   "exposure, cross-modal audio injection, ultrasonic commands, "
                   "and voice-auth spoofing.")

    async def run(self, session, http=None, targets=None, config=None) -> list[Finding]:
        cfg = (config or {}).get("voice_config") or {}
        http_get = getattr(session, "voice_http_get", None)
        http_post = getattr(session, "voice_http_post", None)
        submit_audio = getattr(session, "voice_submit_audio", None)
        oast = getattr(session, "oast_handle", None)
        findings: list[Finding] = []
        log.info("scan_progress: probing voice transport (%s)", cfg.get("transport") or "http")
        try:
            findings.extend(await run_transport_probes(cfg, http_get=http_get,
                                                       http_post=http_post, oast=oast))
        except Exception as e:  # noqa: BLE001
            log.warning("voice transport probes failed: %s", e)
        # Consent gate: dynamic submission only when audio_probes is set.
        if cfg.get("audio_probes"):
            try:
                findings.extend(await run_dynamic_probes(cfg, submit_audio=submit_audio))
            except Exception as e:  # noqa: BLE001
                log.warning("voice dynamic probes failed: %s", e)
            if cfg.get("source_type") == "tts_endpoint":
                try:
                    findings.extend(await run_tts_probes(cfg, http_post=http_post, oast=oast))
                except Exception as e:  # noqa: BLE001
                    log.warning("voice tts probes failed: %s", e)
        return findings

    def get_techniques(self) -> list[str]:
        return [
            "voice:exposed-endpoint",
            "voice:auth-rejected",
            "voice:ssrf",
            "voice:resource-abuse",
            "voice:transcription-injection",
            "voice:ultrasonic-command",
            "voice:auth-spoof",
            "voice:replay-attack",
            "voice:ssml-injection",
            "voice:ssml-parse-abuse",
            "voice:adversarial-audio",
            "voice:transcript-hallucination",
            "voice:number-confusion",
            "voice:homophone-confusion",
        ]
