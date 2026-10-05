# Voice / Speech AI — Source-Aware Registration & Attack-Specific Scanning

- **Date:** 2026-06-17
- **Status:** Draft design → awaiting approval
- **Series:** 5th (final) AI target type. New wire kind `voice`. Mirrors the per-type pattern.

---

## 1. Goal

Turn the "Voice / Speech AI" card (currently `kind="llm"`) into a first-class target that probes STT / TTS / voice-bot / voice-auth endpoints for the research-validated voice-AI attack surface (§7).

## 2. Honest scoping note (this is the heaviest type — greenfield audio)

No audio infra exists in the repo. Voice scanning inherently needs (a) **audio synthesis** (craft adversarial WAVs) and (b) **audio transport** (send to STT/voice endpoints). v1 keeps deps minimal: **stdlib `wave` + `numpy`** for WAV synthesis (no librosa/pydub/torch). The **pure synthesis + verdict logic is unit-tested**; live endpoint probing is best-effort/consent-gated/non-fatal (like the MCP/RAG dynamic layers). The most research-grade attacks (psychoacoustic masking, over-the-air) are approximated/deferred — see §11.

## 3. Scope decisions

| Decision                | Choice                                                                                                                                               |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Modeling                | New wire kind `voice` + `VoiceConfig` (no migration).                                                                                                |
| Sources (v1)            | `stt_endpoint` (audio→text), `voice_bot` (audio→LLM→response/action), `voice_auth` (speaker verification), `tts_endpoint` (text→audio).              |
| Static                  | Always: endpoint/transport posture (auth, audio-URL SSRF surface, file-handling, resource limits) — the research-flagged gap, standard + high-value. |
| Dynamic (consent-gated) | Submit crafted audio + observe — transcription/cross-modal injection, ultrasonic hidden-command, voice-auth spoofing. Best-effort.                   |

## 4. Architecture & data flow

```
Register (kind="voice", VoiceConfig.source_type)
  → Commission scan (consent: voice_enumerate / voice_audio_probe / voice_auth_probe)
  → scan_runner dispatches kind="voice" → scan_voice (mirrors scan_mcp)
  → pencheff voice_scan orchestrator:
       ├─ STATIC transport probes (always): endpoint auth, audio-URL SSRF (OAST-backed), file-format/size handling, resource abuse
       └─ [consent] DYNAMIC audio probes:
            ├─ transcription/cross-modal injection: synth audio carrying an injected instruction → submit → does transcript/response follow it? (OWASP LLM01 multimodal)
            ├─ ultrasonic hidden-command: synth ultrasonic-modulated WAV (numpy) → submit → transcript matches hidden command?
            └─ voice-auth spoofing: synth/altered speaker audio → submit to voice_auth → accepted?
  → Findings (OWASP LLM01 + voice:* technique, CVSS, CWE) → DB → report
```

New engineering: `voice_scan` module — audio generators (numpy/wave, pure) + verdict logic (pure) + endpoint transport (httpx/OAST, best-effort).

## 5. Registration & config — `VoiceConfig`

```
kind: "voice"
source_type: "stt_endpoint" | "voice_bot" | "tts_endpoint" | "voice_auth"
url: str                         # endpoint
audio_format: "wav" | "mp3" | "flac" | "ogg" = "wav"
request_template / response_path: str | None   # how to send audio + read result (custom shapes)
injection_phrase: str | None     # the instruction to embed in cross-modal probes (default a canary)
audio_probes: bool = False       # gate dynamic audio submission
```

Auth → `kind_credentials_encrypted`. New FE `VoiceFormSection` (source_type picker). Validation: all → url; voice_auth → audio_probes recommended.

## 6. Scanner analyzers

### 6a. Static transport/posture probes (always; the research gap, standard checks)

Endpoint reachable without auth? audio-URL parameter → SSRF (OAST canary)? file-format/size validation (oversized/malformed audio handling)? rate/resource limits? → `voice:exposed-endpoint`/`voice:ssrf`/`voice:resource-abuse`, CWE-306/918/400.

### 6b. Audio synthesis (pure numpy/`wave` — unit-tested)

- `synth_speechlike_wav(text_marker)` — a deterministic WAV carrying a recognizable marker (for cross-modal probes; v1 uses a tone/marker pattern, NOT real TTS — note: real spoken injection needs a TTS dep, deferred; the probe still works against STT if the marker is detectable, else it's a transport/format test).
- `synth_ultrasonic_command_wav(carrier_hz=21000)` — DolphinAttack-style: modulate a payload onto an ultrasonic carrier (verify spectrally in tests).
- `synth_perturbed_wav(base, eps)` — small-perturbation variant (adversarial-lite).

### 6c. Dynamic audio probes (consent: voice_audio_probe; best-effort)

- **Cross-modal / transcription injection** (OWASP LLM01 multimodal — the headline): submit injection-carrying audio, observe whether the transcript/voice-bot response follows the injected instruction (reuse the text-verdict idea: does the response contain the injected marker / comply). → `voice:transcription-injection`, high, LLM01.
- **Ultrasonic hidden command**: submit `synth_ultrasonic_command_wav`, check if transcript == hidden command. → `voice:ultrasonic-command`, high.

### 6d. Voice-auth spoofing (consent: voice_auth_probe; voice_auth source)

Submit synthetic/altered speaker audio to a voice-auth endpoint; if accepted (2xx/verified), flag. → `voice:auth-spoof`, critical, CWE-287/290.

## 7. Attack catalog (research-validated, cited — §10)

| Attack                                               | Detection   | Mapping / Source                                                 |
| ---------------------------------------------------- | ----------- | ---------------------------------------------------------------- |
| Ultrasonic inaudible commands                        | 6b+6c       | LLM01 · DolphinAttack (CCS'17, arXiv 1708.09537)                 |
| Psychoacoustic-hidden adversarial audio              | 6b (approx) | LLM01 · Schönherr NDSS'19, Qin-Carlini ICML'19                   |
| Cross-modal / transcription prompt injection         | 6c          | LLM01 (multimodal) · OWASP LLM01:2025; AudioJailbreak; JALMBench |
| Voice cloning / speaker spoofing                     | 6d          | CWE-287/290 · ASVspoof 5 (Malafide/Malacopula)                   |
| STT/TTS pipeline transport (auth/SSRF/file/resource) | 6a          | CWE-306/918/400 · (research gap — standard web checks)           |

Reference benchmarks: **JALMBench**, **ASVspoof 5**, VAS threat survey.

## 8. Consent & safety

Add `voice` to `KIND_REQUIRED_DISCLOSED_ACTIONS`: `voice_enumerate` (static transport probes; always), `voice_audio_probe` (submit crafted audio; gated by `audio_probes`), `voice_auth_probe` (voice-auth spoofing; gated, nested under audio_probes). Graduated like mcp. `start_scan` gate until scanner ships. Sending crafted audio to a third-party endpoint is consent-gated; intended for owned/authorized targets.

## 9. Findings / profiles / FE / dispatch

Reuse Finding/judge/reporting + OAST + the LlmProbe verdict idea (does the response follow the injection). Profiles: Quick = static transport; Standard = + cross-modal injection; Deep = + ultrasonic + auth-spoof. FE: `VoiceFormSection`, consent vocab, list/detail/edit, badge. BE: TargetKind/Config/union; consent; `scan_runner` `voice` dispatch (mirror mcp) + `_run_voice_scan`; pencheff `scan_voice` tool + `voice_scan` module; migration marker. Deps: add `numpy` to plugins/pencheff if not present (stdlib `wave` for WAV I/O).

## 10. Sources (primary, verified 2026-06-17)

- **DolphinAttack** — Zhang et al., ACM CCS 2017 (arXiv 1708.09537).
- **Schönherr et al.** psychoacoustic hiding — NDSS 2019 (arXiv 1808.05665); **Qin/Carlini et al.** — ICML 2019 (arXiv 1903.10346).
- **CommanderSong** — USENIX Security 2018 (arXiv 1801.08535).
- **OWASP LLM01:2025** (multimodal/cross-modal injection). **AudioJailbreak**; **JALMBench**; **ASVspoof 5** (Malafide/Malacopula).

## 11. Out of scope v1 (honest)

Real TTS-synthesized spoken injection (needs a TTS dep — v1 uses marker/tone audio + the cross-modal verdict; deferred); full psychoacoustic-masking + over-the-air robustness (research-grade DSP — v1 does digital/file submission only); watermark-evasion analysis; deepfake-voice generation. The static transport probes + ultrasonic generator + cross-modal injection probe are the testable, high-value v1 core.
