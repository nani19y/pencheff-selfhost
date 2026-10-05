# pencheff/modules/voice_scan/transport_probes.py
"""Static transport/posture probes for a voice endpoint. Best-effort: live HTTP
is injected via http_get/http_post; when None the probes are no-ops (unit-test
mode), mirroring mcp_scan.transport_probes. Never raises."""
from __future__ import annotations

import logging

from pencheff.config import Severity
from pencheff.core.findings import Finding

log = logging.getLogger("pencheff.modules.voice_scan.transport_probes")


async def run_transport_probes(cfg: dict, http_get=None, http_post=None, oast=None) -> list[Finding]:
    if http_get is None:
        return []
    url = cfg.get("url") or ""
    cred = (cfg.get("credentials") or {}) if isinstance(cfg, dict) else {}
    has_creds = bool(cred.get("headers") or cred.get("api_key"))
    out: list[Finding] = []

    def _reachable_finding() -> Finding:
        return Finding(
            title="Voice endpoint reachable without authentication",
            severity=Severity.HIGH, category="voice_exposed_endpoint",
            owasp_category="LLM01", cwe_id="CWE-306",
            description=(
                f"The voice endpoint {url!r} responded to an unauthenticated "
                "request. Anyone can submit audio for transcription / bot "
                "actions / auth without a credential."
            ),
            remediation="Require authentication (API key / OAuth / mTLS) and rate-limit.",
            endpoint=url, metadata={"technique": "voice:exposed-endpoint"},
        )

    def _auth_required_finding(status: int) -> Finding:
        # The endpoint enforces auth (good) but NO credentials were supplied, so
        # the deeper probes couldn't run — the scan is blind. Surface that instead
        # of silently grading the target clean (A).
        return Finding(
            title="Voice endpoint requires authentication — scan ran without credentials",
            severity=Severity.INFO, category="voice_auth_required",
            owasp_category="LLM01", cwe_id="CWE-287",
            description=(
                f"The voice endpoint {url!r} rejected the unauthenticated probe "
                f"with HTTP {status}. No credentials were provided, so the audio "
                "injection / SSRF / resource-abuse probes could not run and this "
                "assessment is incomplete — not a clean bill of health."
            ),
            remediation=(
                "Re-run with an API key / bearer token / custom auth header "
                "(Authentication section on the target form) so Pencheff can "
                "test the authenticated surface."
            ),
            endpoint=url, metadata={"technique": "voice:auth-required", "status": status},
        )

    # 1. Unauthenticated exposure. Always probe WITHOUT credentials so a 2xx
    #    genuinely means "reachable with no auth". Try GET first, then a POST —
    #    STT/voice endpoints are POST-only, so a GET yields 404/405 and would miss
    #    the auth posture entirely (leaving a credential-blind scan graded clean).
    exposure_flagged = False
    seen = {}
    for method in ("get", "post"):
        if exposure_flagged:
            break
        try:
            if method == "get":
                resp = await http_get(url, auth=False)
            elif http_post is not None:
                resp = await http_post(url, auth=False,
                                       files={"audio": ("probe.wav", b"\x00" * 512, "audio/wav")})
            else:
                continue
            status = int(getattr(resp, "status_code", 0)) if resp is not None else 0
            seen[method] = status
            if 200 <= status < 300:
                out.append(_reachable_finding()); exposure_flagged = True
            elif status in (401, 403) and not has_creds:
                out.append(_auth_required_finding(status)); exposure_flagged = True
        except Exception as e:  # noqa: BLE001
            log.warning("voice %s exposure probe failed: %s", method, e)
    # Persisted trace line (starts with "probing" so it survives in scan.log).
    posture = ("reachable WITHOUT auth" if exposure_flagged and any(200 <= v < 300 for v in seen.values())
               else "auth enforced" if any(v in (401, 403) for v in seen.values())
               else "no clear auth signal")
    log.info("scan_progress: probing exposure — unauth GET=%s POST=%s · %s",
             seen.get("get", "n/a"), seen.get("post", "n/a"), posture)

    # 1b. Credentials SUPPLIED but REJECTED. If the operator gave creds yet an
    #     authenticated probe still returns 401/403, the auth scheme is wrong
    #     (e.g. 'Authorization: Bearer' where the API wants a custom key header
    #     like 'api-subscription-key'). The authenticated surface went untested —
    #     never grade that clean.
    if has_creds and http_post is not None:
        try:
            resp = await http_post(url, auth=True,
                                   files={"audio": ("probe.wav", b"\x00" * 512, "audio/wav")})
            status = int(getattr(resp, "status_code", 0)) if resp is not None else 0
            log.info("scan_progress: probing auth — credentials %s (HTTP %s)",
                     "REJECTED" if status in (401, 403) else "accepted", status)
            if status in (401, 403):
                out.append(Finding(
                    title="Supplied credentials were rejected — authenticated surface not tested",
                    severity=Severity.LOW, category="voice_auth_rejected",
                    owasp_category="LLM01", cwe_id="CWE-287",
                    description=(
                        f"The voice endpoint {url!r} rejected the request with HTTP {status} even "
                        "though credentials were supplied. The auth scheme is likely wrong — e.g. an "
                        "'Authorization: Bearer' header where the API expects a custom key header "
                        "such as 'api-subscription-key'. The audio-injection / SSRF / resource-abuse "
                        "probes could not run, so this is a blind scan, not a clean result."
                    ),
                    remediation=(
                        "Check the exact auth header NAME and value the provider expects (not every "
                        "API uses 'Authorization: Bearer') and re-run. This assessment did not "
                        "exercise the authenticated surface."
                    ),
                    endpoint=url, metadata={"technique": "voice:auth-rejected", "status": status},
                ))
        except Exception as e:  # noqa: BLE001
            log.warning("voice authed-reachability probe failed: %s", e)

    # 2. Audio-URL SSRF (only when an OAST canary is available)
    if oast is not None and http_post is not None:
        try:
            canary = oast.new_url() if hasattr(oast, "new_url") else None
            if canary:
                # Try the common remote-fetch param names — endpoints vary
                # (audio_url / url / file_url / source / callback_url / webhook_url).
                for param in ("audio_url", "url", "file_url", "audio", "source",
                              "callback_url", "webhook_url"):
                    await http_post(url, json={param: canary})
                hit = oast.poll() if hasattr(oast, "poll") else None
                if hit:
                    out.append(Finding(
                        title="Voice endpoint fetches attacker-supplied audio URL (SSRF)",
                        severity=Severity.HIGH, category="voice_ssrf",
                        owasp_category="LLM01", cwe_id="CWE-918",
                        description=f"The endpoint fetched an attacker-controlled audio URL ({canary}).",
                        remediation="Disallow remote audio URLs or restrict to an allowlist; block internal ranges.",
                        endpoint=url, metadata={"technique": "voice:ssrf"},
                    ))
        except Exception as e:  # noqa: BLE001
            log.warning("voice ssrf probe failed: %s", e)
    # 3. Oversized/malformed audio handling
    if http_post is not None:
        try:
            resp = await http_post(url, content=b"\x00" * (5 * 1024 * 1024))
            if resp is not None and int(getattr(resp, "status_code", 0)) >= 500:
                out.append(Finding(
                    title="Voice endpoint mishandles oversized/malformed audio",
                    severity=Severity.MEDIUM, category="voice_resource_abuse",
                    owasp_category="LLM01", cwe_id="CWE-400",
                    description="A 5 MB junk payload caused a server error — missing size/format validation.",
                    remediation="Enforce max audio size, validate format before processing, add timeouts/quotas.",
                    endpoint=url, metadata={"technique": "voice:resource-abuse"},
                ))
        except Exception as e:  # noqa: BLE001
            log.warning("voice resource probe failed: %s", e)
    return out
