"""Dispatch findings to the configured external integration (Slack, Teams, ...).

Two surfaces:

* :func:`dispatch_test` — connectivity-check used by ``POST /integrations/{id}/test``.
  Sends a fixed test payload, returns ``{ok, status, response}``.

* :func:`dispatch_event` — lifecycle dispatcher invoked by the Celery
  notify task. Takes one ``Integration`` row and a structured event
  payload (scan_started / scan_done / scan_failed / finding_new /
  finding_changed) and renders the right per-kind message.

Routing logic — which integrations match a given event — lives in
:func:`match_integrations` to keep the per-kind formatters as pure data
transforms.

Phase 1.2 added partner-pentest integrations:

* ``hackerone`` — submits ``finding_new`` rows as draft reports under
  the configured program (HackerOne API v1).
* ``bugcrowd`` — submits ``finding_new`` rows as program submissions
  (Bugcrowd API v3).
* ``cobalt`` — submits findings to a Cobalt pentest's findings list
  (Cobalt API v1).

Generic webhook integrations also gained an opt-in HMAC-SHA256 body
signature (``webhook_secret`` in the integration config). When set, an
``X-Pencheff-Signature: sha256=<hex>`` header is added to every
``webhook`` POST so receivers can verify the body wasn't tampered with
in transit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

log = logging.getLogger(__name__)

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
ALL_EVENTS = ("scan_started", "scan_done", "scan_failed",
              "finding_new", "finding_changed")


async def dispatch_test(kind: str, config: dict[str, Any]) -> dict[str, Any]:
    """Send a test message through the integration to verify connectivity."""
    import httpx

    async def _simple_post(url: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.post(url, json=payload)
            return {"ok": 200 <= r.status_code < 300, "status": r.status_code,
                    "response": r.text[:200]}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    if kind == "slack":
        return await _simple_post(
            config["webhook_url"],
            {"text": ":white_check_mark: Pencheff integration test succeeded."},
        )
    if kind == "teams":
        return await _simple_post(config["webhook_url"], {
            "@type": "MessageCard", "@context": "http://schema.org/extensions",
            "summary": "Pencheff test", "text": "Integration test succeeded.",
        })
    if kind == "discord":
        return await _simple_post(config["webhook_url"],
                                  {"content": "✅ Pencheff integration test succeeded."})
    if kind == "google_chat":
        # Google Chat incoming webhooks accept either a plain ``text`` field
        # for simple messages or a ``cards`` payload for rich formatting.
        # We send the plain shape; the notify task can upgrade to cards
        # when it has structured findings to render.
        return await _simple_post(
            config["webhook_url"],
            {"text": "✅ Pencheff integration test succeeded."},
        )
    if kind == "jira":
        # Jira Cloud REST v3: create a test issue under the configured
        # project to confirm auth + project_key are correct, then delete
        # it (best-effort) so the user's board doesn't fill up.
        try:
            base = config["base_url"].rstrip("/")
            email = config["email"]
            token = config["api_token"]
            project_key = config["project_key"]
            issue_type = config.get("issue_type", "Task")
            payload = {
                "fields": {
                    "project": {"key": project_key},
                    "summary": "Pencheff integration test",
                    "description": {
                        "type": "doc", "version": 1,
                        "content": [{"type": "paragraph", "content": [{
                            "type": "text",
                            "text": "Pencheff integration test — safe to delete.",
                        }]}],
                    },
                    "issuetype": {"name": issue_type},
                },
            }
            async with httpx.AsyncClient(timeout=15.0, auth=(email, token)) as c:
                r = await c.post(f"{base}/rest/api/3/issue",
                                 headers={"Content-Type": "application/json"},
                                 json=payload)
                if 200 <= r.status_code < 300:
                    key = r.json().get("key")
                    # Best-effort cleanup. Failure doesn't affect the test.
                    try:
                        await c.delete(f"{base}/rest/api/3/issue/{key}")
                    except Exception:
                        pass
                    return {"ok": True, "status": r.status_code,
                            "issue_key": key,
                            "issue_url": f"{base}/browse/{key}",
                            "response": "test issue created and cleaned up"}
                return {"ok": False, "status": r.status_code,
                        "response": r.text[:300]}
        except KeyError as e:
            return {"ok": False,
                    "error": f"Missing required field: {e.args[0]}"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    if kind == "pagerduty":
        return await _simple_post("https://events.pagerduty.com/v2/enqueue", {
            "routing_key": config.get("routing_key"),
            "event_action": "trigger",
            "dedup_key": "pencheff-test",
            "payload": {
                "summary": "Pencheff integration test",
                "severity": "info",
                "source": "pencheff",
            },
        })
    if kind == "webhook":
        return await _simple_post(config["webhook_url"], {"test": True, "tool": "pencheff"})
    if kind == "splunk":
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.post(
                    config["hec_url"],
                    headers={"Authorization": f"Splunk {config['token']}"},
                    content='{"event":"Pencheff integration test","sourcetype":"pencheff:test"}',
                )
            return {"ok": 200 <= r.status_code < 300, "status": r.status_code, "response": r.text[:200]}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    if kind == "opsgenie":
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.post(
                    "https://api.opsgenie.com/v2/alerts",
                    headers={"Authorization": f"GenieKey {config['api_key']}"},
                    json={"message": "Pencheff integration test", "priority": "P5"},
                )
            return {"ok": 200 <= r.status_code < 300, "status": r.status_code, "response": r.text[:200]}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    if kind == "hackerone":
        # HackerOne API v1 — connectivity check via GET /v1/me. The
        # ``api_token`` field is the program-scoped API token; the
        # ``api_username`` is the integration user the program owner
        # provisioned. See https://api.hackerone.com/.
        try:
            async with httpx.AsyncClient(
                timeout=10.0,
                auth=(config["api_username"], config["api_token"]),
            ) as c:
                r = await c.get("https://api.hackerone.com/v1/me",
                                headers={"Accept": "application/json"})
            return {"ok": 200 <= r.status_code < 300,
                    "status": r.status_code,
                    "response": r.text[:200]}
        except KeyError as e:
            return {"ok": False, "error": f"Missing required field: {e.args[0]}"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    if kind == "bugcrowd":
        # Bugcrowd Crowdcontrol API v4 — connectivity check via
        # GET /me. ``api_token`` is the personal-access-token issued by
        # a researcher / program owner. See
        # https://docs.bugcrowd.com/api/.
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(
                    "https://api.bugcrowd.com/me",
                    headers={
                        "Authorization": f"Token {config['api_token']}",
                        "Accept": "application/vnd.bugcrowd.v4+json",
                    },
                )
            return {"ok": 200 <= r.status_code < 300,
                    "status": r.status_code,
                    "response": r.text[:200]}
        except KeyError as e:
            return {"ok": False, "error": f"Missing required field: {e.args[0]}"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    if kind == "cobalt":
        # Cobalt API v3 — connectivity check via GET /v3/orgs.
        # ``api_token`` is the personal-access-token issued under
        # Settings → API. See https://api-docs.cobalt.io/.
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(
                    "https://api.cobalt.io/orgs",
                    headers={
                        "X-Api-Key": config["api_token"],
                        "X-Api-Version": "2022-09-15",
                        "Accept": "application/json",
                    },
                )
            return {"ok": 200 <= r.status_code < 300,
                    "status": r.status_code,
                    "response": r.text[:200]}
        except KeyError as e:
            return {"ok": False, "error": f"Missing required field: {e.args[0]}"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": False, "error": f"Unknown integration kind: {kind}"}


# ─────────────────────────────────────────────────────────────────
#                    Per-event lifecycle dispatcher
# ─────────────────────────────────────────────────────────────────


def _sev_idx(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index((sev or "info").lower())
    except ValueError:
        return 0


def integration_matches(
    *,
    integration_target_ids: list[str] | None,
    integration_events: list[str] | None,
    integration_severity_filter: str,
    integration_enabled: bool,
    target_id: str,
    event_type: str,
    finding_severity: str | None = None,
    # Per-feature-001 (S-06): target-kind opt-in. None on the integration
    # row means "all kinds" (forward-compat for legacy rows the migration
    # 0045 backfill missed). None on target_kind means "don't filter by kind"
    # (used by call sites that haven't been migrated yet).
    integration_target_kinds: list[str] | None = None,
    target_kind: str | None = None,
) -> bool:
    """Decide whether one integration row should fire for one event.

    A pure function so it's trivially unit-testable without a DB.
    Mirrors the SQL filter the Celery task uses, plus the severity
    check (which can't be expressed in SQL because it's an ordinal
    comparison on a string column).
    """
    if not integration_enabled:
        return False
    if integration_target_ids and target_id not in integration_target_ids:
        return False
    if integration_events and event_type not in integration_events:
        return False
    # Per-feature-001: filter by target.kind opt-in. Legacy integrations were
    # backfilled to ["url","repo","llm"] by migration 0045; new integrations
    # default to NULL (all kinds) at the application layer.
    if (
        integration_target_kinds is not None
        and target_kind is not None
        and target_kind not in integration_target_kinds
    ):
        return False
    # Severity gate applies only to finding-level events.
    if event_type in ("finding_new", "finding_changed") and finding_severity:
        threshold = _sev_idx(integration_severity_filter)
        if _sev_idx(finding_severity) < threshold:
            return False
    return True


# ── Per-event payload builder ─────────────────────────────────────
#
# The Celery task builds a single ``payload`` dict and hands it to every
# matching integration; the formatters below pick the keys they need.

def build_event_payload(
    *,
    event_type: str,
    target_name: str,
    target_url: str,
    scan_id: str,
    profile: str | None = None,
    grade: str | None = None,
    score: int | None = None,
    summary: dict[str, int] | None = None,
    error: str | None = None,
    finding: dict[str, Any] | None = None,
    change_summary: str | None = None,
    finding_url: str | None = None,
    scan_url: str | None = None,
    target_kind: str | None = None,
    llm_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "event": event_type,
        "target_name": target_name, "target_url": target_url,
        "scan_id": scan_id, "profile": profile,
        "grade": grade, "score": score, "summary": summary or {},
        "error": error,
        "finding": finding,                # dict with severity/title/cvss/endpoint/etc.
        "change_summary": change_summary,  # for finding_changed
        "finding_url": finding_url,
        "scan_url": scan_url,
        # LLM-flavored extras. ``target_kind`` is the Target.kind value
        # ('llm' | 'url' | 'repo'); formatters use it to enable extra
        # rendering. ``llm_summary`` is the output of
        # ``pencheff.modules.llm_red_team.reporting.build_red_team_summary``
        # so chat platforms can show per-OWASP-LLM-category counts and
        # top failed techniques without re-querying the DB.
        "target_kind": target_kind,
        "llm_summary": llm_summary or {},
    }


# ── Per-kind formatters ───────────────────────────────────────────


def _emoji(event_type: str, severity: str | None = None) -> str:
    if event_type == "scan_started": return "🚀"
    if event_type == "scan_done":    return "✅"
    if event_type == "scan_failed":  return "❌"
    if event_type == "finding_new":
        return {"critical": "🚨", "high": "🔴", "medium": "🟠",
                "low": "🟡", "info": "🔵"}.get((severity or "info").lower(), "🔵")
    if event_type == "finding_changed": return "🔁"
    return "•"


def _summary_line(p: dict[str, Any]) -> str:
    s = p.get("summary") or {}
    parts = []
    for k in ("critical", "high", "medium", "low", "info"):
        if s.get(k):
            parts.append(f"{s[k]} {k}")
    return ", ".join(parts) or "no findings"


def _llm_summary_line(p: dict[str, Any]) -> str:
    """LLM-flavored single-line summary: per-category + top techniques."""
    s = p.get("llm_summary") or {}
    if not s:
        return ""
    cats = s.get("by_category") or {}
    top_cats = ", ".join(f"{c} ×{n}" for c, n in list(cats.items())[:3]) if cats else "—"
    techniques = s.get("by_technique") or {}
    top_techs = ", ".join(list(techniques.keys())[:3]) if techniques else "—"
    return f"OWASP LLM: {top_cats} · top techniques: {top_techs}"


def _human_text(p: dict[str, Any]) -> str:
    """Single-line plain-text summary for chat platforms."""
    e = p["event"]
    target = f"{p.get('target_name') or p.get('target_url')}"
    is_llm = p.get("target_kind") == "llm"
    if e == "scan_started":
        prof = f" [{p.get('profile')}]" if p.get("profile") else ""
        kind_tag = " (LLM red team)" if is_llm else ""
        return f"{_emoji(e)} Scan started — {target}{prof}{kind_tag}"
    if e == "scan_done":
        grade = f" Grade {p.get('grade')}" if p.get("grade") else ""
        if is_llm:
            llm = _llm_summary_line(p)
            return (f"{_emoji(e)} LLM red team done — {target} ·{grade} · "
                    f"{_summary_line(p)}\n   {llm}".rstrip())
        return (f"{_emoji(e)} Scan done — {target} ·{grade} · "
                f"{_summary_line(p)}")
    if e == "scan_failed":
        return f"{_emoji(e)} Scan failed — {target}: {(p.get('error') or '')[:200]}"
    if e == "finding_new":
        f = p.get("finding") or {}
        sev = (f.get("severity") or "").upper()
        cvss = f.get("cvss_score")
        cvss_part = f" CVSS {cvss}" if cvss else ""
        ep = f.get("endpoint") or ""
        if str(f.get("owasp_category") or "").startswith("LLM"):
            technique = str(f.get("category") or "").removeprefix("llm_")
            return (f"{_emoji(e, f.get('severity'))} [{sev}] LLM red-team "
                    f"{f.get('owasp_category')} / {technique} — "
                    f"{f.get('title', '')}\n   {ep}".rstrip())
        return (f"{_emoji(e, f.get('severity'))} [{sev}]{cvss_part} — "
                f"{f.get('title', '')}\n   {ep}".rstrip())
    if e == "finding_changed":
        f = p.get("finding") or {}
        return (f"{_emoji(e)} Finding updated — {f.get('title', '')}: "
                f"{p.get('change_summary') or '(no change summary)'}")
    return f"{_emoji(e)} {e}: {target}"


def _slack(p: dict[str, Any]) -> dict[str, Any]:
    return {"text": _human_text(p)}


def _teams(p: dict[str, Any]) -> dict[str, Any]:
    text = _human_text(p)
    return {
        "@type": "MessageCard", "@context": "http://schema.org/extensions",
        "summary": text.splitlines()[0],
        "text": text,
    }


def _google_chat(p: dict[str, Any]) -> dict[str, Any]:
    return {"text": _human_text(p)}


def _discord(p: dict[str, Any]) -> dict[str, Any]:
    return {"content": _human_text(p)}


def _webhook(p: dict[str, Any]) -> dict[str, Any]:
    """Generic webhook gets the structured payload verbatim."""
    out = {"tool": "pencheff", **p}
    finding = p.get("finding") or {}
    if str(finding.get("owasp_category") or "").startswith("LLM"):
        technique = str(finding.get("category") or "").removeprefix("llm_")
        out["llm_redteam"] = {
            "owasp_category": finding.get("owasp_category"),
            "technique": technique,
            "strategy": technique.split(":", 1)[1] if ":" in technique else "base",
            "severity": finding.get("severity"),
            "title": finding.get("title"),
        }
    return out


def _splunk_event(p: dict[str, Any]) -> str:
    """Splunk HEC takes a JSON line; sourcetype tags by event."""
    return json.dumps({
        "event": p,
        "sourcetype": f"pencheff:{p.get('event', 'event')}",
    })


def _opsgenie_payload(p: dict[str, Any]) -> dict[str, Any]:
    e = p["event"]
    if e == "scan_failed":
        return {"message": f"Pencheff: scan failed on {p.get('target_name')}",
                "description": p.get("error") or "", "priority": "P3"}
    if e == "finding_new":
        f = p.get("finding") or {}
        sev = (f.get("severity") or "info").lower()
        prio = {"critical": "P1", "high": "P2", "medium": "P3",
                "low": "P4", "info": "P5"}.get(sev, "P5")
        return {"message": f"[{sev.upper()}] {f.get('title','')}",
                "description": (f.get("description") or "")[:500],
                "priority": prio,
                "details": {"endpoint": f.get("endpoint") or "",
                            "cvss": str(f.get("cvss_score") or ""),
                            "scan_id": p.get("scan_id") or ""}}
    return {"message": _human_text(p), "priority": "P5"}


def _pagerduty_payload(p: dict[str, Any], routing_key: str) -> dict[str, Any]:
    e = p["event"]
    if e == "scan_failed":
        return {"routing_key": routing_key, "event_action": "trigger",
                "dedup_key": f"pencheff-{p.get('scan_id')}-fail",
                "payload": {"summary": f"Pencheff scan failed: {p.get('target_name')}",
                            "severity": "error", "source": "pencheff",
                            "custom_details": {"error": p.get("error") or ""}}}
    if e == "finding_new":
        f = p.get("finding") or {}
        sev_map = {"critical": "critical", "high": "error",
                   "medium": "warning", "low": "info", "info": "info"}
        return {"routing_key": routing_key, "event_action": "trigger",
                "dedup_key": f"pencheff-finding-{f.get('id')}",
                "payload": {"summary": f"[{(f.get('severity') or '').upper()}] {f.get('title','')}",
                            "severity": sev_map.get((f.get("severity") or "info").lower(), "info"),
                            "source": p.get("target_name") or "pencheff",
                            "custom_details": {
                                "endpoint": f.get("endpoint") or "",
                                "cvss": str(f.get("cvss_score") or ""),
                                "scan_id": p.get("scan_id") or "",
                            }}}
    return {"routing_key": routing_key, "event_action": "trigger",
            "dedup_key": f"pencheff-{p.get('scan_id')}-{e}",
            "payload": {"summary": _human_text(p),
                        "severity": "info", "source": "pencheff"}}


# ── HMAC signing for outbound webhooks ────────────────────────────


def sign_webhook_body(secret: str, body: str | bytes) -> str:
    """Return ``sha256=<hex>`` for ``body`` keyed by ``secret``.

    Receivers verify by recomputing the same HMAC-SHA256 over the raw
    request body and comparing in constant time. Format matches GitHub
    / Stripe / Twilio webhook signing conventions.
    """
    if isinstance(body, str):
        body = body.encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_webhook_signature(secret: str, body: str | bytes, header: str) -> bool:
    """Constant-time check used by inbound webhook receivers.

    Pencheff itself doesn't ingest signed webhooks today (the GitHub
    receiver uses GitHub's own format), but partner webhooks that
    bounce back at our scan-control plane in Phase 4.2 will use this.
    Exporting it now so the helper is available to that future code.
    """
    expected = sign_webhook_body(secret, body)
    return hmac.compare_digest(expected, header or "")


# ── Partner pentest formatters ────────────────────────────────────


def _hackerone_payload(p: dict[str, Any]) -> dict[str, Any]:
    """Render a ``finding_new`` event into a HackerOne v1 report body.

    The full v1 schema is documented at
    https://api.hackerone.com/customer-resources/#reports-create. The
    fields below cover the required + commonly-mapped subset.
    """
    f = p.get("finding") or {}
    sev = (f.get("severity") or "info").lower()
    sev_map = {"critical": "critical", "high": "high",
               "medium": "medium", "low": "low", "info": "none"}
    title = f"[Pencheff] {f.get('title') or 'finding'}"[:255]
    body = (
        f"## Vulnerability\n\n{f.get('description') or '(no description)'}\n\n"
        f"## Endpoint\n\n`{f.get('endpoint') or 'n/a'}`\n\n"
        f"## CVSS\n\n{f.get('cvss_score') or 'n/a'}\n\n"
        f"## Detected by\n\nPencheff scan `{p.get('scan_id') or ''}`."
    )
    return {
        "data": {
            "type": "report",
            "attributes": {
                "title": title,
                "vulnerability_information": body[:60_000],
                "impact": (f.get("description") or "")[:5_000],
                "severity_rating": sev_map.get(sev, "none"),
            },
        },
    }


def _bugcrowd_payload(p: dict[str, Any]) -> dict[str, Any]:
    """Render a ``finding_new`` into a Bugcrowd submission body.

    Bugcrowd's submission schema (Crowdcontrol API v4) accepts a
    ``submission`` object under ``data`` with ``title``,
    ``vrt_id``, ``description``, and ``severity``. We map our
    severity onto Bugcrowd's 1-5 (P1–P5) scale.
    """
    f = p.get("finding") or {}
    sev = (f.get("severity") or "info").lower()
    sev_to_p = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
    return {
        "data": {
            "type": "submission",
            "attributes": {
                "title": f"[Pencheff] {(f.get('title') or 'finding')[:200]}",
                "description": (
                    f"{f.get('description') or '(no description)'}\n\n"
                    f"Endpoint: {f.get('endpoint') or 'n/a'}\n"
                    f"CVSS: {f.get('cvss_score') or 'n/a'}\n"
                    f"Pencheff scan: {p.get('scan_id') or ''}"
                )[:60_000],
                "severity": sev_to_p.get(sev, 5),
            },
        },
    }


def _cobalt_payload(p: dict[str, Any]) -> dict[str, Any]:
    """Render a ``finding_new`` into a Cobalt API finding body.

    Cobalt API v3 accepts an ``attributes`` dict under ``data`` with
    ``title``, ``description``, ``severity``, ``status`` (we set
    ``new``). The exact schema is at https://api-docs.cobalt.io/.
    """
    f = p.get("finding") or {}
    return {
        "data": {
            "type": "finding",
            "attributes": {
                "title": f"[Pencheff] {(f.get('title') or 'finding')[:200]}",
                "description": (
                    f"{f.get('description') or '(no description)'}\n\n"
                    f"Endpoint: {f.get('endpoint') or 'n/a'}\n"
                    f"CVSS: {f.get('cvss_score') or 'n/a'}\n"
                    f"Pencheff scan: {p.get('scan_id') or ''}"
                )[:60_000],
                "severity": (f.get("severity") or "info").lower(),
                "status": "new",
            },
        },
    }


# ── Outbound HTTP per kind ────────────────────────────────────────


async def dispatch_event(
    *,
    kind: str,
    config: dict[str, Any],
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Render + send one event for one integration. Never raises;
    failures come back as ``{ok: False, error: ...}`` so the caller
    (Celery task) can log and continue with the next integration."""
    import httpx

    async def _post(url: str, body: Any, headers: dict[str, str] | None = None,
                    auth: Any = None) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, auth=auth) as c:
                r = await c.post(url, json=body if not isinstance(body, str) else None,
                                 content=body if isinstance(body, str) else None,
                                 headers=headers or {})
            return {"ok": 200 <= r.status_code < 300, "status": r.status_code,
                    "response": r.text[:200]}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    try:
        if kind == "slack":
            return await _post(config["webhook_url"], _slack(payload))
        if kind == "teams":
            return await _post(config["webhook_url"], _teams(payload))
        if kind == "google_chat":
            return await _post(config["webhook_url"], _google_chat(payload))
        if kind == "discord":
            return await _post(config["webhook_url"], _discord(payload))
        if kind == "webhook":
            body = _webhook(payload)
            headers: dict[str, str] = {}
            secret = config.get("webhook_secret")
            if secret:
                # Receivers verify the body wasn't tampered with by
                # recomputing the same HMAC-SHA256.
                serialized = json.dumps(body, separators=(",", ":"), sort_keys=True)
                headers["X-Pencheff-Signature"] = sign_webhook_body(
                    str(secret), serialized,
                )
                # When signing, post the exact bytes we signed — not a
                # re-serialized json by httpx — so the signature is
                # reproducible. That means switching to ``content``.
                async with httpx.AsyncClient(timeout=15.0) as c:
                    r = await c.post(
                        config["webhook_url"],
                        content=serialized,
                        headers={**headers, "Content-Type": "application/json"},
                    )
                return {"ok": 200 <= r.status_code < 300,
                        "status": r.status_code,
                        "response": r.text[:200]}
            return await _post(config["webhook_url"], body, headers=headers)
        if kind == "splunk":
            return await _post(
                config["hec_url"], _splunk_event(payload),
                headers={"Authorization": f"Splunk {config['token']}"},
            )
        if kind == "opsgenie":
            return await _post(
                "https://api.opsgenie.com/v2/alerts", _opsgenie_payload(payload),
                headers={"Authorization": f"GenieKey {config['api_key']}"},
            )
        if kind == "pagerduty":
            return await _post(
                "https://events.pagerduty.com/v2/enqueue",
                _pagerduty_payload(payload, config["routing_key"]),
            )
        if kind == "jira":
            return await _jira_dispatch(config, payload)
        if kind == "hackerone":
            # Only ``finding_new`` flows through to a HackerOne report —
            # scan_started / done / failed events stay internal so the
            # program owner's queue isn't flooded with lifecycle noise.
            if payload.get("event") != "finding_new":
                return {"ok": True, "skipped": "non-finding event"}
            return await _post(
                "https://api.hackerone.com/v1/reports",
                _hackerone_payload(payload),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                auth=(config["api_username"], config["api_token"]),
            )
        if kind == "bugcrowd":
            if payload.get("event") != "finding_new":
                return {"ok": True, "skipped": "non-finding event"}
            program_uuid = config["program_uuid"]
            return await _post(
                f"https://api.bugcrowd.com/programs/{program_uuid}/submissions",
                _bugcrowd_payload(payload),
                headers={
                    "Authorization": f"Token {config['api_token']}",
                    "Accept": "application/vnd.bugcrowd.v4+json",
                    "Content-Type": "application/vnd.bugcrowd.v4+json",
                },
            )
        if kind == "cobalt":
            if payload.get("event") != "finding_new":
                return {"ok": True, "skipped": "non-finding event"}
            return await _post(
                f"https://api.cobalt.io/pentests/{config['pentest_id']}/findings",
                _cobalt_payload(payload),
                headers={
                    "X-Api-Key": config["api_token"],
                    "X-Api-Version": "2022-09-15",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
    except KeyError as e:
        return {"ok": False, "error": f"Missing config field: {e.args[0]}"}
    return {"ok": False, "error": f"Unknown integration kind: {kind}"}


async def _jira_dispatch(config: dict[str, Any], p: dict[str, Any]) -> dict[str, Any]:
    """Jira: create one issue per finding_new; comment on finding_changed
    if we have the prior issue key on the finding's external_refs.

    For scan_started/done/failed we create a tracking issue summarising
    the scan — this keeps the project's audit trail complete without
    flooding it with one issue per alert. Workspaces that don't want
    those events on Jira can untick them in the integration's events
    list.
    """
    import httpx

    base = config["base_url"].rstrip("/")
    auth = (config["email"], config["api_token"])
    project_key = config["project_key"]
    issue_type = config.get("issue_type", "Task")

    e = p["event"]
    if e == "finding_new":
        f = p.get("finding") or {}
        body = {"fields": {
            "project": {"key": project_key},
            "issuetype": {"name": issue_type},
            "summary": f"[{(f.get('severity') or 'info').upper()}] {f.get('title','')}",
            "description": _jira_doc(
                f"**Severity:** {f.get('severity','info')}  "
                f"**CVSS:** {f.get('cvss_score','n/a')}\n\n"
                f"**Endpoint:** {f.get('endpoint','')}\n\n"
                f"{(f.get('description') or '')[:2000]}\n\n"
                f"_Pencheff scan {p.get('scan_id','')}_"),
        }}
    elif e == "scan_done":
        body = {"fields": {
            "project": {"key": project_key},
            "issuetype": {"name": issue_type},
            "summary": f"Pencheff scan done: {p.get('target_name')}",
            "description": _jira_doc(
                f"Grade {p.get('grade','?')} · {_summary_line(p)}\n"
                f"Scan {p.get('scan_id','')}"),
        }}
    elif e == "scan_failed":
        body = {"fields": {
            "project": {"key": project_key},
            "issuetype": {"name": issue_type},
            "summary": f"Pencheff scan FAILED: {p.get('target_name')}",
            "description": _jira_doc(p.get("error") or "(no error message)"),
        }}
    elif e == "scan_started":
        body = {"fields": {
            "project": {"key": project_key},
            "issuetype": {"name": issue_type},
            "summary": f"Pencheff scan started: {p.get('target_name')}",
            "description": _jira_doc(
                f"Profile: {p.get('profile') or 'standard'}\nScan {p.get('scan_id','')}"),
        }}
    elif e == "finding_changed":
        # Best-effort: if the worker passed an existing issue key, comment
        # on it. Otherwise create a new tracking issue so the change is
        # still visible.
        f = p.get("finding") or {}
        existing_key = (f.get("external_refs") or {}).get(f"jira:{project_key}")
        if existing_key:
            try:
                async with httpx.AsyncClient(timeout=15.0, auth=auth) as c:
                    r = await c.post(
                        f"{base}/rest/api/3/issue/{existing_key}/comment",
                        json={"body": _jira_doc(
                            f"Pencheff update: {p.get('change_summary') or ''}\n"
                            f"Scan {p.get('scan_id','')}")},
                    )
                return {"ok": 200 <= r.status_code < 300,
                        "status": r.status_code,
                        "issue_key": existing_key,
                        "response": r.text[:200]}
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        body = {"fields": {
            "project": {"key": project_key},
            "issuetype": {"name": issue_type},
            "summary": f"[update] {f.get('title','(unknown finding)')}",
            "description": _jira_doc(
                f"{p.get('change_summary') or ''}\n\nScan {p.get('scan_id','')}"),
        }}
    else:
        return {"ok": False, "error": f"unknown event for jira: {e}"}

    try:
        async with httpx.AsyncClient(timeout=15.0, auth=auth) as c:
            r = await c.post(f"{base}/rest/api/3/issue",
                             headers={"Content-Type": "application/json"},
                             json=body)
        if 200 <= r.status_code < 300:
            return {"ok": True, "status": r.status_code,
                    "issue_key": r.json().get("key"),
                    "issue_url": f"{base}/browse/{r.json().get('key')}"}
        return {"ok": False, "status": r.status_code, "response": r.text[:300]}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _jira_doc(text: str) -> dict[str, Any]:
    """Wrap a string in Atlassian Document Format."""
    return {
        "type": "doc", "version": 1,
        "content": [{"type": "paragraph",
                     "content": [{"type": "text", "text": text or ""}]}],
    }
