"""Transactional email via Resend (https://resend.com).

A very small wrapper — Resend's API is a single POST to /emails. We talk
to it directly with httpx (already a dependency) rather than pulling the
official SDK for a one-call feature.

Behaviour when Resend is not configured (``RESEND_API_KEY`` is empty):
  * ``send_invite_email`` returns ``False`` and logs a warning.
  * The caller (org-invite endpoint) keeps returning the raw token in the
    POST response so the admin can copy-share the link — we never block
    invites on email delivery.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from ..config import get_settings

_log = logging.getLogger("pencheff.email")

_RESEND_URL = "https://api.resend.com/emails"
_TIMEOUT = 10.0


def _resend_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def is_configured() -> bool:
    return bool(get_settings().resend_api_key)


def _send(payload: dict[str, Any]) -> bool:
    settings = get_settings()
    if not settings.resend_api_key:
        _log.info("resend not configured — skipping email to %s", payload.get("to"))
        return False
    try:
        resp = httpx.post(
            _RESEND_URL,
            headers=_resend_headers(settings.resend_api_key),
            json=payload,
            timeout=_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        _log.warning("resend request failed: %s", exc)
        return False
    if resp.status_code >= 400:
        _log.warning(
            "resend returned %s for email to %s: %s",
            resp.status_code,
            payload.get("to"),
            resp.text[:400],
        )
        return False
    return True


def _invite_html(org_name: str, inviter_name: str | None, role: str, url: str) -> str:
    who = inviter_name or "A teammate"
    # Minimal inlined-CSS HTML — email clients are picky; keep it simple.
    return f"""
    <!doctype html>
    <html>
      <body style="margin:0;padding:32px;background:#f4efe3;font-family:Georgia,serif;color:#2a2a2a;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
               style="max-width:560px;margin:0 auto;background:#ffffff;
                      border:1px solid #d8d3c4;border-radius:4px;padding:40px;">
          <tr><td>
            <p style="font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:#8a8374;margin:0 0 16px;">
              Pencheff · Invitation
            </p>
            <h1 style="font-size:24px;line-height:1.25;margin:0 0 16px;color:#1a1a1a;">
              You've been invited to join {org_name}.
            </h1>
            <p style="font-size:15px;line-height:1.6;margin:0 0 24px;">
              {who} has invited you to join <strong>{org_name}</strong> on Pencheff
              as a <strong>{role}</strong>. Pencheff delivers adversarial security
              assessments with the rigour of an audit.
            </p>
            <p style="margin:0 0 32px;">
              <a href="{url}"
                 style="display:inline-block;background:#1a1a1a;color:#ffffff;
                        text-decoration:none;padding:12px 22px;border-radius:3px;
                        font-family:Helvetica,Arial,sans-serif;font-size:14px;
                        letter-spacing:0.04em;">
                Accept invitation
              </a>
            </p>
            <p style="font-size:12px;color:#6a6456;margin:0 0 8px;">
              This invitation expires in 14 days. If the button doesn't open,
              copy the link below into your browser:
            </p>
            <p style="font-family:Menlo,monospace;font-size:12px;word-break:break-all;color:#6a6456;margin:0;">
              {url}
            </p>
          </td></tr>
        </table>
        <p style="max-width:560px;margin:16px auto 0;font-size:11px;color:#8a8374;text-align:center;">
          If you weren't expecting this, you can safely ignore this email.
        </p>
      </body>
    </html>
    """


def _invite_text(org_name: str, inviter_name: str | None, role: str, url: str) -> str:
    who = inviter_name or "A teammate"
    return (
        f"{who} has invited you to join {org_name} on Pencheff as a {role}.\n\n"
        f"Accept the invitation: {url}\n\n"
        f"The link expires in 14 days."
    )


def send_invite_email(
    to: str,
    org_name: str,
    invite_url: str,
    role: str,
    inviter_name: str | None = None,
) -> bool:
    """Email a Pencheff org invite. Returns True on Resend 2xx, False otherwise."""
    settings = get_settings()
    subject = f"You're invited to join {org_name} on Pencheff"
    payload = {
        "from": settings.email_from,
        "to": [to],
        "subject": subject,
        "html": _invite_html(org_name, inviter_name, role, invite_url),
        "text": _invite_text(org_name, inviter_name, role, invite_url),
    }
    return _send(payload)


# ── Severity-bar shared snippet ─────────────────────────────────────

_SEV_HEX = {
    "critical": "#C00000",
    "high": "#E06666",
    "medium": "#E69138",
    "low": "#6FA8DC",
    "info": "#B7B7B7",
}


def _severity_bar_html(summary: dict | None) -> str:
    """Render a horizontal severity-count strip for the email body."""
    s = summary or {}
    cells = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = int(s.get(sev) or 0)
        cells.append(
            f'<td align="center" style="padding:8px 6px;background:{_SEV_HEX[sev]};'
            f'color:#ffffff;font-family:Helvetica,Arial,sans-serif;font-size:12px;'
            f'letter-spacing:0.04em;">'
            f'<div style="font-size:18px;font-weight:bold;">{n}</div>'
            f'<div style="text-transform:uppercase;font-size:10px;letter-spacing:0.16em;">'
            f"{sev[:4]}</div></td>"
        )
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="2" '
        'style="margin:16px 0;">'
        f"<tr>{''.join(cells)}</tr></table>"
    )


# ── Scan-completion email ───────────────────────────────────────────


def _scan_complete_html(
    target_name: str,
    grade: str | None,
    status: str,
    summary: dict | None,
    dashboard_url: str,
    error: str | None = None,
) -> str:
    grade_label = grade or "—"
    headline = (
        "Scan complete." if status == "done" else "Scan finished with errors."
    )
    grade_block = (
        f'<div style="display:inline-block;border:2px solid #1a1a1a;border-radius:4px;'
        f'padding:14px 22px;font-family:Georgia,serif;font-size:32px;line-height:1;">'
        f"{grade_label}</div>"
    )
    err_block = (
        f'<p style="background:#fbe9e7;border:1px solid #c00000;color:#1a1a1a;'
        f'padding:12px;font-family:Menlo,monospace;font-size:12px;'
        f'white-space:pre-wrap;margin:16px 0 0;">{error}</p>'
        if error else ""
    )
    return f"""
    <!doctype html>
    <html>
      <body style="margin:0;padding:32px;background:#f4efe3;font-family:Georgia,serif;color:#2a2a2a;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
               style="max-width:580px;margin:0 auto;background:#ffffff;
                      border:1px solid #d8d3c4;border-radius:4px;padding:40px;">
          <tr><td>
            <p style="font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:#8a8374;margin:0 0 12px;">
              Pencheff · {headline}
            </p>
            <h1 style="font-size:22px;line-height:1.25;margin:0 0 16px;color:#1a1a1a;">
              {target_name}
            </h1>
            <p style="font-size:13px;color:#6a6456;margin:0 0 16px;">
              Grade
            </p>
            {grade_block}
            {_severity_bar_html(summary)}
            <p style="margin:24px 0 8px;">
              <a href="{dashboard_url}"
                 style="display:inline-block;background:#1a1a1a;color:#ffffff;
                        text-decoration:none;padding:12px 22px;border-radius:3px;
                        font-family:Helvetica,Arial,sans-serif;font-size:14px;
                        letter-spacing:0.04em;">
                Open dashboard
              </a>
            </p>
            <p style="font-size:12px;color:#6a6456;margin:0;">
              {dashboard_url}
            </p>
            {err_block}
          </td></tr>
        </table>
      </body>
    </html>
    """


def _scan_complete_text(
    target_name: str,
    grade: str | None,
    status: str,
    summary: dict | None,
    dashboard_url: str,
    error: str | None = None,
) -> str:
    s = summary or {}
    sev = " · ".join(
        f"{sev}: {int(s.get(sev) or 0)}"
        for sev in ("critical", "high", "medium", "low", "info")
    )
    head = "Scan complete." if status == "done" else "Scan finished with errors."
    body = [
        f"{head}",
        f"Target: {target_name}",
        f"Grade: {grade or '—'}",
        f"Findings: {sev}",
        "",
        f"Dashboard: {dashboard_url}",
    ]
    if error:
        body += ["", f"Error: {error}"]
    return "\n".join(body)


def send_scan_complete_email(
    to: list[str],
    target_name: str,
    grade: str | None,
    status: str,
    summary: dict | None,
    dashboard_url: str,
    error: str | None = None,
) -> bool:
    """Notify subscribed recipients that a scan finished. ``status`` is
    the terminal Scan.status — ``done`` or ``failed`` — and changes the
    subject/headline. Returns True on Resend 2xx, False otherwise."""
    if not to:
        return False
    settings = get_settings()
    if status == "done":
        subject = f"Scan complete · {grade or '—'} · {target_name}"
    else:
        subject = f"Scan failed · {target_name}"
    payload = {
        "from": settings.email_from,
        "to": list(to),
        "subject": subject,
        "html": _scan_complete_html(
            target_name, grade, status, summary, dashboard_url, error
        ),
        "text": _scan_complete_text(
            target_name, grade, status, summary, dashboard_url, error
        ),
    }
    return _send(payload)


# ── Per-target weekly digest ────────────────────────────────────────


def _digest_recent_rows_html(scans: list[dict]) -> str:
    """Render the recent-scans table for a digest email. Each row =
    one Scan dict with keys grade, status, summary (sev counts),
    finished_at."""
    if not scans:
        return (
            '<p style="font-size:13px;color:#6a6456;font-style:italic;">'
            "No scans completed in the past week.</p>"
        )
    rows = []
    for s in scans:
        sev = s.get("summary") or {}
        sev_strip = " · ".join(
            f'<span style="color:{_SEV_HEX[k]};">{int(sev.get(k) or 0)}</span>'
            for k in ("critical", "high", "medium", "low", "info")
        )
        finished = (s.get("finished_at") or "")[:10] or "—"
        rows.append(
            "<tr>"
            f'<td style="padding:8px 0;border-bottom:1px solid #e8e2d3;'
            f'font-family:Menlo,monospace;font-size:12px;color:#6a6456;">{finished}</td>'
            f'<td style="padding:8px 0;border-bottom:1px solid #e8e2d3;'
            f'font-family:Georgia,serif;font-size:14px;color:#1a1a1a;">{s.get("grade") or "—"}</td>'
            f'<td style="padding:8px 0;border-bottom:1px solid #e8e2d3;'
            f'font-family:Menlo,monospace;font-size:12px;">{sev_strip}</td>'
            "</tr>"
        )
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="margin:8px 0 16px;">'
        '<tr><th align="left" style="font-family:Helvetica,Arial,sans-serif;font-size:10px;'
        "letter-spacing:0.16em;text-transform:uppercase;color:#8a8374;padding-bottom:4px;"
        '">Date</th>'
        '<th align="left" style="font-family:Helvetica,Arial,sans-serif;font-size:10px;'
        'letter-spacing:0.16em;text-transform:uppercase;color:#8a8374;padding-bottom:4px;">Grade</th>'
        '<th align="left" style="font-family:Helvetica,Arial,sans-serif;font-size:10px;'
        'letter-spacing:0.16em;text-transform:uppercase;color:#8a8374;padding-bottom:4px;">Severity</th></tr>'
        f"{''.join(rows)}</table>"
    )


def _target_digest_html(
    target_name: str,
    scans: list[dict],
    target_url: str,
) -> str:
    return f"""
    <!doctype html>
    <html>
      <body style="margin:0;padding:32px;background:#f4efe3;font-family:Georgia,serif;color:#2a2a2a;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
               style="max-width:580px;margin:0 auto;background:#ffffff;
                      border:1px solid #d8d3c4;border-radius:4px;padding:40px;">
          <tr><td>
            <p style="font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:#8a8374;margin:0 0 12px;">
              Pencheff · Weekly digest
            </p>
            <h1 style="font-size:22px;line-height:1.25;margin:0 0 8px;color:#1a1a1a;">
              {target_name}
            </h1>
            <p style="font-size:13px;color:#6a6456;margin:0 0 16px;">
              Last 7 days of assessments.
            </p>
            {_digest_recent_rows_html(scans)}
            <p style="margin:24px 0 8px;">
              <a href="{target_url}"
                 style="display:inline-block;background:#1a1a1a;color:#ffffff;
                        text-decoration:none;padding:12px 22px;border-radius:3px;
                        font-family:Helvetica,Arial,sans-serif;font-size:14px;
                        letter-spacing:0.04em;">
                Open target dashboard
              </a>
            </p>
            <p style="font-size:11px;color:#8a8374;margin:0;">
              You receive this because your email is on the digest list for
              this target. Update recipients on the target settings page.
            </p>
          </td></tr>
        </table>
      </body>
    </html>
    """


def _target_digest_text(
    target_name: str, scans: list[dict], target_url: str
) -> str:
    lines = [
        f"Pencheff weekly digest — {target_name}",
        "",
        "Last 7 days of assessments:",
    ]
    if not scans:
        lines.append("  (none)")
    else:
        for s in scans:
            sev = s.get("summary") or {}
            sev_strip = " ".join(
                f"{k}={int(sev.get(k) or 0)}"
                for k in ("critical", "high", "medium", "low", "info")
            )
            lines.append(
                f"  {(s.get('finished_at') or '')[:10] or '—'} · "
                f"grade {s.get('grade') or '—'} · {sev_strip}"
            )
    lines += ["", f"Target dashboard: {target_url}"]
    return "\n".join(lines)


def send_target_weekly_digest(
    to: list[str], target_name: str, scans: list[dict], target_url: str
) -> bool:
    """Send the per-target weekly digest."""
    if not to:
        return False
    settings = get_settings()
    payload = {
        "from": settings.email_from,
        "to": list(to),
        "subject": f"Weekly digest · {target_name}",
        "html": _target_digest_html(target_name, scans, target_url),
        "text": _target_digest_text(target_name, scans, target_url),
    }
    return _send(payload)


# ── Per-workspace weekly digest ─────────────────────────────────────


def _workspace_digest_html(
    workspace_name: str,
    targets: list[dict],
    app_url: str,
) -> str:
    if not targets:
        body_inner = (
            '<p style="font-size:13px;color:#6a6456;font-style:italic;">'
            "No completed scans across this workspace in the past week.</p>"
        )
    else:
        rows = []
        for t in targets:
            sev = t.get("summary") or {}
            sev_strip = " · ".join(
                f'<span style="color:{_SEV_HEX[k]};">{int(sev.get(k) or 0)}</span>'
                for k in ("critical", "high", "medium", "low", "info")
            )
            rows.append(
                "<tr>"
                f'<td style="padding:10px 0;border-bottom:1px solid #e8e2d3;'
                f'font-family:Georgia,serif;font-size:14px;color:#1a1a1a;">'
                f'{t.get("name") or "—"}</td>'
                f'<td style="padding:10px 0;border-bottom:1px solid #e8e2d3;'
                f'font-family:Georgia,serif;font-size:14px;text-align:center;">'
                f'{t.get("grade") or "—"}</td>'
                f'<td style="padding:10px 0;border-bottom:1px solid #e8e2d3;'
                f'font-family:Menlo,monospace;font-size:12px;text-align:right;">{sev_strip}</td>'
                "</tr>"
            )
        body_inner = (
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="margin:8px 0 16px;">'
            '<tr><th align="left" style="font-family:Helvetica,Arial,sans-serif;font-size:10px;'
            'letter-spacing:0.16em;text-transform:uppercase;color:#8a8374;padding-bottom:4px;">Target</th>'
            '<th align="center" style="font-family:Helvetica,Arial,sans-serif;font-size:10px;'
            'letter-spacing:0.16em;text-transform:uppercase;color:#8a8374;padding-bottom:4px;">Grade</th>'
            '<th align="right" style="font-family:Helvetica,Arial,sans-serif;font-size:10px;'
            'letter-spacing:0.16em;text-transform:uppercase;color:#8a8374;padding-bottom:4px;">Severity</th></tr>'
            f"{''.join(rows)}</table>"
        )
    return f"""
    <!doctype html>
    <html>
      <body style="margin:0;padding:32px;background:#f4efe3;font-family:Georgia,serif;color:#2a2a2a;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
               style="max-width:640px;margin:0 auto;background:#ffffff;
                      border:1px solid #d8d3c4;border-radius:4px;padding:40px;">
          <tr><td>
            <p style="font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:#8a8374;margin:0 0 12px;">
              Pencheff · Workspace digest
            </p>
            <h1 style="font-size:22px;line-height:1.25;margin:0 0 8px;color:#1a1a1a;">
              {workspace_name}
            </h1>
            <p style="font-size:13px;color:#6a6456;margin:0 0 16px;">
              Latest grade and severity counts across every active target.
            </p>
            {body_inner}
            <p style="margin:24px 0 8px;">
              <a href="{app_url}"
                 style="display:inline-block;background:#1a1a1a;color:#ffffff;
                        text-decoration:none;padding:12px 22px;border-radius:3px;
                        font-family:Helvetica,Arial,sans-serif;font-size:14px;
                        letter-spacing:0.04em;">
                Open workspace
              </a>
            </p>
          </td></tr>
        </table>
      </body>
    </html>
    """


def _workspace_digest_text(
    workspace_name: str, targets: list[dict], app_url: str
) -> str:
    lines = [
        f"Pencheff workspace digest — {workspace_name}",
        "",
        "Latest grade per target:",
    ]
    if not targets:
        lines.append("  (no scans this week)")
    else:
        for t in targets:
            sev = t.get("summary") or {}
            sev_strip = " ".join(
                f"{k}={int(sev.get(k) or 0)}"
                for k in ("critical", "high", "medium", "low", "info")
            )
            lines.append(
                f"  {t.get('name') or '—'} · grade {t.get('grade') or '—'} · {sev_strip}"
            )
    lines += ["", f"Workspace: {app_url}"]
    return "\n".join(lines)


def send_workspace_weekly_digest(
    to: list[str],
    workspace_name: str,
    targets: list[dict],
    app_url: str,
) -> bool:
    """Send a workspace-rollup weekly digest covering every target."""
    if not to:
        return False
    settings = get_settings()
    payload = {
        "from": settings.email_from,
        "to": list(to),
        "subject": f"Weekly digest · {workspace_name}",
        "html": _workspace_digest_html(workspace_name, targets, app_url),
        "text": _workspace_digest_text(workspace_name, targets, app_url),
    }
    return _send(payload)


# ── Support-ticket notifications ────────────────────────────────────


def send_support_ticket_email(*, to: list[str], subject: str, ticket_id: str,
                              preview: str, is_agent_view: bool) -> bool:
    s = get_settings()
    base = (s.email_app_url or s.web_base_url).rstrip("/")
    # customers land on the portal thread; agents on the agent view
    path = f"/support/agent/tickets/{ticket_id}" if is_agent_view else f"/support/tickets/{ticket_id}"
    url = f"{base}{path}"
    html = (
        f"<p>{preview}</p>"
        f'<p><a href="{url}">View the ticket</a></p>'
    )
    ok = True
    for addr in to:
        ok = _send({"from": s.email_from, "to": addr, "subject": subject,
                    "html": html}) and ok
    return ok
