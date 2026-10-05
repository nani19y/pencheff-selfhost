from __future__ import annotations

import csv
import io
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, get_current_user, get_membership
from ..db.base import get_session
from ..db.models import OrgMember, User, Workspace, WorkstationCompliance
from ..schemas.compliance import WorkstationComplianceOut, WorkstationComplianceReport

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.post("/report", status_code=status.HTTP_200_OK)
async def report_compliance(
    body: WorkstationComplianceReport,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Uploads the local workstation compliance state from Pencheff Studio."""
    # Check if a compliance record already exists for this user
    stmt = select(WorkstationCompliance).where(WorkstationCompliance.user_id == user.id)
    compliance = (await session.execute(stmt)).scalar_one_or_none()

    if compliance is None:
        compliance = WorkstationCompliance(
            id=str(sa_uuid()),
            org_id=workspace.org_id,
            workspace_id=workspace.id,
            user_id=user.id,
            studio_installed=True,
            monitors_enabled=True,
            overall_device_score=body.overall_device_score,
            overall_file_status=body.overall_file_status,
            device_checks_json=body.device_checks,
            file_checks_json=body.file_checks,
        )
        session.add(compliance)
    else:
        compliance.workspace_id = workspace.id
        compliance.org_id = workspace.org_id
        compliance.studio_installed = True
        compliance.monitors_enabled = True
        compliance.overall_device_score = body.overall_device_score
        compliance.overall_file_status = body.overall_file_status
        compliance.device_checks_json = body.device_checks
        compliance.file_checks_json = body.file_checks
        compliance.updated_at = datetime.now(timezone.utc)

    await session.commit()
    return {"status": "success", "message": "Compliance state reported successfully."}


@router.get("/my", response_model=WorkstationComplianceOut)
async def get_my_compliance(
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> WorkstationComplianceOut:
    """Returns the workstation compliance status for the current user."""
    member = await get_membership(session, user.id, workspace.org_id)
    role_str = member.role if member else "member"

    stmt = select(WorkstationCompliance).where(WorkstationCompliance.user_id == user.id)
    wc = (await session.execute(stmt)).scalar_one_or_none()

    if wc is not None:
        return WorkstationComplianceOut(
            user_id=str(user.id),
            email=user.email,
            name=getattr(user, "name", None),
            role=role_str,
            studio_installed=wc.studio_installed,
            monitors_enabled=wc.monitors_enabled,
            overall_device_score=wc.overall_device_score,
            overall_file_status=wc.overall_file_status,
            device_checks_json=wc.device_checks_json,
            file_checks_json=wc.file_checks_json,
            updated_at=wc.updated_at,
        )
    else:
        return WorkstationComplianceOut(
            user_id=str(user.id),
            email=user.email,
            name=getattr(user, "name", None),
            role=role_str,
            studio_installed=False,
            monitors_enabled=False,
            overall_device_score=0,
            overall_file_status="Unknown",
            device_checks_json=None,
            file_checks_json=None,
            updated_at=None,
        )


@router.get("/members", response_model=list[WorkstationComplianceOut])
async def list_member_compliance(
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[WorkstationComplianceOut]:
    """Returns compliance status for all workspace members. Only org owners and admins are allowed."""
    member = await get_membership(session, user.id, workspace.org_id)
    if member is None or member.role not in ("owner", "admin"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only organization owners and admins can view workstation compliance data.",
        )

    # Left join to find members who haven't installed Pencheff Studio
    stmt = (
        select(OrgMember, User, WorkstationCompliance)
        .join(User, User.id == OrgMember.user_id)
        .outerjoin(
            WorkstationCompliance,
            WorkstationCompliance.user_id == OrgMember.user_id,
        )
        .where(OrgMember.org_id == workspace.org_id)
        .order_by(User.email.asc())
    )

    rows = (await session.execute(stmt)).all()
    results = []
    for om, u, wc in rows:
        if wc is not None:
            results.append(
                WorkstationComplianceOut(
                    user_id=str(u.id),
                    email=u.email,
                    name=getattr(u, "name", None),
                    role=om.role,
                    studio_installed=wc.studio_installed,
                    monitors_enabled=wc.monitors_enabled,
                    overall_device_score=wc.overall_device_score,
                    overall_file_status=wc.overall_file_status,
                    device_checks_json=wc.device_checks_json,
                    file_checks_json=wc.file_checks_json,
                    updated_at=wc.updated_at,
                )
            )
        else:
            # Studio not installed / enabled
            results.append(
                WorkstationComplianceOut(
                    user_id=str(u.id),
                    email=u.email,
                    name=getattr(u, "name", None),
                    role=om.role,
                    studio_installed=False,
                    monitors_enabled=False,
                    overall_device_score=0,
                    overall_file_status="Unknown",
                    device_checks_json=None,
                    file_checks_json=None,
                    updated_at=None,
                )
            )
    return results


@router.get("/export/csv")
async def export_compliance_csv(
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> StreamingResponse:
    """Exports combined compliance data for all org members as a CSV."""
    member = await get_membership(session, user.id, workspace.org_id)
    if member is None or member.role not in ("owner", "admin"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only organization owners and admins can export compliance data.",
        )

    # Fetch all member compliance records
    stmt = (
        select(OrgMember, User, WorkstationCompliance)
        .join(User, User.id == OrgMember.user_id)
        .outerjoin(
            WorkstationCompliance,
            WorkstationCompliance.user_id == OrgMember.user_id,
        )
        .where(OrgMember.org_id == workspace.org_id)
        .order_by(User.email.asc())
    )

    rows = (await session.execute(stmt)).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "User Email", "Full Name", "Role", "Studio Installed",
        "Monitors Enabled", "Device Security Score", "File Security Status",
        "Last Audit Timestamp"
    ])

    for om, u, wc in rows:
        if wc is not None:
            writer.writerow([
                u.email,
                getattr(u, "name", "") or "",
                om.role,
                "Yes" if wc.studio_installed else "No",
                "Yes" if wc.monitors_enabled else "No",
                f"{wc.overall_device_score}%",
                wc.overall_file_status,
                wc.updated_at.isoformat() if wc.updated_at else "",
            ])
        else:
            writer.writerow([
                u.email,
                getattr(u, "name", "") or "",
                om.role,
                "No",
                "No",
                "0%",
                "Unknown",
                "Never",
            ])

    response = StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
    )
    response.headers["Content-Disposition"] = (
        f"attachment; filename=pencheff_workstation_compliance_{workspace.name.lower().replace(' ', '_')}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    )
    return response


@router.get("/export/pdf/{target_user_id}")
async def export_compliance_pdf(
    target_user_id: str,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FileResponse:
    """Generates and downloads a beautiful, detailed PDF compliance report for an individual user."""
    member = await get_membership(session, user.id, workspace.org_id)
    if member is None or member.role not in ("owner", "admin"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only organization owners and admins can export compliance reports.",
        )

    # Fetch target user and their compliance data
    target_user = await session.get(User, target_user_id)
    if not target_user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    target_membership = await get_membership(session, target_user_id, workspace.org_id)
    if not target_membership:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not a member of this workspace")

    stmt = select(WorkstationCompliance).where(WorkstationCompliance.user_id == target_user_id)
    wc = (await session.execute(stmt)).scalar_one_or_none()

    # Generate HTML content
    from weasyprint import HTML

    overall_score = wc.overall_device_score if wc else 0
    file_status = wc.overall_file_status if wc else "Unknown"
    installed_str = "Installed & Active" if (wc and wc.studio_installed) else "NOT INSTALLED"
    monitors_str = "Enabled" if (wc and wc.monitors_enabled) else "DISABLED"
    updated_str = wc.updated_at.isoformat() if (wc and wc.updated_at) else "Never"
    name_str = getattr(target_user, "name", "") or "—"

    # Score color CSS mapping
    score_class = "secure" if overall_score >= 90 else ("warning" if overall_score >= 70 else "critical")
    file_class = "secure" if file_status == "Clean" else ("warning" if file_status == "Suspicious Activity" else "critical")

    # Generate device compliance checks list HTML
    device_checks_html = ""
    if wc and wc.device_checks_json:
        for check in wc.device_checks_json:
            chk_status = check.get("status", "PENDING").lower()
            device_checks_html += f"""
            <div class="check-card">
              <div class="check-header">
                <span class="check-title">{check.get('name', 'Check')}</span>
                <span class="badge {chk_status}">{chk_status.upper()}</span>
              </div>
              <div class="check-desc">{check.get('description', '')}</div>
              <div class="terminal-box">$ {check.get('command', '')} {" ".join(check.get('args', []))}<br>{check.get('rawOutput', '')}</div>
            </div>
            """
    else:
        device_checks_html = "<div class='warning-box'>No device audits recorded. The user has not run Pencheff Studio yet.</div>"

    # Generate file compliance checks list HTML
    file_checks_html = ""
    if wc and wc.file_checks_json:
        for file in wc.file_checks_json:
            fl_status = file.get("status", "CLEAN").lower()
            file_checks_html += f"""
            <div class="check-card">
              <div class="check-header">
                <span class="check-title">{file.get('name', 'File')}</span>
                <span class="badge {fl_status}">{fl_status.upper()}</span>
              </div>
              <div class="check-desc">Path: {file.get('path', '')} &middot; Size: {file.get('formattedSize', '0 KB')} &middot; Source: {file.get('downloadSource', 'Local')}</div>
              <div class="terminal-box">Unix Permissions: {file.get('permissions', '')}</div>
            </div>
            """
    else:
        file_checks_html = "<div class='warning-box'>No downloaded file checks recorded. The user has not enabled Downloads File Monitoring.</div>"

    html = f"""
    <!doctype html>
    <html>
    <head>
    <style>
      body {{ font-family: Helvetica, Arial, sans-serif; color: #1e1e24; margin: 30px; line-height: 1.4; }}
      h1 {{ border-bottom: 4px solid #ff7e1d; padding-bottom: 12px; font-size: 28px; font-weight: 800; }}
      h2 {{ border-bottom: 2px solid #e1dbcd; padding-bottom: 6px; font-size: 20px; margin-top: 30px; }}
      .meta-box {{ background: #fdfbf5; padding: 15px; border: 1px solid #e1dbcd; margin-bottom: 25px; border-radius: 4px; }}
      .score-container {{ display: flex; margin-bottom: 25px; }}
      .score-card {{ flex: 1; border: 1px solid #e1dbcd; padding: 15px; border-radius: 4px; text-align: center; margin-right: 15px; }}
      .score-card:last-child {{ margin-right: 0; }}
      .score-value {{ font-size: 36px; font-weight: bold; margin-top: 8px; }}
      .score-value.secure {{ color: #32963b; }}
      .score-value.warning {{ color: #d97706; }}
      .score-value.critical {{ color: #dc2626; }}
      .check-card {{ border: 1px solid #e1dbcd; padding: 12px; margin-bottom: 12px; border-radius: 4px; background: #fff; page-break-inside: avoid; }}
      .check-header {{ font-weight: bold; margin-bottom: 4px; font-size: 14px; }}
      .check-title {{ font-size: 15px; }}
      .check-desc {{ font-size: 12px; color: #64748b; margin-bottom: 8px; }}
      .badge {{ display: inline-block; padding: 3px 8px; font-size: 10px; font-weight: bold; border-radius: 2px; text-transform: uppercase; float: right; }}
      .badge.secure {{ background: #d1fae5; color: #065f46; }}
      .badge.clean {{ background: #d1fae5; color: #065f46; }}
      .badge.warning {{ background: #fef3c7; color: #92400e; }}
      .badge.suspicious {{ background: #fef3c7; color: #92400e; }}
      .badge.critical {{ background: #fee2e2; color: #991b1b; }}
      .badge.malicious {{ background: #fee2e2; color: #991b1b; }}
      .badge.pending {{ background: #f1f5f9; color: #64748b; }}
      .terminal-box {{ background: #1e1e24; color: #f8fafc; font-family: Courier, monospace; font-size: 11px; padding: 8px 12px; border-radius: 3px; margin-top: 6px; white-space: pre-wrap; }}
      .warning-box {{ padding: 15px; background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; border-radius: 4px; }}
    </style>
    </head>
    <body>
      <h1>Workstation Compliance Audit Report</h1>
      <div class="meta-box">
        <p><b>Workspace:</b> {workspace.name}<br>
           <b>User:</b> {name_str} ({target_user.email})<br>
           <b>Workspace Role:</b> {target_membership.role.upper()}<br>
           <b>Pencheff Studio:</b> {installed_str} &middot; <b>Monitors:</b> {monitors_str}<br>
           <b>Last Audited:</b> {updated_str}</p>
      </div>

      <div class="score-container">
        <div class="score-card">
          <div style="font-size:12px; font-weight:bold; color:#64748b;">DEVICE COMPLIANCE SCORE</div>
          <div class="score-value {score_class}">{overall_score}%</div>
        </div>
        <div class="score-card">
          <div style="font-size:12px; font-weight:bold; color:#64748b;">DOWNLOADS COMPLIANCE</div>
          <div class="score-value {file_class}" style="font-size: 24px; padding-top: 12px;">{file_status.upper()}</div>
        </div>
      </div>

      <h2>Device Audits</h2>
      {device_checks_html}

      <h2>Inspected Downloads Metadata</h2>
      {file_checks_html}

      <hr style="margin-top:40px; border:none; border-top:1px solid #e1dbcd;">
      <p style="font-size:9px; color:#64748b; text-align:center; font-style:italic;">
        Pencheff Compliance Reports provide host security validation evidence. This document is fully private and generated on-demand.
      </p>
    </body>
    </html>
    """

    temp_dir = Path(tempfile.gettempdir())
    pdf_path = temp_dir / f"compliance_{target_user_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    
    HTML(string=html).write_pdf(str(pdf_path))

    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        filename=f"pencheff_compliance_{target_user.email.split('@')[0]}.pdf",
    )


def sa_uuid() -> str:
    """Helper to generate standard UUID strings."""
    import uuid
    return str(uuid.uuid4())
