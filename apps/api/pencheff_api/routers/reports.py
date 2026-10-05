import os

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import Report, Scan, Workspace
from ..schemas.reports import ReportCreate, ReportOut
from ..services.worker_lifecycle import ensure_worker_started_or_503
from ..tasks.report_task import generate_report

router = APIRouter(tags=["reports"])


def _to_out(r: Report) -> ReportOut:
    return ReportOut(
        id=r.id, scan_id=r.scan_id, format=r.format, status=r.status,
        bytes=r.bytes, generated_at=r.generated_at, created_at=r.created_at,
        download_url=f"/reports/{r.id}/download" if r.status == "ready" else None,
    )


@router.post(
    "/scans/{scan_id}/reports",
    response_model=ReportOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("reports:export"))],
)
async def create_report(
    scan_id: str,
    body: ReportCreate,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ReportOut:
    scan = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    if scan.status != "done":
        raise HTTPException(status.HTTP_409_CONFLICT, "scan is not complete")
    await ensure_worker_started_or_503()

    report = Report(scan_id=scan.id, format=body.format, status="pending")
    session.add(report)
    await session.commit()
    await session.refresh(report)
    generate_report.delay(report.id)
    return _to_out(report)


@router.get(
    "/scans/{scan_id}/reports",
    response_model=list[ReportOut],
    dependencies=[Depends(require_scope("reports:read"))],
)
async def list_reports(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[ReportOut]:
    scan = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    rows = (await session.execute(
        select(Report).where(Report.scan_id == scan_id).order_by(Report.created_at.desc())
    )).scalars().all()
    return [_to_out(r) for r in rows]


@router.get(
    "/reports/{report_id}",
    response_model=ReportOut,
    dependencies=[Depends(require_scope("reports:read"))],
)
async def get_report(
    report_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> ReportOut:
    row = (await session.execute(
        select(Report, Scan).join(Scan, Scan.id == Report.scan_id)
        .where(Report.id == report_id, Scan.workspace_id == workspace.id)
    )).first()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    return _to_out(row[0])


@router.get(
    "/reports/{report_id}/download",
    dependencies=[Depends(require_scope("reports:read"))],
)
async def download_report(
    report_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FileResponse:
    row = (await session.execute(
        select(Report, Scan).join(Scan, Scan.id == Report.scan_id)
        .where(Report.id == report_id, Scan.workspace_id == workspace.id)
    )).first()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    report = row[0]
    if report.status != "ready" or not report.storage_path or not os.path.exists(report.storage_path):
        raise HTTPException(status.HTTP_409_CONFLICT, "report is not ready yet")
    media = {
        "json": "application/json",
        "csv": "text/csv",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "pdf": "application/pdf",
    }.get(report.format, "application/octet-stream")
    return FileResponse(report.storage_path, media_type=media, filename=os.path.basename(report.storage_path))
