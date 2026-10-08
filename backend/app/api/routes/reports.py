"""Report generation and download."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.misc import ReportCreate, ReportOut
from app.services import audit, reporting

router = APIRouter(tags=["reports"])


@router.get("/reports", response_model=list[ReportOut])
def list_reports(
    target_id: str | None = None,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("reports:read")),
):
    q = select(Report).order_by(Report.created_at.desc())
    if target_id:
        q = q.where(Report.target_id == target_id)
    return db.execute(q).scalars().all()


@router.post("/scans/{scan_id}/report", response_model=ReportOut, status_code=201)
def generate_for_scan(
    scan_id: str,
    body: ReportCreate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("reports:write")),
) -> Report:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    report = Report(
        target_id=scan.target_id,
        scan_id=scan_id,
        title=body.title,
        report_format=body.report_format.value,
        params=body.params,
        created_by=actor.id,
    )
    db.add(report)
    db.flush()
    reporting.generate(db, report)
    audit.record(
        db,
        action="report.generate",
        actor=actor,
        object_type="report",
        object_id=report.id,
        request=request,
        detail={"scan": scan_id, "format": body.report_format.value, "status": report.status},
    )
    db.commit()
    db.refresh(report)
    return report


@router.post("/targets/{target_id}/report", response_model=ReportOut, status_code=201)
def generate_for_target(
    target_id: str,
    body: ReportCreate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("reports:write")),
) -> Report:
    if not db.get(Target, target_id):
        raise HTTPException(status_code=404, detail="Target not found")
    report = Report(
        target_id=target_id,
        title=body.title,
        report_format=body.report_format.value,
        params=body.params,
        created_by=actor.id,
    )
    db.add(report)
    db.flush()
    reporting.generate(db, report)
    audit.record(
        db,
        action="report.generate",
        actor=actor,
        object_type="report",
        object_id=report.id,
        request=request,
        detail={"target": target_id, "format": body.report_format.value},
    )
    db.commit()
    db.refresh(report)
    return report


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(
    report_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("reports:read")),
) -> Report:
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("reports:read")),
) -> Response:
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    loaded = reporting.load_bytes(report)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Report artifact not available")
    data, content_type = loaded
    ext = report.report_format
    filename = f"{report.id}.{'md' if ext == 'markdown' else ext}"
    return Response(
        content=data,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
