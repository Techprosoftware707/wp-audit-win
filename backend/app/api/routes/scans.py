"""Scan lifecycle: start (Full Audit), list, detail, cancel, rescan."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.enums import ScanStatus
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.scan import ScanDetail, ScanOut, ScanStart
from app.services import audit, scan_orchestrator
from app.services import authorization as authz

router = APIRouter(tags=["scans"])


@router.post("/targets/{target_id}/scan", response_model=ScanOut, status_code=201)
def start_scan(
    target_id: str,
    body: ScanStart,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("scans:write")),
) -> Scan:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    try:
        scan = scan_orchestrator.start_scan(
            db,
            target=target,
            user=actor,
            profile=body.profile.value if body.profile else None,
            mode=body.mode.value,
            steps=body.steps,
        )
    except authz.AuthorizationError as exc:
        audit.record(
            db,
            action="scan.start",
            actor=actor,
            object_type="target",
            object_id=target_id,
            result="failure",
            request=request,
            detail={"reason": str(exc)},
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail=f"Target is not authorized for scanning: {exc}",
        ) from exc
    audit.record(
        db,
        action="scan.start",
        actor=actor,
        object_type="scan",
        object_id=scan.id,
        request=request,
        detail={"target": target.host, "intensity": scan.effective_intensity},
    )
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/scans", response_model=list[ScanOut])
def list_scans(
    target_id: str | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("scans:read")),
):
    q = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    if target_id:
        q = q.where(Scan.target_id == target_id)
    return db.execute(q).scalars().all()


@router.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("scans:read")),
) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: str,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("scans:write")),
) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in (
        ScanStatus.COMPLETED.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    ):
        raise HTTPException(status_code=409, detail="Scan already finished")
    scan_orchestrator.cancel_scan(db, scan)
    audit.record(
        db,
        action="scan.cancel",
        actor=actor,
        object_type="scan",
        object_id=scan.id,
        request=request,
    )
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/scans/{scan_id}/rescan", response_model=ScanOut, status_code=201)
def rescan(
    scan_id: str,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("scans:write")),
) -> Scan:
    prev = db.get(Scan, scan_id)
    if not prev:
        raise HTTPException(status_code=404, detail="Scan not found")
    target = db.get(Target, prev.target_id)
    try:
        scan = scan_orchestrator.start_scan(
            db,
            target=target,
            user=actor,
            profile=prev.profile,
            mode=prev.mode,
        )
    except authz.AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=f"Not authorized: {exc}") from exc
    audit.record(
        db,
        action="scan.rescan",
        actor=actor,
        object_type="scan",
        object_id=scan.id,
        request=request,
        detail={"previous": scan_id},
    )
    db.commit()
    db.refresh(scan)
    return scan
