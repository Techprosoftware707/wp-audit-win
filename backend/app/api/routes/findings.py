"""Findings, evidence, and verification endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.base import utcnow
from app.models.enums import FindingStatus
from app.models.finding import Evidence, Finding, VerificationTest
from app.models.user import User
from app.schemas.finding import (
    EvidenceOut,
    FindingOut,
    FindingStatusUpdate,
    VerificationRequest,
    VerificationTestOut,
)
from app.services import audit
from app.services import verification as verification_service

router = APIRouter(tags=["findings"])


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    target_id: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    confirmed: bool | None = Query(default=None),
    limit: int = Query(default=200, le=1000),
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("findings:read")),
):
    q = select(Finding).order_by(Finding.risk_score.desc()).limit(limit)
    if target_id:
        q = q.where(Finding.target_id == target_id)
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if status:
        q = q.where(Finding.status == status)
    if confirmed is not None:
        q = q.where(Finding.confirmed == confirmed)
    return db.execute(q).scalars().all()


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("findings:read")),
) -> Finding:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/findings/{finding_id}/status", response_model=FindingOut)
def update_finding_status(
    finding_id: str,
    body: FindingStatusUpdate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("findings:write")),
) -> Finding:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.status = body.status.value
    if body.remediation is not None:
        finding.remediation = body.remediation
    if body.status in (
        FindingStatus.VERIFIED_FIXED,
        FindingStatus.FIXED,
        FindingStatus.FALSE_POSITIVE,
    ):
        finding.resolved_at = utcnow()
    audit.record(
        db,
        action="finding.status",
        actor=actor,
        object_type="finding",
        object_id=finding.id,
        request=request,
        detail={"status": body.status.value},
    )
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/findings/{finding_id}/evidence", response_model=list[EvidenceOut])
def finding_evidence(
    finding_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("evidence:read")),
):
    return (
        db.execute(
            select(Evidence).where(Evidence.finding_id == finding_id).order_by(Evidence.created_at)
        )
        .scalars()
        .all()
    )


@router.get("/findings/{finding_id}/verification", response_model=list[VerificationTestOut])
def finding_verifications(
    finding_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("verification:read")),
):
    return (
        db.execute(
            select(VerificationTest)
            .where(VerificationTest.finding_id == finding_id)
            .order_by(VerificationTest.created_at)
        )
        .scalars()
        .all()
    )


@router.post("/findings/{finding_id}/verify", response_model=VerificationTestOut)
def verify_finding(
    finding_id: str,
    body: VerificationRequest,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("verification:run")),
) -> VerificationTest:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Approving an active verification requires the approve permission.
    from app.core.rbac import has_permission

    if body.approve and not has_permission(actor.role, "verification:approve"):
        raise HTTPException(status_code=403, detail="Missing permission: verification:approve")

    try:
        test = verification_service.run_verification(
            db,
            finding=finding,
            method=body.method.value,
            mode=body.mode,
            approve=body.approve,
            performed_by=actor.id,
            notes=body.notes,
            poc_id=body.poc_id,
        )
    except verification_service.VerificationError as exc:
        audit.record(
            db,
            action="finding.verify",
            actor=actor,
            object_type="finding",
            object_id=finding_id,
            result="failure",
            request=request,
            detail={"reason": str(exc)},
        )
        db.commit()
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    audit.record(
        db,
        action="finding.verify",
        actor=actor,
        object_type="finding",
        object_id=finding_id,
        request=request,
        detail={"method": body.method.value, "result": test.status, "approved": test.approved},
    )
    db.commit()
    db.refresh(test)
    return test
