"""PoC intelligence library and sources."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.base import utcnow
from app.models.poc import PoC, PoCSource
from app.models.user import User
from app.schemas.misc import (
    PoCCreate,
    PoCOut,
    PoCSourceOut,
    PoCSyncRequest,
    PoCUpdate,
)
from app.services import audit, intel_sync

router = APIRouter(prefix="/pocs", tags=["pocs"])


def _next_code(db: Session) -> str:
    year = utcnow().year
    prefix = f"POC-{year}-"
    count = db.execute(
        select(func.count(PoC.id)).where(PoC.poc_code.like(prefix + "%"))
    ).scalar_one()
    return f"{prefix}{count + 1:05d}"


@router.get("", response_model=list[PoCOut])
def list_pocs(
    q: str | None = Query(default=None),
    cve: str | None = None,
    slug: str | None = None,
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("pocs:read")),
):
    stmt = select(PoC).order_by(PoC.created_at.desc()).limit(limit)
    if cve:
        stmt = stmt.where(PoC.cve == cve.upper())
    if slug:
        stmt = stmt.where(PoC.affected_slug == slug)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(PoC.title.ilike(like), PoC.cve.ilike(like), PoC.affected_slug.ilike(like))
        )
    return db.execute(stmt).scalars().all()


@router.post("", response_model=PoCOut, status_code=201)
def create_poc(
    body: PoCCreate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("pocs:write")),
) -> PoC:
    poc = PoC(
        poc_code=_next_code(db),
        cve=(body.cve.upper() if body.cve else None),
        cwe=body.cwe,
        title=body.title,
        description=body.description,
        affected_product=body.affected_product,
        affected_slug=body.affected_slug,
        affected_type=body.affected_type,
        version_min=body.version_min,
        version_max=body.version_max,
        fixed_version=body.fixed_version,
        attack_type=body.attack_type,
        auth_required=body.auth_required,
        privilege_required=body.privilege_required,
        platform=body.platform,
        source_url=body.source_url,
        source_repo=body.source_repo,
        author=body.author,
        maturity=body.maturity.value,
        safety_classification=body.safety_classification.value,
    )
    db.add(poc)
    audit.record(
        db,
        action="poc.create",
        actor=actor,
        object_type="poc",
        object_id=poc.id,
        request=request,
        detail={"cve": body.cve},
    )
    db.commit()
    db.refresh(poc)
    return poc


@router.get("/sources", response_model=list[PoCSourceOut])
def list_sources(
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("pocs:read")),
):
    intel_sync.ensure_sources(db)
    db.commit()
    return db.execute(select(PoCSource).order_by(PoCSource.name)).scalars().all()


@router.post("/sync")
def sync_sources(
    body: PoCSyncRequest,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("pocs:sync")),
):
    results = intel_sync.run_sync(db, body.sources)
    audit.record(
        db,
        action="poc.sync",
        actor=actor,
        object_type="poc_source",
        request=request,
        detail=results,
    )
    db.commit()
    return {"results": results}


@router.get("/{poc_id}", response_model=PoCOut)
def get_poc(
    poc_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("pocs:read")),
) -> PoC:
    poc = db.get(PoC, poc_id)
    if not poc:
        raise HTTPException(status_code=404, detail="PoC not found")
    return poc


@router.patch("/{poc_id}", response_model=PoCOut)
def update_poc(
    poc_id: str,
    body: PoCUpdate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("pocs:write")),
) -> PoC:
    poc = db.get(PoC, poc_id)
    if not poc:
        raise HTTPException(status_code=404, detail="PoC not found")
    if body.maturity is not None:
        poc.maturity = body.maturity.value
    if body.safety_classification is not None:
        poc.safety_classification = body.safety_classification.value
    if body.description is not None:
        poc.description = body.description
    if body.lab_tested is not None:
        poc.lab_tested = body.lab_tested
    if body.production_verified is not None:
        poc.production_verified = body.production_verified
    audit.record(
        db, action="poc.update", actor=actor, object_type="poc", object_id=poc.id, request=request
    )
    db.commit()
    db.refresh(poc)
    return poc
