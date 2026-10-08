"""Vulnerability intelligence catalog."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.finding import Vulnerability
from app.models.user import User
from app.schemas.finding import VulnerabilityCreate, VulnerabilityOut
from app.services import audit

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=list[VulnerabilityOut])
def list_vulnerabilities(
    q: str | None = Query(default=None, description="search CVE/title/slug"),
    slug: str | None = None,
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("pocs:read")),
):
    stmt = (
        select(Vulnerability).order_by(Vulnerability.published_at.desc().nullslast()).limit(limit)
    )
    if slug:
        stmt = stmt.where(Vulnerability.affected_slug == slug)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                Vulnerability.cve.ilike(like),
                Vulnerability.title.ilike(like),
                Vulnerability.affected_slug.ilike(like),
                Vulnerability.affected_product.ilike(like),
            )
        )
    return db.execute(stmt).scalars().all()


@router.post("", response_model=VulnerabilityOut, status_code=201)
def create_vulnerability(
    body: VulnerabilityCreate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("pocs:write")),
) -> Vulnerability:
    vuln = Vulnerability(
        cve=(body.cve.upper() if body.cve else None),
        title=body.title,
        description=body.description,
        cwe=body.cwe,
        cvss_score=body.cvss_score,
        cvss_vector=body.cvss_vector,
        severity=body.severity,
        affected_product=body.affected_product,
        affected_slug=body.affected_slug,
        affected_type=body.affected_type,
        version_min=body.version_min,
        version_max=body.version_max,
        fixed_version=body.fixed_version,
        references=body.references,
        source=body.source,
        kev=body.kev,
    )
    db.add(vuln)
    audit.record(
        db,
        action="vulnerability.create",
        actor=actor,
        object_type="vulnerability",
        object_id=vuln.id,
        request=request,
        detail={"cve": body.cve},
    )
    db.commit()
    db.refresh(vuln)
    return vuln


@router.get("/{vuln_id}", response_model=VulnerabilityOut)
def get_vulnerability(
    vuln_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("pocs:read")),
) -> Vulnerability:
    vuln = db.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln
