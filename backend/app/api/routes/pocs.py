"""PoC intelligence library and sources."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.base import utcnow
from app.models.poc import PoC, PoCSource
from app.models.user import User
from app.schemas.misc import (
    PoCCollectRequest,
    PoCCreate,
    PoCOut,
    PoCSourceOut,
    PoCSyncRequest,
    PoCUpdate,
)
from app.services import audit, intel_sync, poc_collector

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


@router.post("/collect")
def collect_batch(
    body: PoCCollectRequest,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("pocs:write")),
):
    """Download + statically classify a batch of PoC artifacts.

    Artifacts are fetched (SSRF-guarded, size-capped), hashed, statically
    inspected, classified, and stored. **None are executed**; every record
    stays at its current verification status (UNVERIFIED by default).
    """
    stmt = select(PoC).where(PoC.source_url != "")
    if body.poc_ids:
        stmt = select(PoC).where(PoC.id.in_(body.poc_ids))
    elif body.only_uncollected:
        stmt = stmt.where(PoC.artifact_ref == "")
    stmt = stmt.order_by(PoC.created_at.desc()).limit(body.limit)
    pocs = db.execute(stmt).scalars().all()

    results = []
    for poc in pocs:
        try:
            r = poc_collector.collect(db, poc)
        except Exception as exc:  # noqa: BLE001 — one bad source must not abort the batch
            r = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
        results.append({"poc_id": poc.id, "poc_code": poc.poc_code, **r})

    collected = sum(1 for r in results if r.get("status") == "collected")
    audit.record(
        db,
        action="poc.collect_batch",
        actor=actor,
        object_type="poc",
        request=request,
        detail={"requested": len(pocs), "collected": collected},
    )
    db.commit()
    return {"requested": len(pocs), "collected": collected, "results": results}


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


@router.post("/{poc_id}/collect")
def collect_poc(
    poc_id: str,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("pocs:write")),
):
    """Download + statically classify one PoC's artifact. Never executes it."""
    poc = db.get(PoC, poc_id)
    if not poc:
        raise HTTPException(status_code=404, detail="PoC not found")
    result = poc_collector.collect(db, poc)
    audit.record(
        db,
        action="poc.collect",
        actor=actor,
        object_type="poc",
        object_id=poc.id,
        request=request,
        detail={"status": result.get("status"), "sha256": result.get("sha256")},
    )
    db.commit()
    return result


@router.get("/{poc_id}/artifact")
def download_artifact(
    poc_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("pocs:read")),
) -> Response:
    """Download the stored (never-executed) PoC artifact as an attachment."""
    poc = db.get(PoC, poc_id)
    if not poc:
        raise HTTPException(status_code=404, detail="PoC not found")
    if not poc.artifact_ref:
        raise HTTPException(status_code=404, detail="No artifact collected for this PoC")
    loaded = poc_collector.load_artifact(poc)
    if loaded is None:
        raise HTTPException(status_code=404, detail="PoC artifact not available")
    data, content_type = loaded
    # Force a safe content type + attachment disposition so a stored PoC is
    # never rendered/served as active content by a browser.
    filename = f"{poc.poc_code}-{poc.artifact_sha256[:12]}.txt"
    return Response(
        content=data,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
