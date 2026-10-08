"""Isolated exploit lab management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.lab import Lab, LabInstance
from app.models.user import User
from app.schemas.misc import LabCreate, LabInstanceOut, LabOut
from app.services import audit
from app.services import lab as lab_service

router = APIRouter(prefix="/labs", tags=["labs"])


@router.get("", response_model=list[LabOut])
def list_labs(
    db: Session = Depends(db_session), _: User = Depends(require_permission("labs:read"))
):
    return db.execute(select(Lab).order_by(Lab.created_at.desc())).scalars().all()


@router.post("", response_model=LabOut, status_code=201)
def create_lab(
    body: LabCreate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("labs:write")),
) -> Lab:
    if db.execute(select(Lab).where(Lab.name == body.name)).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Lab name already exists")
    lab = Lab(
        name=body.name,
        description=body.description,
        template=body.template,
        auto_destroy=body.auto_destroy,
        ttl_minutes=body.ttl_minutes,
        created_by=actor.id,
    )
    db.add(lab)
    audit.record(
        db,
        action="lab.create",
        actor=actor,
        object_type="lab",
        object_id=lab.id,
        request=request,
        detail={"name": body.name},
    )
    db.commit()
    db.refresh(lab)
    return lab


@router.get("/{lab_id}/instances", response_model=list[LabInstanceOut])
def list_instances(
    lab_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("labs:read")),
):
    return (
        db.execute(
            select(LabInstance)
            .where(LabInstance.lab_id == lab_id)
            .order_by(LabInstance.created_at.desc())
        )
        .scalars()
        .all()
    )


@router.post("/{lab_id}/instances", response_model=LabInstanceOut, status_code=201)
def create_instance(
    lab_id: str,
    request: Request,
    provider: str = "record",
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("labs:write")),
) -> LabInstance:
    lab = db.get(Lab, lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")
    inst = lab_service.create_instance(db, lab, provider=provider)
    audit.record(
        db,
        action="lab.instance_create",
        actor=actor,
        object_type="lab_instance",
        object_id=inst.id,
        request=request,
        detail={"provider": provider},
    )
    db.commit()
    db.refresh(inst)
    return inst


@router.delete("/instances/{instance_id}", response_model=LabInstanceOut)
def destroy_instance(
    instance_id: str,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("labs:write")),
) -> LabInstance:
    inst = db.get(LabInstance, instance_id)
    if not inst:
        raise HTTPException(status_code=404, detail="Instance not found")
    lab_service.destroy_instance(db, inst)
    audit.record(
        db,
        action="lab.instance_destroy",
        actor=actor,
        object_type="lab_instance",
        object_id=inst.id,
        request=request,
    )
    db.commit()
    db.refresh(inst)
    return inst
