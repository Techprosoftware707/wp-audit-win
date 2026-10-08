"""Targets, authorizations, and credentials."""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import encrypt
from app.core.deps import db_session, require_permission
from app.models.base import utcnow
from app.models.enums import AuthorizationStatus
from app.models.target import Authorization, Credential, Target
from app.models.user import User
from app.schemas.target import (
    AuthorizationCreate,
    AuthorizationOut,
    AuthorizationRevoke,
    AuthorizationStatusUpdate,
    CredentialCreate,
    CredentialOut,
    TargetCreate,
    TargetOut,
    TargetUpdate,
    TargetWithAuth,
)
from app.services import audit
from app.services import authorization as authz

router = APIRouter(prefix="/targets", tags=["targets"])


def _with_auth(db: Session, target: Target) -> TargetWithAuth:
    decision = authz.evaluate(db, target)
    out = TargetWithAuth.model_validate(target)
    out.authorized = decision.allowed
    if decision.authorization:
        out.authorization_status = decision.authorization.status
        out.authorization_expires = decision.authorization.expiration_date
    else:
        latest = target.authorizations[0] if target.authorizations else None
        out.authorization_status = latest.status if latest else "none"
    return out


# ------------------------------------------------------------------ targets
@router.get("", response_model=list[TargetWithAuth])
def list_targets(
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("targets:read")),
):
    targets = db.execute(select(Target).order_by(Target.created_at.desc())).scalars().all()
    return [_with_auth(db, t) for t in targets]


@router.post("", response_model=TargetOut, status_code=201)
def create_target(
    body: TargetCreate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("targets:write")),
) -> Target:
    host = urlparse(str(body.base_url)).hostname or ""
    if not host:
        raise HTTPException(status_code=400, detail="base_url must include a host")
    target = Target(
        name=body.name,
        base_url=str(body.base_url),
        host=host,
        owner=body.owner,
        notes=body.notes,
        tags=body.tags,
        scan_profile=body.scan_profile.value,
        max_intensity=body.max_intensity.value,
        asset_importance=body.asset_importance,
        created_by=actor.id,
    )
    db.add(target)
    audit.record(
        db,
        action="target.create",
        actor=actor,
        object_type="target",
        object_id=target.id,
        request=request,
        detail={"host": host},
    )
    db.commit()
    db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetWithAuth)
def get_target(
    target_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("targets:read")),
) -> TargetWithAuth:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return _with_auth(db, target)


@router.patch("/{target_id}", response_model=TargetOut)
def update_target(
    target_id: str,
    body: TargetUpdate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("targets:write")),
) -> Target:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    for field in ("name", "owner", "notes", "asset_importance"):
        val = getattr(body, field)
        if val is not None:
            setattr(target, field, val)
    if body.tags is not None:
        target.tags = body.tags
    if body.scan_profile is not None:
        target.scan_profile = body.scan_profile.value
    if body.max_intensity is not None:
        target.max_intensity = body.max_intensity.value
    audit.record(
        db,
        action="target.update",
        actor=actor,
        object_type="target",
        object_id=target.id,
        request=request,
    )
    db.commit()
    db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=204)
def delete_target(
    target_id: str,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("targets:write")),
) -> None:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    audit.record(
        db,
        action="target.delete",
        actor=actor,
        object_type="target",
        object_id=target.id,
        request=request,
        detail={"host": target.host},
    )
    db.delete(target)
    db.commit()


# ----------------------------------------------------------- authorizations
@router.get("/{target_id}/authorizations", response_model=list[AuthorizationOut])
def list_authorizations(
    target_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("authz:read")),
):
    return (
        db.execute(
            select(Authorization)
            .where(Authorization.target_id == target_id)
            .order_by(Authorization.created_at.desc())
        )
        .scalars()
        .all()
    )


@router.post("/{target_id}/authorizations", response_model=AuthorizationOut, status_code=201)
def create_authorization(
    target_id: str,
    body: AuthorizationCreate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("authz:write")),
) -> Authorization:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    scope = body.allowed_scope or [target.host]
    auth = Authorization(
        target_id=target_id,
        status=AuthorizationStatus.PENDING.value,
        auth_type=body.auth_type.value,
        authorized_by=body.authorized_by,
        reference=body.reference,
        start_date=body.start_date,
        expiration_date=body.expiration_date,
        allowed_scope=scope,
        testing_profile=body.testing_profile.value,
        max_intensity=body.max_intensity.value,
    )
    db.add(auth)
    audit.record(
        db,
        action="authorization.create",
        actor=actor,
        object_type="authorization",
        object_id=auth.id,
        request=request,
        detail={"target": target.host, "type": body.auth_type.value, "scope": scope},
    )
    db.commit()
    db.refresh(auth)
    return auth


@router.post("/{target_id}/authorizations/{auth_id}/status", response_model=AuthorizationOut)
def set_authorization_status(
    target_id: str,
    auth_id: str,
    body: AuthorizationStatusUpdate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("authz:approve")),
) -> Authorization:
    auth = db.get(Authorization, auth_id)
    if not auth or auth.target_id != target_id:
        raise HTTPException(status_code=404, detail="Authorization not found")
    auth.status = body.status.value
    if body.status == AuthorizationStatus.ACTIVE:
        auth.approved_by_user_id = actor.id
        if not auth.start_date:
            auth.start_date = utcnow()
    audit.record(
        db,
        action="authorization.status",
        actor=actor,
        object_type="authorization",
        object_id=auth.id,
        request=request,
        detail={"status": body.status.value},
    )
    db.commit()
    db.refresh(auth)
    return auth


@router.post("/{target_id}/authorizations/{auth_id}/revoke", response_model=AuthorizationOut)
def revoke_authorization(
    target_id: str,
    auth_id: str,
    body: AuthorizationRevoke,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("authz:approve")),
) -> Authorization:
    auth = db.get(Authorization, auth_id)
    if not auth or auth.target_id != target_id:
        raise HTTPException(status_code=404, detail="Authorization not found")
    auth.status = AuthorizationStatus.REVOKED.value
    auth.revoked_at = utcnow()
    auth.revoke_reason = body.reason
    audit.record(
        db,
        action="authorization.revoke",
        actor=actor,
        object_type="authorization",
        object_id=auth.id,
        request=request,
        detail={"reason": body.reason},
    )
    db.commit()
    db.refresh(auth)
    return auth


# -------------------------------------------------------------- credentials
@router.get("/{target_id}/credentials", response_model=list[CredentialOut])
def list_credentials(
    target_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("credentials:read")),
):
    return db.execute(select(Credential).where(Credential.target_id == target_id)).scalars().all()


@router.post("/{target_id}/credentials", response_model=CredentialOut, status_code=201)
def create_credential(
    target_id: str,
    body: CredentialCreate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("credentials:write")),
) -> Credential:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    cred = Credential(
        target_id=target_id,
        name=body.name,
        cred_type=body.cred_type.value,
        username=body.username,
        secret_encrypted=encrypt(body.secret),
        meta=body.meta,
        created_by=actor.id,
    )
    db.add(cred)
    # The secret is never included in the audit detail.
    audit.record(
        db,
        action="credential.create",
        actor=actor,
        object_type="credential",
        object_id=cred.id,
        request=request,
        detail={"target": target.host, "type": body.cred_type.value, "username": body.username},
    )
    db.commit()
    db.refresh(cred)
    return cred


@router.delete("/{target_id}/credentials/{cred_id}", status_code=204)
def delete_credential(
    target_id: str,
    cred_id: str,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("credentials:write")),
) -> None:
    cred = db.get(Credential, cred_id)
    if not cred or cred.target_id != target_id:
        raise HTTPException(status_code=404, detail="Credential not found")
    audit.record(
        db,
        action="credential.delete",
        actor=actor,
        object_type="credential",
        object_id=cred.id,
        request=request,
    )
    db.delete(cred)
    db.commit()
