"""Owner-authorized administrator recovery & approved remediation.

Every route here requires:
  * an existing target with an ACTIVE authorization (same gate as scanning);
  * for state-changing actions, the ``recovery:execute`` permission (super-admin),
    an explicit ``confirm: true`` flag, and a ``reason``;
  * a stored SSH credential for the target (WP-CLI runs over the owner's access).

State-changing actions back up the database FIRST and abort if the backup fails,
verify the result, audit the action (never the new password), and return
rollback instructions. Nothing here exploits a vulnerability or bypasses auth —
it uses WP-CLI, which already has server-side authority on the owned site.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.target import Target
from app.models.user import User
from app.schemas.recovery import (
    CreateAdminRequest,
    ResetPasswordRequest,
    UpdateComponentRequest,
)
from app.services import audit, recovery
from app.services.authorization import AuthorizationError, assert_scannable

router = APIRouter(prefix="/targets/{target_id}", tags=["recovery"])


def _target_or_404(db: Session, target_id: str) -> Target:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


def _require_authorized(db: Session, target: Target) -> None:
    try:
        assert_scannable(db, target)
    except AuthorizationError as exc:
        raise HTTPException(
            status_code=403, detail=f"Recovery requires an active authorization: {exc}"
        ) from exc


def _require_confirmation(confirm: bool, reason: str) -> None:
    if not confirm or not reason.strip():
        raise HTTPException(
            status_code=400,
            detail="This action changes the site: pass confirm=true and a non-empty reason.",
        )


def _runner_or_400(db: Session, target: Target):
    try:
        return recovery.make_runner(db, target)
    except recovery.RecoveryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/recovery/detect")
def detect(
    target_id: str,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("recovery:read")),
):
    """Read-only: enumerate administrators and flag lockout / damaged roles."""
    target = _target_or_404(db, target_id)
    _require_authorized(db, target)
    runner = _runner_or_400(db, target)
    try:
        result = recovery.detect_admins(runner)
    finally:
        getattr(runner, "close", lambda: None)()
    audit.record(
        db,
        action="recovery.detect",
        actor=actor,
        object_type="target",
        object_id=target.id,
        request=request,
        detail={
            "administrator_count": result.get("administrator_count"),
            "locked_out": result.get("locked_out"),
        },
    )
    db.commit()
    return result


@router.post("/recovery/reset-password")
def reset_password(
    target_id: str,
    body: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("recovery:execute")),
):
    """Reset an existing administrator's password (backup first, verify, audit)."""
    target = _target_or_404(db, target_id)
    _require_authorized(db, target)
    _require_confirmation(body.confirm, body.reason)
    runner = _runner_or_400(db, target)
    try:
        result = recovery.reset_password(runner, body.user)
    except recovery.RecoveryError as exc:
        audit.record(
            db,
            action="recovery.reset_password",
            actor=actor,
            object_type="target",
            object_id=target.id,
            result="failure",
            request=request,
            detail={"user": body.user, "reason": body.reason, "error": str(exc)[:300]},
        )
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        getattr(runner, "close", lambda: None)()
    # Audit WITHOUT the new password.
    audit.record(
        db,
        action="recovery.reset_password",
        actor=actor,
        object_type="target",
        object_id=target.id,
        request=request,
        detail={
            "user": body.user,
            "reason": body.reason,
            "backup_file": result["backup_file"],
            "verified_admin": result["verified_admin"],
        },
    )
    db.commit()
    return result


@router.post("/recovery/create-admin")
def create_admin(
    target_id: str,
    body: CreateAdminRequest,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("recovery:execute")),
):
    """Create a NEW administrator (explicit confirmation required; backup first)."""
    target = _target_or_404(db, target_id)
    _require_authorized(db, target)
    _require_confirmation(body.confirm, body.reason)
    runner = _runner_or_400(db, target)
    try:
        result = recovery.create_admin(runner, body.login, str(body.email))
    except recovery.RecoveryError as exc:
        audit.record(
            db,
            action="recovery.create_admin",
            actor=actor,
            object_type="target",
            object_id=target.id,
            result="failure",
            request=request,
            detail={"login": body.login, "reason": body.reason, "error": str(exc)[:300]},
        )
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        getattr(runner, "close", lambda: None)()
    audit.record(
        db,
        action="recovery.create_admin",
        actor=actor,
        object_type="target",
        object_id=target.id,
        request=request,
        detail={
            "login": body.login,
            "email": str(body.email),
            "reason": body.reason,
            "user_id": result.get("user_id"),
            "backup_file": result["backup_file"],
        },
    )
    db.commit()
    return result


@router.post("/remediation/update")
def update_component(
    target_id: str,
    body: UpdateComponentRequest,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("recovery:execute")),
):
    """Update a plugin/theme after approval (backup first; never downgrades)."""
    target = _target_or_404(db, target_id)
    _require_authorized(db, target)
    _require_confirmation(body.confirm, body.reason)
    runner = _runner_or_400(db, target)
    try:
        result = recovery.update_component(
            runner, body.component_type, body.slug, to_version=body.to_version
        )
    except recovery.RecoveryError as exc:
        audit.record(
            db,
            action="remediation.update",
            actor=actor,
            object_type="target",
            object_id=target.id,
            result="failure",
            request=request,
            detail={"component": f"{body.component_type}:{body.slug}", "error": str(exc)[:300]},
        )
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        getattr(runner, "close", lambda: None)()
    audit.record(
        db,
        action="remediation.update",
        actor=actor,
        object_type="target",
        object_id=target.id,
        request=request,
        detail={
            "component": f"{body.component_type}:{body.slug}",
            "version_before": result["version_before"],
            "version_after": result["version_after"],
            "backup_file": result["backup_file"],
            "reason": body.reason,
        },
    )
    db.commit()
    return result
