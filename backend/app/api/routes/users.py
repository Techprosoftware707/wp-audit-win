"""User management (admin)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import security
from app.core.deps import db_session, require_permission
from app.models.user import User
from app.schemas.auth import UserCreate, UserOut, UserUpdate
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("users:read")),
):
    return db.execute(select(User).order_by(User.created_at)).scalars().all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("users:write")),
) -> User:
    if db.execute(select(User).where(User.email == body.email)).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(
        email=body.email,
        full_name=body.full_name,
        role=body.role.value,
        hashed_password=security.hash_password(body.password),
    )
    db.add(user)
    audit.record(
        db,
        action="user.create",
        actor=actor,
        object_type="user",
        object_id=user.id,
        request=request,
        detail={"email": body.email, "role": body.role.value},
    )
    db.commit()
    db.refresh(user)
    return user


@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("users:read")),
) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    body: UserUpdate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("users:write")),
) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        user.role = body.role.value
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.password:
        user.hashed_password = security.hash_password(body.password)
    audit.record(
        db,
        action="user.update",
        actor=actor,
        object_type="user",
        object_id=user.id,
        request=request,
    )
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=204)
def delete_user(
    user_id: str,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("users:write")),
) -> None:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == actor.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    audit.record(
        db,
        action="user.delete",
        actor=actor,
        object_type="user",
        object_id=user.id,
        request=request,
        detail={"email": user.email},
    )
    db.delete(user)
    db.commit()
