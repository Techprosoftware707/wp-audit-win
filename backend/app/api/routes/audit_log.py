"""Audit log (read-only)."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.system import AuditLog
from app.models.user import User
from app.schemas.common import ORMModel

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditLogOut(ORMModel):
    id: str
    created_at: dt.datetime
    actor_user_id: str | None
    actor_email: str
    action: str
    object_type: str
    object_id: str | None
    result: str
    ip: str
    detail: dict


@router.get("", response_model=list[AuditLogOut])
def list_audit(
    action: str | None = None,
    object_type: str | None = None,
    limit: int = Query(default=200, le=1000),
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("audit:read")),
):
    q = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if action:
        q = q.where(AuditLog.action == action)
    if object_type:
        q = q.where(AuditLog.object_type == object_type)
    return db.execute(q).scalars().all()
