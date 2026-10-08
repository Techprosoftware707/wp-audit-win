"""Worker fleet status."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.system import Worker
from app.models.user import User
from app.schemas.misc import WorkerOut

router = APIRouter(prefix="/workers", tags=["workers"])


@router.get("", response_model=list[WorkerOut])
def list_workers(
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("workers:read")),
):
    return db.execute(select(Worker).order_by(Worker.name)).scalars().all()
