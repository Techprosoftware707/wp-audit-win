"""Scan schedules (continuous scanning)."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.base import utcnow
from app.models.report import Schedule
from app.models.target import Target
from app.models.user import User
from app.schemas.misc import ScheduleCreate, ScheduleOut
from app.services import audit

router = APIRouter(tags=["schedules"])

_INTERVALS = {
    "hourly": dt.timedelta(hours=1),
    "6h": dt.timedelta(hours=6),
    "daily": dt.timedelta(days=1),
    "weekly": dt.timedelta(weeks=1),
    "monthly": dt.timedelta(days=30),
}


def compute_next_run(
    interval: str, cron: str, from_time: dt.datetime | None = None
) -> dt.datetime | None:
    base = from_time or utcnow()
    if cron:
        # Cron strings are evaluated by the scheduler daemon; next_run is advisory.
        return base + dt.timedelta(hours=1)
    return base + _INTERVALS.get(interval, dt.timedelta(days=1))


@router.get("/schedules", response_model=list[ScheduleOut])
def list_schedules(
    target_id: str | None = None,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("schedules:read")),
):
    q = select(Schedule).order_by(Schedule.created_at.desc())
    if target_id:
        q = q.where(Schedule.target_id == target_id)
    return db.execute(q).scalars().all()


@router.post("/targets/{target_id}/schedules", response_model=ScheduleOut, status_code=201)
def create_schedule(
    target_id: str,
    body: ScheduleCreate,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("schedules:write")),
) -> Schedule:
    if not db.get(Target, target_id):
        raise HTTPException(status_code=404, detail="Target not found")
    sched = Schedule(
        target_id=target_id,
        name=body.name,
        interval=body.interval,
        cron=body.cron,
        profile=body.profile.value,
        enabled=body.enabled,
        trigger=body.trigger,
        next_run_at=compute_next_run(body.interval, body.cron),
        created_by=actor.id,
    )
    db.add(sched)
    audit.record(
        db,
        action="schedule.create",
        actor=actor,
        object_type="schedule",
        object_id=sched.id,
        request=request,
    )
    db.commit()
    db.refresh(sched)
    return sched


@router.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(
    schedule_id: str,
    request: Request,
    db: Session = Depends(db_session),
    actor: User = Depends(require_permission("schedules:write")),
) -> None:
    sched = db.get(Schedule, schedule_id)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    audit.record(
        db,
        action="schedule.delete",
        actor=actor,
        object_type="schedule",
        object_id=sched.id,
        request=request,
    )
    db.delete(sched)
    db.commit()
