"""Dashboard home statistics."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.base import utcnow
from app.models.enums import ScanStatus, Severity, VerificationStatus, WorkerStatus
from app.models.finding import Finding
from app.models.poc import PoC
from app.models.report import Schedule
from app.models.scan import Scan
from app.models.system import Worker
from app.models.target import Target
from app.models.user import User
from app.schemas.misc import DashboardStats
from app.services import authorization as authz

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _count(db: Session, stmt) -> int:
    return int(db.execute(stmt).scalar_one() or 0)


@router.get("/stats", response_model=DashboardStats)
def stats(
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("findings:read")),
) -> DashboardStats:
    total_targets = _count(db, select(func.count(Target.id)))

    authorized = 0
    for t in db.execute(select(Target)).scalars():
        if authz.evaluate(db, t).allowed:
            authorized += 1

    currently_scanning = _count(
        db, select(func.count(Scan.id)).where(Scan.status == ScanStatus.RUNNING.value)
    )
    critical = _count(
        db, select(func.count(Finding.id)).where(Finding.severity == Severity.CRITICAL.value)
    )
    high = _count(db, select(func.count(Finding.id)).where(Finding.severity == Severity.HIGH.value))
    confirmed = _count(db, select(func.count(Finding.id)).where(Finding.confirmed.is_(True)))
    unverified = _count(
        db,
        select(func.count(Finding.id)).where(
            Finding.verification_status == VerificationStatus.UNVERIFIED.value
        ),
    )
    recent_cutoff = utcnow() - dt.timedelta(days=7)
    recently_fixed = _count(
        db,
        select(func.count(Finding.id)).where(
            Finding.resolved_at.is_not(None), Finding.resolved_at >= recent_cutoff
        ),
    )
    poc_size = _count(db, select(func.count(PoC.id)))

    online_cutoff = utcnow() - dt.timedelta(seconds=90)
    workers_online = 0
    for w in db.execute(select(Worker)).scalars():
        if w.status != WorkerStatus.OFFLINE.value and w.last_heartbeat:
            hb = w.last_heartbeat
            if hb.tzinfo is None:
                hb = hb.replace(tzinfo=online_cutoff.tzinfo)
            if hb >= online_cutoff:
                workers_online += 1

    last_scan = db.execute(
        select(Scan.started_at)
        .where(Scan.started_at.is_not(None))
        .order_by(Scan.started_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    next_sched = db.execute(
        select(Schedule.next_run_at)
        .where(Schedule.enabled.is_(True), Schedule.next_run_at.is_not(None))
        .order_by(Schedule.next_run_at.asc())
        .limit(1)
    ).scalar_one_or_none()

    return DashboardStats(
        total_targets=total_targets,
        authorized_targets=authorized,
        currently_scanning=currently_scanning,
        critical_findings=critical,
        high_findings=high,
        confirmed_findings=confirmed,
        unverified_findings=unverified,
        recently_fixed=recently_fixed,
        poc_library_size=poc_size,
        workers_online=workers_online,
        last_scan_at=last_scan,
        next_scheduled_at=next_sched,
    )
