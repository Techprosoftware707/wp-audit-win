"""Scan scheduler — fires due schedules (continuous scanning).

Workers run :func:`fire_due_schedules` periodically. A schedule only fires if its
target still has a valid authorization at fire time (the same gate as manual
scans); otherwise the run is skipped and the schedule is re-armed.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.base import utcnow
from app.models.report import Schedule
from app.models.target import Target
from app.services import authorization as authz
from app.services import scan_orchestrator

log = get_logger("scheduler")

_INTERVALS = {
    "hourly": dt.timedelta(hours=1),
    "6h": dt.timedelta(hours=6),
    "daily": dt.timedelta(days=1),
    "weekly": dt.timedelta(weeks=1),
    "monthly": dt.timedelta(days=30),
}


def compute_next_run(interval: str, cron: str, from_time: dt.datetime | None = None) -> dt.datetime:
    base = from_time or utcnow()
    if cron:
        # A full cron parser is an optional dependency; without it, cron schedules
        # are advanced hourly (documented in docs/STATUS.md). Interval presets are
        # exact.
        return base + dt.timedelta(hours=1)
    return base + _INTERVALS.get(interval, dt.timedelta(days=1))


def fire_due_schedules(db: Session) -> int:
    """Start scans for all enabled schedules whose next_run_at has passed."""
    now = utcnow()
    due = (
        db.execute(
            select(Schedule).where(
                Schedule.enabled.is_(True),
                Schedule.next_run_at.is_not(None),
                Schedule.next_run_at <= now,
            )
        )
        .scalars()
        .all()
    )
    fired = 0
    for sch in due:
        target = db.get(Target, sch.target_id)
        if target is None:
            sch.enabled = False
            db.add(sch)
            continue
        try:
            scan = scan_orchestrator.start_scan(db, target=target, user=None, profile=sch.profile)
            fired += 1
            log.info("schedule %s fired scan %s for %s", sch.id, scan.id, target.host)
        except authz.AuthorizationError:
            log.info("schedule %s skipped: target %s not authorized", sch.id, target.host)
        sch.last_run_at = now
        sch.next_run_at = compute_next_run(sch.interval, sch.cron, now)
        db.add(sch)
    db.commit()
    return fired
