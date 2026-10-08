"""Health & readiness."""

from __future__ import annotations

import datetime as dt
import shutil

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app import __version__
from app.core.config import settings
from app.core.deps import db_session, require_permission
from app.models.base import utcnow
from app.models.system import Worker
from app.models.user import User
from app.schemas.misc import HealthComponent, HealthOut

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health(db: Session = Depends(db_session)) -> HealthOut:
    """Public liveness/readiness: DB connectivity + version."""
    components: list[HealthComponent] = []
    try:
        db.execute(text("SELECT 1"))
        components.append(HealthComponent(name="database", ok=True))
    except Exception as exc:  # noqa: BLE001
        components.append(HealthComponent(name="database", ok=False, detail=str(exc)[:200]))
    ok = all(c.ok for c in components)
    return HealthOut(ok=ok, version=__version__, components=components)


@router.get("/health/detailed", response_model=HealthOut)
def health_detailed(
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("settings:read")),
) -> HealthOut:
    components: list[HealthComponent] = []

    # Database.
    try:
        db.execute(text("SELECT 1"))
        components.append(
            HealthComponent(name="database", ok=True, detail=settings.database_url.split("@")[-1])
        )
    except Exception as exc:  # noqa: BLE001
        components.append(HealthComponent(name="database", ok=False, detail=str(exc)[:200]))

    # Redis / queue.
    if settings.queue_backend == "redis":
        try:
            from app.core.redis import get_redis

            get_redis().ping()
            components.append(HealthComponent(name="redis", ok=True))
        except Exception as exc:  # noqa: BLE001
            components.append(HealthComponent(name="redis", ok=False, detail=str(exc)[:200]))
    else:
        components.append(HealthComponent(name="queue", ok=True, detail="in-process (dev/test)"))

    # MinIO.
    try:
        from app.services import evidence

        ok = evidence._ensure_bucket()  # noqa: SLF001 - internal check
        components.append(
            HealthComponent(
                name="minio", ok=ok, detail="" if ok else "unreachable (evidence stored inline)"
            )
        )
    except Exception as exc:  # noqa: BLE001
        components.append(HealthComponent(name="minio", ok=False, detail=str(exc)[:200]))

    # Workers online.
    cutoff = utcnow() - dt.timedelta(seconds=90)
    online = 0
    for w in db.execute(select(Worker)).scalars():
        if w.last_heartbeat:
            hb = w.last_heartbeat
            if hb.tzinfo is None:
                hb = hb.replace(tzinfo=cutoff.tzinfo)
            if hb >= cutoff and w.status != "offline":
                online += 1
    total = int(db.execute(select(func.count(Worker.id))).scalar_one() or 0)
    components.append(
        HealthComponent(
            name="workers",
            ok=online > 0 or total == 0,
            detail=f"{online} online / {total} registered",
        )
    )

    # Disk.
    try:
        usage = shutil.disk_usage("/")
        free_pct = usage.free / usage.total * 100
        components.append(
            HealthComponent(name="disk", ok=free_pct > 5, detail=f"{free_pct:.0f}% free")
        )
    except Exception as exc:  # noqa: BLE001
        components.append(HealthComponent(name="disk", ok=True, detail=str(exc)[:100]))

    return HealthOut(ok=all(c.ok for c in components), version=__version__, components=components)
