"""Append-only audit logging.

Every sensitive action records WHO / WHAT / WHERE / WHEN / RESULT. The table has
no update/delete paths in the API, giving an immutable-style trail.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.base import utcnow
from app.models.system import AuditLog
from app.models.user import User

log = get_logger("audit")


def record(
    db: Session,
    *,
    action: str,
    actor: User | None = None,
    actor_email: str = "",
    object_type: str = "",
    object_id: str | None = None,
    result: str = "success",
    request: Request | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    ip = ""
    ua = ""
    if request is not None:
        fwd = request.headers.get("x-forwarded-for")
        ip = fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "")
        ua = request.headers.get("user-agent", "")[:512]

    entry = AuditLog(
        created_at=utcnow(),
        actor_user_id=actor.id if actor else None,
        actor_email=actor.email if actor else actor_email,
        action=action,
        object_type=object_type,
        object_id=object_id,
        result=result,
        ip=ip,
        user_agent=ua,
        detail=detail or {},
    )
    db.add(entry)
    # Mirror to the application log (secrets are redacted by the log filter).
    log.info(
        "audit action=%s object=%s/%s actor=%s result=%s",
        action,
        object_type,
        object_id,
        entry.actor_email or "anon",
        result,
    )
    return entry
