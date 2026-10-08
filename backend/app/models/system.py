"""System-level models: roles/permissions catalog, workers, audit log."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk
from app.models.enums import WorkerStatus


class Role(Base, TimestampMixin):
    """Catalog of roles (display/extensibility). Enforcement uses the code matrix
    in app.core.rbac, keyed on User.role."""

    __tablename__ = "roles"

    id: Mapped[str] = uuid_pk()
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    permissions: Mapped[list] = mapped_column(JSON, default=list)


class Permission(Base, TimestampMixin):
    __tablename__ = "permissions"

    id: Mapped[str] = uuid_pk()
    code: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")


class Worker(Base, TimestampMixin):
    __tablename__ = "workers"

    id: Mapped[str] = uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    queues: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(16), default=WorkerStatus.OFFLINE.value)
    host: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(32), default="")
    current_job: Mapped[str | None] = mapped_column(String(255), nullable=True)
    job_count: Mapped[int] = mapped_column(Integer, default=0)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0)
    ram_mb: Mapped[float] = mapped_column(Float, default=0.0)
    last_heartbeat: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = uuid_pk()
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    actor_user_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    actor_email: Mapped[str] = mapped_column(String(255), default="")
    action: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    object_type: Mapped[str] = mapped_column(String(64), default="", index=True)
    object_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    result: Mapped[str] = mapped_column(String(16), default="success")
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(512), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
