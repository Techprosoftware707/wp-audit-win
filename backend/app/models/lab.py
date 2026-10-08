"""Isolated exploit-lab definitions and instances.

Lab instances are network-isolated and auto-reset. Actual container provisioning
is performed by the lab worker through a pluggable provider; the default provider
records lifecycle state and requires explicit operator action to launch a real
disposable instance (see app/services/lab.py and docs/LAB.md).
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, uuid_pk
from app.models.enums import LabInstanceStatus


class Lab(Base, TimestampMixin):
    __tablename__ = "labs"

    id: Mapped[str] = uuid_pk()
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    template: Mapped[dict] = mapped_column(JSON, default=dict)  # wp/plugin/theme/php spec
    isolation_network: Mapped[str] = mapped_column(String(64), default="wpsec-lab")
    auto_destroy: Mapped[bool] = mapped_column(Boolean, default=True)
    ttl_minutes: Mapped[int] = mapped_column(Integer, default=60)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    instances: Mapped[list[LabInstance]] = relationship(
        back_populates="lab", cascade="all, delete-orphan"
    )


class LabInstance(Base, TimestampMixin):
    __tablename__ = "lab_instances"

    id: Mapped[str] = uuid_pk()
    lab_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("labs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(16), default=LabInstanceStatus.PENDING.value, index=True
    )
    provider: Mapped[str] = mapped_column(String(32), default="record")  # record/docker
    container_ref: Mapped[str] = mapped_column(String(255), default="")
    wp_version: Mapped[str] = mapped_column(String(32), default="")
    php_version: Mapped[str] = mapped_column(String(32), default="")
    plugin_slug: Mapped[str] = mapped_column(String(255), default="")
    plugin_version: Mapped[str] = mapped_column(String(64), default="")
    theme_slug: Mapped[str] = mapped_column(String(255), default="")
    theme_version: Mapped[str] = mapped_column(String(64), default="")
    endpoint_url: Mapped[str] = mapped_column(String(1024), default="")
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    destroyed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    lab: Mapped[Lab] = relationship(back_populates="instances")
