"""Scans, their steps, discovered assets/technologies, and change events."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, uuid_pk
from app.models.enums import AssetType, Intensity, ScanMode, ScanStatus, StepStatus


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    authorization_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default=ScanStatus.QUEUED.value, index=True)
    mode: Mapped[str] = mapped_column(String(16), default=ScanMode.PRODUCTION.value)
    profile: Mapped[str] = mapped_column(String(16), default=Intensity.SAFE.value)
    effective_intensity: Mapped[str] = mapped_column(String(16), default=Intensity.SAFE.value)

    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    summary: Mapped[dict] = mapped_column(JSON, default=dict)  # severity counts etc.
    error: Mapped[str] = mapped_column(Text, default="")

    steps: Mapped[list[ScanStep]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="ScanStep.ordering"
    )


class ScanStep(Base, TimestampMixin):
    __tablename__ = "scan_steps"

    id: Mapped[str] = uuid_pk()
    scan_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)  # step/queue type
    queue: Mapped[str] = mapped_column(String(64), default="default")
    ordering: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default=StepStatus.PENDING.value, index=True)
    depends_on: Mapped[list] = mapped_column(JSON, default=list)  # list of step names
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    output_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped[Scan] = relationship(back_populates="steps")


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(32), default=AssetType.URL.value, index=True)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Technology(Base, TimestampMixin):
    __tablename__ = "technologies"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), default="")
    category: Mapped[str] = mapped_column(String(64), default="")
    source: Mapped[str] = mapped_column(String(64), default="")
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    first_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ChangeEvent(Base, TimestampMixin):
    __tablename__ = "change_events"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    change_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    before: Mapped[dict] = mapped_column(JSON, default=dict)
    after: Mapped[dict] = mapped_column(JSON, default=dict)
