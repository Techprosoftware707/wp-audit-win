"""Reports and scan schedules."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk
from app.models.enums import Intensity, ReportFormat, ReportStatus


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    title: Mapped[str] = mapped_column(String(512), default="")
    report_format: Mapped[str] = mapped_column(String(16), default=ReportFormat.HTML.value)
    status: Mapped[str] = mapped_column(String(16), default=ReportStatus.PENDING.value, index=True)
    storage_key: Mapped[str] = mapped_column(String(512), default="")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")


class Schedule(Base, TimestampMixin):
    __tablename__ = "schedules"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), default="")
    # Either a preset interval ("hourly","6h","daily","weekly","monthly") or a cron string.
    interval: Mapped[str] = mapped_column(String(64), default="daily")
    cron: Mapped[str] = mapped_column(String(128), default="")
    profile: Mapped[str] = mapped_column(String(16), default=Intensity.SAFE.value)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    trigger: Mapped[str] = mapped_column(String(32), default="schedule")  # schedule/on_change/etc.
    next_run_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
