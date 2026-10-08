"""Shared model mixins: string UUID primary keys and timestamps."""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base  # re-exported for models

__all__ = ["Base", "uuid_pk", "utcnow", "TimestampMixin"]


def new_uuid() -> str:
    return uuid.uuid4().hex


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def uuid_pk() -> Mapped[str]:
    return mapped_column(String(32), primary_key=True, default=new_uuid)


class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
        nullable=False,
    )
