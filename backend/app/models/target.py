"""Targets, their authorizations (first-class), and stored credentials."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, uuid_pk
from app.models.enums import (
    AuthorizationStatus,
    AuthorizationType,
    CredType,
    Intensity,
)


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[str] = uuid_pk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    host: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    owner: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)

    # Default scan profile and the per-target hard ceiling on intensity.
    scan_profile: Mapped[str] = mapped_column(String(16), default=Intensity.SAFE.value)
    max_intensity: Mapped[str] = mapped_column(String(16), default=Intensity.STANDARD.value)

    asset_importance: Mapped[str] = mapped_column(
        String(16), default="medium"
    )  # low/medium/high/critical
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    authorizations: Mapped[list[Authorization]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
        order_by="Authorization.created_at.desc()",
    )
    credentials: Mapped[list[Credential]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class Authorization(Base, TimestampMixin):
    __tablename__ = "authorizations"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(16), default=AuthorizationStatus.PENDING.value, index=True
    )
    auth_type: Mapped[str] = mapped_column(
        String(32), default=AuthorizationType.WRITTEN_CONSENT.value
    )
    authorized_by: Mapped[str] = mapped_column(String(255), default="")
    reference: Mapped[str] = mapped_column(String(512), default="")  # ticket/doc/URL

    start_date: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expiration_date: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Allowed scope: list of hostnames / IPs / CIDRs this authorization covers.
    allowed_scope: Mapped[list] = mapped_column(JSON, default=list)
    testing_profile: Mapped[str] = mapped_column(String(16), default=Intensity.SAFE.value)
    max_intensity: Mapped[str] = mapped_column(String(16), default=Intensity.STANDARD.value)

    approved_by_user_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[str] = mapped_column(Text, default="")

    target: Mapped[Target] = relationship(back_populates="authorizations")


class Credential(Base, TimestampMixin):
    __tablename__ = "credentials"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), default="")
    cred_type: Mapped[str] = mapped_column(String(32), default=CredType.WP_PASSWORD.value)
    username: Mapped[str] = mapped_column(String(255), default="")
    # Secret is always encrypted at rest (Fernet). Never logged, never returned raw.
    secret_encrypted: Mapped[str] = mapped_column(Text, default="")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    target: Mapped[Target] = relationship(back_populates="credentials")
