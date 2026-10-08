"""WordPress-specific discovery: core info, plugins, themes, enumerated users."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk


class WordPressInfo(Base, TimestampMixin):
    __tablename__ = "wordpress_info"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    is_wordpress: Mapped[bool] = mapped_column(Boolean, default=False)
    core_version: Mapped[str] = mapped_column(String(32), default="")
    latest_version: Mapped[str] = mapped_column(String(32), default="")
    is_multisite: Mapped[bool] = mapped_column(Boolean, default=False)
    readme_found: Mapped[bool] = mapped_column(Boolean, default=False)
    xmlrpc_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    rest_api_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    login_url: Mapped[str] = mapped_column(String(1024), default="")
    detection: Mapped[dict] = mapped_column(JSON, default=dict)


class Plugin(Base, TimestampMixin):
    __tablename__ = "plugins"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    slug: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(64), default="")
    latest_version: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(32), default="unknown")  # active/inactive/unknown
    outdated: Mapped[bool] = mapped_column(Boolean, default=False)
    vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    source: Mapped[str] = mapped_column(String(64), default="")
    first_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Theme(Base, TimestampMixin):
    __tablename__ = "themes"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    slug: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(64), default="")
    latest_version: Mapped[str] = mapped_column(String(64), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    outdated: Mapped[bool] = mapped_column(Boolean, default=False)
    vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    source: Mapped[str] = mapped_column(String(64), default="")
    first_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WPUser(Base, TimestampMixin):
    __tablename__ = "wp_users"

    id: Mapped[str] = uuid_pk()
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    wp_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    login: Mapped[str] = mapped_column(String(255), default="")
    display_name: Mapped[str] = mapped_column(String(255), default="")
    roles: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
