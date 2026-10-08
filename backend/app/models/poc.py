"""PoC / exploit *intelligence* records and their sources.

These are METADATA records about publicly known vulnerabilities and research.
The platform does not auto-execute collected artifacts; everything starts as
UNVERIFIED and any active use is operator-driven and (for active methods)
human-approved. See docs/POC_INTELLIGENCE.md.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import JSON, Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, uuid_pk
from app.models.enums import PoCMaturity, SafetyClass, VerificationStatus


class PoC(Base, TimestampMixin):
    __tablename__ = "pocs"

    id: Mapped[str] = uuid_pk()
    poc_code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    cve: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    cwe: Mapped[str] = mapped_column(String(32), default="")
    title: Mapped[str] = mapped_column(String(512), default="")
    description: Mapped[str] = mapped_column(Text, default="")

    affected_product: Mapped[str] = mapped_column(String(255), default="", index=True)
    affected_slug: Mapped[str] = mapped_column(String(255), default="", index=True)
    affected_type: Mapped[str] = mapped_column(String(16), default="")  # core/plugin/theme
    version_min: Mapped[str] = mapped_column(String(64), default="")
    version_max: Mapped[str] = mapped_column(String(64), default="")
    fixed_version: Mapped[str] = mapped_column(String(64), default="")

    attack_type: Mapped[str] = mapped_column(String(64), default="")
    auth_required: Mapped[bool] = mapped_column(Boolean, default=True)
    privilege_required: Mapped[str] = mapped_column(String(32), default="")
    platform: Mapped[str] = mapped_column(String(64), default="wordpress")

    source_url: Mapped[str] = mapped_column(String(1024), default="")
    source_repo: Mapped[str] = mapped_column(String(1024), default="")
    author: Mapped[str] = mapped_column(String(255), default="")
    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    maturity: Mapped[str] = mapped_column(String(24), default=PoCMaturity.UNKNOWN.value, index=True)
    safety_classification: Mapped[str] = mapped_column(
        String(24), default=SafetyClass.UNKNOWN.value
    )
    verification_status: Mapped[str] = mapped_column(
        String(24), default=VerificationStatus.UNVERIFIED.value
    )
    lab_tested: Mapped[bool] = mapped_column(Boolean, default=False)
    production_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # Optional locally-stored artifact (object-storage key + hash). May be empty
    # when only a reference/metadata is retained.
    artifact_ref: Mapped[str] = mapped_column(String(512), default="")
    artifact_sha256: Mapped[str] = mapped_column(String(64), default="")

    # Static-inspection / test bookkeeping.
    last_tested_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    test_result: Mapped[dict] = mapped_column(JSON, default=dict)
    source_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class PoCSource(Base, TimestampMixin):
    __tablename__ = "poc_sources"

    id: Mapped[str] = uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    source_type: Mapped[str] = mapped_column(String(64), default="")  # nvd/cisa-kev/gh-advisory/...
    url: Mapped[str] = mapped_column(String(1024), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    requires_key: Mapped[bool] = mapped_column(Boolean, default=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    last_synced_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_status: Mapped[str] = mapped_column(String(255), default="")
