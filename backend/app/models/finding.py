"""Vulnerability intelligence catalog, findings, evidence, verification tests."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, uuid_pk
from app.models.enums import FindingStatus, Severity, VerificationStatus


class Vulnerability(Base, TimestampMixin):
    """A known vulnerability definition (intelligence), independent of any target."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = uuid_pk()
    cve: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    cwe: Mapped[str] = mapped_column(String(32), default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(128), default="")
    severity: Mapped[str] = mapped_column(String(16), default=Severity.MEDIUM.value, index=True)

    affected_product: Mapped[str] = mapped_column(String(255), default="", index=True)
    affected_slug: Mapped[str] = mapped_column(String(255), default="", index=True)
    affected_type: Mapped[str] = mapped_column(String(16), default="")  # core/plugin/theme
    version_min: Mapped[str] = mapped_column(String(64), default="")
    version_max: Mapped[str] = mapped_column(
        String(64), default=""
    )  # affected up to (exclusive of fix)
    fixed_version: Mapped[str] = mapped_column(String(64), default="")

    references: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(64), default="")  # nvd/wpvulndb/manual
    kev: Mapped[bool] = mapped_column(Boolean, default=False)  # CISA Known Exploited
    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Finding(Base, TimestampMixin):
    """An issue discovered on a specific target (deduplicated across scanners)."""

    __tablename__ = "findings"
    # Enforce one finding per (target, dedup signature); add_finding() handles the
    # resulting IntegrityError by merging the concurrent detector.
    __table_args__ = (
        UniqueConstraint("target_id", "dedup_key", name="uq_finding_target_dedup"),
    )

    id: Mapped[str] = uuid_pk()
    finding_code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    target_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    vulnerability_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default=Severity.MEDIUM.value, index=True)
    cve: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    cwe: Mapped[str] = mapped_column(String(32), default="")
    affected_asset: Mapped[str] = mapped_column(String(1024), default="")

    status: Mapped[str] = mapped_column(String(24), default=FindingStatus.OPEN.value, index=True)
    verification_status: Mapped[str] = mapped_column(
        String(24), default=VerificationStatus.UNVERIFIED.value, index=True
    )
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    # Which scanners independently reported this (raises confidence).
    detectors: Mapped[list] = mapped_column(JSON, default=list)
    detector_count: Mapped[int] = mapped_column(Integer, default=1)

    # Stable key used to deduplicate/correlate within a target.
    dedup_key: Mapped[str] = mapped_column(String(255), index=True, nullable=False)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), default=Severity.MEDIUM.value)
    risk_factors: Mapped[dict] = mapped_column(JSON, default=dict)

    first_detected_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_detected_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    remediation: Mapped[str] = mapped_column(Text, default="")

    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    verification_tests: Mapped[list[VerificationTest]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base, TimestampMixin):
    __tablename__ = "evidence"

    id: Mapped[str] = uuid_pk()
    finding_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=True
    )
    scan_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=True
    )
    target_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=True
    )

    kind: Mapped[str] = mapped_column(String(32), default="request_response")
    scanner: Mapped[str] = mapped_column(String(64), default="")
    request: Mapped[str] = mapped_column(Text, default="")
    response: Mapped[str] = mapped_column(Text, default="")
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    body_excerpt: Mapped[str] = mapped_column(Text, default="")

    # Larger artifacts (screenshots, raw output) live in object storage.
    storage_key: Mapped[str] = mapped_column(String(512), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class VerificationTest(Base, TimestampMixin):
    """A record of a verification attempt. Active methods require human approval."""

    __tablename__ = "verification_tests"

    id: Mapped[str] = uuid_pk()
    finding_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    poc_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    method: Mapped[str] = mapped_column(String(32), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), default="production")  # production/lab
    status: Mapped[str] = mapped_column(
        String(24), default=VerificationStatus.UNVERIFIED.value, index=True
    )
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    performed_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    request: Mapped[str] = mapped_column(Text, default="")
    response: Mapped[str] = mapped_column(Text, default="")
    evidence_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")

    finding: Mapped[Finding] = relationship(back_populates="verification_tests")
