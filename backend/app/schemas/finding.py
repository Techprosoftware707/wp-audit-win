"""Finding, evidence, verification, and vulnerability schemas."""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel

from app.models.enums import FindingStatus, VerificationMethod
from app.schemas.common import ORMModel


class FindingOut(ORMModel):
    id: str
    finding_code: str
    target_id: str
    scan_id: str | None
    vulnerability_id: str | None
    title: str
    description: str
    severity: str
    cve: str | None
    cwe: str
    affected_asset: str
    status: str
    verification_status: str
    confirmed: bool
    detectors: list[str]
    detector_count: int
    risk_score: float
    risk_level: str
    risk_factors: dict
    first_detected_at: dt.datetime | None
    last_detected_at: dt.datetime | None
    resolved_at: dt.datetime | None
    remediation: str
    created_at: dt.datetime


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    remediation: str | None = None


class EvidenceOut(ORMModel):
    id: str
    finding_id: str | None
    scan_id: str | None
    target_id: str | None
    kind: str
    scanner: str
    request: str
    response: str
    http_status: int | None
    headers: dict
    body_excerpt: str
    storage_key: str
    sha256: str
    meta: dict
    created_at: dt.datetime


class VerificationRequest(BaseModel):
    method: VerificationMethod
    mode: str = "production"
    poc_id: str | None = None
    notes: str = ""
    # Active methods require explicit approval before they run.
    approve: bool = False


class VerificationTestOut(ORMModel):
    id: str
    finding_id: str
    poc_id: str | None
    method: str
    mode: str
    status: str
    approved: bool
    approved_by: str | None
    performed_by: str | None
    request: str
    response: str
    evidence_id: str | None
    notes: str
    created_at: dt.datetime


class VulnerabilityOut(ORMModel):
    id: str
    cve: str | None
    title: str
    description: str
    cwe: str
    cvss_score: float | None
    cvss_vector: str
    severity: str
    affected_product: str
    affected_slug: str
    affected_type: str
    version_min: str
    version_max: str
    fixed_version: str
    references: list
    source: str
    kev: bool
    published_at: dt.datetime | None
    created_at: dt.datetime


class VulnerabilityCreate(BaseModel):
    cve: str | None = None
    title: str
    description: str = ""
    cwe: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    severity: str = "medium"
    affected_product: str = ""
    affected_slug: str = ""
    affected_type: str = ""
    version_min: str = ""
    version_max: str = ""
    fixed_version: str = ""
    references: list = []
    source: str = "manual"
    kev: bool = False
