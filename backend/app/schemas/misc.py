"""PoC, worker, schedule, report, lab, dashboard, and health schemas."""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, Field

from app.models.enums import Intensity, PoCMaturity, ReportFormat, SafetyClass
from app.schemas.common import ORMModel


# ------------------------------------------------------------------- PoC
class PoCOut(ORMModel):
    id: str
    poc_code: str
    cve: str | None
    cwe: str
    title: str
    description: str
    affected_product: str
    affected_slug: str
    affected_type: str
    version_min: str
    version_max: str
    fixed_version: str
    attack_type: str
    auth_required: bool
    privilege_required: str
    platform: str
    source_url: str
    source_repo: str
    author: str
    published_at: dt.datetime | None
    maturity: str
    safety_classification: str
    verification_status: str
    lab_tested: bool
    production_verified: bool
    artifact_ref: str
    artifact_sha256: str
    created_at: dt.datetime


class PoCCreate(BaseModel):
    cve: str | None = None
    cwe: str = ""
    title: str
    description: str = ""
    affected_product: str = ""
    affected_slug: str = ""
    affected_type: str = ""
    version_min: str = ""
    version_max: str = ""
    fixed_version: str = ""
    attack_type: str = ""
    auth_required: bool = True
    privilege_required: str = ""
    platform: str = "wordpress"
    source_url: str = ""
    source_repo: str = ""
    author: str = ""
    maturity: PoCMaturity = PoCMaturity.COLLECTED
    safety_classification: SafetyClass = SafetyClass.UNKNOWN


class PoCUpdate(BaseModel):
    maturity: PoCMaturity | None = None
    safety_classification: SafetyClass | None = None
    description: str | None = None
    lab_tested: bool | None = None
    production_verified: bool | None = None


class PoCSyncRequest(BaseModel):
    sources: list[str] | None = None  # source names; None = all enabled


class PoCCollectRequest(BaseModel):
    """Batch artifact collection. Downloads + statically classifies; never runs."""

    poc_ids: list[str] | None = None  # explicit ids; None = select by filter
    only_uncollected: bool = True  # skip PoCs that already have an artifact
    limit: int = Field(default=25, ge=1, le=200)


class PoCSourceOut(ORMModel):
    id: str
    name: str
    source_type: str
    url: str
    enabled: bool
    requires_key: bool
    last_synced_at: dt.datetime | None
    last_status: str


# --------------------------------------------------------------- workers
class WorkerOut(ORMModel):
    id: str
    name: str
    queues: str
    status: str
    host: str
    version: str
    current_job: str | None
    job_count: int
    cpu_percent: float
    ram_mb: float
    last_heartbeat: dt.datetime | None


# -------------------------------------------------------------- schedules
class ScheduleCreate(BaseModel):
    name: str = ""
    interval: str = "daily"
    cron: str = ""
    profile: Intensity = Intensity.SAFE
    enabled: bool = True
    trigger: str = "schedule"


class ScheduleOut(ORMModel):
    id: str
    target_id: str
    name: str
    interval: str
    cron: str
    profile: str
    enabled: bool
    trigger: str
    next_run_at: dt.datetime | None
    last_run_at: dt.datetime | None
    created_at: dt.datetime


# ---------------------------------------------------------------- reports
class ReportCreate(BaseModel):
    report_format: ReportFormat = ReportFormat.HTML
    title: str = ""
    params: dict = Field(default_factory=dict)


class ReportOut(ORMModel):
    id: str
    target_id: str
    scan_id: str | None
    title: str
    report_format: str
    status: str
    storage_key: str
    created_at: dt.datetime
    finished_at: dt.datetime | None
    error: str


# ------------------------------------------------------------------- labs
class LabCreate(BaseModel):
    name: str
    description: str = ""
    template: dict = Field(default_factory=dict)
    auto_destroy: bool = True
    ttl_minutes: int = 60


class LabOut(ORMModel):
    id: str
    name: str
    description: str
    template: dict
    isolation_network: str
    auto_destroy: bool
    ttl_minutes: int
    created_at: dt.datetime


class LabInstanceOut(ORMModel):
    id: str
    lab_id: str
    status: str
    provider: str
    wp_version: str
    php_version: str
    plugin_slug: str
    plugin_version: str
    endpoint_url: str
    expires_at: dt.datetime | None
    created_at: dt.datetime


# --------------------------------------------------------------- dashboard
class DashboardStats(BaseModel):
    total_targets: int
    authorized_targets: int
    currently_scanning: int
    critical_findings: int
    high_findings: int
    confirmed_findings: int
    unverified_findings: int
    recently_fixed: int
    poc_library_size: int
    workers_online: int
    last_scan_at: dt.datetime | None
    next_scheduled_at: dt.datetime | None


class HealthComponent(BaseModel):
    name: str
    ok: bool
    detail: str = ""


class HealthOut(BaseModel):
    ok: bool
    version: str
    components: list[HealthComponent]
