"""Enumerations used across models, schemas, and services.

Stored in the database as their string ``value`` (portable across SQLite and
PostgreSQL). Validation happens in Pydantic schemas and service code.
"""

from __future__ import annotations

from enum import StrEnum  # Python 3.11+ (requires-python >= 3.11)


class UserRole(StrEnum):
    SUPER_ADMIN = "super_admin"
    SECURITY_ADMIN = "security_admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    READ_ONLY = "read_only"


class Intensity(StrEnum):
    PASSIVE = "passive"
    SAFE = "safe"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


class AuthorizationStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AuthorizationType(StrEnum):
    WRITTEN_CONSENT = "written_consent"
    INTERNAL_ASSET = "internal_asset"
    BUG_BOUNTY_SCOPE = "bug_bounty_scope"
    LAB = "lab"
    OTHER = "other"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanMode(StrEnum):
    PRODUCTION = "production"
    LAB = "lab"


class StepStatus(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Numeric ordering for sorting/aggregation.
SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    RETEST_REQUIRED = "retest_required"
    VERIFIED_FIXED = "verified_fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class VerificationStatus(StrEnum):
    UNVERIFIED = "unverified"
    NOT_VULNERABLE = "not_vulnerable"
    LIKELY_VULNERABLE = "likely_vulnerable"
    VULNERABLE = "vulnerable"
    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTABLE = "not_testable"


class PoCMaturity(StrEnum):
    UNKNOWN = "unknown"
    COLLECTED = "collected"
    PARSED = "parsed"
    STATIC_CHECKED = "static_checked"
    LAB_TESTED = "lab_tested"
    VERIFIED = "verified"
    BROKEN = "broken"
    OBSOLETE = "obsolete"
    UNSAFE = "unsafe"


class SafetyClass(StrEnum):
    UNKNOWN = "unknown"
    BENIGN_CHECK = "benign_check"  # read-only existence/version check
    ACTIVE_BENIGN = "active_benign"  # sends a request but non-destructive
    INTRUSIVE = "intrusive"  # changes state; lab-only by default
    DESTRUCTIVE = "destructive"  # never auto-run


class CredType(StrEnum):
    WP_PASSWORD = "wp_password"
    APP_PASSWORD = "app_password"
    API_TOKEN = "api_token"
    COOKIE = "cookie"
    SSH = "ssh"


class AssetType(StrEnum):
    HOST = "host"
    URL = "url"
    ENDPOINT = "endpoint"
    SERVICE = "service"
    REST_ROUTE = "rest_route"
    XMLRPC = "xmlrpc"
    FILE = "file"


class WorkerStatus(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"


class ReportFormat(StrEnum):
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"


class ReportStatus(StrEnum):
    PENDING = "pending"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"


class LabInstanceStatus(StrEnum):
    PENDING = "pending"
    PROVISIONING = "provisioning"
    RUNNING = "running"
    STOPPED = "stopped"
    DESTROYED = "destroyed"
    FAILED = "failed"


class VerificationMethod(StrEnum):
    ENDPOINT_PRESENCE = "endpoint_presence"
    PARAM_BEHAVIOR = "param_behavior"
    AUTHZ_CHECK = "authz_check"
    VERSION_MATCH = "version_match"
    INFO_EXPOSURE = "info_exposure"
    MANUAL = "manual"


class ChangeType(StrEnum):
    PLUGIN_ADDED = "plugin_added"
    PLUGIN_REMOVED = "plugin_removed"
    PLUGIN_VERSION_CHANGED = "plugin_version_changed"
    THEME_CHANGED = "theme_changed"
    WP_VERSION_CHANGED = "wp_version_changed"
    ENDPOINT_ADDED = "endpoint_added"
    VULN_NEW = "vuln_new"
    VULN_FIXED = "vuln_fixed"
    SERVICE_NEW = "service_new"
    CONFIG_CHANGE = "config_change"
