"""Model registry. Importing this package registers all tables on Base.metadata."""

from __future__ import annotations

from app.models.base import Base
from app.models.finding import Evidence, Finding, VerificationTest, Vulnerability
from app.models.lab import Lab, LabInstance
from app.models.poc import PoC, PoCSource
from app.models.report import Report, Schedule
from app.models.scan import Asset, ChangeEvent, Scan, ScanStep, Technology
from app.models.system import AuditLog, Permission, Role, Worker
from app.models.target import Authorization, Credential, Target
from app.models.user import ApiKey, User
from app.models.wordpress import Plugin, Theme, WordPressInfo, WPUser

__all__ = [
    "Base",
    "User",
    "ApiKey",
    "Role",
    "Permission",
    "Worker",
    "AuditLog",
    "Target",
    "Authorization",
    "Credential",
    "Scan",
    "ScanStep",
    "Asset",
    "Technology",
    "ChangeEvent",
    "WordPressInfo",
    "Plugin",
    "Theme",
    "WPUser",
    "Vulnerability",
    "Finding",
    "Evidence",
    "VerificationTest",
    "PoC",
    "PoCSource",
    "Lab",
    "LabInstance",
    "Report",
    "Schedule",
]
