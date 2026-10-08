"""Role-based access control.

Enforcement is a static permission matrix keyed on the user's role. The
``roles``/``permissions`` tables exist as a catalog (seeded at bootstrap) for
display and future dynamic RBAC; the checks the API runs use this matrix so
authorization decisions are explicit, fast, and unit-testable.
"""

from __future__ import annotations

from app.models.enums import UserRole

# Coarse, meaningful permission codes.
PERMISSIONS: dict[str, str] = {
    "targets:read": "View targets",
    "targets:write": "Create/edit/delete targets",
    "authz:read": "View authorizations",
    "authz:write": "Create/edit authorizations",
    "authz:approve": "Approve/activate or revoke authorizations",
    "scans:read": "View scans",
    "scans:write": "Start/stop/cancel scans",
    "findings:read": "View findings",
    "findings:write": "Change finding status / remediation",
    "verification:read": "View verification tests",
    "verification:run": "Run verification tests",
    "verification:approve": "Approve active verification tests",
    "pocs:read": "View PoC intelligence",
    "pocs:write": "Edit PoC intelligence",
    "pocs:sync": "Trigger PoC/vuln source sync",
    "evidence:read": "View evidence",
    "credentials:read": "List credential metadata (never secrets)",
    "credentials:write": "Store/update/delete credentials",
    "labs:read": "View labs",
    "labs:write": "Create/destroy lab instances",
    "reports:read": "View/download reports",
    "reports:write": "Generate reports",
    "schedules:read": "View schedules",
    "schedules:write": "Create/edit schedules",
    "workers:read": "View workers",
    "users:read": "View users",
    "users:write": "Manage users",
    "audit:read": "View audit log",
    "settings:read": "View settings",
    "settings:write": "Change settings",
}

_ALL = set(PERMISSIONS)

_READ_ONLY = {
    "targets:read",
    "authz:read",
    "scans:read",
    "findings:read",
    "verification:read",
    "pocs:read",
    "evidence:read",
    "reports:read",
    "schedules:read",
    "workers:read",
}

_AUDITOR = _READ_ONLY | {"audit:read", "users:read", "settings:read", "credentials:read"}

_ANALYST = _READ_ONLY | {
    "targets:write",
    "scans:write",
    "findings:write",
    "verification:run",
    "pocs:write",
    "reports:write",
    "schedules:write",
    "authz:write",
}

_SECURITY_ADMIN = _ALL - {"users:write", "settings:write"}

ROLE_PERMISSIONS: dict[str, set[str]] = {
    UserRole.SUPER_ADMIN.value: set(_ALL),
    UserRole.SECURITY_ADMIN.value: set(_SECURITY_ADMIN),
    UserRole.ANALYST.value: set(_ANALYST),
    UserRole.AUDITOR.value: set(_AUDITOR),
    UserRole.READ_ONLY.value: set(_READ_ONLY),
}


def permissions_for(role: str) -> set[str]:
    return ROLE_PERMISSIONS.get(role, set())


def has_permission(role: str, code: str) -> bool:
    return code in permissions_for(role)
