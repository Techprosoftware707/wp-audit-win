"""Idempotent bootstrap: seed roles/permissions/sources and the initial admin.

Run automatically by the API entrypoint and via `make bootstrap`. Safe to run
repeatedly.
"""

from __future__ import annotations

import secrets
import sys

from sqlalchemy import func, select

from app.core.config import settings
from app.core.db import create_all, session_scope
from app.core.rbac import PERMISSIONS, ROLE_PERMISSIONS
from app.core.security import hash_password
from app.models.enums import UserRole
from app.models.system import Permission, Role
from app.models.user import User
from app.services import intel_sync


def seed_catalog(db) -> None:
    for code, desc in PERMISSIONS.items():
        if not db.execute(select(Permission).where(Permission.code == code)).scalar_one_or_none():
            db.add(Permission(code=code, description=desc))
    for role, perms in ROLE_PERMISSIONS.items():
        existing = db.execute(select(Role).where(Role.name == role)).scalar_one_or_none()
        if existing:
            existing.permissions = sorted(perms)
        else:
            db.add(Role(name=role, description=f"{role} role", permissions=sorted(perms)))
    intel_sync.ensure_sources(db)


def ensure_admin(db) -> str | None:
    existing = db.execute(select(func.count(User.id))).scalar_one()
    if (
        existing
        and db.execute(select(User).where(User.email == settings.admin_email)).scalar_one_or_none()
    ):
        return None  # admin already present
    if existing:
        return None  # some user already exists; don't auto-create

    password = settings.admin_password or secrets.token_urlsafe(16)
    user = User(
        email=settings.admin_email,
        full_name="Administrator",
        role=UserRole.SUPER_ADMIN.value,
        hashed_password=hash_password(password),
        is_active=True,
    )
    db.add(user)
    return password if not settings.admin_password else "(from WPSEC_ADMIN_PASSWORD)"


def main() -> None:
    if settings.is_sqlite:
        create_all()
    with session_scope() as db:
        seed_catalog(db)
        generated = ensure_admin(db)
    if generated and generated.startswith("("):
        print(f"[bootstrap] admin ready: {settings.admin_email}")
    elif generated:
        print("=" * 60)
        print(" Initial administrator created")
        print(f"   email:    {settings.admin_email}")
        print(f"   password: {generated}")
        print("   >>> Save this password now; it will not be shown again. <<<")
        print("=" * 60)
    else:
        print(f"[bootstrap] admin already present ({settings.admin_email}); catalog synced")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
