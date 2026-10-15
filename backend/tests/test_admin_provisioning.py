"""Phase 3A — Super Administrator provisioning & credential controls.

Every assertion runs against the real bootstrap routine and the real API; none
fabricate a result. Covers: single-super-admin provisioning, idempotent and
non-reusable bootstrap, argon2 hashing (never plaintext), privileged-function
access, ordinary-user denial, role-change auditing, immediate disable, and
self-service credential change.
"""

from __future__ import annotations

from sqlalchemy import func, select

from app.cli import bootstrap
from app.core.db import SessionLocal
from app.core.security import verify_password
from app.models.user import User

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "AdminPassw0rd!xyz"


# --------------------------------------------------------------- provisioning
def test_bootstrap_provisions_single_super_admin():
    bootstrap.main()
    with SessionLocal() as db:
        users = db.execute(select(User)).scalars().all()
        assert len(users) == 1
        assert users[0].email == ADMIN_EMAIL
        assert users[0].role == "super_admin"
        assert users[0].is_active is True


def test_bootstrap_is_idempotent_and_non_reusable():
    # First run creates the admin; a second run must NOT create a duplicate.
    bootstrap.main()
    bootstrap.main()
    with SessionLocal() as db:
        assert db.execute(select(func.count(User.id))).scalar_one() == 1

    # Even after the admin is gone, if ANY user exists the bootstrap refuses to
    # mint a new administrator — it cannot be reused to seize admin post-setup.
    with SessionLocal() as db:
        from app.core.security import hash_password

        db.query(User).delete()
        db.add(
            User(
                email="reader@example.com",
                full_name="r",
                role="read_only",
                hashed_password=hash_password("x" * 12),
                is_active=True,
            )
        )
        db.commit()
    with SessionLocal() as db:
        assert bootstrap.ensure_admin(db) is None
        db.rollback()
    with SessionLocal() as db:
        admins = db.execute(select(User).where(User.role == "super_admin")).scalars().all()
        assert admins == []  # no admin was auto-created over the existing user


def test_admin_password_is_argon2_hashed_not_plaintext(client):
    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.email == ADMIN_EMAIL)).scalar_one()
        assert admin.hashed_password != ADMIN_PASSWORD
        assert admin.hashed_password.startswith("$argon2")
        assert verify_password(ADMIN_PASSWORD, admin.hashed_password)


# ------------------------------------------------------ privilege enforcement
def _mk_user(client, admin_headers, email, role, password="UserPassw0rd!xyz"):
    r = client.post(
        "/users",
        headers=admin_headers,
        json={"email": email, "password": password, "role": role},
    )
    assert r.status_code == 201, r.text
    uid = r.json()["id"]
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return uid, {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_admin_reaches_privileged_functions(client, admin_headers):
    assert client.get("/users", headers=admin_headers).status_code == 200
    assert client.get("/audit", headers=admin_headers).status_code == 200


def test_ordinary_user_cannot_reach_super_admin_functions(client, admin_headers):
    _, reader = _mk_user(client, admin_headers, "reader2@example.com", "read_only")
    # user management is super-admin/user:write only
    r = client.post(
        "/users",
        headers=reader,
        json={"email": "x@y.z", "password": "p" * 12, "role": "read_only"},
    )
    assert r.status_code == 403 and "users:write" in r.json()["detail"]
    assert client.get("/audit", headers=reader).status_code == 403


def test_role_change_is_recorded_in_audit(client, admin_headers):
    uid, _ = _mk_user(client, admin_headers, "promote@example.com", "read_only")
    r = client.patch(f"/users/{uid}", headers=admin_headers, json={"role": "analyst"})
    assert r.status_code == 200 and r.json()["role"] == "analyst"
    entries = client.get("/audit", headers=admin_headers).json()
    assert any(e["action"] == "user.update" and e.get("object_id") == uid for e in entries), (
        "role change must be in the audit log"
    )


def test_disabling_account_denies_existing_token_immediately(client, admin_headers):
    uid, hdr = _mk_user(client, admin_headers, "disable@example.com", "analyst")
    assert client.get("/auth/me", headers=hdr).status_code == 200
    client.patch(f"/users/{uid}", headers=admin_headers, json={"is_active": False})
    # The already-issued token is now refused server-side (no waiting for expiry):
    # deactivation both fails the is_active check and bumps the token epoch.
    r = client.get("/auth/me", headers=hdr)
    assert r.status_code in (401, 403)


# ------------------------------------------------------ credential change
def test_self_service_password_change(client, admin_headers):
    email = "changer@example.com"
    _, hdr = _mk_user(client, admin_headers, email, "analyst", password="OldPassw0rd!xyz")
    # wrong current password is rejected
    bad = client.post(
        "/auth/change-password",
        headers=hdr,
        json={"current_password": "nope", "new_password": "NewPassw0rd!xyz"},
    )
    assert bad.status_code == 400
    # correct current password rotates the credential
    ok = client.post(
        "/auth/change-password",
        headers=hdr,
        json={"current_password": "OldPassw0rd!xyz", "new_password": "NewPassw0rd!xyz"},
    )
    assert ok.status_code == 200
    # old password no longer logs in; new one does
    assert (
        client.post("/auth/login", json={"email": email, "password": "OldPassw0rd!xyz"}).status_code
        == 401
    )
    assert (
        client.post("/auth/login", json={"email": email, "password": "NewPassw0rd!xyz"}).status_code
        == 200
    )


def test_password_change_rejects_reuse_of_current(client, admin_headers):
    _, hdr = _mk_user(
        client, admin_headers, "samepw@example.com", "analyst", password="SamePassw0rd!1"
    )
    r = client.post(
        "/auth/change-password",
        headers=hdr,
        json={"current_password": "SamePassw0rd!1", "new_password": "SamePassw0rd!1"},
    )
    assert r.status_code == 400
