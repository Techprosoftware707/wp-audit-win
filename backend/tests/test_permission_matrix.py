"""Phase 3C — permission & privilege regression matrix.

Exercises the real API with tokens for every role plus the negative cases the
master prompt enumerates: unauthenticated access, per-role allow/deny, expired /
invalid / wrong-type tokens, revoked API keys, cross-user record isolation,
immediate effect of a role change, and a meta-check that NO mutating route is
reachable without authentication.
"""

from __future__ import annotations

import datetime as dt

import jwt
import pytest

from app.core.config import settings
from app.main import app

ROLES = ["read_only", "auditor", "analyst", "security_admin", "super_admin"]


def _mk_user(client, admin_headers, role):
    email = f"{role}@example.com"
    pw = "MatrixPassw0rd!1"
    r = client.post(
        "/users", headers=admin_headers, json={"email": email, "password": pw, "role": role}
    )
    assert r.status_code == 201, r.text
    uid = r.json()["id"]
    tok = client.post("/auth/login", json={"email": email, "password": pw}).json()["access_token"]
    return uid, {"Authorization": f"Bearer {tok}"}


# ------------------------------------------------------------- unauthenticated
def test_unauthenticated_is_denied_everywhere():
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        for path in [
            "/targets",
            "/scans",
            "/findings",
            "/users",
            "/audit",
            "/pocs",
            "/dashboard/stats",
        ]:
            assert c.get(path).status_code == 401, path


# ------------------------------------------------------------- per-role allow
@pytest.mark.parametrize(
    "role,allowed_get",
    [
        ("read_only", "/targets"),
        ("auditor", "/audit"),
        ("analyst", "/targets"),
        ("security_admin", "/audit"),
        ("super_admin", "/users"),
    ],
)
def test_role_allowed_reads(client, admin_headers, role, allowed_get):
    _, hdr = _mk_user(client, admin_headers, role)
    assert client.get(allowed_get, headers=hdr).status_code == 200


@pytest.mark.parametrize(
    "role,path,method,body,perm",
    [
        # read_only cannot create targets
        (
            "read_only",
            "/targets",
            "post",
            {"name": "x", "base_url": "http://x.test"},
            "targets:write",
        ),
        # auditor is read+audit but cannot write targets
        (
            "auditor",
            "/targets",
            "post",
            {"name": "x", "base_url": "http://x.test"},
            "targets:write",
        ),
        # analyst can write targets but NOT manage users or read audit
        (
            "analyst",
            "/users",
            "post",
            {"email": "n@n.test", "password": "p" * 12, "role": "read_only"},
            "users:write",
        ),
        # security_admin has almost everything EXCEPT user management
        (
            "security_admin",
            "/users",
            "post",
            {"email": "m@m.test", "password": "p" * 12, "role": "read_only"},
            "users:write",
        ),
    ],
)
def test_role_denied_writes(client, admin_headers, role, path, method, body, perm):
    _, hdr = _mk_user(client, admin_headers, role)
    r = getattr(client, method)(path, headers=hdr, json=body)
    assert r.status_code == 403, r.text
    assert perm in r.json()["detail"]


def test_analyst_cannot_read_audit(client, admin_headers):
    _, hdr = _mk_user(client, admin_headers, "analyst")
    assert client.get("/audit", headers=hdr).status_code == 403


def test_analyst_can_create_target(client, admin_headers):
    _, hdr = _mk_user(client, admin_headers, "analyst")
    r = client.post("/targets", headers=hdr, json={"name": "a", "base_url": "http://a.test"})
    assert r.status_code == 201


# ------------------------------------------------------------- token integrity
def _forge(sub, role, *, ttype="access", minutes=5):
    now = dt.datetime.now(dt.UTC)
    exp = now + dt.timedelta(minutes=minutes)
    return jwt.encode(
        {
            "sub": sub,
            "role": role,
            "type": ttype,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
        },
        settings.secret_key,
        algorithm="HS256",
    )


def test_expired_access_token_denied(client, admin_headers):
    me = client.get("/auth/me", headers=admin_headers).json()
    expired = _forge(me["id"], "super_admin", minutes=-5)
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_refresh_token_cannot_authenticate_as_access(client):
    tokens = client.post(
        "/auth/login", json={"email": "admin@example.com", "password": "AdminPassw0rd!xyz"}
    ).json()
    # Presenting the refresh token as a Bearer access token must be rejected.
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {tokens['refresh_token']}"})
    assert r.status_code == 401


def test_garbage_and_wrong_signature_tokens_denied(client):
    assert client.get("/auth/me", headers={"Authorization": "Bearer not.a.jwt"}).status_code == 401
    # Correct shape, wrong signing key.
    bad = jwt.encode(
        {"sub": "x", "role": "super_admin", "type": "access"}, "wrong-key", algorithm="HS256"
    )
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {bad}"}).status_code == 401


# ------------------------------------------------------------- API-key lifecycle
def test_revoked_api_key_is_denied(client, admin_headers):
    created = client.post("/auth/api-keys", headers=admin_headers, json={"name": "k"}).json()
    raw = created["key"]
    assert client.get("/auth/me", headers={"X-API-Key": raw}).status_code == 200
    client.delete(f"/auth/api-keys/{created['id']}", headers=admin_headers)
    assert client.get("/auth/me", headers={"X-API-Key": raw}).status_code == 401


def test_cross_user_api_key_isolation(client, admin_headers):
    _, alice = _mk_user(client, admin_headers, "analyst")
    # bob is a second analyst
    client.post(
        "/users",
        headers=admin_headers,
        json={"email": "bob@example.com", "password": "p" * 12, "role": "analyst"},
    )
    btok = client.post(
        "/auth/login", json={"email": "bob@example.com", "password": "p" * 12}
    ).json()["access_token"]
    bob = {"Authorization": f"Bearer {btok}"}

    alice_key = client.post("/auth/api-keys", headers=alice, json={"name": "a"}).json()
    # Bob cannot see Alice's key, nor revoke it.
    assert all(k["id"] != alice_key["id"] for k in client.get("/auth/api-keys", headers=bob).json())
    assert client.delete(f"/auth/api-keys/{alice_key['id']}", headers=bob).status_code == 404


# ------------------------------------------------------------- live role change
def test_role_change_takes_effect_on_existing_token(client, admin_headers):
    uid, hdr = _mk_user(client, admin_headers, "read_only")
    # read_only cannot read the audit log
    assert client.get("/audit", headers=hdr).status_code == 403
    # promote to security_admin (which has audit:read)
    client.patch(f"/users/{uid}", headers=admin_headers, json={"role": "security_admin"})
    # SAME token is now authorized — authority is read from the DB, not the token claim
    assert client.get("/audit", headers=hdr).status_code == 200
    # demote back -> denied again on the same token
    client.patch(f"/users/{uid}", headers=admin_headers, json={"role": "read_only"})
    assert client.get("/audit", headers=hdr).status_code == 403


# ------------------------------------------------------------- meta: no open mutations
def test_no_mutating_route_is_reachable_unauthenticated():
    """Enumerate EVERY mutating endpoint from the OpenAPI schema and confirm none
    performs its mutation without authentication. Uses the schema (not app.routes)
    so it is robust to how routers are mounted."""
    import re

    from fastapi.testclient import TestClient

    # Endpoints that legitimately take no auth (public auth entrypoints).
    PUBLIC = {("/auth/login", "post"), ("/auth/refresh", "post")}
    mutating = {"post", "put", "patch", "delete"}
    checked = 0
    with TestClient(app) as c:
        paths = c.get("/openapi.json").json()["paths"]
        for raw_path, ops in paths.items():
            concrete = re.sub(r"\{[^}]+\}", "deadbeef", raw_path)
            for method in ops:
                if method.lower() not in mutating or (raw_path, method.lower()) in PUBLIC:
                    continue
                r = c.request(method.upper(), concrete, json={})
                # The mutation must NOT succeed without authentication.
                assert r.status_code not in (200, 201, 204), (
                    f"{method} {raw_path} -> {r.status_code}"
                )
                checked += 1
    assert checked > 20, f"expected to probe many mutating routes, only hit {checked}"
