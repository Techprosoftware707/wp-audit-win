"""Authentication, token, and RBAC enforcement."""

from __future__ import annotations


def test_login_success_and_me(client, admin_headers):
    r = client.get("/auth/me", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["email"] == "admin@example.com"
    assert r.json()["role"] == "super_admin"


def test_login_bad_password(client):
    r = client.post("/auth/login", json={"email": "admin@example.com", "password": "wrong"})
    assert r.status_code == 401


def test_unauthenticated_rejected(client):
    assert client.get("/targets").status_code == 401
    assert client.get("/dashboard/stats").status_code == 401


def test_refresh_token(client):
    r = client.post(
        "/auth/login", json={"email": "admin@example.com", "password": "AdminPassw0rd!xyz"}
    )
    refresh = r.json()["refresh_token"]
    r2 = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r2.status_code == 200
    assert r2.json()["access_token"]


def _make_reader(client, admin_headers):
    r = client.post(
        "/users",
        headers=admin_headers,
        json={
            "email": "reader@example.com",
            "password": "ReaderPassw0rd!",
            "role": "read_only",
        },
    )
    assert r.status_code == 201
    r = client.post(
        "/auth/login", json={"email": "reader@example.com", "password": "ReaderPassw0rd!"}
    )
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_rbac_read_only_cannot_write(client, admin_headers):
    reader = _make_reader(client, admin_headers)
    # read allowed
    assert client.get("/targets", headers=reader).status_code == 200
    # write denied
    r = client.post(
        "/targets",
        headers=reader,
        json={
            "name": "x",
            "base_url": "http://x.example.test",
        },
    )
    assert r.status_code == 403
    assert "targets:write" in r.json()["detail"]


def test_rbac_read_only_cannot_read_audit(client, admin_headers):
    reader = _make_reader(client, admin_headers)
    assert client.get("/audit", headers=reader).status_code == 403


def test_api_key_auth(client, admin_headers):
    r = client.post("/auth/api-keys", headers=admin_headers, json={"name": "cli"})
    assert r.status_code == 201
    raw = r.json()["key"]
    # Use the API key instead of the bearer token.
    r2 = client.get("/auth/me", headers={"X-API-Key": raw})
    assert r2.status_code == 200
    assert r2.json()["email"] == "admin@example.com"
