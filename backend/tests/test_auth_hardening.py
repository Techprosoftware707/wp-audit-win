"""Regression tests for the audit-driven auth hardening:

- token-epoch revocation (password change invalidates old access + refresh tokens)
- step-up re-auth for MFA management (disable/setup require the current password)
- API-key callers are blocked from key-management and MFA-management routes
- a leaked API key cannot mint another API key (no self-replication/persistence)
"""

from __future__ import annotations

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "AdminPassw0rd!xyz"


def _login(client, email=ADMIN_EMAIL, password=ADMIN_PASSWORD):
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _bearer(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


# --------------------------------------------------------- token-epoch revocation
def test_password_change_invalidates_old_access_token(client):
    tokens = _login(client)
    hdr = _bearer(tokens)
    assert client.get("/auth/me", headers=hdr).status_code == 200
    r = client.post(
        "/auth/change-password",
        headers=hdr,
        json={"current_password": ADMIN_PASSWORD, "new_password": "BrandNewPassw0rd!1"},
    )
    assert r.status_code == 200
    # The access token minted under the old epoch is now rejected.
    assert client.get("/auth/me", headers=hdr).status_code == 401


def test_password_change_invalidates_old_refresh_token(client):
    tokens = _login(client)
    hdr = _bearer(tokens)
    client.post(
        "/auth/change-password",
        headers=hdr,
        json={"current_password": ADMIN_PASSWORD, "new_password": "BrandNewPassw0rd!1"},
    )
    # The old refresh token can no longer mint new access tokens.
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401


# --------------------------------------------------------- MFA step-up re-auth
def test_mfa_disable_requires_current_password(client):
    hdr = _bearer(_login(client))
    # No body / wrong password is rejected; the second factor is NOT removed.
    assert client.post("/auth/mfa/disable", headers=hdr, json={}).status_code == 422
    r = client.post("/auth/mfa/disable", headers=hdr, json={"current_password": "wrong"})
    assert r.status_code == 400
    # Correct password succeeds.
    ok = client.post("/auth/mfa/disable", headers=hdr, json={"current_password": ADMIN_PASSWORD})
    assert ok.status_code == 200


def test_mfa_setup_requires_current_password(client):
    hdr = _bearer(_login(client))
    assert (
        client.post("/auth/mfa/setup", headers=hdr, json={"current_password": "wrong"}).status_code
        == 400
    )
    ok = client.post("/auth/mfa/setup", headers=hdr, json={"current_password": ADMIN_PASSWORD})
    assert ok.status_code == 200
    assert ok.json()["secret"]


# --------------------------------------------------------- API-key blast radius
def test_api_key_cannot_mint_another_api_key(client, admin_headers):
    # Create a key using an interactive (bearer) session…
    created = client.post("/auth/api-keys", headers=admin_headers, json={"name": "k"}).json()
    key = {"X-API-Key": created["key"]}
    # …but the key itself cannot create more keys (no self-replication/persistence).
    r = client.post("/auth/api-keys", headers=key, json={"name": "evil"})
    assert r.status_code == 403
    assert "session" in r.json()["detail"].lower()


def test_api_key_cannot_disable_mfa_or_change_password(client, admin_headers):
    created = client.post("/auth/api-keys", headers=admin_headers, json={"name": "k"}).json()
    key = {"X-API-Key": created["key"]}
    assert (
        client.post(
            "/auth/mfa/disable", headers=key, json={"current_password": ADMIN_PASSWORD}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/auth/change-password",
            headers=key,
            json={"current_password": ADMIN_PASSWORD, "new_password": "X" * 14},
        ).status_code
        == 403
    )


def test_api_key_last_used_at_is_recorded(client, admin_headers):
    created = client.post("/auth/api-keys", headers=admin_headers, json={"name": "k"}).json()
    assert created["last_used_at"] is None
    client.get("/auth/me", headers={"X-API-Key": created["key"]})
    listed = client.get("/auth/api-keys", headers=admin_headers).json()
    row = next(k for k in listed if k["id"] == created["id"])
    assert row["last_used_at"] is not None
