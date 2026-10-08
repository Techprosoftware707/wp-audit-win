"""The authorization gate: no active scanning without valid authorization."""

from __future__ import annotations

import datetime as dt

from tests.conftest import make_authorized_target


def test_scan_blocked_without_authorization(client, admin_headers, mock_wp):
    r = client.post(
        "/targets",
        headers=admin_headers,
        json={
            "name": "NoAuth",
            "base_url": "http://noauth.example.test",
        },
    )
    tid = r.json()["id"]
    r = client.post(f"/targets/{tid}/scan", headers=admin_headers, json={"profile": "safe"})
    assert r.status_code == 403
    assert "not authorized" in r.json()["detail"].lower()


def test_scan_allowed_after_authorization(client, admin_headers, mock_wp):
    tid, _ = make_authorized_target(client, admin_headers)
    r = client.post(f"/targets/{tid}/scan", headers=admin_headers, json={"profile": "safe"})
    assert r.status_code == 201
    assert r.json()["status"] == "completed"


def test_scope_mismatch_blocks_scan(client, admin_headers, mock_wp):
    # Authorization scope covers a different host than the target.
    tid, _ = make_authorized_target(
        client, admin_headers, host="wp.example.test", scope=["other.example.test"]
    )
    r = client.post(f"/targets/{tid}/scan", headers=admin_headers, json={"profile": "safe"})
    assert r.status_code == 403


def test_expired_authorization_blocks_scan(client, admin_headers, mock_wp):
    r = client.post(
        "/targets",
        headers=admin_headers,
        json={
            "name": "Exp",
            "base_url": "http://exp.example.test",
        },
    )
    tid = r.json()["id"]
    now = dt.datetime.now(dt.UTC)
    r = client.post(
        f"/targets/{tid}/authorizations",
        headers=admin_headers,
        json={
            "auth_type": "written_consent",
            "start_date": (now - dt.timedelta(days=10)).isoformat(),
            "expiration_date": (now - dt.timedelta(days=1)).isoformat(),  # already expired
            "allowed_scope": ["exp.example.test"],
        },
    )
    aid = r.json()["id"]
    client.post(
        f"/targets/{tid}/authorizations/{aid}/status",
        headers=admin_headers,
        json={"status": "active"},
    )
    r = client.post(f"/targets/{tid}/scan", headers=admin_headers, json={"profile": "safe"})
    assert r.status_code == 403


def test_revocation_blocks_subsequent_scan(client, admin_headers, mock_wp):
    tid, aid = make_authorized_target(client, admin_headers)
    assert (
        client.post(
            f"/targets/{tid}/scan", headers=admin_headers, json={"profile": "safe"}
        ).status_code
        == 201
    )
    client.post(
        f"/targets/{tid}/authorizations/{aid}/revoke",
        headers=admin_headers,
        json={"reason": "engagement ended"},
    )
    r = client.post(f"/targets/{tid}/scan", headers=admin_headers, json={"profile": "safe"})
    assert r.status_code == 403


def test_target_shows_authorized_flag(client, admin_headers):
    tid, _ = make_authorized_target(client, admin_headers)
    r = client.get(f"/targets/{tid}", headers=admin_headers)
    assert r.json()["authorized"] is True
    assert r.json()["authorization_status"] == "active"
