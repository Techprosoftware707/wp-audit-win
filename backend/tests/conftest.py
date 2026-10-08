"""Pytest fixtures. Runs against in-memory SQLite with the in-process queue and a
mocked HTTP transport, so no external services are required."""

from __future__ import annotations

import os

os.environ.setdefault("WPSEC_ENV", "test")
os.environ.setdefault("WPSEC_ADMIN_EMAIL", "admin@example.com")
os.environ.setdefault("WPSEC_ADMIN_PASSWORD", "AdminPassw0rd!xyz")

import datetime as dt

import httpx
import pytest
from fastapi.testclient import TestClient

from app.cli.bootstrap import main as bootstrap_main
from app.core.db import Base, create_all, engine
from app.main import app
from app.workers import http as whttp

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "AdminPassw0rd!xyz"

WP_HOME = """<!doctype html><html><head>
<meta name="generator" content="WordPress 6.4.1" />
<link href="/wp-content/plugins/contact-form-7/style.css?ver=5.8.1">
<link href="/wp-content/plugins/woocommerce/app.js?ver=8.2.0">
<link href="/wp-content/themes/twentytwentyone/style.css?ver=1.4">
<link rel="https://api.w.org/" href="/wp-json/" />
</head><body>hi</body></html>"""


def _wp_handler(request: httpx.Request) -> httpx.Response:
    p = request.url.path
    if p in ("", "/"):
        return httpx.Response(200, html=WP_HOME, headers={"server": "nginx"})
    if p == "/readme.html":
        return httpx.Response(200, text="<h1>WordPress</h1> Version 6.4.1")
    if p == "/wp-json/":
        return httpx.Response(200, json={"name": "d"}, headers={"content-type": "application/json"})
    if p == "/wp-json/wp/v2/users":
        return httpx.Response(
            200,
            text='[{"id":1,"name":"Admin","slug":"admin"}]',
            headers={"content-type": "application/json"},
        )
    if p == "/xmlrpc.php":
        return httpx.Response(405, text="XML-RPC server accepts POST requests only.")
    return httpx.Response(404, text="nf")


@pytest.fixture(autouse=True)
def _fresh_db():
    Base.metadata.drop_all(engine)
    create_all()
    # Reset the in-process login rate-limit window between tests.
    from app.core import deps

    deps._memory_buckets.clear()
    yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        bootstrap_main()
        yield c


@pytest.fixture
def admin_headers(client):
    r = client.post("/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def mock_wp():
    whttp.set_transport_for_tests(httpx.MockTransport(_wp_handler))
    yield
    whttp.set_transport_for_tests(None)


def make_authorized_target(client, headers, *, host="wp.example.test", scope=None):
    r = client.post(
        "/targets",
        headers=headers,
        json={
            "name": "Demo",
            "base_url": f"http://{host}",
            "owner": "me",
            "scan_profile": "standard",
            "max_intensity": "standard",
        },
    )
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    now = dt.datetime.now(dt.UTC)
    r = client.post(
        f"/targets/{tid}/authorizations",
        headers=headers,
        json={
            "auth_type": "written_consent",
            "authorized_by": "owner",
            "start_date": (now - dt.timedelta(days=1)).isoformat(),
            "expiration_date": (now + dt.timedelta(days=30)).isoformat(),
            "allowed_scope": scope if scope is not None else [host],
            "max_intensity": "standard",
        },
    )
    aid = r.json()["id"]
    client.post(
        f"/targets/{tid}/authorizations/{aid}/status", headers=headers, json={"status": "active"}
    )
    return tid, aid
