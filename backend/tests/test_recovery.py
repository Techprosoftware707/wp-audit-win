"""Owner-authorized admin recovery & remediation.

Service logic is exercised with a fake WP-CLI runner (no SSH / live WordPress):
backup-first ordering, no-downgrade, non-admin refusal, lockout detection. API
tests cover the gating: active authorization required, explicit confirmation
required, recovery:execute is super-admin-only, and the new password is returned
once but NEVER written to the audit log.
"""

from __future__ import annotations

from app.services import recovery
from app.workers.sshexec import WpResult
from tests.conftest import make_authorized_target


class FakeRunner:
    """Records every `wp` call and returns whatever the handler decides."""

    def __init__(self, handler):
        self.handler = handler
        self.calls: list[list[str]] = []

    def wp(self, args, timeout=120):
        self.calls.append(list(args))
        return self.handler(list(args))

    def close(self):
        pass

    def field(self, args):
        for a in args:
            if a.startswith("--field="):
                return a.split("=", 1)[1]
        return ""


def R(rc=0, out="", err=""):
    return WpResult(rc, out, err)


# ------------------------------------------------------------- detect (read-only)
def test_detect_admins_normal():
    def h(args):
        if args[:2] == ["user", "list"] and "--role=administrator" in args:
            return R(out='[{"ID":1,"user_login":"admin","roles":"administrator"}]')
        if args[:2] == ["user", "list"]:
            return R(out='[{"ID":1,"roles":"administrator"},{"ID":2,"roles":"subscriber"}]')
        return R()

    out = recovery.detect_admins(FakeRunner(h))
    assert out["administrator_count"] == 1
    assert out["locked_out"] is False
    assert out["total_users"] == 2
    assert out["warnings"] == []


def test_detect_admins_lockout_and_damaged_roles():
    def h(args):
        if "--role=administrator" in args:
            return R(out="[]")  # no admins -> locked out
        return R(out="[]")

    out = recovery.detect_admins(FakeRunner(h))
    assert out["locked_out"] is True
    assert any("locked out" in w.lower() for w in out["warnings"])


# ------------------------------------------------------------- backup-first
def test_backup_failure_aborts_before_any_mutation():
    runner = FakeRunner(
        lambda args: (
            R(rc=1, err="disk full") if args[:2] == ["db", "export"] else R(out="administrator")
        )
    )
    try:
        recovery.reset_password(runner, "admin")
        raise AssertionError("expected RecoveryError")
    except recovery.RecoveryError as exc:
        assert "backup failed" in str(exc)
    # The password update must NOT have run after a failed backup.
    assert not any(c[:2] == ["user", "update"] for c in runner.calls)


def test_reset_password_backs_up_before_updating():
    def h(args):
        if args[:2] == ["user", "get"]:
            return R(out="administrator")
        return R()

    runner = FakeRunner(h)
    res = recovery.reset_password(runner, "admin")
    order = [c[:2] for c in runner.calls]
    assert order.index(["db", "export"]) < order.index(["user", "update"])
    assert res["new_password"] and res["verified_admin"] is True
    assert res["rollback"].startswith("wp db import")


def test_reset_password_refuses_non_admin():
    runner = FakeRunner(lambda args: R(out="editor") if args[:2] == ["user", "get"] else R())
    try:
        recovery.reset_password(runner, "bob")
        raise AssertionError("expected RecoveryError")
    except recovery.RecoveryError as exc:
        assert "not an administrator" in str(exc)
    assert not any(c[:2] == ["db", "export"] for c in runner.calls)


# ------------------------------------------------------------- create admin
def test_create_admin_refuses_existing_login():
    def h(args):
        if args[:2] == ["user", "get"] and "--field=ID" in args:
            return R(out="5")  # already exists
        return R()

    try:
        recovery.create_admin(FakeRunner(h), "admin", "a@b.com")
        raise AssertionError("expected RecoveryError")
    except recovery.RecoveryError as exc:
        assert "already exists" in str(exc)


def test_create_admin_happy_path():
    def h(args):
        if args[:2] == ["user", "get"] and "--field=ID" in args:
            return R(rc=1, err="not found")  # does not exist yet
        if args[:2] == ["user", "create"]:
            return R(out="7")
        if args[:2] == ["user", "get"] and "--field=roles" in args:
            return R(out="administrator")
        return R()

    res = recovery.create_admin(FakeRunner(h), "newadmin", "n@b.com")
    assert res["user_id"] == "7" and res["verified_admin"] is True
    assert res["new_password"]


# ------------------------------------------------------------- remediation
def test_update_component_refuses_downgrade():
    runner = FakeRunner(lambda args: R(out="5.8.1") if args[:2] in (["plugin", "get"],) else R())
    try:
        recovery.update_component(runner, "plugin", "contact-form-7", to_version="5.0.0")
        raise AssertionError("expected RecoveryError")
    except recovery.RecoveryError as exc:
        assert "downgrade" in str(exc)
    assert not any(c[:2] == ["db", "export"] for c in runner.calls)


def test_update_component_happy_path_reports_before_after():
    state = {"ver": "5.8.1"}

    def h(args):
        if args[:2] == ["plugin", "get"]:
            return R(out=state["ver"])
        if args[:2] == ["plugin", "update"]:
            state["ver"] = "5.9.1"
            return R(out="Success")
        return R()

    res = recovery.update_component(FakeRunner(h), "plugin", "contact-form-7")
    assert res["version_before"] == "5.8.1" and res["version_after"] == "5.9.1"
    assert res["backup_file"]


# ------------------------------------------------------------- API gating
def _good_handler(args):
    if args[:2] == ["user", "get"]:
        return R(out="administrator")
    if args[:2] == ["user", "list"] and "--role=administrator" in args:
        return R(out='[{"ID":1,"user_login":"admin","roles":"administrator"}]')
    if args[:2] == ["user", "list"]:
        return R(out='[{"ID":1,"roles":"administrator"}]')
    return R()


def _patch_runner(monkeypatch):
    monkeypatch.setattr(recovery, "make_runner", lambda db, target: FakeRunner(_good_handler))


def _analyst_headers(client, admin_headers, role="analyst"):
    email = f"{role}@example.com"
    client.post(
        "/users", headers=admin_headers, json={"email": email, "password": "p" * 12, "role": role}
    )
    tok = client.post("/auth/login", json={"email": email, "password": "p" * 12}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {tok}"}


def test_reset_password_requires_active_authorization(client, admin_headers, monkeypatch):
    _patch_runner(monkeypatch)
    # Target with NO authorization.
    tid = client.post(
        "/targets", headers=admin_headers, json={"name": "u", "base_url": "http://u.example.test"}
    ).json()["id"]
    r = client.post(
        f"/targets/{tid}/recovery/reset-password",
        headers=admin_headers,
        json={"user": "admin", "confirm": True, "reason": "locked out"},
    )
    assert r.status_code == 403 and "authorization" in r.json()["detail"].lower()


def test_reset_password_requires_confirmation(client, admin_headers, monkeypatch):
    _patch_runner(monkeypatch)
    tid, _ = make_authorized_target(client, admin_headers)
    r = client.post(
        f"/targets/{tid}/recovery/reset-password",
        headers=admin_headers,
        json={"user": "admin", "confirm": False, "reason": ""},
    )
    assert r.status_code == 400 and "confirm" in r.json()["detail"].lower()


def test_execute_is_super_admin_only(client, admin_headers, monkeypatch):
    _patch_runner(monkeypatch)
    tid, _ = make_authorized_target(client, admin_headers)
    analyst = _analyst_headers(client, admin_headers, "analyst")
    sec = _analyst_headers(client, admin_headers, "security_admin")
    body = {"user": "admin", "confirm": True, "reason": "x"}
    assert (
        client.post(
            f"/targets/{tid}/recovery/reset-password", headers=analyst, json=body
        ).status_code
        == 403
    )
    assert (
        client.post(f"/targets/{tid}/recovery/reset-password", headers=sec, json=body).status_code
        == 403
    )
    # security_admin may run read-only detection though.
    assert client.post(f"/targets/{tid}/recovery/detect", headers=sec, json={}).status_code == 200


def test_reset_password_happy_path_and_password_not_audited(client, admin_headers, monkeypatch):
    _patch_runner(monkeypatch)
    tid, _ = make_authorized_target(client, admin_headers)
    r = client.post(
        f"/targets/{tid}/recovery/reset-password",
        headers=admin_headers,
        json={"user": "admin", "confirm": True, "reason": "owner locked out"},
    )
    assert r.status_code == 200, r.text
    pw = r.json()["new_password"]
    assert pw and r.json()["verified_admin"] is True
    # The new password must appear NOWHERE in the audit log.
    entries = client.get("/audit", headers=admin_headers).json()
    assert any(e["action"] == "recovery.reset_password" for e in entries)
    assert pw not in str(entries)


def test_remediation_update_downgrade_rejected_via_api(client, admin_headers, monkeypatch):
    monkeypatch.setattr(
        recovery,
        "make_runner",
        lambda db, target: FakeRunner(
            lambda a: R(out="5.8.1") if a[:2] == ["plugin", "get"] else R()
        ),
    )
    tid, _ = make_authorized_target(client, admin_headers)
    r = client.post(
        f"/targets/{tid}/remediation/update",
        headers=admin_headers,
        json={
            "component_type": "plugin",
            "slug": "contact-form-7",
            "to_version": "5.0.0",
            "confirm": True,
            "reason": "test",
        },
    )
    assert r.status_code == 422 and "downgrade" in r.json()["detail"]
