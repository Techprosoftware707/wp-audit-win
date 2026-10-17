"""Owner-authorized administrator recovery & approved remediation via WP-CLI.

Every state-changing action here is a legitimate, owner-driven operation on a
site the operator controls and has an ACTIVE authorization for, performed over
the owner's stored SSH credential. These are NOT exploitation paths:

* nothing here bypasses authentication or exploits a vulnerability to gain
  access — it uses WP-CLI, which already has server-side authority;
* the API layer requires an active authorization, an explicit ``confirm`` flag,
  and the ``recovery:execute`` permission before any mutation runs;
* every mutation takes a database backup FIRST and aborts if the backup fails;
* actions are audit-logged (never the new password) and return rollback steps.

The functions take an injectable ``runner`` (``.wp(args) -> WpResult``) so the
logic is unit-testable with a fake — no SSH or live WordPress required.
"""

from __future__ import annotations

import json
import secrets

from sqlalchemy import select

from app.models.base import utcnow
from app.models.enums import CredType
from app.models.target import Credential
from app.services import versions
from app.workers.sshexec import SSHWpRunner


class RecoveryError(Exception):
    """A recovery/remediation operation could not be completed safely."""


def make_runner(db, target) -> SSHWpRunner:
    """Build a real SSH runner from the target's stored SSH credential."""
    cred = (
        db.execute(
            select(Credential).where(
                Credential.target_id == target.id,
                Credential.cred_type == CredType.SSH.value,
            )
        )
        .scalars()
        .first()
    )
    if cred is None:
        raise RecoveryError("no SSH credential assigned to this target")
    try:
        import paramiko  # noqa: F401
    except ImportError as exc:
        raise RecoveryError("paramiko not installed on this host") from exc
    cred.last_used_at = utcnow()
    return SSHWpRunner.from_credential(cred, target.host)


def _json(res) -> list:
    try:
        return json.loads(res.stdout or "[]")
    except (ValueError, json.JSONDecodeError):
        return []


# --------------------------------------------------------------- read-only
def detect_admins(runner) -> dict:
    """Read-only: enumerate administrators and flag lockout / damaged roles."""
    res = runner.wp(
        [
            "user",
            "list",
            "--role=administrator",
            "--format=json",
            "--fields=ID,user_login,display_name,roles",
        ]
    )
    admins = _json(res) if res.ok else []
    allres = runner.wp(["user", "list", "--format=json", "--fields=ID,roles"])
    total = len(_json(allres)) if allres.ok else None

    warnings = []
    locked_out = bool(res.ok) and len(admins) == 0
    if locked_out:
        warnings.append("No administrator account found — the site is locked out of admin.")
    for a in admins:
        if not a.get("roles"):
            warnings.append(
                f"User {a.get('user_login', a.get('ID'))} has empty/damaged capabilities."
            )

    return {
        "ok": bool(res.ok),
        "error": "" if res.ok else res.stderr.strip()[:200],
        "administrator_count": len(admins),
        "total_users": total,
        "locked_out": locked_out,
        "administrators": admins,
        "warnings": warnings,
    }


# --------------------------------------------------------------- backup-first
def backup_db(runner, label: str) -> str:
    """Export the database to a timestamped file on the server; abort on failure.

    Returns the backup filename (relative to the WordPress dir). MUST be called
    before any mutating action — a failed backup raises and the caller aborts.
    """
    name = f"wpsec-backup-{label}-{secrets.token_hex(4)}.sql"
    res = runner.wp(["db", "export", name, "--add-drop-table"])
    if not res.ok:
        raise RecoveryError(
            f"database backup failed; aborting before any change: {res.stderr.strip()[:200]}"
        )
    return name


# --------------------------------------------------------------- mutations
def reset_password(runner, user: str, *, new_password: str | None = None) -> dict:
    """Reset an EXISTING administrator's password (backup first, then verify)."""
    new_password = new_password or secrets.token_urlsafe(18)
    # Confirm the target user exists and is an administrator before touching it.
    roles = runner.wp(["user", "get", str(user), "--field=roles"])
    if not roles.ok:
        raise RecoveryError(f"user {user!r} not found: {roles.stderr.strip()[:200]}")
    if "administrator" not in (roles.stdout or ""):
        raise RecoveryError(f"user {user!r} is not an administrator; refusing to reset")

    backup = backup_db(runner, "pwreset")
    res = runner.wp(["user", "update", str(user), f"--user_pass={new_password}"])
    if not res.ok:
        raise RecoveryError(
            f"password reset failed (backup at {backup}); rollback: wp db import {backup}"
            f" — {res.stderr.strip()[:200]}"
        )
    verify = runner.wp(["user", "get", str(user), "--field=roles"])
    return {
        "action": "reset_password",
        "user": str(user),
        "new_password": new_password,  # returned once; caller must NOT log it
        "backup_file": backup,
        "verified_admin": "administrator" in (verify.stdout or ""),
        "rollback": f"wp db import {backup}",
    }


def create_admin(runner, login: str, email: str, *, new_password: str | None = None) -> dict:
    """Create a NEW administrator (explicit-confirmation gated at the API layer)."""
    new_password = new_password or secrets.token_urlsafe(18)
    exists = runner.wp(["user", "get", login, "--field=ID"])
    if exists.ok and (exists.stdout or "").strip():
        raise RecoveryError(f"user '{login}' already exists; use reset-password instead")

    backup = backup_db(runner, "mkadmin")
    res = runner.wp(
        [
            "user",
            "create",
            login,
            email,
            "--role=administrator",
            f"--user_pass={new_password}",
            "--porcelain",
        ]
    )
    if not res.ok:
        raise RecoveryError(
            f"admin creation failed (backup at {backup}); rollback: wp db import {backup}"
            f" — {res.stderr.strip()[:200]}"
        )
    new_id = (res.stdout or "").strip()
    verify = runner.wp(["user", "get", new_id or login, "--field=roles"])
    return {
        "action": "create_admin",
        "login": login,
        "email": email,
        "user_id": new_id,
        "new_password": new_password,  # returned once; caller must NOT log it
        "backup_file": backup,
        "verified_admin": "administrator" in (verify.stdout or ""),
        "rollback": f"wp user delete {new_id or login} --yes  (or: wp db import {backup})",
    }


def update_component(runner, ctype: str, slug: str, *, to_version: str | None = None) -> dict:
    """Update a plugin/theme to latest (or an explicit HIGHER version).

    Never downgrades: an explicit target version below the installed version is
    refused. Backs up first, updates via WP-CLI, then re-reads the version.
    """
    if ctype not in ("plugin", "theme"):
        raise RecoveryError("component type must be 'plugin' or 'theme'")

    cur = runner.wp([ctype, "get", slug, "--field=version"])
    if not cur.ok:
        raise RecoveryError(f"{ctype} '{slug}' not found: {cur.stderr.strip()[:200]}")
    current_version = (cur.stdout or "").strip()

    if to_version and current_version and versions.lt(to_version, current_version):
        raise RecoveryError(f"refusing to downgrade {slug} from {current_version} to {to_version}")

    backup = backup_db(runner, "update")
    args = [ctype, "update", slug]
    if to_version:
        args.append(f"--version={to_version}")
    res = runner.wp(args)
    if not res.ok:
        raise RecoveryError(
            f"{ctype} update failed (backup at {backup}); rollback: wp db import {backup}"
            f" — {res.stderr.strip()[:200]}"
        )
    after = runner.wp([ctype, "get", slug, "--field=version"])
    return {
        "action": "update_component",
        "component_type": ctype,
        "slug": slug,
        "version_before": current_version,
        "version_after": (after.stdout or "").strip(),
        "backup_file": backup,
        "rollback": f"wp db import {backup}",
    }
