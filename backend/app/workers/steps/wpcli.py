"""WP-CLI step — authenticated, authorized inspection over SSH.

Runs read-only WP-CLI commands on the target host using a stored SSH credential
(core/plugin/theme/user/site-health/integrity). It is fully wired but requires:
  * an SSH credential assigned to the target (cred_type = ssh), and
  * the `paramiko` SSH library available on the worker.
When either is missing it skips with a clear reason rather than failing. See
docs/STATUS.md.
"""

from __future__ import annotations

import json
import shlex

from sqlalchemy import select

from app.core.crypto import decrypt
from app.models.enums import CredType, VerificationStatus
from app.models.target import Credential
from app.workers.base import StepContext

READ_ONLY_COMMANDS = {
    "core_version": ["core", "version"],
    "plugins": ["plugin", "list", "--format=json"],
    "themes": ["theme", "list", "--format=json"],
    "users": ["user", "list", "--format=json"],
    "core_check": ["core", "verify-checksums"],
}


def run(ctx: StepContext) -> dict:
    cred = (
        ctx.db.execute(
            select(Credential).where(
                Credential.target_id == ctx.target.id,
                Credential.cred_type == CredType.SSH.value,
            )
        )
        .scalars()
        .first()
    )
    if cred is None:
        return {"skipped": True, "reason": "no SSH credential assigned to this target"}

    try:
        import paramiko  # noqa: F401
    except ImportError:
        return {"skipped": True, "reason": "paramiko not installed on this worker"}

    meta = cred.meta or {}
    host = meta.get("host") or ctx.target.host
    port = int(meta.get("port", 22))
    wp_path = meta.get("wp_path", "")
    secret = decrypt(cred.secret_encrypted) if cred.secret_encrypted else ""

    import paramiko

    client = paramiko.SSHClient()
    known_hosts_file = meta.get("known_hosts_file")
    if known_hosts_file:
        # Pin host keys from an operator-provided known_hosts file and reject
        # anything not in it.
        client.load_host_keys(known_hosts_file)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    elif meta.get("accept_unknown_host_key"):
        # Operator explicitly opted in to trust-on-first-use for this credential.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        # Secure default: refuse an unknown host key (prevents MITM). Pin a key
        # via meta.known_hosts_file, or set meta.accept_unknown_host_key=true.
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

    results: dict = {}
    try:
        if meta.get("auth") == "key":
            import io as _io

            pkey = paramiko.RSAKey.from_private_key(_io.StringIO(secret))
            client.connect(host, port=port, username=cred.username, pkey=pkey, timeout=20)
        else:
            client.connect(host, port=port, username=cred.username, password=secret, timeout=20)

        # Quote the operator-supplied path so it cannot inject shell syntax.
        prefix = f"cd {shlex.quote(wp_path)} && " if wp_path else ""
        for name, cmd in READ_ONLY_COMMANDS.items():
            full = prefix + "wp " + " ".join(cmd) + " --skip-plugins --skip-themes"
            _in, out, errp = client.exec_command(full, timeout=60)  # noqa: S601 - controlled
            results[name] = out.read().decode(errors="replace")
    except Exception as exc:  # noqa: BLE001
        return {"skipped": True, "reason": f"ssh/wp-cli failed: {type(exc).__name__}: {exc}"}
    finally:
        client.close()
        cred.last_used_at = ctx.now()

    return _ingest(ctx, results)


def _ingest(ctx: StepContext, results: dict) -> dict:
    counts = {"plugins": 0, "themes": 0, "users": 0}
    core_version = (results.get("core_version") or "").strip()
    if core_version:
        ctx.add_technology(
            "WordPress", version=core_version, category="cms", source="wpcli", confidence=99
        )
        ctx.set_wp_info(core_version=core_version, is_wordpress=True)

    for key, kind in (("plugins", "plugin"), ("themes", "theme")):
        try:
            items = json.loads(results.get(key, "") or "[]")
        except (ValueError, json.JSONDecodeError):
            items = []
        for it in items:
            slug = it.get("name") or it.get("title") or ""
            if not slug:
                continue
            fields = dict(
                name=slug,
                version=it.get("version", ""),
                status=it.get("status", "unknown"),
                outdated=(it.get("update") == "available"),
                source="wpcli",
                confidence=99,
            )
            if kind == "plugin":
                ctx.add_plugin(slug, **fields)
            else:
                ctx.add_theme(
                    slug,
                    name=slug,
                    version=it.get("version", ""),
                    active=(it.get("status") == "active"),
                    outdated=(it.get("update") == "available"),
                    source="wpcli",
                    confidence=99,
                )
            counts[key] += 1

    try:
        users = json.loads(results.get("users", "") or "[]")
    except (ValueError, json.JSONDecodeError):
        users = []
    for u in users:
        ctx.add_wp_user(
            login=u.get("user_login", ""),
            display_name=u.get("display_name", ""),
            wp_user_id=u.get("ID"),
            roles=[u.get("roles", "")],
            source="wpcli",
        )
        counts["users"] += 1

    # Core integrity.
    check = results.get("core_check", "")
    if check and "Success" not in check and check.strip():
        f = ctx.add_finding(
            title="WordPress core integrity check reported modifications",
            severity="high",
            dedup_key=f"sig:core-integrity:{ctx.target.host}",
            detector="wpcli",
            description="`wp core verify-checksums` reported differences from official checksums.",
            affected_asset=ctx.target.base_url,
            cwe="CWE-345",
            verification_status=VerificationStatus.CONFIRMED.value,
            remediation="Investigate modified core files; reinstall WordPress core if unexpected.",
        )
        f.confirmed = True
        ctx.add_evidence(
            finding=f,
            kind="output",
            request="wp core verify-checksums",
            response=check[:4000],
            meta={"tool": "wp-cli"},
        )

    return {"core_version": core_version, **counts, "authenticated": True}
