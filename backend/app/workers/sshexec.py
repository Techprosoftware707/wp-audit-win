"""SSH WP-CLI runner for owner-authorized recovery/remediation.

Executes `wp` subcommands on a target host over SSH using a stored SSH
credential, with the same host-key verification policy as the read-only wpcli
scan step. Arguments are shell-quoted individually (no shell interpolation of
untrusted input). The runner is an injectable object so the recovery logic can
be unit-tested with a fake that records commands and returns canned output —
no SSH or live WordPress required.
"""

from __future__ import annotations

import io
import shlex
from dataclasses import dataclass

from app.core.crypto import decrypt
from app.models.target import Credential


@dataclass
class WpResult:
    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


class SSHWpRunner:
    """Runs `wp ...` over SSH. Build via :func:`from_credential`."""

    def __init__(self, *, host, port, username, secret, auth, wp_path, hostkey):
        self._host = host
        self._port = int(port or 22)
        self._username = username
        self._secret = secret
        self._auth = auth  # "key" | "password"
        self._wp_path = wp_path or ""
        self._hostkey = hostkey  # dict: known_hosts_file / accept_unknown_host_key
        self._client = None

    @classmethod
    def from_credential(cls, cred: Credential, default_host: str) -> SSHWpRunner:
        meta = cred.meta or {}
        return cls(
            host=meta.get("host") or default_host,
            port=meta.get("port", 22),
            username=cred.username,
            secret=decrypt(cred.secret_encrypted) if cred.secret_encrypted else "",
            auth=meta.get("auth", "password"),
            wp_path=meta.get("wp_path", ""),
            hostkey={
                "known_hosts_file": meta.get("known_hosts_file"),
                "accept_unknown_host_key": bool(meta.get("accept_unknown_host_key")),
            },
        )

    def connect(self) -> None:
        import paramiko

        client = paramiko.SSHClient()
        if self._hostkey.get("known_hosts_file"):
            client.load_host_keys(self._hostkey["known_hosts_file"])
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        elif self._hostkey.get("accept_unknown_host_key"):
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        if self._auth == "key":
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(self._secret))
            client.connect(
                self._host, port=self._port, username=self._username, pkey=pkey, timeout=20
            )
        else:
            client.connect(
                self._host,
                port=self._port,
                username=self._username,
                password=self._secret,
                timeout=20,
            )
        self._client = client

    def wp(self, args: list[str], timeout: int = 120) -> WpResult:
        """Run `wp <args>` with each arg individually shell-quoted."""
        if self._client is None:
            self.connect()
        prefix = f"cd {shlex.quote(self._wp_path)} && " if self._wp_path else ""
        cmd = prefix + " ".join(["wp", *(shlex.quote(a) for a in args)])
        _in, out, err = self._client.exec_command(cmd, timeout=timeout)  # noqa: S601
        rc = out.channel.recv_exit_status()
        return WpResult(
            rc, out.read().decode(errors="replace"), err.read().decode(errors="replace")
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> SSHWpRunner:
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()
