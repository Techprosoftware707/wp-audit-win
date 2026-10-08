"""Helpers for invoking external scanner binaries safely."""

from __future__ import annotations

import shutil
import subprocess  # noqa: S404 - args are controlled; shell is never used

from app.core.config import INTENSITY_ORDER
from app.core.logging import get_logger

log = get_logger("tools")


def which(binary: str) -> str | None:
    return shutil.which(binary)


def run_cmd(args: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Run a command (no shell). Returns (returncode, stdout, stderr)."""
    log.info("exec: %s", " ".join(args[:8]))
    try:
        proc = subprocess.run(  # noqa: S603 - controlled argv, shell=False
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return 127, "", "binary not found"


def intensity_at_least(current: str, minimum: str) -> bool:
    try:
        return INTENSITY_ORDER.index(current.lower()) >= INTENSITY_ORDER.index(minimum.lower())
    except ValueError:
        return False
