"""Structured logging with secret redaction.

Secrets must never hit the logs. A filter scrubs values of known-sensitive keys
and anything that looks like a bearer token / password in log messages.
"""

from __future__ import annotations

import logging
import re
import sys

from app.core.config import settings

_SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)(password\"?\s*[:=]\s*\"?)[^\s,\"'}]+"),
    re.compile(r"(?i)(token\"?\s*[:=]\s*\"?)[^\s,\"'}]+"),
    re.compile(r"(?i)(secret\"?\s*[:=]\s*\"?)[^\s,\"'}]+"),
    re.compile(r"(?i)(api[_-]?key\"?\s*[:=]\s*\"?)[^\s,\"'}]+"),
]


def _redact(message: str) -> str:
    out = message
    for pat in _SENSITIVE_PATTERNS:
        out = pat.sub(lambda m: m.group(1) + "***REDACTED***", out)
    return out


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            record.msg = _redact(str(record.msg))
        except Exception:  # noqa: BLE001
            pass
        return True


def configure_logging() -> None:
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    handler.addFilter(RedactionFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Quiet noisy third parties a notch.
    for noisy in ("httpx", "urllib3", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
