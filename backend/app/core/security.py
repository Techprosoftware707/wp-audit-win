"""Authentication primitives: password hashing, JWT, TOTP (MFA-ready)."""

from __future__ import annotations

import datetime as dt
import secrets
import uuid

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.core.config import settings

_hasher = PasswordHasher()

ALGO = "HS256"


# ------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def needs_rehash(hashed: str) -> bool:
    try:
        return _hasher.check_needs_rehash(hashed)
    except Exception:  # noqa: BLE001
        return False


# ----------------------------------------------------------------------- JWT
def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def create_access_token(subject: str, *, role: str, extra: dict | None = None) -> str:
    now = _now()
    payload = {
        "sub": str(subject),
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(minutes=settings.access_token_minutes)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=ALGO)


def create_refresh_token(subject: str) -> str:
    now = _now()
    payload = {
        "sub": str(subject),
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(days=settings.refresh_token_days)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGO)


def decode_token(token: str) -> dict:
    """Decode & verify a JWT. Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, settings.secret_key, algorithms=[ALGO])


# ----------------------------------------------------------------------- TOTP
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="wp-audit-win")


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


# ------------------------------------------------------------------- API keys
def generate_api_key() -> tuple[str, str]:
    """Return (plaintext_key, display_prefix). The caller stores a hash."""
    key = "wpsec_" + secrets.token_urlsafe(32)
    return key, key[:12]
