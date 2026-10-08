"""Symmetric encryption for credentials/secrets stored at rest.

Uses Fernet (AES-128-CBC + HMAC) from the `cryptography` package.

The key comes from WPSEC_CREDENTIAL_KEY. In production that must be an explicit
32-byte url-safe base64 key. In dev/test, if unset, a deterministic key is
derived from the secret key so the app runs out of the box (never in prod).
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


def _load_key() -> bytes:
    raw = settings.credential_key.strip()
    if raw:
        # Accept a proper Fernet key, or any string we hash down to one.
        try:
            Fernet(raw.encode())
            return raw.encode()
        except (ValueError, TypeError):
            digest = hashlib.sha256(raw.encode()).digest()
            return base64.urlsafe_b64encode(digest)
    if settings.is_production:
        raise RuntimeError("WPSEC_CREDENTIAL_KEY must be set in production")
    # Deterministic dev/test fallback derived from the secret key.
    digest = hashlib.sha256(("derive:" + settings.secret_key).encode()).digest()
    return base64.urlsafe_b64encode(digest)


_fernet = Fernet(_load_key())


def encrypt(plaintext: str) -> str:
    """Encrypt a string, returning url-safe base64 ciphertext."""
    if plaintext is None:
        plaintext = ""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt ciphertext produced by :func:`encrypt`."""
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:  # pragma: no cover - key mismatch is operator error
        raise ValueError("could not decrypt value (wrong credential key?)") from exc


def new_key() -> str:
    """Generate a fresh Fernet key (for install.sh / key rotation)."""
    return Fernet.generate_key().decode()
