"""FastAPI dependencies: DB session, authentication, RBAC, rate limiting."""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Iterator

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.rbac import has_permission
from app.core.redis import get_redis
from app.core.security import decode_token
from app.models.user import ApiKey, User

bearer_scheme = HTTPBearer(auto_error=False)


def db_session() -> Iterator[Session]:
    yield from get_db()


def _ip_in(entries: list[str], ip: str) -> bool:
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in entries:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def get_client_ip(request: Request) -> str:
    """Resolve the real client IP, trusting X-Forwarded-For ONLY from configured
    reverse proxies. Otherwise the header is attacker-controlled and ignored."""
    peer = request.client.host if request.client else ""
    trusted = settings.trusted_proxy_list
    fwd = request.headers.get("x-forwarded-for")
    if fwd and trusted and _ip_in(trusted, peer):
        # Walk the chain right-to-left, discarding our own trusted proxies; the
        # first non-trusted hop is the real client as seen by the edge proxy.
        for hop in reversed([h.strip() for h in fwd.split(",") if h.strip()]):
            if not _ip_in(trusted, hop):
                return hop
    return peer


def _user_from_bearer(db: Session, token: str) -> User | None:
    try:
        payload = decode_token(token)
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "access":
        return None
    user = db.get(User, payload.get("sub"))
    return user


def _user_from_api_key(db: Session, raw_key: str) -> User | None:
    from app.core.security import verify_password  # local import avoids cycle

    prefix = raw_key[:12]
    rows = db.execute(
        select(ApiKey).where(ApiKey.prefix == prefix, ApiKey.revoked.is_(False))
    ).scalars()
    for row in rows:
        if verify_password(raw_key, row.hashed_key):
            return db.get(User, row.user_id)
    return None


def get_current_user(
    db: Session = Depends(db_session),
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> User:
    user: User | None = None
    if creds and creds.scheme.lower() == "bearer":
        user = _user_from_bearer(db, creds.credentials)
    elif x_api_key:
        user = _user_from_api_key(db, x_api_key)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
    return user


def require_permission(code: str):
    """Dependency factory enforcing a permission code for the current user."""

    def _guard(user: User = Depends(get_current_user)) -> User:
        if not has_permission(user.role, code):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {code}",
            )
        return user

    return _guard


# ------------------------------------------------------------- rate limiting
_memory_buckets: dict[str, list[float]] = defaultdict(list)


def rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    """Return True if allowed, False if the limit is exceeded.

    Uses Redis when available; falls back to an in-process window (good enough
    for single-process dev/test)."""
    now = time.time()
    if settings.queue_backend == "redis":
        try:
            r = get_redis()
            rk = f"wpsec:rl:{key}"
            pipe = r.pipeline()
            pipe.incr(rk)
            pipe.expire(rk, window_seconds)
            count, _ = pipe.execute()
            return int(count) <= limit
        except Exception:  # noqa: BLE001 - never fail open to a crash; degrade
            pass
    bucket = _memory_buckets[key]
    cutoff = now - window_seconds
    bucket[:] = [t for t in bucket if t > cutoff]
    bucket.append(now)
    return len(bucket) <= limit


def enforce_login_rate(request: Request, email: str) -> None:
    """Throttle login by BOTH source IP and target account, so rotating a spoofed
    X-Forwarded-For cannot mint fresh buckets and per-account guessing is capped."""
    ip = get_client_ip(request)
    email_key = (email or "").strip().lower()
    too_many = not rate_limit(f"login:ip:{ip}", limit=20, window_seconds=300)
    too_many |= not rate_limit(f"login:email:{email_key}", limit=10, window_seconds=300)
    if too_many:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts; try again later.",
        )
