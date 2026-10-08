"""Authorization gating — the platform's primary safety control.

No active scan step may run against a production target unless an ACTIVE
authorization record covers it: the time window must include *now* and the
target host must fall inside the authorization's allowed scope. This is enforced
here, server-side, and called by the scan orchestrator before any step runs.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.base import utcnow
from app.models.enums import AuthorizationStatus, ScanMode
from app.models.target import Authorization, Target


class AuthorizationError(Exception):
    """Raised when an action is attempted without valid authorization."""


@dataclass
class AuthorizationDecision:
    allowed: bool
    authorization: Authorization | None
    reason: str


def _host_matches(host: str, entry: str) -> bool:
    host = host.strip().lower()
    entry = entry.strip().lower()
    if not entry:
        return False
    # CIDR / IP range match.
    try:
        net = ipaddress.ip_network(entry, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    except ValueError:
        pass
    # Exact or wildcard hostname match (e.g. *.example.com).
    if entry == host:
        return True
    return fnmatch.fnmatch(host, entry)


def host_in_scope(host: str, allowed_scope: list[str]) -> bool:
    return any(_host_matches(host, e) for e in (allowed_scope or []))


def refresh_expiry(db: Session, auth: Authorization) -> None:
    """Flip an ACTIVE authorization to EXPIRED once its window has passed."""
    now = utcnow()
    if auth.status == AuthorizationStatus.ACTIVE.value and auth.expiration_date:
        exp = auth.expiration_date
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=now.tzinfo)
        if exp < now:
            auth.status = AuthorizationStatus.EXPIRED.value
            db.add(auth)


def evaluate(
    db: Session, target: Target, *, mode: str = ScanMode.PRODUCTION.value
) -> AuthorizationDecision:
    """Decide whether ``target`` may be actively tested right now."""
    now = utcnow()
    candidates = (
        db.execute(select(Authorization).where(Authorization.target_id == target.id))
        .scalars()
        .all()
    )

    for auth in candidates:
        refresh_expiry(db, auth)

    active = [a for a in candidates if a.status == AuthorizationStatus.ACTIVE.value]
    if not active:
        return AuthorizationDecision(False, None, "no active authorization for this target")

    for auth in active:
        # Time window.
        if auth.start_date:
            start = auth.start_date
            if start.tzinfo is None:
                start = start.replace(tzinfo=now.tzinfo)
            if start > now:
                continue
        if auth.expiration_date:
            exp = auth.expiration_date
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=now.tzinfo)
            if exp < now:
                continue
        # Scope. If a scope list is provided it must cover the host; an empty
        # scope is treated as "this target's own host only" for safety.
        scope = auth.allowed_scope or [target.host]
        if not host_in_scope(target.host, scope):
            continue
        return AuthorizationDecision(True, auth, "authorized")

    return AuthorizationDecision(
        False, None, "no active authorization covers this host/time window"
    )


def assert_scannable(
    db: Session, target: Target, *, mode: str = ScanMode.PRODUCTION.value
) -> Authorization:
    """Return the governing authorization or raise AuthorizationError."""
    decision = evaluate(db, target, mode=mode)
    if not decision.allowed or decision.authorization is None:
        raise AuthorizationError(decision.reason)
    return decision.authorization
