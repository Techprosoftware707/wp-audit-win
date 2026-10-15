"""Authentication, current-user, MFA, and API-key endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import settings
from app.core.crypto import decrypt, encrypt
from app.core.deps import (
    db_session,
    deny_api_key_auth,
    enforce_login_rate,
    get_current_user,
)
from app.models.base import utcnow
from app.models.user import ApiKey, User
from app.schemas.auth import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    LoginRequest,
    MFASetupOut,
    MFAVerifyRequest,
    PasswordChange,
    PasswordReauth,
    RefreshRequest,
    TokenPair,
    UserOut,
)
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])

# Fixed hash used to equalize login timing for unknown/disabled accounts so an
# attacker cannot distinguish them by response latency (user enumeration).
_DUMMY_HASH = security.hash_password("timing-equalization-placeholder")


@router.post("/login", response_model=TokenPair)
def login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(db_session),
) -> TokenPair:
    # Throttle by IP + account (after the body is parsed so we know the email).
    enforce_login_rate(request, body.email)
    user = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
    if user and user.is_active:
        ok = security.verify_password(body.password, user.hashed_password)
    else:
        # Burn equivalent time on a dummy hash so missing/disabled accounts are
        # indistinguishable from a wrong password by timing.
        security.verify_password(body.password, _DUMMY_HASH)
        ok = False
    if ok and user.mfa_enabled:
        secret = decrypt(user.mfa_secret_encrypted) if user.mfa_secret_encrypted else ""
        ok = security.verify_totp(secret, body.totp_code or "")
    if not ok:
        audit.record(
            db,
            action="auth.login",
            actor=user,
            actor_email=body.email,
            result="failure",
            request=request,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if security.needs_rehash(user.hashed_password):
        user.hashed_password = security.hash_password(body.password)
    user.last_login_at = utcnow()
    audit.record(db, action="auth.login", actor=user, result="success", request=request)
    db.commit()

    return TokenPair(
        access_token=security.create_access_token(user.id, role=user.role, epoch=user.token_epoch),
        refresh_token=security.create_refresh_token(user.id, epoch=user.token_epoch),
        expires_in=settings.access_token_minutes * 60,
    )


@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshRequest, db: Session = Depends(db_session)) -> TokenPair:
    import jwt

    try:
        payload = security.decode_token(body.refresh_token)
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from exc
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")
    user = db.get(User, payload.get("sub"))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or disabled")
    # Reject refresh tokens minted before a credential change / deactivation.
    if int(payload.get("ep", 0)) != int(user.token_epoch or 0):
        raise HTTPException(status_code=401, detail="Refresh token has been invalidated")
    return TokenPair(
        access_token=security.create_access_token(user.id, role=user.role, epoch=user.token_epoch),
        refresh_token=security.create_refresh_token(user.id, epoch=user.token_epoch),
        expires_in=settings.access_token_minutes * 60,
    )


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.post("/change-password", response_model=UserOut)
def change_password(
    body: PasswordChange,
    request: Request,
    user: User = Depends(deny_api_key_auth),
    db: Session = Depends(db_session),
) -> User:
    """Self-service credential change. Requires the CURRENT password, so a stolen
    access token alone cannot rotate the victim's password; it changes only the
    caller's own credential and never alters role/permissions. Not available to
    API-key callers, and bumps the token epoch so old tokens stop working."""
    if not security.verify_password(body.current_password, user.hashed_password):
        audit.record(
            db,
            action="auth.password_change",
            actor=user,
            result="failure",
            request=request,
        )
        db.commit()
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current one")
    user.hashed_password = security.hash_password(body.new_password)
    user.token_epoch = (user.token_epoch or 0) + 1  # invalidate existing tokens
    audit.record(db, action="auth.password_change", actor=user, request=request)
    db.commit()
    db.refresh(user)
    return user


@router.post("/mfa/setup", response_model=MFASetupOut)
def mfa_setup(
    body: PasswordReauth,
    user: User = Depends(deny_api_key_auth),
    db: Session = Depends(db_session),
) -> MFASetupOut:
    # Step-up: re-authenticate with the current password before (re)keying the
    # TOTP secret, so a hijacked token cannot silently replace the second factor.
    if not security.verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    secret = security.new_totp_secret()
    user.mfa_secret_encrypted = encrypt(secret)
    db.commit()
    return MFASetupOut(
        secret=secret,
        provisioning_uri=security.totp_provisioning_uri(secret, user.email),
    )


@router.post("/mfa/enable", response_model=UserOut)
def mfa_enable(
    body: MFAVerifyRequest,
    request: Request,
    user: User = Depends(deny_api_key_auth),
    db: Session = Depends(db_session),
) -> User:
    secret = decrypt(user.mfa_secret_encrypted) if user.mfa_secret_encrypted else ""
    if not security.verify_totp(secret, body.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    user.mfa_enabled = True
    audit.record(db, action="auth.mfa_enable", actor=user, request=request)
    db.commit()
    return user


@router.post("/mfa/disable", response_model=UserOut)
def mfa_disable(
    body: PasswordReauth,
    request: Request,
    user: User = Depends(deny_api_key_auth),
    db: Session = Depends(db_session),
) -> User:
    # Step-up: disabling the second factor requires the current password, so a
    # hijacked access token alone cannot strip MFA. Bumps the token epoch too.
    if not security.verify_password(body.current_password, user.hashed_password):
        audit.record(db, action="auth.mfa_disable", actor=user, result="failure", request=request)
        db.commit()
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    user.token_epoch = (user.token_epoch or 0) + 1
    audit.record(db, action="auth.mfa_disable", actor=user, request=request)
    db.commit()
    return user


# ------------------------------------------------------------------- API keys
@router.get("/api-keys", response_model=list[ApiKeyOut])
def list_api_keys(user: User = Depends(get_current_user), db: Session = Depends(db_session)):
    return db.execute(select(ApiKey).where(ApiKey.user_id == user.id)).scalars().all()


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=201)
def create_api_key(
    body: ApiKeyCreate,
    request: Request,
    user: User = Depends(deny_api_key_auth),
    db: Session = Depends(db_session),
) -> ApiKeyCreated:
    raw, prefix = security.generate_api_key()
    key = ApiKey(
        user_id=user.id, name=body.name, prefix=prefix, hashed_key=security.hash_password(raw)
    )
    db.add(key)
    audit.record(
        db,
        action="auth.api_key_create",
        actor=user,
        object_type="api_key",
        object_id=key.id,
        request=request,
        detail={"name": body.name},
    )
    db.commit()
    db.refresh(key)
    return ApiKeyCreated(
        id=key.id,
        name=key.name,
        prefix=key.prefix,
        revoked=key.revoked,
        last_used_at=key.last_used_at,
        created_at=key.created_at,
        key=raw,
    )


@router.delete("/api-keys/{key_id}", status_code=204)
def revoke_api_key(
    key_id: str,
    request: Request,
    user: User = Depends(deny_api_key_auth),
    db: Session = Depends(db_session),
) -> None:
    key = db.get(ApiKey, key_id)
    if not key or key.user_id != user.id:
        raise HTTPException(status_code=404, detail="API key not found")
    key.revoked = True
    audit.record(
        db,
        action="auth.api_key_revoke",
        actor=user,
        object_type="api_key",
        object_id=key.id,
        request=request,
    )
    db.commit()
