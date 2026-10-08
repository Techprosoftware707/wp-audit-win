"""Auth & user schemas."""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, EmailStr, Field

from app.models.enums import UserRole
from app.schemas.common import ORMModel


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    totp_code: str | None = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class UserOut(ORMModel):
    id: str
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    mfa_enabled: bool
    last_login_at: dt.datetime | None = None
    created_at: dt.datetime


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = ""
    password: str = Field(min_length=12)
    role: UserRole = UserRole.READ_ONLY


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12)


class MFASetupOut(BaseModel):
    secret: str
    provisioning_uri: str


class MFAVerifyRequest(BaseModel):
    code: str


class ApiKeyCreate(BaseModel):
    name: str = ""


class ApiKeyOut(ORMModel):
    id: str
    name: str
    prefix: str
    revoked: bool
    last_used_at: dt.datetime | None = None
    created_at: dt.datetime


class ApiKeyCreated(ApiKeyOut):
    key: str  # shown once at creation time only
