"""Target, authorization, and credential schemas."""

from __future__ import annotations

import datetime as dt

from pydantic import AnyHttpUrl, BaseModel, Field

from app.models.enums import (
    AuthorizationStatus,
    AuthorizationType,
    CredType,
    Intensity,
)
from app.schemas.common import ORMModel


# ------------------------------------------------------------------ targets
class TargetCreate(BaseModel):
    name: str
    base_url: AnyHttpUrl
    owner: str = ""
    notes: str = ""
    tags: list[str] = Field(default_factory=list)
    scan_profile: Intensity = Intensity.SAFE
    max_intensity: Intensity = Intensity.STANDARD
    asset_importance: str = "medium"


class TargetUpdate(BaseModel):
    name: str | None = None
    owner: str | None = None
    notes: str | None = None
    tags: list[str] | None = None
    scan_profile: Intensity | None = None
    max_intensity: Intensity | None = None
    asset_importance: str | None = None


class TargetOut(ORMModel):
    id: str
    name: str
    base_url: str
    host: str
    owner: str
    notes: str
    tags: list[str]
    scan_profile: str
    max_intensity: str
    asset_importance: str
    created_at: dt.datetime
    updated_at: dt.datetime


class TargetWithAuth(TargetOut):
    authorized: bool = False
    authorization_status: str = "none"
    authorization_expires: dt.datetime | None = None


# ----------------------------------------------------------- authorizations
class AuthorizationCreate(BaseModel):
    auth_type: AuthorizationType = AuthorizationType.WRITTEN_CONSENT
    authorized_by: str = ""
    reference: str = ""
    start_date: dt.datetime | None = None
    expiration_date: dt.datetime | None = None
    allowed_scope: list[str] = Field(default_factory=list)
    testing_profile: Intensity = Intensity.SAFE
    max_intensity: Intensity = Intensity.STANDARD


class AuthorizationOut(ORMModel):
    id: str
    target_id: str
    status: str
    auth_type: str
    authorized_by: str
    reference: str
    start_date: dt.datetime | None
    expiration_date: dt.datetime | None
    allowed_scope: list[str]
    testing_profile: str
    max_intensity: str
    revoked_at: dt.datetime | None
    revoke_reason: str
    created_at: dt.datetime


class AuthorizationRevoke(BaseModel):
    reason: str = ""


class AuthorizationStatusUpdate(BaseModel):
    status: AuthorizationStatus


# ------------------------------------------------------------- credentials
class CredentialCreate(BaseModel):
    name: str = ""
    cred_type: CredType = CredType.WP_PASSWORD
    username: str = ""
    secret: str  # plaintext in; stored encrypted; never returned
    meta: dict = Field(default_factory=dict)


class CredentialOut(ORMModel):
    """Credential metadata only — the secret is never serialized."""

    id: str
    target_id: str
    name: str
    cred_type: str
    username: str
    meta: dict
    last_used_at: dt.datetime | None
    created_at: dt.datetime
