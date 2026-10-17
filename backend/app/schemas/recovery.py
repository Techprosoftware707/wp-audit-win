"""Request schemas for owner-authorized recovery & remediation."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class ResetPasswordRequest(BaseModel):
    user: str = Field(description="Administrator login or numeric user ID to reset")
    confirm: bool = False
    reason: str = ""


class CreateAdminRequest(BaseModel):
    login: str = Field(min_length=1)
    email: EmailStr
    confirm: bool = False
    reason: str = ""


class UpdateComponentRequest(BaseModel):
    component_type: str = Field(pattern="^(plugin|theme)$")
    slug: str = Field(min_length=1)
    to_version: str | None = None
    confirm: bool = False
    reason: str = ""
