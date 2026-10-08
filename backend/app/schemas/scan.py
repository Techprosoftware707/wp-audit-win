"""Scan schemas."""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel

from app.models.enums import Intensity, ScanMode
from app.schemas.common import ORMModel


class ScanStart(BaseModel):
    profile: Intensity | None = None
    mode: ScanMode = ScanMode.PRODUCTION
    steps: list[str] | None = None  # override the default pipeline


class ScanStepOut(ORMModel):
    id: str
    name: str
    queue: str
    ordering: int
    status: str
    depends_on: list[str]
    started_at: dt.datetime | None
    finished_at: dt.datetime | None
    output_summary: dict
    error: str


class ScanOut(ORMModel):
    id: str
    target_id: str
    authorization_id: str | None
    status: str
    mode: str
    profile: str
    effective_intensity: str
    created_by: str | None
    started_at: dt.datetime | None
    finished_at: dt.datetime | None
    summary: dict
    error: str
    created_at: dt.datetime


class ScanDetail(ScanOut):
    steps: list[ScanStepOut] = []
