"""Shared schema base classes and helpers."""

from __future__ import annotations

import datetime as dt
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class Message(BaseModel):
    message: str


class IdOut(BaseModel):
    id: str


def iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if value else None
