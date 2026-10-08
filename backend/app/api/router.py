"""Aggregate API router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import (
    audit_log,
    auth,
    dashboard,
    findings,
    health,
    inventory,
    labs,
    pocs,
    reports,
    scans,
    schedules,
    targets,
    users,
    vulnerabilities,
    workers,
)

api_router = APIRouter()
for module in (
    health,
    auth,
    users,
    dashboard,
    targets,
    inventory,
    scans,
    findings,
    vulnerabilities,
    pocs,
    workers,
    schedules,
    reports,
    labs,
    audit_log,
):
    api_router.include_router(module.router)
