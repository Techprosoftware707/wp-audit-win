"""Read-only target inventory: WordPress info, plugins, themes, users, assets."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import db_session, require_permission
from app.models.scan import Asset, ChangeEvent, Technology
from app.models.user import User
from app.models.wordpress import Plugin, Theme, WordPressInfo, WPUser

router = APIRouter(prefix="/targets/{target_id}", tags=["inventory"])


def _ser(obj) -> dict[str, Any]:
    return {c.key: getattr(obj, c.key) for c in obj.__table__.columns}


@router.get("/wordpress")
def wordpress_info(
    target_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("targets:read")),
):
    info = (
        db.execute(
            select(WordPressInfo)
            .where(WordPressInfo.target_id == target_id)
            .order_by(WordPressInfo.created_at.desc())
        )
        .scalars()
        .first()
    )
    return _ser(info) if info else {}


@router.get("/plugins")
def plugins(
    target_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("targets:read")),
):
    rows = (
        db.execute(select(Plugin).where(Plugin.target_id == target_id).order_by(Plugin.slug))
        .scalars()
        .all()
    )
    return [_ser(r) for r in rows]


@router.get("/themes")
def themes(
    target_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("targets:read")),
):
    rows = (
        db.execute(select(Theme).where(Theme.target_id == target_id).order_by(Theme.slug))
        .scalars()
        .all()
    )
    return [_ser(r) for r in rows]


@router.get("/wp-users")
def wp_users(
    target_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("targets:read")),
):
    rows = db.execute(select(WPUser).where(WPUser.target_id == target_id)).scalars().all()
    return [_ser(r) for r in rows]


@router.get("/assets")
def assets(
    target_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("targets:read")),
):
    rows = (
        db.execute(select(Asset).where(Asset.target_id == target_id).order_by(Asset.asset_type))
        .scalars()
        .all()
    )
    return [_ser(r) for r in rows]


@router.get("/technologies")
def technologies(
    target_id: str,
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("targets:read")),
):
    rows = db.execute(select(Technology).where(Technology.target_id == target_id)).scalars().all()
    return [_ser(r) for r in rows]


@router.get("/changes")
def changes(
    target_id: str,
    limit: int = Query(default=100, le=500),
    db: Session = Depends(db_session),
    _: User = Depends(require_permission("targets:read")),
):
    rows = (
        db.execute(
            select(ChangeEvent)
            .where(ChangeEvent.target_id == target_id)
            .order_by(ChangeEvent.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [_ser(r) for r in rows]
