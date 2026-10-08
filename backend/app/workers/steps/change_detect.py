"""Change-detection step — diff this scan's inventory against the previous scan.

Records ChangeEvent rows for added/removed/updated plugins and themes and for a
changed WordPress core version, so the dashboard can show what changed between
scans (new plugin, version bump, removed component, core update)."""

from __future__ import annotations

from sqlalchemy import select

from app.models.enums import ChangeType
from app.models.scan import ChangeEvent, Scan
from app.models.wordpress import Plugin, Theme, WordPressInfo
from app.workers.base import StepContext


def _previous_scan_id(ctx: StepContext) -> str | None:
    rows = (
        ctx.db.execute(
            select(Scan.id)
            .where(Scan.target_id == ctx.target.id, Scan.id != ctx.scan.id)
            .order_by(Scan.created_at.desc())
        )
        .scalars()
        .all()
    )
    return rows[0] if rows else None


def _versions(ctx: StepContext, model, scan_id: str | None) -> dict[str, str]:
    if scan_id is None:
        return {}
    rows = (
        ctx.db.execute(
            select(model).where(model.target_id == ctx.target.id, model.scan_id == scan_id)
        )
        .scalars()
        .all()
    )
    return {r.slug: (r.version or "") for r in rows}


def _record(ctx: StepContext, change_type: str, description: str, before: dict, after: dict):
    ctx.db.add(
        ChangeEvent(
            target_id=ctx.target.id,
            scan_id=ctx.scan.id,
            change_type=change_type,
            description=description,
            before=before,
            after=after,
        )
    )


def _diff_components(ctx: StepContext, model, prev_id, added_t, removed_t, changed_t) -> int:
    cur = _versions(ctx, model, ctx.scan.id)
    prev = _versions(ctx, model, prev_id)
    n = 0
    for slug, ver in cur.items():
        if slug not in prev:
            _record(ctx, added_t, f"{slug} {ver} added", {}, {"slug": slug, "version": ver})
            n += 1
        elif prev[slug] != ver:
            _record(
                ctx,
                changed_t,
                f"{slug} {prev[slug]} -> {ver}",
                {"version": prev[slug]},
                {"version": ver},
            )
            n += 1
    for slug, ver in prev.items():
        if slug not in cur:
            _record(ctx, removed_t, f"{slug} {ver} removed", {"slug": slug, "version": ver}, {})
            n += 1
    return n


def run(ctx: StepContext) -> dict:
    prev_id = _previous_scan_id(ctx)
    if prev_id is None:
        return {"baseline": True, "changes": 0}

    changes = 0
    changes += _diff_components(
        ctx,
        Plugin,
        prev_id,
        ChangeType.PLUGIN_ADDED.value,
        ChangeType.PLUGIN_REMOVED.value,
        ChangeType.PLUGIN_VERSION_CHANGED.value,
    )
    changes += _diff_components(
        ctx,
        Theme,
        prev_id,
        ChangeType.THEME_CHANGED.value,
        ChangeType.THEME_CHANGED.value,
        ChangeType.THEME_CHANGED.value,
    )

    # WordPress core version change.
    def _core(scan_id: str) -> str:
        info = (
            ctx.db.execute(
                select(WordPressInfo).where(
                    WordPressInfo.target_id == ctx.target.id, WordPressInfo.scan_id == scan_id
                )
            )
            .scalars()
            .first()
        )
        return (info.core_version if info else "") or ""

    cur_core, prev_core = _core(ctx.scan.id), _core(prev_id)
    if cur_core and prev_core and cur_core != prev_core:
        _record(
            ctx,
            ChangeType.WP_VERSION_CHANGED.value,
            f"WordPress core {prev_core} -> {cur_core}",
            {"version": prev_core},
            {"version": cur_core},
        )
        changes += 1

    ctx.db.flush()
    return {"baseline": False, "changes": changes, "previous_scan": prev_id}
