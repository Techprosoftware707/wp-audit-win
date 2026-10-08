"""Isolated exploit-lab lifecycle.

Lab instances are disposable, network-isolated WordPress environments used to
reproduce vulnerabilities aggressively and safely. Provisioning is pluggable:

  * "record"  (default) — records instance lifecycle without launching anything.
                Safe everywhere; used for planning and for environments where the
                API tier intentionally has no Docker access.
  * "docker"  — launches a disposable WordPress container on the isolated lab
                network via the lab worker (NOT the API, which has no Docker
                socket). Enabled by the operator; see docs/LAB.md.

Auto-destroy/TTL is honored by the lab worker's reaper.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from app.models.base import utcnow
from app.models.enums import LabInstanceStatus
from app.models.lab import Lab, LabInstance


def create_instance(db: Session, lab: Lab, *, provider: str = "record") -> LabInstance:
    tpl = lab.template or {}
    now = utcnow()
    inst = LabInstance(
        lab_id=lab.id,
        provider=provider,
        wp_version=tpl.get("wp_version", "latest"),
        php_version=tpl.get("php_version", "8.2"),
        plugin_slug=tpl.get("plugin_slug", ""),
        plugin_version=tpl.get("plugin_version", ""),
        theme_slug=tpl.get("theme_slug", ""),
        theme_version=tpl.get("theme_version", ""),
        expires_at=now + dt.timedelta(minutes=lab.ttl_minutes) if lab.auto_destroy else None,
        meta={"template": tpl},
    )
    if provider == "record":
        # No container launched; the record provider tracks intent/state only.
        inst.status = LabInstanceStatus.PENDING.value
        inst.meta["note"] = (
            "recorded only; enable the docker provider on the lab worker to launch "
            "a disposable instance (see docs/LAB.md)"
        )
    else:
        # The lab worker picks up provisioning for non-record providers.
        inst.status = LabInstanceStatus.PROVISIONING.value
    db.add(inst)
    db.flush()
    return inst


def destroy_instance(db: Session, inst: LabInstance) -> LabInstance:
    inst.status = LabInstanceStatus.DESTROYED.value
    inst.destroyed_at = utcnow()
    db.add(inst)
    db.flush()
    return inst
