"""Authorization step — re-verifies authorization at scan time and records it.

This runs first in every pipeline. Even though start_scan already checked
authorization, re-checking here means a revocation that happened between
enqueue and execution stops the scan before any active step runs.
"""

from __future__ import annotations

from app.services import authorization as authz
from app.workers.base import StepContext


def run(ctx: StepContext) -> dict:
    decision = authz.evaluate(ctx.db, ctx.target, mode=ctx.scan.mode)
    if not decision.allowed or decision.authorization is None:
        # Abort the scan safely: raise so the step is marked failed and the
        # 'authorization' hard-step failure fails the whole scan.
        raise PermissionError(f"authorization check failed: {decision.reason}")

    auth = decision.authorization
    ctx.scan.authorization_id = auth.id
    ctx.add_evidence(
        kind="authorization",
        request=f"authorization check for {ctx.target.host}",
        response=(
            f"status={auth.status} type={auth.auth_type} "
            f"authorized_by={auth.authorized_by} expires={auth.expiration_date}"
        ),
        meta={
            "authorization_id": auth.id,
            "allowed_scope": auth.allowed_scope or [ctx.target.host],
            "testing_profile": auth.testing_profile,
            "effective_intensity": ctx.scan.effective_intensity,
        },
    )
    return {
        "authorized": True,
        "authorization_id": auth.id,
        "effective_intensity": ctx.scan.effective_intensity,
    }
