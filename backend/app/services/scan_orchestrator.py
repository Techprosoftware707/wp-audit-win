"""Scan orchestration.

Builds the step DAG for a scan, enforces authorization + intensity limits, and
drives execution. The same step runner is used by the in-process path
(dev/test) and the distributed workers, so behaviour is identical everywhere.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import INTENSITY_ORDER, settings
from app.core.logging import get_logger
from app.core.redis import get_queue
from app.models.base import utcnow
from app.models.enums import ScanMode, ScanStatus, Severity, StepStatus
from app.models.scan import Scan, ScanStep
from app.models.system import Worker
from app.models.target import Authorization, Target
from app.models.user import User
from app.services import authorization as authz

log = get_logger("orchestrator")

# Each entry: (step name, queue, [dependency step names]).
DEFAULT_PIPELINE: list[tuple[str, str, list[str]]] = [
    ("authorization", "default", []),
    ("discovery", "fingerprint", ["authorization"]),
    ("wp_fingerprint", "fingerprint", ["discovery"]),
    # Discovery-driven scanners (need only the base URL).
    ("whatweb", "whatweb", ["discovery"]),
    ("nmap", "nmap", ["discovery"]),
    ("nikto", "nikto", ["discovery"]),
    ("ffuf", "ffuf", ["discovery"]),
    ("zap", "zap", ["discovery"]),
    ("burp", "burp", ["discovery"]),
    # Static source analysis (never touches the live target).
    ("semgrep", "semgrep", ["discovery"]),
    ("gitleaks", "gitleaks", ["discovery"]),
    # WordPress-aware scanners (benefit from the fingerprint).
    ("wpscan", "wpscan", ["wp_fingerprint"]),
    ("nuclei", "nuclei", ["wp_fingerprint"]),
    ("wpcli", "wpcli", ["wp_fingerprint"]),
    (
        "correlation",
        "correlation",
        [
            "wp_fingerprint",
            "whatweb",
            "wpscan",
            "nuclei",
            "nmap",
            "nikto",
            "ffuf",
            "zap",
            "burp",
            "semgrep",
            "gitleaks",
            "wpcli",
        ],
    ),
    ("poc_match", "poc", ["correlation"]),
    ("change_detect", "correlation", ["correlation"]),
    ("risk", "correlation", ["correlation", "poc_match"]),
    # Terminal stage of a one-click Full Audit: auto-generate the report.
    ("auto_report", "report", ["risk"]),
]

TERMINAL_STEP_STATES = {
    StepStatus.COMPLETED.value,
    StepStatus.FAILED.value,
    StepStatus.SKIPPED.value,
}


def _intensity_rank(name: str) -> int:
    try:
        return INTENSITY_ORDER.index(name.lower())
    except ValueError:
        return INTENSITY_ORDER.index("safe")


def _scan_scope(db: Session, scan: Scan, target: Target) -> list[str]:
    """The authorization's allowed scope for this scan (falls back to the host).

    Passed to target-facing HTTP so redirects/verification cannot leave scope.
    """
    if scan.authorization_id:
        auth = db.get(Authorization, scan.authorization_id)
        if auth and auth.allowed_scope:
            return list(auth.allowed_scope)
    return [target.host]


def effective_intensity(requested: str, target: Target, auth) -> str:
    ranks = [
        _intensity_rank(requested),
        _intensity_rank(target.max_intensity),
        _intensity_rank(auth.max_intensity),
        settings.max_intensity_rank,
    ]
    return INTENSITY_ORDER[min(ranks)]


def queue_has_worker(db: Session, queue: str, *, max_age_seconds: int = 90) -> bool:
    cutoff = utcnow() - dt.timedelta(seconds=max_age_seconds)
    workers = db.execute(select(Worker).where(Worker.status != "offline")).scalars().all()
    for w in workers:
        if w.last_heartbeat is None:
            continue
        hb = w.last_heartbeat
        if hb.tzinfo is None:
            hb = hb.replace(tzinfo=cutoff.tzinfo)
        if hb < cutoff:
            continue
        if queue in [q.strip() for q in (w.queues or "").split(",")]:
            return True
    return False


def start_scan(
    db: Session,
    *,
    target: Target,
    user: User | None,
    profile: str | None = None,
    mode: str = ScanMode.PRODUCTION.value,
    steps: list[str] | None = None,
) -> Scan:
    """Create and launch a scan. Raises authz.AuthorizationError if not allowed."""
    auth = authz.assert_scannable(db, target, mode=mode)

    requested = profile or target.scan_profile
    eff = effective_intensity(requested, target, auth)

    scan = Scan(
        target_id=target.id,
        authorization_id=auth.id,
        status=ScanStatus.QUEUED.value,
        mode=mode,
        profile=requested,
        effective_intensity=eff,
        created_by=user.id if user else None,
        started_at=utcnow(),
    )
    db.add(scan)
    db.flush()

    pipeline = DEFAULT_PIPELINE
    always = {"authorization", "correlation", "risk", "auto_report"}
    wanted = (set(steps) | always) if steps else None
    # Which pipeline steps will actually be created (so we can prune dangling deps).
    included = {name for name, _q, _d in pipeline if wanted is None or name in wanted}
    for i, (name, queue, deps) in enumerate(pipeline):
        if name not in included:
            continue
        # Prune dependencies to included steps only, so an override cannot leave a
        # step waiting forever on a dependency that was not created.
        pruned = [d for d in deps if d in included]
        db.add(
            ScanStep(
                scan_id=scan.id,
                name=name,
                queue=queue,
                ordering=i,
                depends_on=pruned,
                status=StepStatus.PENDING.value,
            )
        )
    db.flush()

    log.info("scan %s created for target %s (intensity=%s)", scan.id, target.host, eff)

    if settings.queue_backend == "memory":
        execute_scan_inline(db, scan)
    else:
        scan.status = ScanStatus.RUNNING.value
        enqueue_ready(db, scan)
    return scan


def _steps(db: Session, scan: Scan) -> list[ScanStep]:
    return (
        db.execute(select(ScanStep).where(ScanStep.scan_id == scan.id).order_by(ScanStep.ordering))
        .scalars()
        .all()
    )


# Steps whose FAILURE must abort the whole scan (safety gates). The
# authorization step re-checks authorization at execution time; if it fails, no
# downstream step may run against the (now unauthorized) target.
CRITICAL_STEPS = {"authorization"}


def _ready_steps(steps: list[ScanStep]) -> list[ScanStep]:
    """PENDING steps whose every dependency has reached a terminal state.

    A terminal dependency (completed / skipped / failed) satisfies the edge, so an
    ordinary leaf-scanner failure does not block correlation/report. A failed
    CRITICAL step is handled separately by :func:`_abort_if_critical_failed`,
    which runs first and prevents any dependent from becoming ready."""
    done = {s.name for s in steps if s.status in TERMINAL_STEP_STATES}
    ready = []
    for s in steps:
        if s.status != StepStatus.PENDING.value:
            continue
        if all(dep in done for dep in (s.depends_on or [])):
            ready.append(s)
    return ready


def _abort_if_critical_failed(db: Session, scan: Scan, steps: list[ScanStep]) -> bool:
    """If a CRITICAL step failed, skip every not-yet-terminal step (aborting the
    scan) and return True. This is the control that halts all scanning when the
    run-time authorization re-check fails."""
    failed_crit = [
        s.name for s in steps if s.name in CRITICAL_STEPS and s.status == StepStatus.FAILED.value
    ]
    if not failed_crit:
        return False
    changed = False
    for s in steps:
        if s.status in (StepStatus.PENDING.value, StepStatus.QUEUED.value):
            s.status = StepStatus.SKIPPED.value
            s.error = f"aborted: critical step failed ({', '.join(failed_crit)})"
            s.finished_at = utcnow()
            db.add(s)
            changed = True
    return changed


def enqueue_ready(db: Session, scan: Scan) -> None:
    """Enqueue ready steps to their queues; skip steps with no capable worker.

    The step's QUEUED status is COMMITTED before the Redis job is pushed, so a
    consumer that pops the job immediately always sees the row (no lost job)."""
    queue = get_queue()
    changed = True
    while changed:
        changed = False
        steps = _steps(db, scan)
        if _abort_if_critical_failed(db, scan, steps):
            db.commit()
            break
        for step in _ready_steps(steps):
            if not queue_has_worker(db, step.queue):
                step.status = StepStatus.SKIPPED.value
                step.error = f"no online worker serving queue '{step.queue}'"
                step.finished_at = utcnow()
                db.add(step)
                changed = True
                continue
            step.status = StepStatus.QUEUED.value
            step.started_at = None
            db.add(step)
            # Commit BEFORE enqueue so the row is visible to any worker that
            # pops the job (fixes enqueue-before-commit job loss).
            db.commit()
            queue.enqueue(
                step.queue,
                {
                    "scan_id": scan.id,
                    "step_id": step.id,
                    "step_name": step.name,
                },
            )
    db.commit()
    _maybe_finalize(db, scan)


def run_step(db: Session, step_id: str) -> None:
    """Execute a single step (called inline or by a worker), then advance."""
    from app.workers.base import StepContext
    from app.workers.steps import get_registry

    step = db.get(ScanStep, step_id)
    if step is None or step.status in TERMINAL_STEP_STATES:
        return
    scan = db.get(Scan, step.scan_id)
    target = db.get(Target, scan.target_id)

    # Respect cancellation: a worker may pop a queued job after the scan was
    # cancelled — do not run it against the target.
    if scan.status == ScanStatus.CANCELLED.value:
        step.status = StepStatus.SKIPPED.value
        step.error = "cancelled"
        step.finished_at = utcnow()
        db.add(step)
        db.flush()
        return

    step.status = StepStatus.RUNNING.value
    step.started_at = utcnow()
    db.add(step)
    db.flush()

    registry = get_registry()
    fn = registry.get(step.name)
    try:
        if fn is None:
            step.status = StepStatus.SKIPPED.value
            step.error = f"no implementation for step '{step.name}'"
        else:
            ctx = StepContext(
                db=db,
                scan=scan,
                target=target,
                step_name=step.name,
                intensity=scan.effective_intensity,
                scope=_scan_scope(db, scan, target),
            )
            summary = fn(ctx) or {}
            step.output_summary = summary
            step.status = (
                StepStatus.SKIPPED.value if summary.get("skipped") else StepStatus.COMPLETED.value
            )
            if summary.get("skipped"):
                step.error = str(summary.get("reason", ""))
    except Exception as exc:  # noqa: BLE001 - isolate step failures
        step.status = StepStatus.FAILED.value
        step.error = f"{type(exc).__name__}: {exc}"
        log.exception("step %s failed", step.name)
    finally:
        step.finished_at = utcnow()
        db.add(step)
        db.flush()


def execute_scan_inline(db: Session, scan: Scan) -> None:
    """Run the whole scan synchronously (dev/test). Steps self-skip if a tool
    is unavailable, so this always terminates."""
    scan.status = ScanStatus.RUNNING.value
    db.flush()
    guard = 0
    while True:
        guard += 1
        if guard > 500:  # safety against a malformed DAG
            break
        steps = _steps(db, scan)
        if _abort_if_critical_failed(db, scan, steps):
            db.flush()
            break
        ready = _ready_steps(steps)
        if not ready:
            break
        for step in ready:
            run_step(db, step.id)
    _maybe_finalize(db, scan)


def advance(db: Session, scan: Scan) -> None:
    """Called by a worker after finishing a step (redis mode)."""
    enqueue_ready(db, scan)


def _maybe_finalize(db: Session, scan: Scan) -> None:
    # A cancelled scan is terminal; never resurrect it to completed/failed.
    if scan.status == ScanStatus.CANCELLED.value:
        return
    steps = _steps(db, scan)
    if not steps:
        return
    if not all(s.status in TERMINAL_STEP_STATES for s in steps):
        # Still work to do.
        if scan.status == ScanStatus.QUEUED.value:
            scan.status = ScanStatus.RUNNING.value
        return

    from app.models.finding import Finding

    findings = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
    counts = {s.value: 0 for s in Severity}
    confirmed = 0
    unverified = 0
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        if f.confirmed:
            confirmed += 1
        if f.verification_status == "unverified":
            unverified += 1

    # A scan is 'failed' only if it could not get past authorization/discovery.
    hard = {s.name: s for s in steps if s.name in ("authorization", "discovery")}
    failed_hard = any(s.status == StepStatus.FAILED.value for s in hard.values())

    scan.summary = {
        **counts,
        "total": len(findings),
        "confirmed": confirmed,
        "unverified": unverified,
        "steps_total": len(steps),
        "steps_skipped": sum(1 for s in steps if s.status == StepStatus.SKIPPED.value),
        "steps_failed": sum(1 for s in steps if s.status == StepStatus.FAILED.value),
    }
    scan.finished_at = utcnow()
    scan.status = ScanStatus.FAILED.value if failed_hard else ScanStatus.COMPLETED.value
    db.add(scan)
    db.flush()
    log.info("scan %s finalized status=%s summary=%s", scan.id, scan.status, scan.summary)


def _age_seconds(ts: dt.datetime | None, now: dt.datetime) -> float:
    if ts is None:
        return 0.0
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=now.tzinfo)
    return (now - ts).total_seconds()


def reap_stale_scans(db: Session, *, step_timeout_s: int = 1800, requeue_after_s: int = 300) -> int:
    """Self-healing sweep (run periodically by workers).

    - A step stuck RUNNING past step_timeout_s is failed (the worker likely died).
    - A step stuck QUEUED past requeue_after_s (a lost job) is reset to PENDING so
      it is re-enqueued.
    Then each RUNNING scan is re-driven so it can finalize. Returns #scans touched."""
    now = utcnow()
    running = (
        db.execute(select(Scan).where(Scan.status == ScanStatus.RUNNING.value)).scalars().all()
    )
    touched = 0
    for scan in running:
        steps = _steps(db, scan)
        changed = False
        for s in steps:
            if (
                s.status == StepStatus.RUNNING.value
                and _age_seconds(s.started_at, now) > step_timeout_s
            ):
                s.status = StepStatus.FAILED.value
                s.error = "step timed out (reaper)"
                s.finished_at = now
                db.add(s)
                changed = True
            elif (
                s.status == StepStatus.QUEUED.value
                and _age_seconds(s.updated_at, now) > requeue_after_s
            ):
                s.status = StepStatus.PENDING.value  # lost job -> re-enqueue
                db.add(s)
                changed = True
        if changed:
            db.commit()
            touched += 1
        enqueue_ready(db, scan)
    return touched


def cancel_scan(db: Session, scan: Scan) -> None:
    for step in _steps(db, scan):
        if step.status in (StepStatus.PENDING.value, StepStatus.QUEUED.value):
            step.status = StepStatus.SKIPPED.value
            step.error = "cancelled"
            step.finished_at = utcnow()
            db.add(step)
    scan.status = ScanStatus.CANCELLED.value
    scan.finished_at = utcnow()
    db.add(scan)
    db.flush()
