"""Worker runtime.

Consumes jobs from its configured queues, executes the step, advances the scan,
and maintains a heartbeat row in the ``workers`` table so the orchestrator knows
which queues have a live worker and the dashboard can show worker health.
"""

from __future__ import annotations

import os
import platform
import resource
import signal
import socket
import threading
import time

from sqlalchemy import select

from app import __version__
from app.core.config import settings
from app.core.db import session_scope
from app.core.logging import configure_logging, get_logger
from app.core.redis import get_queue
from app.models.base import utcnow
from app.models.enums import WorkerStatus
from app.models.scan import Scan, ScanStep
from app.models.system import Worker
from app.services import scan_orchestrator

log = get_logger("worker")
_stop = threading.Event()


def _ram_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KB, macOS bytes.
    return (
        round(usage / 1024.0, 1)
        if platform.system() == "Linux"
        else round(usage / 1024.0 / 1024.0, 1)
    )


def _cpu() -> float:
    try:
        return round(os.getloadavg()[0], 2)
    except OSError:
        return 0.0


def _upsert_worker(status: str, current_job: str | None = None, inc_job: bool = False) -> None:
    with session_scope() as db:
        w = db.execute(
            select(Worker).where(Worker.name == settings.worker_name)
        ).scalar_one_or_none()
        if w is None:
            w = Worker(name=settings.worker_name)
            db.add(w)
        w.queues = ",".join(settings.worker_queue_list)
        w.status = status
        w.host = socket.gethostname()
        w.version = __version__
        w.current_job = current_job
        w.cpu_percent = _cpu()
        w.ram_mb = _ram_mb()
        w.last_heartbeat = utcnow()
        if inc_job:
            w.job_count = (w.job_count or 0) + 1


def _heartbeat_loop() -> None:
    while not _stop.is_set():
        try:
            _upsert_worker(WorkerStatus.ONLINE.value)
        except Exception as exc:  # noqa: BLE001
            log.warning("heartbeat failed: %s", exc)
        _stop.wait(20)


def _handle_job(job: dict) -> None:
    step_id = job.get("step_id")
    if not step_id:
        return
    _upsert_worker(
        WorkerStatus.BUSY.value, current_job=f"{job.get('step_name')}:{step_id}", inc_job=True
    )
    with session_scope() as db:
        scan_orchestrator.run_step(db, step_id)
        step = db.get(ScanStep, step_id)
        if step is not None:
            scan = db.get(Scan, step.scan_id)
            if scan is not None:
                scan_orchestrator.advance(db, scan)
    _upsert_worker(WorkerStatus.ONLINE.value, current_job=None)


def main() -> None:
    configure_logging()
    queues = settings.worker_queue_list
    log.info(
        "worker '%s' starting; queues=%s backend=%s",
        settings.worker_name,
        queues,
        settings.queue_backend,
    )

    def _sig(_signum, _frame):
        log.info("shutdown signal received")
        _stop.set()

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    _upsert_worker(WorkerStatus.ONLINE.value)
    hb = threading.Thread(target=_heartbeat_loop, daemon=True)
    hb.start()

    q = get_queue()
    while not _stop.is_set():
        try:
            job = q.dequeue(queues, timeout=5)
        except Exception as exc:  # noqa: BLE001
            log.warning("dequeue error: %s", exc)
            time.sleep(2)
            continue
        if job is None:
            continue
        try:
            _handle_job(job)
        except Exception:  # noqa: BLE001
            log.exception("job failed: %s", job)

    _upsert_worker(WorkerStatus.OFFLINE.value)
    log.info("worker '%s' stopped", settings.worker_name)


if __name__ == "__main__":
    main()
