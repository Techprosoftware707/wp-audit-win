#!/usr/bin/env bash
# Entrypoint for the wp-audit-win backend/worker image.
# Usage: entrypoint <api|worker|migrate|bootstrap|shell>
set -euo pipefail

CMD="${1:-api}"

wait_for_db() {
  python - <<'PY'
import os, time, sys
import sqlalchemy
from sqlalchemy import text
url = (
    f"postgresql+psycopg://{os.environ['POSTGRES_USER']}:{os.environ['POSTGRES_PASSWORD']}"
    f"@{os.environ.get('POSTGRES_HOST','postgres')}:{os.environ.get('POSTGRES_PORT','5432')}"
    f"/{os.environ['POSTGRES_DB']}"
)
for i in range(60):
    try:
        e = sqlalchemy.create_engine(url)
        with e.connect() as c:
            c.execute(text("SELECT 1"))
        print("database is ready")
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        print(f"waiting for database ({i})... {exc}", flush=True)
        time.sleep(2)
print("database not reachable", file=sys.stderr)
sys.exit(1)
PY
}

case "$CMD" in
  api)
    wait_for_db
    echo "[entrypoint] running migrations"
    alembic upgrade head
    echo "[entrypoint] bootstrapping admin (idempotent)"
    python -m app.cli.bootstrap || true
    echo "[entrypoint] starting API"
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'
    ;;
  worker)
    wait_for_db
    echo "[entrypoint] starting worker ${WPSEC_WORKER_NAME:-worker}"
    exec python -m app.workers.runner
    ;;
  migrate)
    wait_for_db
    exec alembic upgrade head
    ;;
  bootstrap)
    wait_for_db
    exec python -m app.cli.bootstrap
    ;;
  shell)
    exec /bin/bash
    ;;
  *)
    exec "$@"
    ;;
esac
