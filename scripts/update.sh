#!/usr/bin/env bash
# Update wp-audit-win: pull latest code, rebuild images, run migrations.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[update] backing up before update"
./scripts/backup.sh || echo "[update] backup failed/skipped; continuing"

if [ -d .git ]; then
  echo "[update] pulling latest code"
  git pull --ff-only || echo "[update] git pull skipped (local changes or detached HEAD)"
fi

echo "[update] rebuilding and restarting"
docker compose up -d --build

echo "[update] running migrations"
docker compose exec -T api alembic upgrade head

echo "[update] health check"
./scripts/health-check.sh || true
echo "[update] done"
