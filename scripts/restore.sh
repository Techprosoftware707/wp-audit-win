#!/usr/bin/env bash
# Restore a wp-audit-win backup tarball produced by backup.sh.
# Usage: ./scripts/restore.sh backups/wpsec-backup-<ts>.tar.gz
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
. ./.env 2>/dev/null || true

ARCHIVE="${1:-}"
[ -n "$ARCHIVE" ] && [ -f "$ARCHIVE" ] || { echo "usage: $0 <backup.tar.gz>" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
tar -C "$TMP" -xzf "$ARCHIVE"
DIR="$(find "$TMP" -maxdepth 1 -type d -name 'wpsec-backup-*' | head -1)"
[ -n "$DIR" ] || { echo "invalid backup archive" >&2; exit 1; }

echo "[restore] WARNING: this overwrites the current database."
read -r -p "Continue? [y/N] " ans
[ "$ans" = "y" ] || { echo "aborted"; exit 1; }

echo "[restore] ensuring database service is up"
docker compose up -d postgres
sleep 3

echo "[restore] restoring PostgreSQL"
gunzip -c "${DIR}/postgres.sql.gz" | docker compose exec -T postgres \
  psql -U "${POSTGRES_USER:-wpsec}" "${POSTGRES_DB:-wpsec}"

if [ -f "${DIR}/evidence.tar.gz" ]; then
  echo "[restore] restoring MinIO evidence"
  docker compose up -d minio; sleep 3
  tar -C "$TMP" -xzf "${DIR}/evidence.tar.gz"
  docker compose cp "$TMP/evidence-export" minio:/tmp/evidence-import >/dev/null 2>&1 || true
  docker compose exec -T minio sh -c '
    mc alias set local http://localhost:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null 2>&1 &&
    mc mb -p "local/${MINIO_BUCKET:-wpsec-evidence}" >/dev/null 2>&1;
    mc mirror --quiet /tmp/evidence-import "local/${MINIO_BUCKET:-wpsec-evidence}" >/dev/null 2>&1' || \
    echo "[restore] evidence restore skipped"
fi

echo "[restore] restarting stack"
docker compose up -d
echo "[restore] done"
