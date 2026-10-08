#!/usr/bin/env bash
# Back up the wp-audit-win database, MinIO evidence, and .env to a timestamped
# tarball under ./backups.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
. ./.env 2>/dev/null || true

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="backups/wpsec-backup-${TS}"
mkdir -p "$OUT"

echo "[backup] dumping PostgreSQL"
# --clean --if-exists so restore can overwrite a populated database.
docker compose exec -T postgres pg_dump --clean --if-exists \
  -U "${POSTGRES_USER:-wpsec}" "${POSTGRES_DB:-wpsec}" \
  | gzip > "${OUT}/postgres.sql.gz"

echo "[backup] exporting MinIO evidence bucket"
if docker compose exec -T minio sh -c '
  mc alias set local http://localhost:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null 2>&1 &&
  mc mirror --quiet "local/${MINIO_BUCKET:-wpsec-evidence}" /tmp/evidence-export >/dev/null 2>&1 &&
  tar -C /tmp -czf - evidence-export' > "${OUT}/evidence.tar.gz" 2>/dev/null; then
  echo "[backup] evidence exported"
else
  echo "[backup] evidence bucket empty or MinIO unavailable; skipping"
  rm -f "${OUT}/evidence.tar.gz"
fi

echo "[backup] copying .env (contains secrets — keep this archive secure)"
cp .env "${OUT}/env.backup" 2>/dev/null || true

tar -C backups -czf "${OUT}.tar.gz" "$(basename "$OUT")"
rm -rf "$OUT"
echo "[backup] wrote ${OUT}.tar.gz"
