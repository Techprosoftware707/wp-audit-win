#!/usr/bin/env bash
# System health check for wp-audit-win. Exits non-zero if a core component fails.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Load secrets (REDIS_PASSWORD etc.) so checks authenticate correctly.
set -a
# shellcheck disable=SC1091
[ -f ./.env ] && . ./.env
set +a

pass() { printf "  \033[1;32m✓\033[0m %s\n" "$*"; }
fail() { printf "  \033[1;31m✗\033[0m %s\n" "$*"; FAILED=1; }
FAILED=0

echo "wp-audit-win health check"

check() {  # name  command...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}

check "docker daemon"          docker info
check "postgres"               docker compose exec -T postgres pg_isready
check "redis"                  bash -c 'docker compose exec -T redis redis-cli -a "'"${REDIS_PASSWORD:-}"'" --no-auth-warning ping 2>/dev/null | grep -q PONG'
check "minio"                  docker compose exec -T minio mc --version
check "api /health"            docker compose exec -T api curl -fsS http://localhost:8000/health
check "frontend"               docker compose exec -T frontend wget -qO- http://localhost:3000 --timeout=5

# Workers online (reported via the API).
if docker compose exec -T api curl -fsS http://localhost:8000/health/detailed >/dev/null 2>&1; then
  pass "detailed health endpoint reachable"
fi

# Optional scanner tools (only present with the scanners profile).
for svc in worker-wpscan worker-zap worker-wpcli zap; do
  if docker compose ps --services --status running 2>/dev/null | grep -q "^${svc}$"; then
    pass "optional scanner service: ${svc} running"
  fi
done

# Host resources.
DISK_FREE=$(df -Pk . | awk 'NR==2{printf "%d", $4/1024}')
echo "  disk free: ${DISK_FREE} MB"
MEM=$(free -m 2>/dev/null | awk '/Mem:/{print $7}') || MEM="n/a"
echo "  mem available: ${MEM} MB"

if [ "$FAILED" -ne 0 ]; then
  echo "Health check: FAILURES detected."
  exit 1
fi
echo "Health check: all core components healthy."
