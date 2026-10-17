#!/usr/bin/env bash
# =============================================================================
# wp-audit-win uninstaller.
#
# Stops and removes the application's containers (and optionally its images and
# data volumes). SAFE BY DEFAULT: it never deletes your database, backups, or
# .env unless you pass --purge, and it never touches unrelated Docker resources
# or user data elsewhere on the host.
#
#   ./scripts/uninstall.sh            # stop + remove containers; keep data/.env/backups
#   ./scripts/uninstall.sh --purge    # ALSO remove data volumes, images, .env (DESTRUCTIVE)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

say()  { printf "\033[1;36m[uninstall]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[warn]\033[0m %s\n" "$*"; }

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

if ! command -v docker >/dev/null 2>&1; then
  warn "Docker not found; nothing to stop. Removing only local build artifacts."
else
  say "Stopping and removing application containers (all profiles)"
  # --remove-orphans cleans up containers from profiles too; volumes are kept.
  docker compose --profile scanners down --remove-orphans || docker compose down --remove-orphans || true
fi

# Local build artifacts are always safe to remove (reproducible).
rm -rf wordpress-plugin/dist 2>/dev/null || true
say "Removed built plugin artifact (wordpress-plugin/dist)"

if [ "$PURGE" -eq 1 ]; then
  warn "PURGE requested — this permanently deletes the database, object storage,"
  warn "generated secrets (.env), and application data directories."
  read -r -p "Type 'purge' to confirm destructive removal: " ans
  if [ "$ans" = "purge" ]; then
    if command -v docker >/dev/null 2>&1; then
      say "Removing named data volumes and built images"
      docker compose --profile scanners down -v --rmi local --remove-orphans \
        || docker compose down -v --rmi local --remove-orphans || true
    fi
    rm -rf data 2>/dev/null || true          # reports/evidence local fallback
    rm -f .env 2>/dev/null || true           # generated secrets
    say "Removed data/ and .env."
    warn "Backups in ./backups were KEPT. Delete them manually if you are sure."
  else
    warn "Purge not confirmed; left all data in place."
  fi
else
  say "Kept: database volumes, object storage, ./backups, ./data, and .env."
  say "Re-run with --purge to remove those too."
fi

cat <<EOF

============================================================
 wp-audit-win uninstalled (containers stopped/removed).

 Kept (unless --purge): .env, ./backups, ./data, data volumes.
 To also remove the companion WordPress plugin, delete it from
 each WordPress site's Plugins screen (its uninstall.php cleans
 up its own options). Unrelated Docker resources were untouched.
============================================================
EOF
