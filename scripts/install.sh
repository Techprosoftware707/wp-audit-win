#!/usr/bin/env bash
# =============================================================================
# wp-audit-win installer (Ubuntu 24.04 LTS)
#
# Checks the host, installs Docker if needed, generates strong secrets, starts
# the stack, runs migrations, creates the initial administrator, and runs
# health checks.  Idempotent: re-running keeps existing secrets.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

say()  { printf "\033[1;36m[install]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[warn]\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m[error]\033[0m %s\n" "$*" >&2; exit 1; }

# --- 1. Check Ubuntu version -------------------------------------------------
if [ -r /etc/os-release ]; then
  . /etc/os-release
  say "Detected: ${PRETTY_NAME:-unknown}"
  case "${VERSION_ID:-}" in
    24.04) : ;;
    22.04) warn "Ubuntu 22.04 detected; 24.04 is recommended but this should work." ;;
    *) warn "Untested Ubuntu/Linux version '${VERSION_ID:-?}'. Continuing." ;;
  esac
else
  warn "Cannot read /etc/os-release; continuing anyway."
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "Run as root or install sudo."
  SUDO="sudo"
fi

# --- 2/3. Install host dependencies + Docker ---------------------------------
if ! command -v openssl >/dev/null 2>&1; then
  say "Installing openssl"
  $SUDO apt-get update -y && $SUDO apt-get install -y openssl
fi

if ! command -v docker >/dev/null 2>&1; then
  say "Docker not found; installing via get.docker.com"
  curl -fsSL https://get.docker.com | $SUDO sh
  $SUDO systemctl enable --now docker || true
else
  say "Docker present: $(docker --version)"
fi

if ! docker compose version >/dev/null 2>&1; then
  die "Docker Compose v2 plugin is required (docker compose). Please install it."
fi

# --- 4. Create application directories ---------------------------------------
mkdir -p data/reports backups

# --- 5. Generate secrets (only if .env is missing) ---------------------------
gen() { openssl rand -base64 "${1:-32}" | tr -d '\n'; }
fernet() { openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'; }

if [ ! -f .env ]; then
  say "Generating .env with fresh secrets"
  ADMIN_PW="$(gen 18 | tr -d '/+=' | cut -c1-24)"
  cp .env.example .env
  # Fill secrets in place.
  sed -i "s|^WPSEC_SECRET_KEY=.*|WPSEC_SECRET_KEY=$(gen 48 | tr -d '/+=' )|" .env
  sed -i "s|^WPSEC_CREDENTIAL_KEY=.*|WPSEC_CREDENTIAL_KEY=$(fernet)|" .env
  sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(gen 24 | tr -d '/+=' )|" .env
  sed -i "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=$(gen 24 | tr -d '/+=' )|" .env
  sed -i "s|^MINIO_ROOT_PASSWORD=.*|MINIO_ROOT_PASSWORD=$(gen 24 | tr -d '/+=' )|" .env
  sed -i "s|^WPSEC_ADMIN_PASSWORD=.*|WPSEC_ADMIN_PASSWORD=${ADMIN_PW}|" .env
  chmod 600 .env
else
  say ".env already exists; keeping existing secrets."
  ADMIN_PW="$(grep -E '^WPSEC_ADMIN_PASSWORD=' .env | cut -d= -f2-)"
fi

ADMIN_EMAIL="$(grep -E '^WPSEC_ADMIN_EMAIL=' .env | cut -d= -f2-)"
PUBLIC_URL="$(grep -E '^WPSEC_PUBLIC_URL=' .env | cut -d= -f2-)"

# --- 6/7. Start services -----------------------------------------------------
say "Building and starting the stack (this can take a while on first run)…"
docker compose up -d --build

# --- 8. Migrations + 9. admin (handled by the api entrypoint) ---------------
say "Waiting for the API to become healthy…"
ok=0
for i in $(seq 1 60); do
  if docker compose exec -T api curl -fsS http://localhost:8000/health >/dev/null 2>&1; then
    ok=1; break
  fi
  sleep 3
done
[ "$ok" -eq 1 ] || { docker compose logs --tail=50 api; die "API did not become healthy."; }

# --- 10. Health checks -------------------------------------------------------
say "Running health checks"
./scripts/health-check.sh || warn "Some health checks reported issues (see above)."

# --- 11. Dashboard URL -------------------------------------------------------
cat <<EOF

============================================================
 wp-audit-win is up.

   Dashboard : ${PUBLIC_URL:-https://localhost}
   API docs  : ${PUBLIC_URL:-https://localhost}/api/docs
   Login     : ${ADMIN_EMAIL}
   Password  : ${ADMIN_PW}

 (The TLS certificate is self-signed by default; your browser
  will warn on first visit. Point a real domain at this host and
  edit deploy/caddy/Caddyfile for automatic Let's Encrypt certs.)

 Heavy scanners (WPScan/ZAP/WP-CLI) are optional:
   docker compose --profile scanners up -d
============================================================
EOF
